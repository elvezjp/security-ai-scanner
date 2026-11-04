"""Shared machine-profile and credential contract (also run by cair)."""
from pathlib import Path
import os

import pytest

from security_ai_scanner.connection import load_connection_settings, read_auth_token


@pytest.fixture
def setup(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    config = tmp_path / "config.toml"
    config.write_text('[profiles.local]\nengine="openai"\nbase_url="http://profile.invalid/v1"\nmodel="profile-model"\nauth_token_file="token"\n')
    token = tmp_path / "token"
    token.write_text("profile-key\n")
    token.chmod(0o600)
    return target, config, token


@pytest.mark.parametrize("prefix", ["SAIS", "CAIR"])
def test_shared_profile_and_field_precedence(setup, prefix):
    target, config, token = setup
    env = {prefix + "_CONFIG": str(config), prefix + "_PROFILE": "local"}
    load = lambda **kw: load_connection_settings(prefix=prefix, target=target, environ=env, **kw)
    assert load().as_kwargs(target) == dict(engine="openai", base_url="http://profile.invalid/v1", model="profile-model", auth_token=None, auth_token_file=token.resolve())
    env.update({prefix + "_ENGINE": "claude", prefix + "_BASE_URL": "http://env.invalid", prefix + "_MODEL": "env-model", prefix + "_AUTH_TOKEN": "env-key"})
    selected = load()
    assert (selected.engine, selected.base_url, selected.model, selected.auth_token_file, selected.auth_token) == ("claude", "http://env.invalid", "env-model", None, "env-key")
    selected = load(engine="openai", base_url="http://cli.invalid", model="cli-model", auth_token="")
    assert (selected.engine, selected.base_url, selected.model, selected.auth_token) == ("openai", "http://cli.invalid", "cli-model", "")
    assert "env-key" not in repr(load()) and str(token) not in repr(load())


def test_credential_forms_compete_at_the_same_level(setup):
    target, config, token = setup
    env = {"SAIS_CONFIG": str(config), "SAIS_PROFILE": "local", "SAIS_AUTH_TOKEN": "env"}
    selected = load_connection_settings(prefix="SAIS", target=target, environ=env, auth_token_file=token)
    assert selected.auth_token is None and selected.auth_token_file == token.resolve()
    env["SAIS_AUTH_TOKEN_FILE"] = str(token)
    with pytest.raises(ValueError, match="not both"):
        load_connection_settings(prefix="SAIS", target=target, environ=env)
    with pytest.raises(ValueError, match="not both"):
        load_connection_settings(prefix="SAIS", environ={}, auth_token="x", auth_token_file=token)


@pytest.mark.parametrize("link", [False, True])
def test_repository_connection_config_is_rejected_before_read(setup, monkeypatch, link):
    target, config, _ = setup
    inside = target / "config.toml"
    inside.write_text(config.read_text())
    chosen = inside
    if link:
        chosen = target.parent / "outside-link"
        try:
            chosen.symlink_to(inside)
        except OSError:
            pytest.skip("Symlink creation is unavailable")
    def forbidden(*args, **kwargs):
        raise AssertionError("Repository configuration was opened")
    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(ValueError, match="outside the target"):
        load_connection_settings(prefix="SAIS", target=target, profile="local", config_path=chosen, environ={})


def test_no_implicit_configuration_read_or_repository_discovery(setup, monkeypatch):
    target, config, _ = setup
    monkeypatch.chdir(target)
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected file read")
    monkeypatch.setattr(Path, "open", forbidden)
    selected = load_connection_settings(prefix="CAIR", target=target, environ={"CAIR_CONFIG": str(config)})
    assert selected.engine == "openai" and selected.model is None


def test_xdg_profile_location(setup):
    target, config, _ = setup
    xdg = target.parent / "machine"
    destination = xdg / "elvez-quality-gate/config.toml"
    destination.parent.mkdir(parents=True)
    destination.write_text('[profiles.local]\nengine="openai"\nmodel="auto"\n')
    selected = load_connection_settings(prefix="CAIR", target=target, profile="local", environ={"XDG_CONFIG_HOME":str(xdg)})
    assert selected.model == "auto" and selected.source_file == destination.resolve()


@pytest.mark.parametrize("content", ['[profiles.local]\npassword="secret-profile-value"', '[profiles.local]\nmodel=123', '[profiles.local]\nbroken="secret-profile-value'])
def test_bad_profile_does_not_echo_contents_or_path(setup, content):
    target, config, _ = setup
    config.write_text(content)
    with pytest.raises(ValueError) as error:
        load_connection_settings(prefix="SAIS", target=target, profile="local", config_path=config, environ={})
    assert "secret-profile-value" not in str(error.value)
    assert str(config) not in str(error.value)


@pytest.mark.parametrize("contents,expected", [(b" key \n", " key "), (b"key\r\n", "key"), (b"key", "key")])
def test_token_preserves_contents_except_one_newline(setup, contents, expected):
    target, _, token = setup
    token.write_bytes(contents)
    assert read_auth_token(None, token, target=target) == expected


@pytest.mark.parametrize("contents", [b"", b"key\n\n", b"key\nsecond", b"\xff", b"x" * 65537],
                         ids=["empty", "extra-newline", "multiline", "non-utf8", "oversized"])
def test_bad_token_is_not_echoed(setup, contents):
    target, _, token = setup
    token.write_bytes(contents)
    with pytest.raises(ValueError) as error:
        read_auth_token(None, token, target=target)
    assert str(token) not in str(error.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX access bits")
def test_group_or_other_readable_token_is_rejected(setup):
    target, _, token = setup
    for mode in (0o640, 0o604, 0o644):
        token.chmod(mode)
        with pytest.raises(ValueError, match="chmod 600"):
            read_auth_token(None, token, target=target)


def test_credentials_in_target_are_rejected(setup):
    target, _, _ = setup
    inside = target / "token"
    inside.write_text("do-not-use")
    inside.chmod(0o600)
    with pytest.raises(ValueError, match="outside the target"):
        read_auth_token(None, inside, target=target)


def test_token_is_reloaded_and_missing_path_is_not_echoed(setup):
    target, _, token = setup
    assert read_auth_token(None, token, target=target) == "profile-key"
    token.write_text("rotated-key\n")
    assert read_auth_token(None, token, target=target) == "rotated-key"
    token.unlink()
    with pytest.raises(ValueError) as error:
        read_auth_token(None, token, target=target)
    assert str(token) not in str(error.value)


@pytest.mark.parametrize("url", ["file:///tmp/a", "http://user:secret@host/v1", "http://host?token=secret", "http://host/#secret"])
def test_endpoint_credentials_and_query_are_not_accepted(url):
    with pytest.raises(ValueError) as error:
        load_connection_settings(prefix="CAIR", environ={}, base_url=url)
    assert "secret" not in str(error.value)


def test_parent_repository_boundary_is_checked_before_loading(setup):
    target, config, _ = setup
    (target / ".git").mkdir()
    nested = target / "nested"
    nested.mkdir()
    inside = target / "connection.toml"
    inside.write_text(config.read_text())
    with pytest.raises(ValueError, match="outside the target"):
        load_connection_settings(prefix="CAIR", target=nested, profile="local", config_path=inside, environ={})


def test_control_characters_in_environment_token_are_not_echoed():
    with pytest.raises(ValueError) as error:
        load_connection_settings(prefix="SAIS", environ={"SAIS_AUTH_TOKEN":"secret\r\nInjected: value"})
    assert "secret" not in str(error.value)
