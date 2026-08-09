"""Tests for pointing the scanner at a local (self-hosted) endpoint."""

from pathlib import Path

import pytest

from security_ai_scanner.cli import build_parser
from security_ai_scanner.config import ScanConfig
from security_ai_scanner.engine.base import ScanRequest
from security_ai_scanner.engine.claude import _build_env
from security_ai_scanner.runner import build_user_prompt


def _request(**overrides) -> ScanRequest:
    base = dict(
        prompt="p",
        system_prompt="s",
        cwd=Path("/tmp"),
        output_schema={},
    )
    base.update(overrides)
    return ScanRequest(**base)


class TestStructuredOutputDefault:
    def test_hosted_api_uses_structured_output(self):
        assert ScanConfig(target=Path(".")).use_structured_output() is True

    def test_local_endpoint_disables_structured_output(self):
        config = ScanConfig(target=Path("."), base_url="http://127.0.0.1:8000")
        assert config.use_structured_output() is False

    def test_explicit_override_wins(self):
        config = ScanConfig(
            target=Path("."),
            base_url="http://127.0.0.1:8000",
            structured_output=True,
        )
        assert config.use_structured_output() is True


class TestBuildEnv:
    def test_hosted_api_sets_no_overrides(self):
        assert _build_env(_request()) == {}

    def test_local_endpoint_sets_base_url_and_token(self):
        env = _build_env(
            _request(base_url="http://127.0.0.1:8000", auth_token="local-token")
        )
        assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8000"
        assert env["ANTHROPIC_AUTH_TOKEN"] == "local-token"

    def test_hosted_credentials_are_cleared(self):
        env = _build_env(_request(base_url="http://127.0.0.1:8000"))
        assert env["ANTHROPIC_API_KEY"] == ""
        assert env["CLAUDE_CODE_OAUTH_TOKEN"] == ""

    def test_default_auth_token(self):
        env = _build_env(_request(base_url="http://127.0.0.1:8000"))
        assert env["ANTHROPIC_AUTH_TOKEN"] == "local"

    def test_model_pins_every_slot(self):
        env = _build_env(
            _request(base_url="http://127.0.0.1:8000", model="deepseek-v4-flash")
        )
        for slot in (
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            "CLAUDE_CODE_SUBAGENT_MODEL",
        ):
            assert env[slot] == "deepseek-v4-flash"

    def test_no_model_leaves_slots_unset(self):
        env = _build_env(_request(base_url="http://127.0.0.1:8000"))
        assert "ANTHROPIC_MODEL" not in env


class TestPromptFallback:
    def test_json_instruction_added_when_unstructured(self):
        config = ScanConfig(target=Path("."), base_url="http://127.0.0.1:8000")
        prompt = build_user_prompt(config)
        assert "```json" in prompt
        assert '"findings"' in prompt

    def test_no_json_instruction_for_hosted_api(self):
        prompt = build_user_prompt(ScanConfig(target=Path(".")))
        assert "```json" not in prompt


class TestCliArgs:
    def test_base_url_and_token(self, tmp_path):
        args = build_parser().parse_args(
            [
                "scan",
                str(tmp_path),
                "--base-url",
                "http://127.0.0.1:8000",
                "--auth-token",
                "t",
                "--model",
                "deepseek-v4-flash",
            ]
        )
        assert args.base_url == "http://127.0.0.1:8000"
        assert args.auth_token == "t"
        assert args.model == "deepseek-v4-flash"
        assert args.structured_output is None

    @pytest.mark.parametrize(
        "flag,expected",
        [("--structured-output", True), ("--no-structured-output", False)],
    )
    def test_structured_output_toggle(self, tmp_path, flag, expected):
        args = build_parser().parse_args(["scan", str(tmp_path), flag])
        assert args.structured_output is expected


class TestAuthTokenEnvVar:
    def _config(self, argv):
        from security_ai_scanner.cli import _config_from_args

        return _config_from_args(build_parser().parse_args(argv))

    def test_env_var_is_used(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAIS_AUTH_TOKEN", "from-env")
        config = self._config(["scan", str(tmp_path)])
        assert config.auth_token == "from-env"

    def test_cli_flag_wins_over_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAIS_AUTH_TOKEN", "from-env")
        config = self._config(
            ["scan", str(tmp_path), "--auth-token", "from-flag"]
        )
        assert config.auth_token == "from-flag"

    def test_unset_leaves_none(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SAIS_AUTH_TOKEN", raising=False)
        config = self._config(["scan", str(tmp_path)])
        assert config.auth_token is None

    def test_explicit_empty_flag_overrides_env_var(self, tmp_path, monkeypatch):
        # `--auth-token ""` is an explicit "send no credential"; it must
        # not fall through to a token meant for a different endpoint.
        monkeypatch.setenv("SAIS_AUTH_TOKEN", "from-env")
        config = self._config(["scan", str(tmp_path), "--auth-token", ""])
        assert config.auth_token == ""

        request = ScanRequest(
            prompt="p",
            system_prompt="s",
            cwd=tmp_path,
            output_schema={},
            base_url="http://localhost:8080",
            auth_token=config.auth_token,
        )
        assert _build_env(request)["ANTHROPIC_AUTH_TOKEN"] == "local"

    def test_empty_env_var_leaves_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAIS_AUTH_TOKEN", "")
        config = self._config(["scan", str(tmp_path)])
        assert config.auth_token is None
