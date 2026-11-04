"""Machine-owned AI connection contract shared with code-ai-reviewer.

Keep this dependency-free module identical in both distributions. Environment
and profile loading is opt-in; importing it never reads machine settings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import tomllib
from typing import Mapping
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_endpoint(request, *, timeout):
    # Credentials and repository content must stay at the selected endpoint.
    return build_opener(_NoRedirect()).open(request, timeout=timeout)


def enclosing_repository(path: Path) -> Path | None:
    root = path.resolve()
    return next((p for p in (root, *root.parents) if (p / ".git").exists()), None)


def outside_target(path: Path, target: Path | None) -> Path:
    try:
        resolved = path.expanduser().resolve()
        boundary = (enclosing_repository(target) or target.resolve()) if target is not None else None
        if boundary is not None and resolved.is_relative_to(boundary):
            raise ValueError("Connection files must be outside the target repository")
        return resolved
    except (OSError, RuntimeError):
        raise ValueError("Cannot resolve connection file") from None


@dataclass(frozen=True)
class ConnectionSettings:
    engine: str
    base_url: str | None = field(default=None, repr=False)
    model: str | None = None
    auth_token: str | None = field(default=None, repr=False)
    auth_token_file: Path | None = field(default=None, repr=False)
    source_file: Path | None = field(default=None, repr=False)

    def as_kwargs(self, target: Path | None = None) -> dict:
        if self.source_file is not None:
            outside_target(self.source_file, target)
        if self.auth_token_file is not None:
            outside_target(self.auth_token_file, target)
        return {name: getattr(self, name) for name in
                ("engine", "base_url", "model", "auth_token", "auth_token_file")}


def validate_connection(engine, base_url, model, auth_token, auth_token_file):
    if auth_token is not None and (not isinstance(auth_token, str)
                                  or any(ord(c) < 32 or ord(c) == 127 for c in auth_token)):
        raise ValueError("Authentication token contains invalid characters")
    if model == "auto" and engine != "openai":
        raise ValueError("model=auto requires the openai engine")
    if auth_token is not None and auth_token_file is not None:
        raise ValueError("Choose auth_token or auth_token_file, not both")
    if base_url is not None:
        try:
            parsed = urlsplit(base_url)
            valid = (parsed.scheme in {"http", "https"} and parsed.hostname
                     and parsed.username is None and parsed.password is None
                     and not parsed.query and not parsed.fragment)
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Connection URL must be HTTP(S) without credentials, query, or fragment")


def load_connection_settings(*, prefix: str, target: Path | None = None,
                             profile: str | None = None, config_path: Path | None = None,
                             engine: str | None = None, base_url: str | None = None,
                             model: str | None = None, auth_token: str | None = None,
                             auth_token_file: Path | str | None = None,
                             environ: Mapping[str, str] | None = None) -> ConnectionSettings:
    """Opt in to CLI > environment > selected machine profile resolution.

    Credential value/file forms compete as one setting at each precedence
    level, so an explicit empty CLI value never falls back to an ambient key.
    """
    if prefix not in {"SAIS", "CAIR"}:
        raise ValueError("Unknown connection settings prefix")
    env = os.environ if environ is None else environ
    selected = profile if profile is not None else env.get(prefix + "_PROFILE")
    source = None
    values = {}
    if selected:
        configured = config_path or env.get(prefix + "_CONFIG")
        default = Path(env.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "elvez-quality-gate/config.toml"
        source = outside_target(Path(configured) if configured else default, target)
        try:
            with source.open("rb") as stream:
                document = tomllib.load(stream)
        except (OSError, ValueError):
            # Parser diagnostics may contain profile contents or credential paths.
            raise ValueError("Cannot read a valid machine connection configuration") from None
        profiles = document.get("profiles")
        if not isinstance(profiles, dict) or not isinstance(profiles.get(selected), dict):
            raise ValueError("Selected connection profile does not exist")
        values = profiles[selected]
        allowed = {"engine", "base_url", "model", "auth_token_file"}
        if set(values) - allowed or any(not isinstance(v, str) or not v for v in values.values()):
            raise ValueError("Connection profile has unsupported fields or invalid values")

    resolved = {}
    for key, explicit in (("engine", engine), ("base_url", base_url), ("model", model)):
        resolved[key] = explicit if explicit is not None else env.get(prefix + "_" + key.upper()) or values.get(key)
    resolved["engine"] = resolved["engine"] or ("claude" if prefix == "SAIS" else "openai")
    token, token_file = auth_token, auth_token_file
    relative_to = Path.cwd()
    if token is None and token_file is None:
        token = env.get(prefix + "_AUTH_TOKEN") or None
        token_file = env.get(prefix + "_AUTH_TOKEN_FILE") or None
        if token is None and token_file is None:
            token_file = values.get("auth_token_file")
            relative_to = source.parent if source is not None else Path.cwd()
    if resolved["engine"] not in {"openai", "claude"}:
        raise ValueError("Unknown connection engine")
    validate_connection(**resolved, auth_token=token, auth_token_file=token_file)
    if token_file is not None:
        path = Path(token_file).expanduser()
        token_file = outside_target(path if path.is_absolute() else relative_to / path, target)
    result = ConnectionSettings(**resolved, auth_token=token, auth_token_file=token_file, source_file=source)
    result.as_kwargs(target)
    return result


def read_auth_token(auth_token: str | None, auth_token_file: Path | None,
                    *, target: Path) -> str | None:
    """Read a private regular credential file at each run, without path errors."""
    if auth_token_file is None:
        return auth_token
    if auth_token is not None:
        raise ValueError("Choose auth_token or auth_token_file, not both")
    path = outside_target(Path(auth_token_file), target)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Credential file must be a regular file")
            if os.name == "posix" and info.st_mode & 0o044:
                raise ValueError("Credential file must not be readable by group or others (use chmod 600)")
            raw = stream.read(65_537)
        if len(raw) > 65_536:
            raise ValueError("Credential file is too large")
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        token = raw.decode("utf-8")
        if not token or any(ord(c) < 32 or ord(c) == 127 for c in token):
            raise ValueError("Credential file must contain one nonempty token")
        return token
    except (OSError, UnicodeError):
        raise ValueError("Cannot read credential file") from None


def redact(value, secrets):
    """Remove known credentials from reflected endpoint text and metadata."""
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(str(secret), "[redacted]")
        return value
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, dict):
        return {redact(key, secrets): redact(item, secrets) for key, item in value.items()}
    return value


def resolve_model(requested: str, base_url: str, headers: dict, transport):
    """Resolve only a single advertised model; never pick one from a list."""
    if requested != "auto":
        return requested, {}
    document = transport(base_url.rstrip("/") + "/models", None, headers)
    entries = document.get("data") if isinstance(document, dict) else None
    if (not isinstance(entries, list) or not entries
            or any(not isinstance(item, dict) or not isinstance(item.get("id"), str)
                   or not item["id"].strip() for item in entries)):
        raise ValueError("model=auto requires a valid nonempty /models list")
    if len(entries) != 1:
        names = ", ".join(item["id"] for item in entries[:20])
        raise ValueError("model=auto requires exactly one model; available: " + names)
    selected = entries[0]
    if selected.get("ixv_mode") == "beast":
        raise ValueError("model=auto refuses IXV beast mode for quality gates")
    metadata = {}
    if isinstance(selected.get("file"), str):
        metadata["file"] = Path(selected["file"]).name
    if type(selected.get("context_length")) is int and selected["context_length"] > 0:
        metadata["context_length"] = selected["context_length"]
    if isinstance(selected.get("ixv_mode"), str):
        metadata["ixv_mode"] = selected["ixv_mode"]
    return selected["id"], metadata
