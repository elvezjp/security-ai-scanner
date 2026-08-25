"""Schema-version-1 run identity and subject resolution."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from uuid import UUID, uuid4


SCHEMA_VERSION = 1
_FULL_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GIT_TIMEOUT_SECONDS = 5
_GIT_ENVIRONMENT_OVERRIDES = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_CONFIG_COUNT",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
}


@dataclass(frozen=True)
class Subject:
    """Identity of the content selected for one scan."""

    kind: str
    root: str
    head_sha: str | None
    base_sha: str | None
    dirty: bool | None
    content_digest: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NativeRun:
    """Values shared by every native artifact from one invocation."""

    run_id: str
    generated_at: str
    subject: Subject
    schema_version: int = SCHEMA_VERSION

    def metadata(self, *, tool: str, version: str) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "tool": tool,
            "version": version,
            "generated_at": self.generated_at,
            "subject": self.subject.to_dict(),
        }


def _filesystem_subject(root: Path) -> Subject:
    return Subject(
        kind="filesystem",
        root=str(root),
        head_sha=None,
        base_sha=None,
        dirty=None,
        content_digest=None,
    )


def _run_git(executable: str, root: Path, arguments: Sequence[str]) -> bytes:
    """Run one fixed git command without a shell and return stdout."""
    environment = os.environ.copy()
    for key in tuple(environment):
        if (
            key in _GIT_ENVIRONMENT_OVERRIDES
            or key.startswith("GIT_CONFIG_KEY_")
            or key.startswith("GIT_CONFIG_VALUE_")
        ):
            environment.pop(key)
    environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        [
            executable,
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-C",
            str(root),
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        shell=False,
        timeout=_GIT_TIMEOUT_SECONDS,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git exited with status {completed.returncode}")
    return completed.stdout


def resolve_subject(target: Path) -> Subject:
    """Resolve Git identity when safely available, otherwise use filesystem."""
    root = target.resolve()
    fallback = _filesystem_subject(root)
    executable = shutil.which("git")
    if executable is None:
        return fallback

    try:
        inside = _run_git(
            executable, root, ("rev-parse", "--is-inside-work-tree")
        ).strip()
        if inside != b"true":
            return fallback

        head_sha = _run_git(
            executable, root, ("rev-parse", "--verify", "HEAD")
        ).decode("ascii").strip().lower()
        if not _FULL_OBJECT_ID.fullmatch(head_sha):
            return fallback

        status = _run_git(
            executable,
            root,
            (
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                ".",
            ),
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, UnicodeError):
        return fallback

    return Subject(
        kind="git",
        root=str(root),
        head_sha=head_sha,
        base_sha=None,
        dirty=bool(status.strip()),
        content_digest=None,
    )


def format_utc(value: datetime) -> str:
    """Return an RFC 3339 timestamp normalized to UTC with a ``Z`` suffix."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def create_native_run(
    target: Path,
    *,
    generated_at: datetime | None = None,
    run_id: UUID | None = None,
) -> NativeRun:
    """Create the run identity once, before analysis starts."""
    return NativeRun(
        run_id=str(run_id or uuid4()),
        generated_at=format_utc(generated_at or datetime.now(timezone.utc)),
        subject=resolve_subject(target),
    )
