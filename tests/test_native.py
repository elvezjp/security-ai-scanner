"""Tests for schema-version-1 run and subject identity."""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

import security_ai_scanner.native as native
from security_ai_scanner.native import create_native_run, resolve_subject


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.stdout.strip()


def _committed_repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "sais tests")
    _git(root, "config", "user.email", "sais@example.invalid")
    (root / "tracked.py").write_text("clean = True\n", encoding="utf-8")
    _git(root, "add", "tracked.py")
    _git(root, "commit", "-m", "initial")
    return root


def test_create_native_run_uses_one_uuid_and_utc_timestamp(tmp_path, monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda _name: None)
    run = create_native_run(
        tmp_path,
        generated_at=datetime(2026, 8, 25, 7, 0, tzinfo=timezone.utc),
        run_id=UUID("9e533fc0-a84d-44e1-91f3-11d8e54eac62"),
    )
    assert run.schema_version == 1
    assert run.run_id == "9e533fc0-a84d-44e1-91f3-11d8e54eac62"
    assert run.generated_at == "2026-08-25T07:00:00Z"
    assert run.subject.root == str(tmp_path.resolve())


def test_non_git_target_has_no_invented_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda _name: None)
    subject = resolve_subject(tmp_path)
    assert subject.kind == "filesystem"
    assert subject.head_sha is None
    assert subject.base_sha is None
    assert subject.dirty is None
    assert subject.content_digest is None


def test_git_failure_falls_back_without_failing_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda _name: "/usr/bin/git")

    def fail(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("git", 5)

    monkeypatch.setattr(native, "_run_git", fail)
    assert resolve_subject(tmp_path).kind == "filesystem"


def test_git_invocation_is_fixed_and_sanitizes_overrides(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setenv("GIT_DIR", "/hostile")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "hostile-command")

    class Completed:
        returncode = 0
        stdout = b"true\n"

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    native._run_git("/usr/bin/git", tmp_path, ("rev-parse", "--is-inside-work-tree"))

    assert captured["command"][:5] == [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={native.os.devnull}",
    ]
    assert captured["kwargs"]["shell"] is False
    environment = captured["kwargs"]["env"]
    assert "GIT_DIR" not in environment
    assert "GIT_CONFIG_COUNT" not in environment
    assert "GIT_CONFIG_KEY_0" not in environment
    assert "GIT_CONFIG_VALUE_0" not in environment


@pytest.mark.skipif(shutil.which("git") is None, reason="git is unavailable")
def test_clean_git_subject_uses_full_head(tmp_path):
    root = _committed_repository(tmp_path)
    subject = resolve_subject(root)
    assert subject.kind == "git"
    assert subject.head_sha == _git(root, "rev-parse", "HEAD")
    assert len(subject.head_sha) in (40, 64)
    assert subject.base_sha is None
    assert subject.dirty is False
    assert subject.content_digest is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git is unavailable")
def test_tracked_and_untracked_content_are_dirty(tmp_path):
    root = _committed_repository(tmp_path)
    (root / "tracked.py").write_text("clean = False\n", encoding="utf-8")
    assert resolve_subject(root).dirty is True

    _git(root, "restore", "tracked.py")
    (root / "untracked.py").write_text("new = True\n", encoding="utf-8")
    assert resolve_subject(root).dirty is True


@pytest.mark.skipif(shutil.which("git") is None, reason="git is unavailable")
def test_dirty_scope_is_limited_to_scan_target(tmp_path):
    root = _committed_repository(tmp_path)
    nested = root / "src"
    nested.mkdir()
    (root / "outside.txt").write_text("outside\n", encoding="utf-8")
    assert resolve_subject(nested).kind == "git"
    assert resolve_subject(nested).dirty is False


@pytest.mark.skipif(shutil.which("git") is None, reason="git is unavailable")
def test_unborn_repository_falls_back_to_filesystem(tmp_path):
    root = tmp_path / "unborn"
    root.mkdir()
    _git(root, "init")
    assert resolve_subject(root).kind == "filesystem"
