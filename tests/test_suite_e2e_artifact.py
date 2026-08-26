from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from tools.generate_suite_e2e_artifact import generate_artifact


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _repository(root: Path) -> str:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Suite Fixture")
    _git(root, "config", "user.email", "suite@example.invalid")
    source = root / "src/health.py"
    source.parent.mkdir()
    source.write_text(
        "import subprocess\n\n\ndef check(host):\n"
        "    return subprocess.run(f\"ping -c 1 {host}\", shell=True)\n",
        encoding="utf-8",
    )
    _git(root, "add", "src/health.py")
    _git(root, "commit", "-qm", "fixture")
    return _git(root, "rev-parse", "HEAD")


@pytest.mark.parametrize(
    ("scenario", "status", "total"),
    [
        ("findings", "completed", 1),
        ("clean", "completed", 0),
        ("incomplete", "incomplete", 0),
    ],
)
def test_suite_artifact_uses_clean_revision_and_disables_local_gate(
    tmp_path,
    scenario,
    status,
    total,
):
    target = tmp_path / "repo"
    head = _repository(target)
    output = tmp_path / "out"

    summary = generate_artifact(
        target=target,
        output_dir=output,
        scenario=scenario,
        generated_at=datetime(2026, 8, 26, 8, tzinfo=UTC),
        run_id=UUID("2ca2bfb4-1b86-50ea-bb95-a6e754f4380e"),
        portable_root="/workspace/project",
    )

    content = (output / "findings.json").read_bytes()
    assert summary["status"] == status
    assert summary["subject"] == {
        "kind": "git",
        "root": "/workspace/project",
        "head_sha": head,
        "base_sha": None,
        "dirty": False,
        "content_digest": None,
    }
    assert summary["gate"] == {"fail_on": "none", "failed": False}
    assert summary["exit_code"] == 0
    assert summary["counts"]["total"] == total
    assert summary["outputs"]["findings.json"] == {
        "path": "findings.json",
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
    }
