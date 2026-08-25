"""Tests for exclusive, atomic output publication."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import security_ai_scanner.publication as publication_module
from security_ai_scanner.exceptions import PublicationError
from security_ai_scanner.publication import LOCK_NAME, OutputPublication


def test_session_invalidates_stale_summary_and_releases_lock(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    summary = output_dir / "summary.json"
    summary.write_text("old summary\n", encoding="utf-8")

    with OutputPublication(output_dir, "run-1"):
        assert not summary.exists()
        assert (output_dir / LOCK_NAME).is_file()

    assert not (output_dir / LOCK_NAME).exists()


def test_existing_lock_rejects_without_changing_artifacts(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    summary = output_dir / "summary.json"
    summary.write_text("old summary\n", encoding="utf-8")
    (output_dir / LOCK_NAME).write_text("other writer\n", encoding="utf-8")

    with pytest.raises(PublicationError, match="already in use"):
        with OutputPublication(output_dir, "run-2"):
            pass

    assert summary.read_text(encoding="utf-8") == "old summary\n"
    assert (output_dir / LOCK_NAME).read_text(encoding="utf-8") == (
        "other writer\n"
    )


def test_atomic_write_exposes_only_old_or_complete_bytes(tmp_path, monkeypatch):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    final_path = output_dir / "findings.json"
    final_path.write_text("old\n", encoding="utf-8")
    real_replace = os.replace

    def inspect_replace(source, destination):
        source = Path(source)
        destination = Path(destination)
        assert source.parent == output_dir
        assert source.read_text(encoding="utf-8") == "complete new bytes\n"
        assert destination.read_text(encoding="utf-8") == "old\n"
        real_replace(source, destination)

    monkeypatch.setattr(publication_module.os, "replace", inspect_replace)

    with OutputPublication(output_dir, "run-3") as publication:
        publication.write_text("findings.json", "complete new bytes\n")

    assert final_path.read_text(encoding="utf-8") == "complete new bytes\n"


def test_failed_replace_preserves_final_and_removes_temporary_file(
    tmp_path, monkeypatch
):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    final_path = output_dir / "findings.json"
    final_path.write_text("old\n", encoding="utf-8")

    def fail_replace(_source, _destination):
        raise OSError("injected interruption")

    monkeypatch.setattr(publication_module.os, "replace", fail_replace)

    with OutputPublication(output_dir, "run-4") as publication:
        with pytest.raises(PublicationError, match="atomically publish"):
            publication.write_text("findings.json", "new\n")

    assert final_path.read_text(encoding="utf-8") == "old\n"
    assert list(output_dir.glob(".*.tmp")) == []


def test_lock_is_released_when_publication_body_raises(tmp_path):
    output_dir = tmp_path / "out"

    with pytest.raises(RuntimeError, match="stop"):
        with OutputPublication(output_dir, "run-5"):
            raise RuntimeError("stop")

    assert not (output_dir / LOCK_NAME).exists()
