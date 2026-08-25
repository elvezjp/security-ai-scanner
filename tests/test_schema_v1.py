"""Producer-side conformance tests for the common schema-version-1 files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from security_ai_scanner.config import ScanConfig
from security_ai_scanner.engine.base import EngineResult, ScanEngine
from security_ai_scanner.native import create_native_run
from security_ai_scanner.runner import build_error_summary, run_scan


ROOT = Path(__file__).resolve().parents[1]


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def _validate(instance: dict, schema_name: str) -> None:
    validator = Draft202012Validator(
        _schema(schema_name), format_checker=FormatChecker()
    )
    validator.validate(instance)


class FixedEngine(ScanEngine):
    name = "fixed"

    def __init__(self, result: EngineResult):
        self.result = result

    async def run(self, request) -> EngineResult:
        return self.result


def _run(tmp_path: Path, monkeypatch, *, stopped: str | None = None):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("print('ok')\n", encoding="utf-8")
    engine = FixedEngine(
        EngineResult(
            structured_output={"findings": [], "summary": "clean"},
            stopped_reason=stopped,
        )
    )
    monkeypatch.setattr(
        "security_ai_scanner.runner.get_engine", lambda _name: engine
    )
    config = ScanConfig(
        target=target,
        output_dir=tmp_path / "out",
        engine="fixed",
        fail_on="none",
    )
    return config, run_scan(config)


def test_completed_artifacts_validate_and_share_run_identity(tmp_path, monkeypatch):
    _config, result = _run(tmp_path, monkeypatch)
    output_dir = tmp_path / "out"
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))

    _validate(summary, "native-summary-v1.schema.json")
    _validate(findings, "native-findings-v1.schema.json")
    assert summary["status"] == "completed"
    for key in ("schema_version", "run_id", "tool", "version", "generated_at", "subject"):
        assert summary[key] == findings[key]
    assert result.summary == summary


def test_output_descriptors_match_final_bytes(tmp_path, monkeypatch):
    _config, result = _run(tmp_path, monkeypatch)
    assert "summary.json" not in result.summary["outputs"]
    for name, descriptor in result.summary["outputs"].items():
        content = (tmp_path / "out" / name).read_bytes()
        assert descriptor == {
            "path": name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }


def test_incomplete_summary_validates(tmp_path, monkeypatch):
    _config, result = _run(tmp_path, monkeypatch, stopped="future_reason")
    _validate(result.summary, "native-summary-v1.schema.json")
    assert result.summary["status"] == "incomplete"
    assert result.summary["stopped"] == "future_reason"


def test_error_model_validates_without_live_engine(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.setattr(
        "security_ai_scanner.native.shutil.which", lambda _name: None
    )
    config = ScanConfig(target=target, output_dir=tmp_path / "out")
    summary = build_error_summary(
        config, create_native_run(target), message="engine failed"
    )
    _validate(summary, "native-summary-v1.schema.json")
    assert summary["status"] == "error"
    assert summary["exit_code"] == 2
