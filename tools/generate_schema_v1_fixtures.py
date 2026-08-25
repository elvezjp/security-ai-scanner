#!/usr/bin/env python3
"""Generate deterministic Schema v1 artifacts through the real sais runner."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security_ai_scanner.config import ScanConfig  # noqa: E402
from security_ai_scanner.engine.base import (  # noqa: E402
    EngineResult,
    ScanEngine,
)
from security_ai_scanner.exceptions import EngineError  # noqa: E402
from security_ai_scanner.native import NativeRun, Subject  # noqa: E402
import security_ai_scanner.runner as runner  # noqa: E402


OUTPUT_ROOT = ROOT / "tests" / "fixtures" / "sais-v1-release-candidate"
FIXTURE_VERSION = "0.3.0-dev"
GENERATED_AT = "2026-08-25T00:00:00Z"
RUN_IDS = {
    "completed": "d7481457-56c3-593a-a486-3d2e713c80c4",
    "incomplete": "e4fba3fc-4c9f-55a2-b21f-f21f69d9bf0d",
    "error": "fbcc6f2e-4c8c-573b-9258-9b97251fd502",
}
SUBJECT = Subject(
    kind="git",
    root="/workspace/project",
    head_sha="0123456789abcdef0123456789abcdef01234567",
    base_sha=None,
    dirty=False,
    content_digest=None,
)
FINDING = {
    "title": "Release-candidate fixture finding",
    "severity": "high",
    "confidence": "high",
    "file": "src/example.py",
    "start_line": 10,
    "end_line": 12,
    "cwe": "CWE-79",
    "description": "A deterministic finding emitted through the real runner.",
    "recommendation": "Keep the producer fixture aligned with Schema v1.",
    "evidence": "def example():",
}


class FixtureEngine(ScanEngine):
    """Offline engine returning one fixed result."""

    name = "fixture"

    def __init__(self, result: EngineResult):
        self.result = result

    async def run(self, _request) -> EngineResult:
        return self.result


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def engine_result(status: str) -> EngineResult:
    if status == "error":
        return EngineResult(is_error=True, error_message="fixture engine failure")
    return EngineResult(
        structured_output={
            "findings": [FINDING],
            "summary": f"deterministic {status} fixture",
            "files_reviewed": 1,
        },
        duration_ms=25,
        total_cost_usd=0.0,
        total_tokens=100,
        stopped_reason="budget_exceeded" if status == "incomplete" else None,
    )


def generate_case(status: str, temporary_root: Path) -> dict[str, bytes]:
    target = temporary_root / f"target-{status}"
    output_dir = temporary_root / f"output-{status}"
    target.mkdir()
    (target / "example.py").write_text("print('fixture')\n", encoding="utf-8")
    native_run = NativeRun(
        run_id=RUN_IDS[status],
        generated_at=GENERATED_AT,
        subject=SUBJECT,
    )
    original_engine = runner.get_engine
    original_run = runner.create_native_run
    original_version = runner.__version__
    runner.get_engine = lambda _name: FixtureEngine(engine_result(status))
    runner.create_native_run = lambda *_args, **_kwargs: native_run
    runner.__version__ = FIXTURE_VERSION
    try:
        config = ScanConfig(
            target=target,
            output_dir=output_dir,
            engine="fixture",
            fail_on="none",
            formats=("json",),
        )
        if status == "error":
            try:
                runner.run_scan(config)
            except EngineError:
                pass
            else:  # pragma: no cover - generator invariant
                raise RuntimeError("error fixture unexpectedly completed")
        else:
            runner.run_scan(config)
    finally:
        runner.get_engine = original_engine
        runner.create_native_run = original_run
        runner.__version__ = original_version

    case = {
        "expectation.json": json_bytes(
            {
                "description": (
                    "Schema-version-1 security-ai-scanner "
                    f"{status} release-candidate artifacts."
                ),
                "valid": True,
            }
        ),
        "summary.json": (output_dir / "summary.json").read_bytes(),
    }
    findings_path = output_dir / "findings.json"
    if findings_path.exists():
        case["findings.json"] = findings_path.read_bytes()
    return case


def generated_files() -> dict[str, bytes]:
    files = {
        "GENERATION.json": json_bytes(
            {
                "generated_at": GENERATED_AT,
                "generator": "tools/generate_schema_v1_fixtures.py",
                "version": FIXTURE_VERSION,
            }
        )
    }
    with tempfile.TemporaryDirectory(prefix="sais-fixtures-") as temporary:
        temporary_root = Path(temporary)
        for status in ("completed", "incomplete", "error"):
            for name, content in generate_case(status, temporary_root).items():
                files[f"sais-{status}/{name}"] = content
    return files


def check(files: dict[str, bytes]) -> bool:
    actual = {
        str(path.relative_to(OUTPUT_ROOT)): path.read_bytes()
        for path in OUTPUT_ROOT.rglob("*")
        if path.is_file()
    } if OUTPUT_ROOT.exists() else {}
    if actual == files:
        return True
    expected_names = set(files)
    actual_names = set(actual)
    for name in sorted(expected_names - actual_names):
        print(f"missing generated fixture: {name}", file=sys.stderr)
    for name in sorted(actual_names - expected_names):
        print(f"obsolete generated fixture: {name}", file=sys.stderr)
    for name in sorted(expected_names & actual_names):
        if files[name] != actual[name]:
            print(f"changed generated fixture: {name}", file=sys.stderr)
    return False


def write(files: dict[str, bytes]) -> None:
    if OUTPUT_ROOT.exists():
        shutil.rmtree(OUTPUT_ROOT)
    for name, content in files.items():
        path = OUTPUT_ROOT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when committed fixtures differ from runner output",
    )
    args = parser.parse_args()
    files = generated_files()
    if args.check:
        if not check(files):
            return 1
        print(f"Schema v1 fixture check passed ({len(files)} files)")
        return 0
    write(files)
    print(f"wrote {len(files)} files below {OUTPUT_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
