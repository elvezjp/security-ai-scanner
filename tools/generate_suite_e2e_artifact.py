#!/usr/bin/env python3
"""Emit one deterministic native artifact set for the three-product E2E suite."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from uuid import UUID


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security_ai_scanner.config import ScanConfig  # noqa: E402
from security_ai_scanner.engine.base import (  # noqa: E402
    EngineResult,
    ScanEngine,
)
from security_ai_scanner.native import (  # noqa: E402
    NativeRun,
    create_native_run,
)
import security_ai_scanner.runner as runner  # noqa: E402


FINDING = {
    "title": "Shell interpolation permits command injection",
    "severity": "high",
    "confidence": "high",
    "file": "src/health.py",
    "start_line": 5,
    "end_line": 5,
    "cwe": "CWE-78",
    "description": "Untrusted host data reaches a shell command.",
    "recommendation": "Pass a fixed argument vector without a shell.",
    "evidence": "return subprocess.run(f\"ping -c 1 {host}\", shell=True)",
}
SCENARIOS = ("findings", "clean", "incomplete")


class SuiteFixtureEngine(ScanEngine):
    """Offline engine used only by the suite conformance generator."""

    name = "suite-fixture"

    def __init__(self, scenario: str):
        self.scenario = scenario

    async def run(self, _request) -> EngineResult:
        findings = [FINDING] if self.scenario == "findings" else []
        return EngineResult(
            structured_output={
                "findings": findings,
                "summary": f"deterministic suite {self.scenario} result",
                "files_reviewed": 1,
            },
            duration_ms=25,
            total_cost_usd=0.0,
            total_tokens=100,
            stopped_reason=(
                "budget_exceeded" if self.scenario == "incomplete" else None
            ),
        )


def generate_artifact(
    *,
    target: Path,
    output_dir: Path,
    scenario: str,
    generated_at: datetime,
    run_id: UUID,
    portable_root: str | None = None,
) -> dict:
    """Run the real producer path with deterministic engine and identity inputs."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unsupported suite scenario: {scenario}")
    native_run = create_native_run(
        target,
        generated_at=generated_at,
        run_id=run_id,
    )
    if native_run.subject.kind != "git" or native_run.subject.dirty is not False:
        raise ValueError("suite target must be a clean Git worktree")
    if portable_root is not None:
        native_run = NativeRun(
            run_id=native_run.run_id,
            generated_at=native_run.generated_at,
            subject=replace(native_run.subject, root=portable_root),
        )

    original_get_engine = runner.get_engine
    original_create_native_run = runner.create_native_run
    runner.get_engine = lambda _name: SuiteFixtureEngine(scenario)
    runner.create_native_run = lambda *_args, **_kwargs: native_run
    try:
        result = runner.run_scan(
            ScanConfig(
                target=target,
                output_dir=output_dir,
                engine="suite-fixture",
                fail_on="none",
                formats=("json",),
            )
        )
    finally:
        runner.get_engine = original_get_engine
        runner.create_native_run = original_create_native_run

    if result.summary["exit_code"] != 0 or result.summary["gate"] != {
        "fail_on": "none",
        "failed": False,
    }:
        raise RuntimeError("suite producer-local gate was not disabled")
    return result.summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--scenario",
        required=True,
        choices=SCENARIOS,
    )
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--run-id", required=True, type=UUID)
    parser.add_argument("--portable-root")
    args = parser.parse_args()
    summary = generate_artifact(
        target=args.target,
        output_dir=args.output_dir,
        scenario=args.scenario,
        generated_at=datetime.fromisoformat(
            args.generated_at.replace("Z", "+00:00")
        ),
        run_id=args.run_id,
        portable_root=args.portable_root,
    )
    print(json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
