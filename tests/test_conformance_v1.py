"""Cross-repository and real-producer Schema v1 conformance tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
QK_FIXTURES = ROOT / "tests" / "fixtures" / "qk-v1"
PRODUCER_FIXTURES = (
    ROOT / "tests" / "fixtures" / "sais-v1-release-candidate"
)
STATUSES = ("completed", "incomplete", "error")
IDENTITY_FIELDS = (
    "schema_version",
    "run_id",
    "tool",
    "version",
    "generated_at",
    "subject",
)
SEVERITIES = ("critical", "high", "medium", "low", "info")


def reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_bytes(), parse_constant=reject_non_json_constant
    )


def schema_validator(name: str) -> Draft202012Validator:
    schema = load_json(ROOT / "schemas" / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


SUMMARY_VALIDATOR = schema_validator("native-summary-v1.schema.json")
FINDINGS_VALIDATOR = schema_validator("native-findings-v1.schema.json")


def validate_case(case_dir: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Apply qk's native-pair checks to one fixture directory."""
    summary_path = case_dir / "summary.json"
    findings_path = case_dir / "findings.json"
    summary = load_json(summary_path)
    SUMMARY_VALIDATOR.validate(summary)

    if summary["status"] == "error" and not findings_path.exists():
        return summary, None
    if not findings_path.exists():
        raise AssertionError(f"findings.json is missing from {case_dir}")

    findings_bytes = findings_path.read_bytes()
    findings_document = load_json(findings_path)
    FINDINGS_VALIDATOR.validate(findings_document)

    for field in IDENTITY_FIELDS:
        if summary[field] != findings_document[field]:
            raise AssertionError(f"identity mismatch: {field}")

    descriptor = summary["outputs"].get("findings.json")
    if descriptor is None:
        raise AssertionError("findings.json is not declared in outputs")
    if descriptor["path"] != "findings.json":
        raise AssertionError("findings.json descriptor has the wrong path")
    if descriptor["sha256"] != hashlib.sha256(findings_bytes).hexdigest():
        raise AssertionError("findings.json digest mismatch")
    if descriptor["bytes"] != len(findings_bytes):
        raise AssertionError("findings.json byte-count mismatch")

    severity_counts = Counter(
        finding["severity"] for finding in findings_document["findings"]
    )
    recomputed = {
        severity: severity_counts[severity] for severity in SEVERITIES
    }
    recomputed["total"] = len(findings_document["findings"])
    if summary["counts"] != recomputed:
        raise AssertionError("summary and findings counts do not match")

    for finding in findings_document["findings"]:
        end_line = finding.get("end_line", finding["start_line"])
        if end_line < finding["start_line"]:
            raise AssertionError("finding ends before it starts")
    return summary, findings_document


def canonical_json_digest(path: Path) -> str:
    value = load_json(path)
    content = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def test_qk_fixture_copies_match_pinned_source_hashes():
    source = load_json(QK_FIXTURES / "SOURCE.json")
    assert source["commit"] == "7dfccff2f8dcd342071072545aac86a155ddd044"
    for name, expected_digest in source["files"].items():
        content = (QK_FIXTURES / name).read_bytes()
        assert hashlib.sha256(content).hexdigest() == expected_digest


def test_producer_schemas_match_pinned_qk_schemas_semantically():
    source = load_json(QK_FIXTURES / "SOURCE.json")
    for name, expected_digest in source[
        "schema_canonical_json_sha256"
    ].items():
        assert canonical_json_digest(ROOT / "schemas" / name) == expected_digest


@pytest.mark.parametrize("status", STATUSES)
def test_pinned_qk_sais_fixtures_pass_conformance(status):
    summary, findings = validate_case(QK_FIXTURES / f"sais-{status}")
    assert summary["status"] == status
    assert (findings is None) == (status == "error")


@pytest.mark.parametrize("status", STATUSES)
def test_real_runner_release_candidate_fixtures_pass_conformance(status):
    summary, findings = validate_case(PRODUCER_FIXTURES / f"sais-{status}")
    assert summary["status"] == status
    assert summary["version"] == "0.3.0-dev"
    assert (findings is None) == (status == "error")


def test_release_candidate_fixtures_are_reproducible():
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "generate_schema_v1_fixtures.py"),
            "--check",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "fixture check passed" in completed.stdout
