"""Finding model, output schema, and parsing/validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any

from .config import SEVERITY_ORDER
from .exceptions import FindingsParseError

CONFIDENCE_LEVELS = ("high", "medium", "low")

#: JSON Schema the engine is asked to produce (via structured output).
#: Kept intentionally flat and additionalProperties-free so that any
#: backend that supports JSON-schema-constrained output can honor it.
FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": list(SEVERITY_ORDER)},
                    "confidence": {
                        "type": "string",
                        "enum": list(CONFIDENCE_LEVELS),
                    },
                    "file": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                    "cwe": {"type": "string"},
                    "description": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": [
                    "title",
                    "severity",
                    "confidence",
                    "file",
                    "start_line",
                    "description",
                    "recommendation",
                ],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
        "files_reviewed": {"type": "integer"},
    },
    "required": ["findings", "summary"],
    "additionalProperties": False,
}


@dataclass
class Finding:
    """One security finding."""

    title: str
    severity: str
    confidence: str
    file: str
    start_line: int
    description: str
    recommendation: str
    end_line: int | None = None
    cwe: str | None = None
    evidence: str | None = None
    id: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ScanOutput:
    """Validated engine output: findings plus scan-level metadata."""

    findings: list[Finding]
    summary: str = ""
    files_reviewed: int | None = None


def severity_rank(severity: str) -> int:
    """Rank a severity: 0 is most severe. Unknown values rank least severe."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def meets_threshold(severity: str, fail_on: str) -> bool:
    """True if ``severity`` is at least as severe as ``fail_on``."""
    if fail_on == "none":
        return False
    return severity_rank(severity) <= severity_rank(fail_on)


def _coerce_finding(raw: dict[str, Any], index: int) -> Finding:
    missing = [
        key
        for key in ("title", "severity", "file", "description")
        if not raw.get(key)
    ]
    if missing:
        raise FindingsParseError(
            f"Finding #{index} is missing required fields: {missing}"
        )

    severity = str(raw["severity"]).lower()
    if severity not in SEVERITY_ORDER:
        severity = "info"
    confidence = str(raw.get("confidence", "medium")).lower()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "medium"

    try:
        start_line = max(1, int(raw.get("start_line", 1)))
    except (TypeError, ValueError):
        start_line = 1
    end_line_raw = raw.get("end_line")
    end_line: int | None
    try:
        end_line = int(end_line_raw) if end_line_raw is not None else None
    except (TypeError, ValueError):
        end_line = None
    if end_line is not None and end_line < start_line:
        end_line = start_line

    return Finding(
        id=f"SAIS-{index + 1:04d}",
        title=str(raw["title"]),
        severity=severity,
        confidence=confidence,
        file=str(raw["file"]).lstrip("/"),
        start_line=start_line,
        end_line=end_line,
        cwe=str(raw["cwe"]) if raw.get("cwe") else None,
        description=str(raw["description"]),
        recommendation=str(raw.get("recommendation", "")),
        evidence=str(raw["evidence"]) if raw.get("evidence") else None,
    )


def parse_scan_output(obj: Any) -> ScanOutput:
    """Validate a structured-output object into a :class:`ScanOutput`."""
    if not isinstance(obj, dict):
        raise FindingsParseError(
            f"Engine output must be a JSON object, got {type(obj).__name__}"
        )
    raw_findings = obj.get("findings")
    if not isinstance(raw_findings, list):
        raise FindingsParseError("Engine output is missing the 'findings' array")

    findings = [
        _coerce_finding(raw, i)
        for i, raw in enumerate(raw_findings)
        if isinstance(raw, dict)
    ]
    findings.sort(key=lambda f: (severity_rank(f.severity), f.file, f.start_line))
    # Re-number after sorting so IDs follow severity order.
    for i, finding in enumerate(findings):
        finding.id = f"SAIS-{i + 1:04d}"

    files_reviewed = obj.get("files_reviewed")
    return ScanOutput(
        findings=findings,
        summary=str(obj.get("summary", "")),
        files_reviewed=int(files_reviewed)
        if isinstance(files_reviewed, int)
        else None,
    )


_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def parse_text_output(text: str) -> ScanOutput:
    """Fallback parser: extract the findings JSON object from free-form text.

    Exactly one schema-conforming JSON block is accepted. The text may
    quote repository content, and a hostile scan target could embed a
    fake "no findings" block there to bypass the CI gate — so ambiguity
    is treated as an error rather than silently picking one candidate.
    """
    candidates = _JSON_BLOCK_RE.findall(text or "")
    if not candidates:
        stripped = (text or "").strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            candidates = [stripped]

    outputs: list[ScanOutput] = []
    for candidate in candidates:
        try:
            outputs.append(parse_scan_output(json.loads(candidate)))
        except (json.JSONDecodeError, FindingsParseError):
            continue
    if not outputs:
        raise FindingsParseError(
            "No parseable findings JSON found in engine output"
        )
    if len(outputs) > 1:
        raise FindingsParseError(
            f"Found {len(outputs)} findings JSON blocks in engine output; "
            "refusing to choose between them (possible injection from the "
            "scanned repository)"
        )
    return outputs[0]
