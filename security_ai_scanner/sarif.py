"""SARIF 2.1.0 export.

Findings are emitted as a standard SARIF log so results integrate with
GitHub Code Scanning, VS Code SARIF viewers, and other AppSec tooling.
Scanner-specific fields (confidence, recommendation) are carried in
``properties`` bags as the SARIF spec intends.
"""

from __future__ import annotations

from typing import Any

from .findings import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

#: Map scanner severities to SARIF levels.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

#: Map scanner severities to GitHub's security-severity score scale.
_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "0.0",
}


def _rule_id(finding: Finding) -> str:
    return finding.cwe or "SAIS-GENERIC"


def to_sarif(
    findings: list[Finding],
    *,
    tool_name: str,
    tool_version: str,
    info_uri: str,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from findings."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = _rule_id(finding)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "properties": {
                    "security-severity": _SEVERITY_TO_SCORE[finding.severity],
                },
            },
        )

        region: dict[str, Any] = {"startLine": finding.start_line}
        if finding.end_line is not None:
            region["endLine"] = finding.end_line
        if finding.evidence:
            region["snippet"] = {"text": finding.evidence}

        message = finding.description
        if finding.recommendation:
            message = f"{message}\n\nRecommendation: {finding.recommendation}"

        results.append(
            {
                "ruleId": rule_id,
                "level": _SEVERITY_TO_LEVEL[finding.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file,
                                "uriBaseId": "SRCROOT",
                            },
                            "region": region,
                        }
                    }
                ],
                "partialFingerprints": {
                    "sais/id": finding.id,
                },
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "title": finding.title,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": info_uri,
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": {"description": {"text": "Scan target root"}}
                },
                "results": results,
            }
        ],
    }
