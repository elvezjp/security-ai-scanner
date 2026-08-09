"""Tests for SARIF export."""

import json

from security_ai_scanner.findings import parse_scan_output
from security_ai_scanner.sarif import to_sarif


def _output_with_findings():
    return parse_scan_output(
        {
            "findings": [
                {
                    "title": "Command injection",
                    "severity": "critical",
                    "confidence": "high",
                    "file": "src/run.py",
                    "start_line": 10,
                    "end_line": 12,
                    "cwe": "CWE-78",
                    "description": "Shell command built from user input.",
                    "recommendation": "Use subprocess with a list argv.",
                    "evidence": "os.system(cmd)",
                },
                {
                    "title": "Weak hash",
                    "severity": "medium",
                    "confidence": "medium",
                    "file": "src/auth.py",
                    "start_line": 5,
                    "description": "MD5 used for passwords.",
                    "recommendation": "Use argon2 or bcrypt.",
                },
            ],
            "summary": "",
        }
    )


class TestSarif:
    def test_basic_structure(self):
        sarif = to_sarif(
            _output_with_findings().findings,
            tool_name="security-ai-scanner",
            tool_version="0.1.0",
            info_uri="https://example.com",
        )
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "security-ai-scanner"
        assert len(run["results"]) == 2

    def test_severity_mapping_and_locations(self):
        sarif = to_sarif(
            _output_with_findings().findings,
            tool_name="t",
            tool_version="0",
            info_uri="u",
        )
        results = sarif["runs"][0]["results"]
        critical = next(r for r in results if r["ruleId"] == "CWE-78")
        assert critical["level"] == "error"
        loc = critical["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/run.py"
        assert loc["region"]["startLine"] == 10
        assert loc["region"]["endLine"] == 12
        assert loc["region"]["snippet"]["text"] == "os.system(cmd)"

        medium = next(r for r in results if "Weak hash" in str(r))
        assert medium["level"] == "warning"
        assert medium["ruleId"] == "SAIS-GENERIC"

    def test_rules_are_deduplicated_and_serializable(self):
        findings = _output_with_findings().findings * 2
        sarif = to_sarif(
            findings, tool_name="t", tool_version="0", info_uri="u"
        )
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids))
        json.dumps(sarif)  # must be JSON-serializable

    def test_empty_findings(self):
        sarif = to_sarif([], tool_name="t", tool_version="0", info_uri="u")
        assert sarif["runs"][0]["results"] == []
