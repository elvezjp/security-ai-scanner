"""Tests for Markdown report generation."""

from datetime import datetime, timezone

import pytest

from security_ai_scanner.findings import parse_scan_output
from security_ai_scanner.report import ReportMeta, render_markdown


def _output():
    return parse_scan_output(
        {
            "findings": [
                {
                    "title": "Hardcoded API key",
                    "severity": "high",
                    "confidence": "high",
                    "file": "config.py",
                    "start_line": 3,
                    "cwe": "CWE-798",
                    "description": "An API key is committed to the repository.",
                    "recommendation": "Move the key to an environment variable.",
                    "evidence": 'API_KEY = "sk-123"',
                }
            ],
            "summary": "One high-severity issue found.",
            "files_reviewed": 4,
        }
    )


def _meta():
    return ReportMeta(
        target="/repo",
        engine="claude",
        timestamp=datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc),
    )


class TestRenderMarkdown:
    def test_english_report(self):
        md = render_markdown(_output(), _meta(), language="en")
        assert "# Security Scan Report" in md
        assert "SAIS-0001: Hardcoded API key" in md
        assert "`config.py:3`" in md
        assert "CWE-798" in md
        assert "2026-07-29 12:00 UTC" in md
        assert "Files reviewed: 4" in md

    def test_japanese_report(self):
        md = render_markdown(_output(), _meta(), language="ja")
        assert "# セキュリティスキャンレポート" in md
        assert "重要度別の件数" in md

    def test_empty_findings_report(self):
        output = parse_scan_output({"findings": [], "summary": "Clean."})
        md = render_markdown(output, _meta(), language="en")
        assert "No findings" in md

    def test_unknown_language_falls_back_to_english(self):
        md = render_markdown(_output(), _meta(), language="fr")
        assert "# Security Scan Report" in md


class TestUntrustedContentEscaping:
    def _output_with(self, **overrides):
        finding = {
            "title": "t",
            "severity": "low",
            "confidence": "high",
            "file": "a.py",
            "start_line": 1,
            "description": "d",
            "recommendation": "r",
        }
        finding.update(overrides)
        return parse_scan_output({"findings": [finding], "summary": "s"})

    def test_evidence_backticks_cannot_break_the_fence(self):
        evidence = 'x = 1\n```\n## fake heading\n[phishing](https://evil.example)'
        md = render_markdown(
            self._output_with(evidence=evidence), _meta(), language="en"
        )
        # The fence is longer than any backtick run in the evidence, so
        # the injected ``` never closes it early.
        fence_start = md.index("````")
        fence_end = md.index("````", fence_start + 4)
        assert "fake heading" in md[fence_start:fence_end]

    def test_title_newlines_are_collapsed(self):
        md = render_markdown(
            self._output_with(title="Real title\n## Fake finding"),
            _meta(),
            language="en",
        )
        assert "\n## Fake finding" not in md
        assert "Real title ## Fake finding" in md

    def test_description_block_openers_are_escaped(self):
        md = render_markdown(
            self._output_with(description="## Fake heading\n```\nfence"),
            _meta(),
            language="en",
        )
        assert "\n\\## Fake heading" in md
        assert "\n\\```" in md

    def test_file_backticks_cannot_break_the_location_span(self):
        md = render_markdown(
            self._output_with(file="a`b.py"), _meta(), language="en"
        )
        assert "`` a`b.py:1 ``" in md

    @pytest.mark.parametrize("underline", ["===", "---", "___", "***"])
    def test_setext_and_thematic_break_lines_are_escaped(self, underline):
        # `Looks clean\n===` renders the first line as an <h1> unless the
        # underline is escaped, letting a finding forge report structure.
        md = render_markdown(
            self._output_with(description=f"Looks clean\n{underline}"),
            _meta(),
            language="en",
        )
        assert f"\nLooks clean\n\\{underline}" in md

    def test_list_bullets_are_not_escaped(self):
        # Only full underline/break lines are structural; a normal bullet
        # list in a description must survive untouched.
        md = render_markdown(
            self._output_with(description="Steps:\n- first\n- second"),
            _meta(),
            language="en",
        )
        assert "\n- first\n- second" in md

    def test_summary_block_openers_are_escaped(self):
        output = parse_scan_output(
            {"findings": [], "summary": "Clean\n## Fake heading"}
        )
        md = render_markdown(output, _meta(), language="en")
        assert "\n\\## Fake heading" in md
