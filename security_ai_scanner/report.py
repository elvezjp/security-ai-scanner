"""Markdown report generation.

Finding fields originate from the LLM engine and may quote content of
the scanned repository, which is untrusted. Everything interpolated
into the report is therefore neutralized: code fences around evidence
are sized dynamically so embedded backticks cannot close them early,
and heading / fence openers in free-text fields are escaped so a
finding cannot inject fake report structure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import SEVERITY_ORDER
from .findings import Finding, ScanOutput

_LABELS = {
    "en": {
        "title": "Security Scan Report",
        "target": "Target",
        "engine": "Engine",
        "date": "Date",
        "files_reviewed": "Files reviewed",
        "summary": "Summary",
        "totals": "Findings by severity",
        "severity": "Severity",
        "count": "Count",
        "findings": "Findings",
        "no_findings": "No findings. 🎉",
        "location": "Location",
        "confidence": "Confidence",
        "cwe": "CWE",
        "evidence": "Evidence",
        "recommendation": "Recommendation",
    },
    "ja": {
        "title": "セキュリティスキャンレポート",
        "target": "対象",
        "engine": "エンジン",
        "date": "実施日時",
        "files_reviewed": "レビューしたファイル数",
        "summary": "総評",
        "totals": "重要度別の件数",
        "severity": "重要度",
        "count": "件数",
        "findings": "検出結果",
        "no_findings": "検出された問題はありません。🎉",
        "location": "場所",
        "confidence": "確度",
        "cwe": "CWE",
        "evidence": "該当箇所",
        "recommendation": "推奨対応",
    },
}

_SEVERITY_BADGES = {
    "critical": "🟥 Critical",
    "high": "🟧 High",
    "medium": "🟨 Medium",
    "low": "🟦 Low",
    "info": "⬜ Info",
}


@dataclass
class ReportMeta:
    target: str
    engine: str
    timestamp: datetime | None = None


def _labels(language: str) -> dict[str, str]:
    return _LABELS.get(language, _LABELS["en"])


#: Line-leading Markdown block openers that untrusted text could use to
#: forge report structure: ATX headings, code fences, and lines made up
#: solely of Setext underline / thematic-break characters (``===`` turns
#: the preceding paragraph line into a heading, ``---`` likewise).
_BLOCK_OPENER_RE = re.compile(
    r"(?m)^([ \t]{0,3})("
    r"#{1,6}(?=[ \t]|$)"
    r"|`{3,}|~{3,}"
    r"|(?:=+|-+|_+|\*+)(?=[ \t]*$)"
    r")"
)

_BACKTICK_RUN_RE = re.compile(r"`+")


def _inline(text: str) -> str:
    """Collapse untrusted text onto one line for use inside a heading."""
    return " ".join(text.split())


def _block(text: str) -> str:
    """Escape block openers so untrusted text stays plain paragraph text."""
    return _BLOCK_OPENER_RE.sub(r"\1\\\2", text.strip())


def _fence(content: str) -> str:
    """A code fence guaranteed to be longer than any backtick run inside."""
    longest = max(
        (len(m.group(0)) for m in _BACKTICK_RUN_RE.finditer(content)),
        default=0,
    )
    return "`" * max(3, longest + 1)


def _code_span(text: str) -> str:
    """An inline code span that embedded backticks cannot close early."""
    text = " ".join(text.split())
    longest = max(
        (len(m.group(0)) for m in _BACKTICK_RUN_RE.finditer(text)),
        default=0,
    )
    delim = "`" * (longest + 1)
    pad = " " if longest else ""
    return f"{delim}{pad}{text}{pad}{delim}"


def _location(finding: Finding) -> str:
    if finding.end_line and finding.end_line != finding.start_line:
        return _code_span(
            f"{finding.file}:{finding.start_line}-{finding.end_line}"
        )
    return _code_span(f"{finding.file}:{finding.start_line}")


def render_markdown(
    output: ScanOutput, meta: ReportMeta, *, language: str = "en"
) -> str:
    """Render a scan output into a human-readable Markdown report."""
    labels = _labels(language)
    timestamp = meta.timestamp or datetime.now(timezone.utc)
    lines: list[str] = []

    lines.append(f"# {labels['title']}")
    lines.append("")
    lines.append(f"- {labels['target']}: `{meta.target}`")
    lines.append(f"- {labels['engine']}: {meta.engine}")
    lines.append(f"- {labels['date']}: {timestamp.strftime('%Y-%m-%d %H:%M UTC')}")
    if output.files_reviewed is not None:
        lines.append(f"- {labels['files_reviewed']}: {output.files_reviewed}")
    lines.append("")

    if output.summary:
        lines.append(f"## {labels['summary']}")
        lines.append("")
        lines.append(_block(output.summary))
        lines.append("")

    lines.append(f"## {labels['totals']}")
    lines.append("")
    lines.append(f"| {labels['severity']} | {labels['count']} |")
    lines.append("|---|---|")
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in output.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    for severity in SEVERITY_ORDER:
        lines.append(f"| {_SEVERITY_BADGES[severity]} | {counts[severity]} |")
    lines.append("")

    lines.append(f"## {labels['findings']}")
    lines.append("")
    if not output.findings:
        lines.append(labels["no_findings"])
        lines.append("")
    for finding in output.findings:
        lines.append(
            f"### {finding.id}: {_inline(finding.title)} "
            f"({_SEVERITY_BADGES[finding.severity]})"
        )
        lines.append("")
        lines.append(f"- {labels['location']}: {_location(finding)}")
        lines.append(f"- {labels['confidence']}: {finding.confidence}")
        if finding.cwe:
            lines.append(f"- {labels['cwe']}: {_inline(finding.cwe)}")
        lines.append("")
        lines.append(_block(finding.description))
        lines.append("")
        if finding.evidence:
            evidence = finding.evidence.strip()
            fence = _fence(evidence)
            lines.append(f"**{labels['evidence']}**")
            lines.append("")
            lines.append(fence)
            lines.append(evidence)
            lines.append(fence)
            lines.append("")
        if finding.recommendation:
            lines.append(f"**{labels['recommendation']}**")
            lines.append("")
            lines.append(_block(finding.recommendation))
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"
