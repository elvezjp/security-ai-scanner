"""Deterministic prepass: facts collected before the engine runs.

The prepass never calls a model. It walks the scan target once and
produces three things:

- deterministic findings for content that has almost no legitimate use and
  targets a human or an AI reader (bidirectional controls, Unicode tag
  characters);
- candidates the engine must judge for malicious intent (instructions aimed
  at AI tools, zero-width characters, agent configuration, install hooks, CI
  configuration, long encoded blobs);
- blind spots: content the read-only tools cannot fully show the model.

Candidate locations are package-generated facts, but the repository content
they point at is untrusted. Excerpts of matched text are deliberately not
copied into the prompt.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .findings import Finding

#: Kept equal to the openai engine's read_file limits, so blind spots
#: describe what the model's tools cannot show.
MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 500
#: Deterministic caps so a hostile repository cannot flood the prompt or
#: summary. Truncation is always recorded.
MAX_PROMPT_CANDIDATES = 200
MAX_SUMMARY_BLIND_SPOTS = 200
MAX_LINES_PER_FINDING = 10
_BINARY_SNIFF_BYTES = 8192

_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_TAG = re.compile("[\U000e0000-\U000e007f]")
_ZERO_WIDTH = re.compile("[\u200b-\u200d\u2060\ufeff]")
_ENCODED_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}|[0-9a-fA-F]{200,}")
_INSTRUCTION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:ignore|disregard|forget)\b[^\n]{0,30}\b(?:previous|prior|above|earlier)\b"
        r"[^\n]{0,20}\b(?:instructions?|prompts?|rules)\b",
        r"\b(?:ai|llm|assistant|reviewer|scanner|agent)\b[^\n]{0,60}"
        r"\b(?:report|return|output|say|respond)\b[^\n]{0,40}"
        r"\b(?:no|zero|0)\s+(?:findings|issues|vulnerabilit(?:y|ies)|problems)\b",
        r"</?\s*(?:system|assistant|instructions?)\s*>",
        r"\bsystem\s+prompt\b",
        r"(?:以前|前|上記|これまで)の(?:指示|命令|プロンプト)を(?:無視|忘れ)",
        r"(?:AI|ＡＩ|LLM|レビュアー|レビューア|スキャナー|アシスタント|エージェント)"
        r"[^\n]{0,40}(?:問題(?:は)?(?:なし|ありません|ない)|脆弱性(?:は)?(?:なし|ありません|ない)"
        r"|所見(?:は)?(?:なし|ありません|ない))",
        r"(?:問題|脆弱性|所見)(?:は|が)?(?:ない|なし|ありません)と(?:報告|出力|回答)",
    )
)
_AGENT_CONFIG_NAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        "gemini.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        "copilot-instructions.md",
        ".mcp.json",
        "mcp.json",
    }
)
_AGENT_CONFIG_DIRS = (".cursor/rules", ".claude", ".github/instructions")
#: Local tool state that is never source. Skipping is recorded as a blind
#: spot so a committed copy (for example a vendored node_modules) stays
#: visible.
_SKIPPED_DIRS = frozenset({"__pycache__", "node_modules", ".venv", "venv", ".tox"})
_INSTALL_HOOK_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")

_TITLES = {
    "en": {
        "bidi": "Bidirectional control characters can hide code from reviewers",
        "tag": "Invisible Unicode tag characters can carry hidden AI instructions",
    },
    "ja": {
        "bidi": "双方向制御文字によってレビュー時にコードが偽装され得る",
        "tag": "不可視のUnicodeタグ文字がAI向けの隠れた指示を運び得る",
    },
}
_DESCRIPTIONS = {
    "en": {
        "bidi": (
            "Detected deterministically before the AI scan: {count} "
            "bidirectional control character(s) on line(s) {lines}. They "
            "reorder how source is displayed, so code can read differently "
            "to a person than to the compiler (Trojan Source, "
            "CVE-2021-42574)."
        ),
        "tag": (
            "Detected deterministically before the AI scan: {count} Unicode "
            "tag character(s) (U+E0000-U+E007F) on line(s) {lines}. They are "
            "invisible to people but readable by language models, and are "
            "used to hide prompt-injection instructions."
        ),
    },
    "ja": {
        "bidi": (
            "AIスキャン前の決定論検査で検出: {lines}行目に双方向制御文字が"
            "{count}個あります。表示上の並びを変えるため、人が読むコードと"
            "コンパイラが解釈するコードを食い違わせられます（Trojan Source、"
            "CVE-2021-42574）。"
        ),
        "tag": (
            "AIスキャン前の決定論検査で検出: {lines}行目にUnicodeタグ文字"
            "（U+E0000〜U+E007F）が{count}個あります。人には見えず言語モデルには"
            "読めるため、プロンプトインジェクションの指示を隠すのに使われます。"
        ),
    },
}
_RECOMMENDATIONS = {
    "en": {
        "bidi": (
            "Remove the control characters unless the file intentionally "
            "contains right-to-left text, and review the affected lines in "
            "an editor that shows them."
        ),
        "tag": (
            "Remove the tag characters and review who introduced them; "
            "they have no legitimate use in source code."
        ),
    },
    "ja": {
        "bidi": (
            "右から左に書く文字を意図的に含む場合を除き制御文字を削除し、"
            "制御文字を表示できるエディタで該当行を確認してください。"
        ),
        "tag": (
            "タグ文字を削除し、誰が混入させたかを確認してください。"
            "ソースコードでの正当な用途はありません。"
        ),
    },
}
_CWE = {"bidi": "CWE-451", "tag": "CWE-1427"}


@dataclass(frozen=True)
class Candidate:
    """One location the engine must judge; never a finding by itself."""

    kind: str
    file: str
    line: int | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class BlindSpot:
    """Content the read-only tools cannot fully show the model."""

    path: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason}


@dataclass
class PrepassResult:
    findings: list[Finding] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    blind_spots: list[BlindSpot] = field(default_factory=list)
    files_scanned: int = 0

    def prompt_facts(self) -> dict[str, Any]:
        candidates = self.candidates[:MAX_PROMPT_CANDIDATES]
        return {
            "deterministic_findings": [
                {"file": f.file, "line": f.start_line, "cwe": f.cwe}
                for f in self.findings[:MAX_PROMPT_CANDIDATES]
            ],
            "deterministic_findings_truncated": len(self.findings)
            > MAX_PROMPT_CANDIDATES,
            "candidates": [item.to_dict() for item in candidates],
            "candidates_truncated": len(self.candidates) > len(candidates),
            "blind_spots": [
                item.to_dict()
                for item in self.blind_spots[:MAX_PROMPT_CANDIDATES]
            ],
            "blind_spots_truncated": len(self.blind_spots)
            > MAX_PROMPT_CANDIDATES,
        }

    def summary(self) -> dict[str, Any]:
        spots = self.blind_spots[:MAX_SUMMARY_BLIND_SPOTS]
        return {
            "files_scanned": self.files_scanned,
            "deterministic_findings": len(self.findings),
            "candidates": len(self.candidates),
            "candidates_in_prompt": min(
                len(self.candidates), MAX_PROMPT_CANDIDATES
            ),
            "blind_spots": [item.to_dict() for item in spots],
            "blind_spots_total": len(self.blind_spots),
            "blind_spots_truncated": len(self.blind_spots) > len(spots),
        }


def _iter_files(
    root: Path, excluded: Iterable[Path], skipped: list[BlindSpot]
) -> Iterable[tuple[Path, str]]:
    excluded_paths = [path.resolve() for path in excluded]
    def unreadable(error: OSError) -> None:
        where = Path(error.filename) if error.filename else root
        rel = where.relative_to(root).as_posix() if where != root else "."
        skipped.append(BlindSpot(rel, "unreadable"))

    for dirpath, dirnames, filenames in os.walk(
        root, onerror=unreadable, followlinks=False
    ):
        current = Path(dirpath)
        kept = []
        for name in sorted(dirnames):
            if name == ".git" or (current / name).resolve() in excluded_paths:
                continue
            if name in _SKIPPED_DIRS:
                rel = (current / name).relative_to(root).as_posix()
                skipped.append(BlindSpot(rel, "skipped_directory"))
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            path = current / name
            if path.is_symlink():
                continue  # a target inside the root is walked on its own
            yield path, path.relative_to(root).as_posix()


def _line_list(lines: list[int]) -> str:
    shown = ", ".join(str(line) for line in lines[:MAX_LINES_PER_FINDING])
    if len(lines) > MAX_LINES_PER_FINDING:
        shown += ", ..."
    return shown


def _finding(kind: str, rel: str, hits: list[tuple[int, int]], language: str) -> Finding:
    lang = language if language in _TITLES else "en"
    lines = sorted({line for line, _ in hits})
    count = sum(n for _, n in hits)
    return Finding(
        title=_TITLES[lang][kind],
        severity="high",
        confidence="high",
        file=rel,
        start_line=lines[0],
        end_line=lines[-1],
        cwe=_CWE[kind],
        description=_DESCRIPTIONS[lang][kind].format(
            count=count, lines=_line_list(lines)
        ),
        recommendation=_RECOMMENDATIONS[lang][kind],
    )


def _is_agent_config(rel: str) -> bool:
    lowered = rel.lower()
    if PurePosixPath(lowered).name in _AGENT_CONFIG_NAMES:
        return True
    return any(
        lowered == prefix or lowered.startswith(prefix + "/")
        for prefix in _AGENT_CONFIG_DIRS
    )


def _is_ci_config(rel: str) -> bool:
    lowered = rel.lower()
    return (
        lowered.startswith(".github/workflows/")
        and lowered.endswith((".yml", ".yaml"))
    ) or PurePosixPath(lowered).name in (".gitlab-ci.yml", "azure-pipelines.yml")


def _install_hooks(rel: str, text: str) -> list[Candidate]:
    name = PurePosixPath(rel).name
    if name in ("setup.py",) or name.endswith(".pth"):
        return [Candidate("install_hook", rel, None, name)]
    if name != "package.json":
        return []
    try:
        scripts = json.loads(text).get("scripts") or {}
    except (ValueError, AttributeError):
        return []
    if not isinstance(scripts, dict):
        return []
    hooks: list[Candidate] = []
    lines = text.splitlines()
    for hook in _INSTALL_HOOK_SCRIPTS:
        if hook not in scripts:
            continue
        line = next(
            (i for i, value in enumerate(lines, 1) if f'"{hook}"' in value),
            None,
        )
        hooks.append(Candidate("install_hook", rel, line, f"scripts.{hook}"))
    return hooks


def run_prepass(
    root: Path,
    *,
    language: str = "en",
    excluded: Iterable[Path] = (),
) -> PrepassResult:
    """Collect deterministic facts about the scan target."""
    root = root.resolve()
    result = PrepassResult()
    for path, rel in _iter_files(root, excluded, result.blind_spots):
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                result.blind_spots.append(BlindSpot(rel, "file_too_large"))
                continue
            data = path.read_bytes()
        except OSError:
            result.blind_spots.append(BlindSpot(rel, "unreadable"))
            continue
        result.files_scanned += 1
        if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
            result.blind_spots.append(BlindSpot(rel, "binary"))
            continue
        text = data.decode("utf-8", errors="replace")

        if _is_agent_config(rel):
            result.candidates.append(Candidate("agent_config", rel, None, "agent configuration"))
        if _is_ci_config(rel):
            result.candidates.append(Candidate("ci_config", rel, None, "CI configuration"))
        result.candidates.extend(_install_hooks(rel, text))

        bidi: list[tuple[int, int]] = []
        tag: list[tuple[int, int]] = []
        long_line = False
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > MAX_LINE_CHARS:
                long_line = True
            if found := _BIDI.findall(line):
                bidi.append((lineno, len(found)))
            if found := _TAG.findall(line):
                tag.append((lineno, len(found)))
            if lineno == 1 and line.startswith("\ufeff"):
                line = line[1:]  # a byte order mark, not hidden content
            if _ZERO_WIDTH.search(line):
                result.candidates.append(
                    Candidate("zero_width", rel, lineno, "zero-width character")
                )
            for index, pattern in enumerate(_INSTRUCTION_PATTERNS):
                if pattern.search(line):
                    result.candidates.append(
                        Candidate(
                            "ai_instruction",
                            rel,
                            lineno,
                            f"instruction-like text (pattern {index + 1})",
                        )
                    )
                    break
            if _ENCODED_BLOB.search(line):
                result.candidates.append(
                    Candidate("encoded_blob", rel, lineno, "long encoded string")
                )
        if long_line:
            result.blind_spots.append(BlindSpot(rel, "long_line"))
        if bidi:
            result.findings.append(_finding("bidi", rel, bidi, language))
        if tag:
            result.findings.append(_finding("tag", rel, tag, language))
    return result


__all__ = ["BlindSpot", "Candidate", "PrepassResult", "run_prepass"]
