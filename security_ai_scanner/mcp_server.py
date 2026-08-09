"""MCP (Model Context Protocol) server exposing the scanner to agent clients.

Run with ``sais mcp`` (stdio transport). MCP clients such as Claude Code,
VS Code, Cursor, and Codex can then call the tools below.

The ``mcp`` dependency is an optional extra (``pip install
'security-ai-scanner[mcp]'``) and its import is confined to this module,
mirroring how engine SDK imports are confined to ``engine/<name>.py``.

Design notes:

- ``scan_repository`` runs one scan to completion and returns the run
  summary (spec.md §4.2) plus a ``scan_id``. A scan takes minutes; progress
  is reported through MCP progress notifications so clients can show a
  spinner instead of timing out.
- Full findings are deliberately not returned by ``scan_repository``:
  they can be large, and most agent flows only need counts first.
  ``get_findings`` retrieves them on demand, optionally filtered.
- Results are held in memory per server process, keyed by ``scan_id``.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

from .config import SEVERITY_ORDER, ScanConfig
from .exceptions import ScannerError
from .runner import ScanResult, run_scan_async

INSTRUCTIONS = """\
security-ai-scanner: AI-powered security scan of a local repository
directory. The scan agent is read-only (Read/Glob/Grep only). A scan takes
several minutes. Start with scan_repository; read counts from its summary;
fetch details with get_findings only when needed. Findings are leads for
human review, not verdicts.
"""

server = FastMCP(
    "security-ai-scanner",
    instructions=INSTRUCTIONS,
)

#: Completed scans by scan_id, newest last. Process-local by design.
_RESULTS: dict[str, ScanResult] = {}


def _next_scan_id() -> str:
    return f"scan-{len(_RESULTS) + 1:04d}"


@server.tool()
async def scan_repository(
    path: str,
    language: str = "en",
    fail_on: str = "high",
    context: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Run a full security scan of a local repository directory.

    Takes several minutes. Returns the machine-readable run summary
    (severity counts, gate verdict, output paths) plus a scan_id for
    get_findings / get_summary.

    Args:
        path: Local repository directory to scan.
        language: Language for findings and report ("en" or "ja").
        fail_on: CI gate threshold (critical/high/medium/low/info/none).
        context: Optional threat-model notes (treated as untrusted data).
    """
    target = Path(path).expanduser()
    # Outputs go to a fresh temp dir: an MCP server must not write into the
    # repository it scans, and has no meaningful cwd to write into either.
    output_dir = Path(tempfile.mkdtemp(prefix="sais-mcp-"))
    config = ScanConfig(
        target=target,
        output_dir=output_dir,
        language=language,
        fail_on=fail_on,
        context=context,
    )
    if ctx is not None:
        await ctx.report_progress(0, None, f"Scanning {target} ...")

    scan_task = asyncio.ensure_future(run_scan_async(config))
    elapsed = 0
    while True:
        done, _ = await asyncio.wait({scan_task}, timeout=5)
        if done:
            break
        elapsed += 5
        if ctx is not None:
            await ctx.report_progress(
                elapsed, None, f"Scan in progress ({elapsed}s elapsed)"
            )
    try:
        result = scan_task.result()
    except (ScannerError, ValueError) as exc:
        raise RuntimeError(f"Scan failed: {exc}") from exc

    scan_id = _next_scan_id()
    _RESULTS[scan_id] = result
    return {"scan_id": scan_id, **result.summary}


@server.tool()
def get_summary(scan_id: str) -> dict[str, Any]:
    """Return the run summary of a completed scan (see scan_repository)."""
    return {"scan_id": scan_id, **_get(scan_id).summary}


@server.tool()
def get_findings(
    scan_id: str,
    min_severity: str = "info",
) -> list[dict[str, Any]]:
    """Return detailed findings of a completed scan.

    Args:
        scan_id: Value returned by scan_repository.
        min_severity: Only findings at or above this severity
            (critical/high/medium/low/info; default returns all).
    """
    if min_severity not in SEVERITY_ORDER:
        raise ValueError(
            f"min_severity must be one of {SEVERITY_ORDER}, got {min_severity!r}"
        )
    max_rank = SEVERITY_ORDER.index(min_severity)
    return [
        finding.to_dict()
        for finding in _get(scan_id).output.findings
        if SEVERITY_ORDER.index(finding.severity) <= max_rank
    ]


def _get(scan_id: str) -> ScanResult:
    if scan_id not in _RESULTS:
        known = ", ".join(_RESULTS) or "none"
        raise ValueError(f"Unknown scan_id: {scan_id!r} (known: {known})")
    return _RESULTS[scan_id]


def main() -> int:
    """Entry point for ``sais mcp``: serve on stdio until the client exits."""
    server.run()
    return 0
