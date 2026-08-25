# security-ai-scanner — Guide for AI Agents

This file tells AI agents (Claude Code, Codex, Cursor, VS Code agents, and
others) how to run this tool and consume its results. Humans: see README.md.

## What this tool does

`sais` scans a local repository directory for security vulnerabilities using
an LLM agent, and writes structured results. The scan agent itself is
**read-only by design** (Read/Glob/Grep only — no shell, no writes, no
network), so running it cannot modify the target repository.

## The one command you need

```bash
sais scan /path/to/repo -o /tmp/sais-out --json
```

- `--json` prints a machine-readable summary to **stdout** (single JSON
  object). Everything else goes to files in `-o` or to stderr.
- A scan takes **several minutes** (typically 2–10 depending on repository
  size and backend). Do not assume it hung; use a generous timeout.

## Exit codes (stable specification)

| Code | Meaning |
|---|---|
| 0 | Scan completed, no finding at or above `--fail-on` (default: high) |
| 1 | Scan completed, findings at or above the threshold (CI gate) |
| 2 | Error (bad arguments, missing target, engine failure, parse failure) |

Exit codes 0 **and** 1 both mean the scan itself succeeded — check
`counts` in the summary. Only 2 means the run failed.

## Reading the results

stdout with `--json` (same object as `summary.json` in the output dir):

```json
{
  "schema_version": 1,
  "run_id": "9e533fc0-a84d-44e1-91f3-11d8e54eac62",
  "tool": "security-ai-scanner",
  "version": "0.3.0",
  "generated_at": "2026-08-25T12:34:56Z",
  "status": "completed",
  "stopped": null,
  "subject": {"kind": "git", "root": "/workspace/project", "head_sha": "0123456789abcdef0123456789abcdef01234567", "base_sha": null, "dirty": false, "content_digest": null},
  "counts": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 3, "total": 6},
  "gate": {"fail_on": "high", "failed": true},
  "exit_code": 1,
  "duration_ms": 123456,
  "total_tokens": 45678,
  "cost_usd": 1.23,
  "outputs": {"findings.json": {"path": "findings.json", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "bytes": 1234}}
}
```

Detailed findings (title, severity, CWE, file, line, description,
recommendation, evidence) are in `findings.json`. SARIF 2.1.0 is in
`findings.sarif` for GitHub Code Scanning. A human-readable report is in
`report.md` (`--language ja` for Japanese).

Treat `summary.json` as the completion marker: if it is missing, do not treat
remaining artifacts as one completed run. A `.sais.lock` file means another
writer may be active; never remove it without first confirming that no scan is
using the output directory.

Exit code 2 may still have a schema-valid `status: "error"` summary. With
`--json`, read it from stdout exactly as for completed and incomplete runs. If
stdout is empty, publication was not possible; do not fall back to stale files.

## Useful options

| Option | Use when |
|---|---|
| `--fail-on none` | You want counts without a gating exit code |
| `--language ja` | The user works in Japanese |
| `--context "..."` | You have threat-model notes (treated as untrusted data) |
| `--base-url URL` | Scanning must stay on-premises via a local Anthropic-compatible LLM server |
| `--format json` | You only need the mandatory native JSON artifacts; `findings.json` and `summary.json` are always written |

## Prefer MCP when available

If your client speaks MCP, connect via `sais mcp` (needs
`pip install 'security-ai-scanner[mcp]'`) instead of shelling out:
`scan_repository(path)` returns the same summary object plus a `scan_id`;
fetch details with `get_findings(scan_id, min_severity)` only when needed.
The server reports progress while the scan runs.

## Rules of thumb

- Scan **directories, not files**; the target must be a local path.
- Do not parse the human-readable stdout — use `--json` or `summary.json`.
- Findings can contain false positives and misses. Treat them as leads for
  review, not verdicts. Do not auto-"fix" findings without human sign-off.
- Authentication follows the Claude Agent SDK (`claude login` session or
  `ANTHROPIC_API_KEY`); with `--base-url` no hosted credentials are used.
