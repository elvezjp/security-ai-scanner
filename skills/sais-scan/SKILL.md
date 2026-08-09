---
name: sais-scan
description: >-
  Run an AI-powered security scan of a repository with security-ai-scanner
  (sais) and report the findings. Use when the user asks to security-scan
  code, audit a repository for vulnerabilities, check for security issues,
  or mentions sais / security-ai-scanner.
---

# sais-scan — Security scan of a repository

Scan a local repository with `sais` and report the results. The scan agent
is read-only (Read/Glob/Grep only) and cannot modify the target.

## Steps

1. **Locate the tool.** Run `sais --version`. If missing, ask the user
   before installing (`pip install security-ai-scanner`). Do not install
   silently.

2. **Confirm the target.** Scan only a repository the user asked about.
   The target must be a local directory. Ask before scanning anything
   outside the current project.

3. **Run the scan** (takes several minutes — use a generous timeout, at
   least 15 minutes):

   ```bash
   sais scan <target-dir> -o <output-dir> --json
   ```

   Use a scratch directory for `-o`, not the repository itself. Add
   `--language ja` when the user works in Japanese.

4. **Read the one-line JSON summary from stdout.** Exit code 0 = no
   finding at or above the gate threshold (default `high`) — NOT
   necessarily a clean repository: medium/low/info findings still exit 0,
   so check `counts.total` in the summary to see whether anything was
   found. 1 = findings at/above the threshold (the scan itself
   succeeded), 2 = the scan failed (report the stderr message).

5. **Report to the user**: total findings and severity counts first, then
   the important findings from `<output-dir>/findings.json` (title,
   severity, file:line, recommendation). Point to `report.md` for the full
   report.

## Rules

- Findings may include false positives — present them as leads for review,
  not verdicts. Do not modify code to "fix" findings unless the user asks.
- Do not paste secrets or full file contents from the scanned repository
  into the conversation; quote only the minimal evidence lines.
- If the user's client supports MCP, `sais mcp` is an alternative to the
  CLI (see AGENTS.md in the repository root).
