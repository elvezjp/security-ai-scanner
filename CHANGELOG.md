# Changelog

[English](./CHANGELOG.md) | [日本語](./CHANGELOG_ja.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-08-25

### Added

- **Native artifact schema version 1**: `summary.json` and `findings.json` now
  share a UUID `run_id`, UTC `generated_at`, tool version, run `status`, and
  resolved Git or filesystem subject identity
- **Artifact integrity metadata**: native output descriptors record each
  artifact's relative path, SHA-256 digest, and byte count; summary counts are
  checked against findings
- **OpenAI-compatible read-only engine**: a built-in agent loop connects to
  OpenAI-compatible local endpoints while exposing only sandboxed `read_file`,
  `glob`, and `grep` tools
- Authoritative JSON Schemas plus deterministic completed, incomplete, and
  error fixtures generated through the real runner for cross-repository
  conformance testing with `quality-keeper`

### Changed

- **Breaking native format boundary**: 0.3.0 schema-version-1 artifacts are not
  compatible with the released 0.2.0 `summary.json` and `findings.json` shape
- Native `findings.json` and `summary.json` are always emitted; `--format`
  selects additional derived artifacts such as SARIF and Markdown
- Artifact publication now holds an output-directory lock, invalidates stale
  summaries, atomically replaces each file, and commits `summary.json` last as
  the completion marker
- Completed, incomplete, and error runs are explicit. Execution failures write
  a schema-valid `status: "error"` summary on a best-effort basis after
  publication begins. Exit-code meanings remain 0 (pass), 1 (local gate
  failure), and 2 (execution error)

## [0.2.0] - 2026-08-09

### Added

- **Agent-friendly summary output**: every scan now writes `summary.json` (severity counts, gate verdict, exit code, duration, output paths) alongside the other outputs, and `scan --json` prints the same object to stdout as a single JSON line for agents and scripts
- `AGENTS.md`: the agent-facing contract (the one command, exit codes, output schema, timing expectations) for coding agents such as Claude Code, Codex, Cursor, and VS Code agents
- README roadmap section (MCP server, webhook notifications, GitHub Action, batch scan, diff scan, triage)
- **MCP server**: `sais mcp` serves the scanner over the Model Context Protocol (stdio) for MCP clients such as Claude Code, VS Code, Cursor, and Codex. Tools: `scan_repository`, `get_summary`, `get_findings`. Requires the optional `mcp` extra (`pip install 'security-ai-scanner[mcp]'`); scan outputs are written to a temp directory, never into the scanned repository
- **Webhook notifications**: `--notify-webhook` (or `SAIS_NOTIFY_WEBHOOK`) POSTs the run summary on completion or failure; `--notify-format` selects `generic` JSON or a `discord` / `slack` incoming-webhook message. Chat formats carry severity counts only — no finding details. Notification failures never change the scan's exit code, and the webhook URL is never printed
- **GitHub Action**: the repository now ships a composite action (`action.yml`) that installs the scanner, runs a scan, and exposes `sarif-file` / `summary-file` / `exit-code` outputs for use with `codeql-action/upload-sarif`
- **Claude Code skill**: `skills/sais-scan/SKILL.md` — a ready-made skill that runs `sais`, reads the JSON summary, and reports findings as review leads
- **Local LLM support**: `--base-url` points the scan at any self-hosted, Anthropic-compatible inference server, so repository contents never leave your infrastructure
- `--auth-token` for the local endpoint, and `--structured-output` / `--no-structured-output` to control schema-constrained output
- Every model slot the agent harness uses (opus / sonnet / haiku / subagent) is pinned to `--model` when `--base-url` is set, since a local server usually serves a single model
- Hosted credentials (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`) are cleared from the agent subprocess environment when a custom `--base-url` is used, so they cannot take precedence over the local endpoint

- **CI**: test matrix across Linux / Windows / macOS on Python 3.11 and 3.14, plus a build job that verifies the scan prompt is packaged into the wheel
- **Release workflows**: tag-triggered PyPI publish and a manually-triggered TestPyPI publish, both authenticating via Trusted Publisher (OIDC) — no API token stored. The PyPI job refuses to publish when the git tag and `pyproject.toml` version disagree
- GitHub Actions are pinned to commit SHAs rather than mutable tags, with dependabot configured to propose updates

### Changed

- **Python 3.11 or higher is now required** (was 3.10)
- Structured output now defaults to off when `--base-url` is set; the scanner asks for a fenced JSON block and parses that instead
- The engine's token-derived cost estimate is no longer printed for a self-hosted endpoint, where no billing occurs

### Security

Fixes for three findings from a self-scan of this repository ([#14](https://github.com/elvezjp/security-ai-scanner/issues/14)):

- **CI gate bypass in unstructured-output mode** (SAIS-0001, CWE-345): findings are now parsed only from the agent's final response, never from intermediate transcript text that may quote the scanned (untrusted) repository. If more than one schema-conforming JSON block appears in that text, the scan fails instead of silently picking one
- **Auth token exposure** (SAIS-0002, CWE-214): the auth token for `--base-url` can now be supplied via the `SAIS_AUTH_TOKEN` environment variable; help text and README warn that command-line arguments leak into process lists and shell history. An explicit `--auth-token` always wins over the environment, including when it is empty
- **Markdown injection in the report** (SAIS-0003, CWE-116): code fences around evidence are sized dynamically so embedded backticks cannot close them early, finding titles are collapsed onto one line, and block openers in description, recommendation, and summary text are escaped — ATX headings, code fences, and Setext underline / thematic-break lines (`===`, `---`, `___`, `***`)

## [0.1.0] - 2026-07-29

### Added

- Initial release
- `security-ai-scanner scan` command (short alias: `sais`) for agentic security scans of a repository directory
- Claude Agent SDK engine with read-only tool policy (Read / Glob / Grep only; Bash, Write, Edit, and network tools disallowed)
- Structured findings via JSON-Schema-constrained output (title, severity, confidence, file/line, CWE, evidence, recommendation)
- SARIF 2.1.0 export compatible with GitHub Code Scanning (`findings.sarif`)
- JSON export (`findings.json`) and Markdown report (`report.md`)
- CI gate: `--fail-on {critical,high,medium,low,info,none}` with exit code 1 when the threshold is met
- English / Japanese report language (`--language`)
- User-supplied scan context (`--context`), handled as untrusted analysis input
- Engine adapter layer for future backends (`--engine`, default `claude`)
- Python library API: `ScanConfig` / `run_scan`
- Test suite (44 tests) covering findings validation, SARIF export, report generation, orchestration, and the CLI

### Notes

- The scan methodology is an independent implementation inspired by the design of [OpenAI Codex Security](https://github.com/openai/codex-security). No code is shared between the projects.

## Links

- [Repository](https://github.com/elvezjp/security-ai-scanner)
- [Issue Tracker](https://github.com/elvezjp/security-ai-scanner/issues)

## Version Comparison

| Version | Key Features |
|---------|---------------|
| 0.3.0   | Schema-version-1 native artifacts, run identity, integrity metadata, atomic publication, explicit incomplete/error states, OpenAI-compatible read-only engine, cross-repository conformance fixtures |
| 0.2.0   | Local LLM support (`--base-url`), agent summary output (`--json`), MCP server, webhook notifications, GitHub Action, Claude Code skill, self-scan security fixes, Python 3.11+ |
| 0.1.0   | Initial release — agentic scan, SARIF/JSON/Markdown output, CI gate |
