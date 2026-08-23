# security-ai-scanner

[English](https://github.com/elvezjp/security-ai-scanner/blob/main/README.md) | [日本語](https://github.com/elvezjp/security-ai-scanner/blob/main/README_ja.md)

[![Elvez](https://img.shields.io/badge/Elvez-Product-3F61A7?style=flat-square)](https://elvez.co.jp/)
[![IXV Ecosystem](https://img.shields.io/badge/IXV-Ecosystem-3F61A7?style=flat-square)](https://elvez.co.jp/ixv/)
[![PyPI version](https://img.shields.io/pypi/v/security-ai-scanner?style=flat-square)](https://pypi.org/project/security-ai-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Stars](https://img.shields.io/github/stars/elvezjp/security-ai-scanner?style=social)](https://github.com/elvezjp/security-ai-scanner/stargazers)

![security-ai-scanner execute demo](https://raw.githubusercontent.com/elvezjp/security-ai-scanner/main/docs/assets/demo.png)

AI-powered security scanner for source code. An LLM agent reads your
repository with read-only tools, traces data flows from source to sink,
and reports validated vulnerabilities as SARIF, JSON, and a
human-readable Markdown report.

## Features

- **Agentic Analysis**: The AI agent explores the repository itself — enumerating entry points, tracing untrusted input to dangerous sinks, and validating each candidate before reporting
- **Read-Only by Design**: The agent is restricted to Read / Glob / Grep; shell, write, and network tools are disallowed during a scan
- **SARIF 2.1.0 Output**: Findings integrate directly with GitHub Code Scanning and standard AppSec tooling
- **CI Gate Built In**: `--fail-on high` exits non-zero when findings meet the threshold, so a scan can block a pipeline
- **Structured Findings**: Results are produced against a JSON Schema (severity, confidence, CWE, evidence, recommendation) — no fragile text parsing
- **Bilingual Reports**: Finding descriptions and the Markdown report can be generated in English or Japanese (`--language ja`)
- **Local LLM Support**: Scan without sending code off the machine — point the built-in `openai` engine at any OpenAI-compatible server (vLLM, Ollama, LM Studio, llama.cpp), or the default `claude` engine at an Anthropic-compatible endpoint
- **Engine-Agnostic Core**: The scanner core talks to a thin engine adapter; the default engine is the Claude Agent SDK, and other backends can be added without touching the core

## Use Cases

- **Pre-Release Audit**: Run a full scan before shipping and review the Markdown report
- **CI Security Gate**: Fail pull-request pipelines when new high-severity findings appear
- **GitHub Code Scanning**: Upload `findings.sarif` to surface findings in the Security tab
- **Security Triage Input**: Feed `findings.json` into your own tracking or ticketing workflow

## Documentation

- [CHANGELOG.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CHANGELOG.md) - Version history
- [CONTRIBUTING.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](https://github.com/elvezjp/security-ai-scanner/blob/main/SECURITY.md) - Security policy and best practices
- [spec.md](https://github.com/elvezjp/security-ai-scanner/blob/main/spec.md) - Technical specification (Japanese)

## Installation

Requires Python 3.11 or higher. The default engine uses the
[Claude Agent SDK](https://pypi.org/project/claude-agent-sdk/), which
bundles the Claude Code CLI — no separate Node.js installation is
required.

```bash
pip install security-ai-scanner
# or with uv
uv add security-ai-scanner
```

After installation, the `security-ai-scanner` command (and its short
alias `sais`) is available on your `PATH`.

### Authentication

The default engine authenticates the same way Claude Code does. Pick one:

```bash
# Option 1: sign in with your Claude account
claude login

# Option 2: use an API key
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

```bash
security-ai-scanner scan path/to/repo
```

This generates, under `./security-scan-results/`:

- `findings.json`: Structured findings with severity, confidence, CWE, evidence, and recommendations
- `findings.sarif`: SARIF 2.1.0 log for GitHub Code Scanning and SARIF viewers
- `report.md`: Human-readable Markdown report

The exit code is `0` when no finding meets the `--fail-on` threshold,
`1` when one does (CI gate), and `2` on errors.

### Common Examples

**Scan with a Japanese report:**
```bash
sais scan path/to/repo --language ja
```

**Use as a CI gate (fail the build on critical findings only):**
```bash
sais scan . --fail-on critical
```

**SARIF only, into a custom directory:**
```bash
sais scan . --format sarif -o ./out
```

**Give the scanner extra context (scope, threat model notes):**
```bash
sais scan . --context "Internet-facing Flask API. Focus on the api/ directory."
```

**Watch the agent's progress:**
```bash
sais scan . -v
```

## Scanning with a Local LLM

Two engines connect to self-hosted endpoints. Either way, nothing is
sent to a hosted API.

### OpenAI-compatible servers (`--engine openai`)

Most self-hosted inference speaks the OpenAI API — vLLM, Ollama,
LM Studio, llama.cpp server, and corporate gateways. The `openai`
engine connects to them directly with a minimal built-in agent loop:
its only tools are `read_file` / `glob` / `grep`, implemented in this
package and sandboxed to the scan root, so the read-only guarantee is
structural — no shell, write, or network tool exists in the loop, and
no third-party agent harness is involved.

```bash
sais scan ./repo \
  --engine openai \
  --base-url http://127.0.0.1:11434/v1 \
  --model qwen2.5-coder:32b
```

`--model` is required (or set `SAIS_MODEL`): there is no default on
purpose, because some servers ignore the model field and a guessed
default would record a wrong model name in the scan outputs. When the
model is missing, the error lists what the server actually offers
(via `GET /v1/models`).

`--max-tokens N` sets a total-token budget for the scan. When the
budget is reached the engine stops calling tools, collects the findings
it has, and marks `summary.json` with `"stopped": "budget_exceeded"`.
A budget-stopped scan with no findings still exits 0, and the model's
prose summary may not admit the scan was cut short — in CI, also check
that `stopped` is null before trusting a clean result. Note that
servers that omit the `usage` field in responses under-count
`total_tokens`, which weakens budget enforcement on such servers.

### Anthropic-compatible servers (`--engine claude`, the default)

Point `--base-url` at a self-hosted, Anthropic-compatible endpoint.
Note that this path runs the Claude Agent SDK's bundled Claude Code CLI
locally as the agent harness; only the inference endpoint changes.

```bash
sais scan ./repo \
  --base-url http://127.0.0.1:8000 \
  --auth-token local \
  --model your-local-model
```

The scanner pins every model slot the agent harness uses (opus / sonnet
/ haiku / subagent) to `--model`, since a local server usually serves a
single model, and clears any hosted credentials from the subprocess
environment so they cannot take precedence over the local endpoint.

### Common to both engines

The scanner sends repository contents to whatever `--base-url` you
give it — treat that URL as trusted infrastructure and never point it
at an endpoint you do not control.

If your endpoint requires a real credential, prefer the
`SAIS_AUTH_TOKEN` environment variable over `--auth-token`:
command-line arguments are visible in process lists, shell history,
and CI logs.

Schema-constrained structured output is turned **off** automatically for
a custom `--base-url`, because support in local servers is inconsistent.
The scanner instead asks for a fenced JSON block and parses that. If
your server does support it (`response_format: json_schema` for the
openai engine), re-enable with `--structured-output`.

### Scope the target to fit the context window

**This is the main practical constraint.** The agent reads source files
into its context as it works, so a whole repository can exhaust a
smaller context window mid-scan. In our testing, a 43-file Python
repository failed against a 100K-token local endpoint (the run stopped
at ~98.5K), while the same scan scoped to the application package
(`backend/app`, 25 files) completed normally.

Point the scan at a component rather than a repository root when using
a local endpoint. This is rarely a real limitation in practice, since
the security-relevant code is usually one package.

### What to expect

We measured this by scanning a repository whose vulnerabilities were
already known and confirmed by hand:

| | Hosted API | Local endpoint |
|---|---|---|
| Known vulnerabilities found | 3 of 3 | 2 of 3, with matching file and line |
| Additional real issues found | — | CORS wildcard with credentials, debug output leaking request contents, dependencies pinned to a branch |
| False positives | none observed | none observed |
| Severity calibration | consistent | inconsistent — rated one path traversal lower and one missing-auth finding higher |
| Throughput | minutes | roughly an order of magnitude slower |

A local model is a genuine reviewer, not a keyword matcher: it traced
data flows and cited accurate line numbers, and it surfaced real issues
the hosted run did not. Where it is weaker is judging *how much a
finding matters* — treat its severities as a starting point for triage
rather than a ranking you can act on directly.

A practical split is local for privacy-sensitive screening, hosted for
release audits and anything where the severity ranking itself drives a
decision.

> **Note:** if your server processes one request at a time, run scans
> serially rather than in parallel.

## Use as a Library

`security-ai-scanner` is also usable as a Python library.

```python
from pathlib import Path
from security_ai_scanner import ScanConfig, run_scan

result = run_scan(ScanConfig(target=Path("path/to/repo"), language="ja"))

for finding in result.output.findings:
    print(finding.severity, finding.file, finding.title)

print(result.gate_failed)   # True if findings meet the fail-on threshold
```

CLI options map 1:1 to `ScanConfig` fields (e.g. `fail_on="critical"`,
`formats=("sarif",)`).

### From source

```bash
git clone https://github.com/elvezjp/security-ai-scanner.git
cd security-ai-scanner
uv sync
```

See [CONTRIBUTING.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CONTRIBUTING.md) for the full developer setup.

## Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output-dir` | `./security-scan-results` | Output directory |
| `--engine` | `claude` | AI engine backend: `claude` (Claude Agent SDK) or `openai` (built-in loop for OpenAI-compatible endpoints) |
| `--model` | Engine default (`claude`) / required (`openai`) | Model passed to the engine (or `SAIS_MODEL` env var) |
| `--base-url` | Hosted API | Self-hosted endpoint: Anthropic-compatible (`claude`) or OpenAI-compatible (`openai`) |
| `--auth-token` | `SAIS_AUTH_TOKEN` env var | Auth token for `--base-url` (prefer the env var for real credentials) |
| `--structured-output` | Auto | Force schema-constrained output on/off (`--no-structured-output` to disable) |
| `--language` | `en` | Language for findings and report (`en` / `ja`) |
| `--context` | - | Extra security context for the scan |
| `--fail-on` | `high` | CI gate threshold (`critical`/`high`/`medium`/`low`/`info`/`none`) |
| `--format` | All | Output format, repeatable (`json`/`sarif`/`markdown`) |
| `--max-turns` | `100` | Maximum agent turns |
| `--max-tokens` | No cap | Total-token budget for the scan (openai engine); stops early with partial findings |
| `-v`, `--verbose` | false | Stream agent progress to stderr |
| `--json` | false | Print the machine-readable summary to stdout (for agents and scripts) |
| `--notify-webhook` | - | Webhook URL to POST the run summary to on completion/failure (or `SAIS_NOTIFY_WEBHOOK`) |
| `--notify-format` | `generic` | Webhook payload: `generic` JSON, or a `discord` / `slack` message |

## For AI Agents

`sais` is designed to be easy for coding agents (Claude Code, Codex, Cursor,
VS Code agents, ...) to drive: stable exit codes, a machine-readable
`summary.json` (always written), and `--json` for a single-line JSON summary
on stdout. See [AGENTS.md](https://github.com/elvezjp/security-ai-scanner/blob/main/AGENTS.md) for the agent-facing contract.

### Claude Code skill

[`skills/sais-scan/SKILL.md`](https://github.com/elvezjp/security-ai-scanner/blob/main/skills/sais-scan/SKILL.md) is a ready-made
skill for Claude Code and compatible agents. Copy it into your skills
directory (e.g. `.claude/skills/sais-scan/`) and ask for a security scan —
the agent runs `sais`, reads the JSON summary, and reports findings as
review leads.

### MCP server

With the `mcp` extra installed (`pip install 'security-ai-scanner[mcp]'`),
`sais mcp` serves the scanner over the Model Context Protocol (stdio), so
MCP clients — Claude Code, VS Code, Cursor, Codex — can scan without
shelling out:

```bash
# Claude Code
claude mcp add sais -- sais mcp
```

```json
// VS Code / Cursor (mcp.json)
{ "servers": { "sais": { "command": "sais", "args": ["mcp"] } } }
```

Tools: `scan_repository(path, ...)` → run summary + `scan_id`,
`get_summary(scan_id)`, `get_findings(scan_id, min_severity)`. A scan takes
minutes; the server sends MCP progress notifications while it runs.

## Notifications

`--notify-webhook URL` (or the `SAIS_NOTIFY_WEBHOOK` environment variable)
POSTs the run summary when a scan completes or fails — so unattended scans
never fail silently:

```bash
# Discord channel notification (counts and gate verdict only)
sais scan . --notify-webhook "$DISCORD_WEBHOOK_URL" --notify-format discord
```

`--notify-format` selects the payload: `generic` (the summary JSON, for CI
and custom receivers), `discord`, or `slack`. Chat formats send a one-line
message with severity counts only — never finding details. A failed
notification prints a warning and does not change the scan's exit code; the
URL is treated as a secret and never printed.

## GitHub Action

The repository doubles as a composite action on top of the SARIF output:

```yaml
- uses: elvezjp/security-ai-scanner@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: security-scan-results/findings.sarif
```

Inputs: `target`, `fail-on`, `language`, `output-dir`, `version`,
`extra-args`. Outputs: `sarif-file`, `summary-file`, `exit-code`.

By default the action installs the latest scanner release from PyPI.
For reproducible CI runs, pin it with `version: "0.2.0"` — pinning the
action reference alone does not pin the scanner itself.

## How It Works

```
┌─────────────┐   prompt +       ┌──────────────────┐
│  Scanner    │   JSON schema    │  Engine adapter  │
│  core       │ ───────────────▶ │  (claude, ...)   │
│             │                  └────────┬─────────┘
│  findings   │                           │ read-only tools
│  validation │                  ┌────────▼─────────┐
│  SARIF /    │ ◀─────────────── │  AI agent reads  │
│  report     │   structured     │  the repository  │
└─────────────┘   findings       └──────────────────┘
```

1. The scanner builds a security-audit prompt and a findings JSON Schema
2. The engine runs an AI agent over the target directory with read-only tools (Read / Glob / Grep only)
3. The agent maps entry points, traces data flows, validates candidates, and returns findings as structured output
4. The scanner validates, ranks, and writes SARIF / JSON / Markdown

## Directory Structure

```
security-ai-scanner/
├── security_ai_scanner/     # Main package
│   ├── cli.py               # Command-line interface
│   ├── config.py            # Scan configuration
│   ├── findings.py          # Finding model, schema, validation
│   ├── sarif.py             # SARIF 2.1.0 export
│   ├── report.py            # Markdown report generation
│   ├── runner.py            # Scan orchestration
│   ├── engine/              # Engine adapters (claude, ...)
│   └── prompts/             # Scan methodology prompts
├── tests/                   # Test suite
├── spec.md                  # Specification
├── docs/                    # Documentation
├── pyproject.toml           # Project metadata
├── LICENSE                  # MIT License
├── README.md / _ja.md       # README (English / Japanese)
├── CONTRIBUTING.md / _ja.md # Contribution guide (English / Japanese)
├── SECURITY.md / _ja.md     # Security policy (English / Japanese)
└── CHANGELOG.md / _ja.md    # Version history (English / Japanese)
```

## Security

For security concerns, please see [SECURITY.md](https://github.com/elvezjp/security-ai-scanner/blob/main/SECURITY.md).

**Key security notes:**
- The scan agent runs with read-only tools; it does not modify the target or execute repository code
- Repository contents are sent to the configured AI engine for analysis — only scan code you are authorized to submit to that engine. Use `--base-url` with a self-hosted endpoint when the code must not leave your infrastructure
- Findings may include false positives and false negatives; treat reports as expert input to human review, not as a certification
- Scan only code you own or are authorized to assess

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CONTRIBUTING.md) for details.

- Report bugs via [GitHub Issues](https://github.com/elvezjp/security-ai-scanner/issues)
- Submit pull requests for improvements
- Follow existing code style
- Add tests for new features

## Roadmap

Planned, in rough order. Scope and timing may change based on feedback.

- **Batch scan** — scan multiple repositories serially with an aggregate summary (`batch-summary.json`). Not implemented yet; today, loop `sais scan` in a shell script and read each run's `summary.json`
- **Diff scan** — limit a scan to a PR / commit range
- **Triage** — re-evaluate existing findings, learn from false-positive feedback

## Changelog

See [CHANGELOG.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CHANGELOG.md) for details.

## Background

This tool was created as a small utility during the development of
**IXV (Ixiv)**, a development support AI for Japanese development
documents and specifications.

IXV addresses the challenges of understanding, structuring, and
utilizing Japanese documents in system development. This repository
publishes a portion of that work.

The scan methodology (agentic scan → validation → structured findings)
is an independent implementation inspired by the design of
[OpenAI Codex Security](https://github.com/openai/codex-security). No
code is shared between the two projects.

## License

MIT License - See [LICENSE](https://github.com/elvezjp/security-ai-scanner/blob/main/LICENSE) for details.

## Contact

- **Email**: info@elvez.co.jp
- **Company**: Elvez, Inc.
