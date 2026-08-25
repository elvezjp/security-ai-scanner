# security-ai-scanner Product Specification

[English](spec.md) | [日本語](spec_ja.md)

Version: 0.3.0 / Last updated: 2026-08-25

This document defines the technical specification of `security-ai-scanner`.
See `README.md` for user-facing instructions.

The English-primary
[Common Result Interchange Specification](https://github.com/elvezjp/quality-keeper/blob/main/docs/common-result-interchange-specification.md)
and its complete
[Japanese counterpart](https://github.com/elvezjp/quality-keeper/blob/main/docs/common-result-interchange-specification_ja.md)
define native artifact format, integrity, and compatibility across the three
products. This specification defines behavior specific to `sais` and does not
weaken the common specification.

Version 0.3.0 is the deliberate breaking release boundary from the published
0.2.0 native artifact format to schema version 1. The 0.2.0 shape is not
preserved under schema version 1. Observable artifact changes are specified
here before implementation.

## 1. Purpose and scope

security-ai-scanner is a CLI tool and Python library that uses an LLM agent to
find security vulnerabilities in a source-code repository.

- Input: a repository directory on the local filesystem.
- Output: structured JSON findings, SARIF 2.1.0, and a Markdown report.
- Current scan scope: one full repository path through the `scan` command.
- Reserved scope: path exclusions, configuration files, diff scans, baselines,
  additional engines, profiles, batches, local-LLM hardening, triage,
  benchmarks, release maturity, and fix proposals. The README roadmap and
  Issues #3 through #13 track these features after schema-version-1 adoption.

## 2. Architecture

```text
cli.py ──▶ runner.py ──▶ engine/ (adapter layer) ──▶ AI backend
              │
              ├─▶ prompts/     scan methodology
              ├─▶ findings.py  finding schema and validation
              ├─▶ sarif.py     SARIF output
              └─▶ report.py    Markdown report
```

### 2.1 Layer responsibilities

| Module | Responsibility | Engine dependency |
|---|---|---|
| `cli.py` | Argument parsing and exit-code selection | None |
| `config.py` | `ScanConfig` and configuration validation | None |
| `runner.py` | Prompt, engine, parsing, and output orchestration | None |
| `findings.py` | Finding model, engine output schema, validation, normalization | None |
| `sarif.py` | SARIF 2.1.0 conversion | None |
| `report.py` | English and Japanese Markdown reports | None |
| `prompts/` | Backend-neutral scan methodology | None |
| `engine/base.py` | `ScanEngine`, `ScanRequest`, `EngineResult`, and registry | None |
| `engine/<name>.py` | One backend adapter | Yes, isolated here |

Invariant: an engine SDK import remains inside `engine/<name>.py`.

### 2.2 Engine interface

An engine receives `ScanRequest` and returns `EngineResult`.

- Input includes `prompt`, `system_prompt`, target `cwd`, finding
  `output_schema`, model, turn limit, verbosity, optional `base_url` and
  `auth_token`, and structured-output selection.
- Output includes preferred `structured_output`, fallback `text`, `is_error`,
  turn count, duration, token usage when available, cost when available, and a
  stopped reason when analysis is partial.
- The agent is read-only for the target. The Claude adapter allows Read, Glob,
  and Grep and denies shell, write, edit, notebook, and web tools. The OpenAI
  adapter exposes equivalent Python-implemented read-only tools.

## 3. Finding schema

The engine-facing `FINDINGS_SCHEMA` requests:

```json
{
  "findings": [
    {
      "title": "required string",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "file": "required repository-relative POSIX path",
      "start_line": 1,
      "end_line": 2,
      "cwe": "CWE-89",
      "description": "required string",
      "recommendation": "required string",
      "evidence": "minimal source excerpt"
    }
  ],
  "summary": "required string",
  "files_reviewed": 0
}
```

The published `findings.json` wraps normalized findings with the schema-version-1
run identity and subject required by the common specification.

### 3.1 Validation and normalization (`findings.py`)

- A finding with an absent or empty title, severity, file, or description
  raises `FindingsParseError`.
- Unknown severity normalizes to `info`; unknown confidence to `medium`.
- `start_line` is clamped to at least 1. A non-numeric `end_line` is discarded;
  an end before the start is normalized to the start.
- File paths normalize to repository-root-relative POSIX paths and cannot
  escape the repository root.
- Findings sort by severity rank, file, and start line, then receive run-local
  IDs in `SAIS-0001` form.
- Without structured output, parsing accepts one schema-valid fenced JSON
  object or one bare response object. Invalid blocks are ignored. Multiple
  schema-valid candidates fail closed with `FindingsParseError`.

## 4. Output specification

The output directory is `--output-dir`, defaulting to
`./security-scan-results/`.

| File | Format | Contents |
|---|---|---|
| `findings.json` | JSON | Normative schema-version-1 findings artifact |
| `findings.sarif` | SARIF 2.1.0 | GitHub Code Scanning-compatible derived output |
| `report.md` | Markdown | English or Japanese human-readable report |
| `summary.json` | JSON | Normative run manifest and completion marker; always written when publication is possible |

### 4.2 Native artifacts and run summary (`summary.json` / `--json`)

`summary.json` is the machine-readable public run manifest. `scan --json`
writes the same object to stdout. Schema version 1 follows the common
specification and the authoritative JSON Schemas published by
`quality-keeper`. `summary.json` and `findings.json` contain identical run
identity and subject values.

```json
{
  "schema_version": 1,
  "run_id": "9e533fc0-a84d-44e1-91f3-11d8e54eac62",
  "tool": "security-ai-scanner",
  "version": "0.3.0",
  "generated_at": "2026-08-25T12:34:56Z",
  "status": "completed",
  "subject": {
    "kind": "git",
    "root": "/workspace/project",
    "head_sha": "0123456789abcdef0123456789abcdef01234567",
    "base_sha": null,
    "dirty": false,
    "content_digest": null
  },
  "engine": "claude",
  "summary": "One-line summary generated by the engine",
  "files_reviewed": 25,
  "counts": {"critical": 0, "high": 2, "medium": 1, "low": 0, "info": 3, "total": 6},
  "gate": {"fail_on": "high", "failed": true},
  "exit_code": 1,
  "duration_ms": 123456,
  "cost_usd": 1.23,
  "total_tokens": 45678,
  "stopped": null,
  "outputs": {
    "findings.json": {
      "path": "findings.json",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "bytes": 1234
    }
  }
}
```

- `status` is `completed`, `incomplete`, or `error`. After configuration and
  target validation succeed and the output lock is acquired, an execution
  error writes an error summary on a best-effort basis. Errors before that
  boundary, including an invalid target or an unavailable output lock, do not
  publish a summary or change existing artifacts.
- Exit codes retain their meanings: 0 local gate pass, 1 local gate failure,
  and 2 execution error. An incomplete run returning 0 or 1 is not proof of
  completeness.
- Usage and cost fields are `null` when the engine cannot account for them.
- A non-null `stopped`, including an unknown future value, means partial output
  and therefore `status: incomplete`.
- Every engine error flag is an execution error even if the engine supplied
  other output. A backend adapter may normalize a known limit or cancellation
  into non-error partial output by setting a non-null `stopped` reason; the
  runner still requires schema-valid final findings before publishing it as
  `incomplete`.
- `outputs` describes each published non-summary artifact with `path`, SHA-256,
  and byte count. It excludes `summary.json`, which cannot digest its own final
  bytes.
- The producer invalidates a stale summary before analysis, atomically replaces
  final artifacts, and publishes `summary.json` last as the completion marker.
- Before invalidating the summary, the producer exclusively creates
  `.sais.lock` in the output directory and holds it until publication ends. If
  the lock already exists, the run fails without changing existing artifacts.
  A lock left by an interrupted process is never removed automatically; an
  operator removes it only after confirming that no writer is active.
- Every artifact is first written to a uniquely named temporary file on the
  destination filesystem. The producer flushes the complete bytes before an
  atomic replacement and removes its temporary file after a failed replacement.
  The lock file and temporary files are coordination data, not outputs.
- A published error summary uses the current run identity, `status: error`,
  `stopped: null`, `exit_code: 2`, zero counts, a non-failed local gate, null
  usage fields, an empty `outputs` object, and a human-readable `error` message.
  It is atomically committed under the same output lock and supersedes any
  partial non-summary artifacts from the failed run.
- On an execution error, `--json` writes the published error summary object to
  stdout, or nothing when no summary could be published. Exit code 2 is
  unchanged in both cases.

### 4.1 SARIF mapping

- `ruleId` is the CWE or `SAIS-GENERIC`.
- critical/high maps to `error`, medium to `warning`, and low/info to `note`.
- Numeric `security-severity` is 9.5, 8.0, 5.0, 3.0, or 0.0 respectively.
- Paths use `uriBaseId: SRCROOT` relative to the scanned root.
- Finding properties retain severity, confidence, and title; the run-local ID
  is stored in `partialFingerprints["sais/id"]`.

### 4.3 Subject resolution

The scanner resolves `subject` once before analysis and records the same
object in both native artifacts.

- `subject.root` is the resolved absolute path of the scan target.
- `kind` is `git` when the scan target is inside a Git work tree and the `git`
  executable is available; otherwise `kind` is `filesystem` with `head_sha`,
  `base_sha`, and `dirty` all `null`.
- Git is invoked without a shell, with a fixed executable and argument list.
  Filesystem-monitor and hook execution are disabled, and environment overrides
  that could redirect repository identity are ignored.
  Any subject-resolution failure falls back to `filesystem`; it never fails
  the scan.
- For `kind: git`, `head_sha` is the full object ID of the resolved `HEAD`
  commit. `base_sha` is always `null` for a full scan and is reserved for the
  diff-scan feature.
- A repository whose `HEAD` is unborn (no commits) resolves as `filesystem`.
- `dirty` is `true` when the scanned content differs from `HEAD` within the
  scanned root: tracked files with uncommitted modifications, or untracked
  files. The scanner reads the working tree, so untracked content contributes
  to the analysis and counts as dirty.
- `content_digest` is `null`. A full-repository scan defines no deterministic
  content normalization, and the common specification forbids inventing a
  digest.

## 5. CLI specification

```text
security-ai-scanner scan TARGET [options]
sais scan TARGET [options]
```

| Option | Default | Description |
|---|---|---|
| `-o/--output-dir` | `./security-scan-results` | Output directory |
| `--engine` | `claude` | Registered engine: `claude` or `openai` |
| `--model` | None | Engine model; `SAIS_MODEL` is also accepted and OpenAI requires a value |
| `--language` | `en` | `en` or `ja` |
| `--context` | None | Additional context, handled as untrusted input |
| `--fail-on` | `high` | Local CI threshold; `none` disables finding exit code 1 |
| `--format` | All formats | Repeatable `json`, `sarif`, or `markdown` selection |
| `--base-url` | None | Anthropic-compatible Claude or OpenAI-compatible OpenAI endpoint |
| `--auth-token` | None | Authentication token for `--base-url` |
| `--structured-output` | Automatic | Defaults on without `--base-url` and off with it |
| `--max-turns` | `100` | Maximum agent turns |
| `--max-tokens` | None | Whole-scan token budget where supported |
| `-v/--verbose` | false | Stream agent text to stderr |
| `--json` | false | Write the Section 4.2 summary to stdout |
| `--notify-webhook` | None | Completion or error webhook; `SAIS_NOTIFY_WEBHOOK` is also accepted |
| `--notify-format` | `generic` | `generic`, `discord`, or `slack` |

`findings.json` and `summary.json` are mandatory native artifacts and are
always published for a completed or incomplete run. `--format` selects the
additional derived outputs; `json` remains accepted for CLI compatibility.

### 5.3 Webhook notification

- Notification occurs after a completed run or an execution error.
- A generic webhook receives the published native error summary when available;
  failures before publication use the legacy minimal error object.
- Discord and Slack messages contain counts and verdict only, never detailed
  findings or source paths.
- Notification failure emits one stderr warning and never changes the scan exit
  code.
- A webhook URL is a secret and is never printed in logs or errors.

### 5.1 Exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis completed and the local finding threshold passed |
| 1 | Analysis completed and the local finding threshold failed |
| 2 | Argument, target, engine, parsing, publication, or other execution error |

When `quality-keeper` is the final CI gate, the canonical producer invocation
is `sais scan ... --fail-on none`. Findings and local gate metadata are still
recorded, but finding exit code 1 is disabled and final policy is centralized
in `qk`. Exit code 2 always stops the workflow.

### 5.2 Self-hosted endpoints

The Claude adapter redirects its child agent through Anthropic-compatible
environment variables. The OpenAI adapter directly uses an OpenAI-compatible
Chat Completions endpoint and Python-implemented read-only tools. Both prevent
hosted credentials from overriding an explicitly selected local endpoint.
Structured output defaults off for self-hosted endpoints and falls back to the
fail-closed text parser.

The Claude adapter supplies the following child-process environment values:

| Environment variable | Value | Purpose |
|---|---|---|
| `ANTHROPIC_BASE_URL` | `--base-url` | Select the endpoint |
| `ANTHROPIC_AUTH_TOKEN` | `--auth-token`, default `local` | Authenticate to the local server |
| `ANTHROPIC_API_KEY` | Empty | Prevent hosted credentials from taking precedence |
| `CLAUDE_CODE_OAUTH_TOKEN` | Empty | Prevent hosted credentials from taking precedence |
| `ANTHROPIC_MODEL` and four model slots | `--model` | Pin all slots to the selected local model |

## 6. Security design

- The scan agent receives read-only tools; shell, write, and agent-accessible
  network tools are forbidden.
- The system prompt treats repository files and `--context` as untrusted data,
  not instructions.
- Findings require real paths, line numbers, and evidence; a clean result is an
  empty array rather than fabricated output.
- Prompt injection, false positives, and misses cannot be eliminated. Findings
  remain leads for human review, not verdicts.

## 7. Library API

The public API is limited to:

- `security_ai_scanner.ScanConfig`;
- `security_ai_scanner.run_scan(config) -> ScanResult`;
- `security_ai_scanner.Finding` and `ScanOutput`;
- `security_ai_scanner.__version__`.

## 8. Test strategy

- Unit tests never call a live AI backend; they use mock engines.
- Live-engine tests carry the `integration` marker and do not run by default.
- Coverage includes finding normalization, SARIF, reports, orchestration, exit
  codes, schema-version-1 conformance, run identity, digest and byte counts,
  finding counts, atomic publication, and stale-summary invalidation.
- Producer conformance pins the valid `sais` fixtures and canonical schema
  digests from a recorded `quality-keeper` commit. The same offline checks run
  against deterministic completed, incomplete, and error artifacts emitted by
  the real runner with a mock engine.

## 9. MCP server

`sais mcp` starts an MCP server over stdio. The `mcp` dependency is optional
and imported only inside `mcp_server.py`.

### 9.1 Tool interface

| Tool | Input | Output |
|---|---|---|
| `scan_repository` | required path plus language, fail threshold, and context | Section 4.2 summary plus `scan_id` |
| `get_summary` | `scan_id` | Section 4.2 summary plus `scan_id` |
| `get_findings` | `scan_id`, optional minimum severity | Normalized finding array |

The scan call blocks until completion and reports progress every five seconds.
Detailed findings are fetched separately to avoid oversized initial responses.
Results and IDs are process-local. Output is written to a temporary directory,
never into the scanned repository.

## 10. Reserved future extensions

- batch scans and `batch-summary.json`;
- diff-scoped security scans;
- finding triage and false-positive feedback;
- proposed fix patches;
- additional adapters registered through `engine/`.
