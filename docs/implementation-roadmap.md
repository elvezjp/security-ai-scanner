# Implementation Roadmap

[English](implementation-roadmap.md) | [日本語](implementation-roadmap_ja.md)

Status: Active implementation; S0-S1 complete

Last updated: 2026-08-25

## 1. Purpose and status

This roadmap explains the implementation order for `security-ai-scanner`
(`sais`) within the three-product quality tool suite. It is informative. The
product specification and the suite's
[Common Result Interchange Specification](https://github.com/elvezjp/quality-keeper/blob/main/docs/common-result-interchange-specification.md)
are normative.

Observable behavior is specified before implementation. Schemas, fixtures, and
conformance tests make the specification executable.

## 2. Suite implementation order

| Phase | Deliverable | Primary repository |
|---|---|---|
| 0 | Common Result Interchange Specification | `quality-keeper` — complete |
| 1 | Schemas and conformance fixtures | `quality-keeper` — complete |
| 2 | First schema-version-1 producer (`sais` 0.3.0) | `security-ai-scanner` |
| 3 | Minimal native consumer validation | `quality-keeper` |
| 4 | Vertical implementation of `cair` | `code-ai-reviewer` |
| 5 | Complete policy engine and reports | `quality-keeper` |
| 6 | Three-product end-to-end validation | All three repositories |

This order connects one real producer to one minimal consumer before the second
producer is built. It tests the interchange specification early and avoids
copying a moving artifact format into `cair`.

## 3. Role of this repository

`sais` is the reference native producer because it already has a working CLI,
engine abstraction, result normalization, SARIF output, reports, and tests.

The target milestone is **security-ai-scanner 0.3.0 with schema version 1**.
The adoption work is tracked in
[Issue #20](https://github.com/elvezjp/security-ai-scanner/issues/20).

Until this milestone is complete, Issue #20 takes precedence over the product
feature roadmap in `README.md`. The P0 items tracked in Issues #3 through #6
follow schema-version-1 conformance and are not scheduled in parallel unless
they are explicitly reprioritized.

Implementation begins after `quality-keeper` publishes the schema-version-1
schemas and conformance fixtures. Those fixtures define the consumer-visible
acceptance boundary; this repository keeps producer-side copies or generated
equivalents for offline tests.

## 4. Work packages

### S0. Specification and release boundary — Complete

- Update the product specification before changing emitted artifacts.
- Declare 0.3.0 as the deliberate breaking boundary from the released 0.2.0
  native artifact format.
- Keep exit-code meanings unchanged: `0` pass, `1` local gate failure, `2`
  execution error.
- Document the canonical `--fail-on none` mode when `qk` is the final CI gate.

Completion condition: the English and Japanese specifications describe the
same 0.3.0 behavior and link to the common interchange specification.

### S1. Run identity and native models — Complete

- Add `schema_version`, UUID `run_id`, `generated_at`, `status`, and `subject`.
- Resolve full Git object IDs when the target is a Git repository.
- Record filesystem targets without inventing a Git identity or digest.
- Include the same run identity and subject metadata in `summary.json` and
  `findings.json`.
- Publish machine-readable schemas for both artifacts.

Completion condition: completed, incomplete, and error objects validate against
schema version 1 without calling a live LLM.

### S2. Artifact integrity and atomic publication — Complete

- Replace each non-summary `outputs` path string with an entry containing
  `path`, `sha256`, and `bytes`. Exclude `summary.json` itself because it is the
  completion marker and cannot contain a digest of its own final bytes.
- Invalidate a stale `summary.json` before a run starts.
- Write artifacts to temporary files on the destination filesystem.
- Atomically replace final artifact paths.
- Publish `summary.json` last as the completion marker.
- Prevent or explicitly reject concurrent writers to one output directory.

Completion condition: interruption tests prove that old and new artifacts
cannot be mistaken for one completed run.

### S3. Completion, interruption, and error behavior — Complete

- Emit `status: completed` only when analysis finishes normally.
- Emit `status: incomplete` for token budget, maximum turn, and other partial
  result conditions.
- Treat every unknown non-null `stopped` reason as incomplete.
- Write an `error` summary on a best-effort basis when the output directory is
  usable, while preserving exit code `2`.
- Keep human-readable output bilingual and machine identifiers language-neutral.

Completion condition: CLI and runner tests cover every status and exit-code
combination allowed by the specification.

### S4. Conformance and regression tests — Complete

- Test run identity equality between the two native artifacts.
- Recompute and verify hashes, byte counts, and severity counts.
- Test stale-summary invalidation and atomic replacement.
- Test clean Git, dirty Git, and non-Git subjects.
- Validate emitted outputs against the canonical hand-authored conformance
  fixtures published by `qk`.
- Preserve all existing engine, parsing, report, SARIF, MCP, and notification
  behavior unless the specification explicitly changes it.

Completion condition: all offline producer conformance tests pass, and real
completed and incomplete schema-version-1 fixtures are ready for `qk`.

### S5. Release and downstream handoff — In progress

- Bump the package and runtime version to 0.3.0.
- Update `README.md`, `README_ja.md`, changelogs, and specifications in the same
  release.
- Record the final source commit for `cair` to copy its OpenAI-compatible
  read-only engine and artifact infrastructure.
- Publish completed and incomplete fixtures for `quality-keeper`.

Completion condition: the 0.3.0 release artifacts and documentation agree, and
the downstream source commit is immutable and recorded.

### S6. Human-facing report acceptance (post-0.3 follow-up)

This work package incorporates the accepted plan from
[Issue #23](https://github.com/elvezjp/security-ai-scanner/issues/23). It starts
after S5 and does not delay the schema-version-1 handoff to `quality-keeper`.

- Before changing output, specify the same `report.md` structure in the English
  and Japanese product specifications.
- Put the local gate verdict, severity counts, and highest-severity actionable
  findings before the first full finding detail; this structural order replaces
  viewer-dependent wording such as "the first screen."
- Order findings by severity and then file, and render `file:line` references.
  Make them links only when a stable source URL can be derived without guessing;
  otherwise retain unambiguous plain references.
- Define an explicit evidence line or character limit and a visible truncation
  marker before implementation.
- Use English and Japanese golden-file tests for the deterministic report
  skeleton without asserting LLM-generated prose.
- Extend the benchmark in Issue #11 with an anchored human-scored rubric for
  concrete input-to-impact descriptions, actionable recommendations, and
  readable Japanese. Use a fixed 0-2 scale per dimension and record model,
  language, prompt version, and evaluator notes with each result.

Completion condition: both report skeletons pass golden-file tests, and the
documented model set has published human-scored prose results in both output
languages.

## 5. Implementation discipline

- Do not add product features unrelated to schema-version-1 conformance in the
  same implementation change.
- Keep engine-specific imports inside `engine/<name>.py`.
- Keep all unit and conformance tests offline; live-engine tests remain marked
  integration tests.
- Do not preserve the legacy 0.2.0 artifact shape under schema version 1.
- Do not start the `cair` code copy until the conforming `sais` source commit is
  selected.

## 6. Handoff to the next phase

After S5, `quality-keeper` implements and verifies the minimal native consumer
path against real `sais` output. Only after that path passes does
`code-ai-reviewer` begin its vertical implementation from the recorded source
commit. S6 may proceed as an independent post-0.3 quality track without
reopening the common machine-readable specification.
