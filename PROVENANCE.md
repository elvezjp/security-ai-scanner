# Provenance

[English](./PROVENANCE.md) | [日本語](./PROVENANCE_ja.md)

This record separates design inspiration, standards, dependencies, and copied
material so that future contributors can preserve the project's licensing
boundary.

## Project implementation

The `security-ai-scanner` implementation and scan prompt were created for this
repository and are distributed by Elvez under the MIT License.

The scan methodology—agentic exploration, validation, and structured
findings—was inspired by the design of
[OpenAI Codex Security](https://github.com/openai/codex-security). The projects
do not share code, prompts, or documentation text. The upstream project is not
a runtime or build dependency and does not endorse this project.

## Standards and interfaces

SARIF output implements the OASIS SARIF 2.1.0 interface. The repository does
not vendor the OASIS schema; generated documents identify the applicable public
schema URI. OpenAI-compatible and Anthropic-compatible describe wire
interfaces and do not imply sponsorship, certification, or partnership.

## Dependencies and redistribution

Optional third-party components are recorded in
[THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md). Release automation derives a
CycloneDX SBOM from the locked dependency graph. A downstream bundle must
repeat the audit for the versions it actually redistributes.

## Contribution rule

Every contribution must be submitted under MIT and with sufficient rights.
Copied or substantially adapted material must record its source, immutable
version or commit, license, affected files, and required notices in the pull
request and, when material, in this document.
