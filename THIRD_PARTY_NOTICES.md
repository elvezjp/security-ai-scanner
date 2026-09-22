# Third-Party Notices

`security-ai-scanner` is licensed under the MIT License. Its built-in
OpenAI-compatible engine uses only the Python standard library at runtime.
Optional features install the following packages as separate distributions;
their distributions remain the authoritative source for complete license texts
and dependency notices.

| Feature | Package | Requirement | Copyright notice | License / terms |
|---|---|---:|---|---|
| Claude engine | [claude-agent-sdk](https://github.com/anthropics/claude-agent-sdk-python) | `>=0.2.131` | Copyright (c) 2025 Anthropic, PBC | MIT; use is also governed by [Anthropic's Commercial Terms of Service](https://www.anthropic.com/legal/commercial-terms) except where a component carries a separate license |
| MCP server | [mcp](https://github.com/modelcontextprotocol/python-sdk) | `>=1.2,<2` | Copyright (c) 2024 Anthropic, PBC | MIT |

The Claude Agent SDK wheel bundles the Claude Code CLI. Selecting a custom
inference endpoint does not remove the SDK or CLI terms. Users enabling the
Claude engine are responsible for reviewing the current commercial terms,
usage policy, data-processing terms, and the licenses shipped with that wheel.

The optional MCP dependency has its own transitive dependency set. Release
automation generates a CycloneDX SBOM from `uv.lock`; a redistributor that
bundles dependencies into an application or container must ship the license
files required by the exact distributions in that SBOM.

OpenAI Codex Security is an acknowledged design inspiration, not a code
dependency. See [PROVENANCE.md](./PROVENANCE.md); no OpenAI code is included in
this distribution.
