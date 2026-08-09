# Security Policy

[English](./SECURITY.md) | [日本語](./SECURITY_ja.md)

## Supported Versions

We support the latest version:

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in security-ai-scanner itself,
please follow responsible disclosure practices:

### How to Report

Report security vulnerabilities via **GitHub Private Security Advisory**, regardless of severity.

1. **Do NOT** create a public GitHub Issue for security vulnerabilities
2. Open a Private Security Advisory at:
   https://github.com/elvezjp/security-ai-scanner/security/advisories/new

For security-related questions that are **not** vulnerabilities (e.g., best practices, configuration), see the [Questions](#questions) section.

### What to Include

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact and severity
- Suggested fix or mitigation
- Contact information (optional)

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Resolution**: Depending on severity
  - Critical: Within 14 days
  - High: Within 30 days
  - Medium: Within 60 days
  - Low: Next release cycle

## Findings in Scanned Repositories

A vulnerability that security-ai-scanner finds in **another repository**
belongs to that repository's owner. Follow that project's security
policy or a coordinated disclosure process, and share the finding only
with people authorized to receive it. Do not post scan results for
third-party code in this project's issue tracker.

## Running Scans Safely

- **Scan only code you own or are explicitly authorized to assess**
- Repository contents are sent to the configured AI engine for analysis.
  Confirm that submitting the code to that engine is permitted by your
  organization and applicable agreements before scanning
- The scan agent runs with read-only tools (Read / Glob / Grep); shell
  execution, file writes, and network tools are disallowed by the
  engine configuration
- Treat repository files, comments, and user-supplied `--context` as
  untrusted input. The scan prompt instructs the agent accordingly, but
  prompt injection can never be fully ruled out — review findings
  before acting on them
- Scan outputs (`findings.json`, `findings.sarif`, `report.md`) contain
  vulnerability details and code snippets. Store them with the same
  care as the source code itself, and keep them out of public issues
  and pull requests
- Findings may include false positives and false negatives. Treat
  reports as expert input to human review, not as a security
  certification

## Dependency Security Monitoring

Dependencies are monitored via Dependabot, configured in [`.github/dependabot.yml`](.github/dependabot.yml)
to open PRs monthly for `uv` and `github-actions` updates. GitHub Actions
are pinned to commit SHAs rather than mutable tags, so an update always
goes through a reviewed PR rather than a silent tag repoint.

Dependabot alerts are triaged as follows:

| Alert type | Response |
|------------|----------|
| Malware | Fixed immediately regardless of where it appears |
| Vulnerable (latest version) | Fixed via a dependency update PR. If bumping the dependency alone resolves it, the package's own version is not bumped |
| Vulnerable (archived/old version) | Dismissed after confirming the affected code path is not in the maintained version |

## Security Best Practices

Recommendations when using security-ai-scanner:

1. **Keep up to date**: Always use the latest version
2. **Scope your scans**: Only scan code you own or are authorized to assess
3. **Verify the engine target**: Confirm `--base-url` points at the endpoint you intend before scanning sensitive code
4. **Review findings before acting**: Treat scan output as expert input to human review, not a certification
5. **Protect scan output**: Store `findings.json` / `findings.sarif` / `report.md` with the same care as source code; keep them out of public issues and PRs
6. **Monitor dependencies**: Keep `claude-agent-sdk` and other dependencies updated

## Questions

For security-related questions that are not vulnerabilities, contact
info@elvez.co.jp.
