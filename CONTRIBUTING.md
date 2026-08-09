# Contributing to security-ai-scanner

[English](./CONTRIBUTING.md) | [日本語](./CONTRIBUTING_ja.md)

This document describes guidelines for contributing to the project.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an Issue on GitHub with the following information:

- A clear and descriptive title
- Steps to reproduce the problem
- Expected behavior
- Actual behavior
- The scanned repository's language/framework (a minimal reproduction repo if possible)
- security-ai-scanner and Python versions
- Engine and model used (e.g. `claude`, default model)
- Operating system

Do **not** include real vulnerability details from private codebases in
public issues. For vulnerabilities in security-ai-scanner itself, follow
[SECURITY.md](./SECURITY.md).

### Feature Requests

Feature requests are welcome! Please create an Issue with:

- A clear and descriptive title
- Detailed description of the proposed feature
- Use cases and benefits
- Related examples or mockups

### Pull Requests

1. **Fork the repository** and create a branch from `main` (format: username/YYYYMMDD-description)
   ```bash
   git checkout -b user/20260729-fix-feature
   ```

2. **Follow the coding style** of the existing codebase
   - Use meaningful variable and function names
   - Add comments for complex logic
   - Follow PEP 8 style guidelines

3. **Write tests** for your changes
   ```bash
   # Run tests
   uv run pytest tests

   # Run tests with coverage
   uv run pytest tests --cov=security_ai_scanner --cov-report=html
   ```

4. **Update documentation** as needed
   - Update README.md / README_ja.md for user-facing changes
   - Update spec.md for specification changes

5. **Commit your changes** with a clear commit message

   Format: `<type>: <summary>`, where `<type>` is one of `feat`, `fix`,
   `docs`, `test`, `refactor`, `ci`, `chore`, `deps`, or `release`.
   Reference related issues or PRs with `#<number>` in the body when
   relevant.

   ```
   # Good
   fix: handle empty findings list in markdown report
   feat: add --max-turns option to cap agent turns (#42)

   # Avoid
   fix bug
   updates
   ```

6. **Push to your fork** and submit a pull request

7. **Wait for review** - maintainers will review the PR and may request changes

## Development Setup

### Prerequisites

- Python 3.11 or higher
- uv package manager

### Installation

```bash
# Install uv (if not already installed)
# Details: https://docs.astral.sh/uv/getting-started/installation/
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone your fork
git clone https://github.com/YOUR-USERNAME/security-ai-scanner.git
cd security-ai-scanner

# Install dependencies (including test dependencies)
uv sync --extra test
```

### Running Tests

```bash
# Run all tests (no AI engine or network access required)
uv run pytest tests

# Run a specific test file
uv run pytest tests/test_findings.py

# Run with coverage
uv run pytest tests --cov=security_ai_scanner --cov-report=html
```

The unit test suite uses a mock engine and never calls a real AI
backend. To manually verify the real engine, run a scan against a small
repository you own:

```bash
uv run security-ai-scanner scan path/to/small-repo -v
```

Note that real scans consume engine (API) usage.

## CI and Releases

Every push and pull request to `main` runs the test matrix (Linux /
Windows / macOS on Python 3.11 and 3.14) plus a build job that verifies
the scan prompt is packaged into the wheel. The suite uses a mock
engine, so CI needs no AI credentials and makes no network calls.

Releases are tag-driven:

```bash
# bump version in pyproject.toml and update CHANGELOG first
git tag v0.2.0
git push origin v0.2.0
```

The publish workflow re-runs the tests, refuses to publish if the tag
and `pyproject.toml` version disagree, and uploads to PyPI via Trusted
Publisher (OIDC) — no API token is stored in the repository. To
rehearse the release path, run the **Publish to TestPyPI** workflow
manually from the Actions tab.

GitHub Actions are pinned to commit SHAs rather than mutable tags, so a
tag repoint cannot silently change what CI executes. Dependabot
proposes updates monthly; review those PRs rather than editing the
SHAs by hand.

## Coding Guidelines

### Python Style

- Follow PEP 8 style guidelines
- Use type hints (`from __future__ import annotations` style)
- Maximum line length: 100 characters (flexible for long strings)
- Use meaningful variable names
- Add a docstring to public functions and classes describing what they
  do and why, not a restatement of the signature; skip docstrings on
  small private helpers where the name already makes the behavior clear

### Architecture Rules

- The scanner core (`config`, `findings`, `sarif`, `report`, `runner`)
  must stay engine-agnostic — never import an engine SDK there
- Engine-specific code lives under `security_ai_scanner/engine/`;
  new backends implement `ScanEngine` and register in `get_engine()`
- Scan methodology text lives under `security_ai_scanner/prompts/`;
  keep prompts backend-neutral
- Treat all scanned repository content and user-supplied context as
  untrusted data in prompts, never as instructions

## Questions

For questions that are not bugs or feature requests, contact
info@elvez.co.jp.
