"""Command-line interface.

Exit codes:
    0  scan completed, no finding at or above the --fail-on threshold
    1  scan completed, findings at or above the threshold (CI gate)
    2  scan failed (bad arguments, engine error, parse error)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .config import FAIL_ON_CHOICES, OUTPUT_FORMATS, ScanConfig
from .exceptions import ScannerError

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-ai-scanner",
        description=(
            "AI-powered security scanner: agentic LLM analysis of a source "
            "repository with SARIF / JSON / Markdown output."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan", help="Scan a repository directory for security issues"
    )
    scan.add_argument("target", type=Path, help="Path to the repository to scan")
    scan.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("security-scan-results"),
        help="Directory for scan outputs (default: ./security-scan-results)",
    )
    scan.add_argument(
        "--engine",
        default="claude",
        choices=("claude", "openai"),
        help=(
            "AI engine backend: 'claude' (Claude Agent SDK, hosted API or "
            "Anthropic-compatible --base-url) or 'openai' (built-in "
            "read-only loop for OpenAI-compatible endpoints; requires "
            "--base-url and --model) (default: claude)"
        ),
    )
    scan.add_argument(
        "--model",
        default=None,
        help=(
            "Model passed to the engine (or set SAIS_MODEL). Optional for "
            "--engine claude; required for --engine openai, which has no "
            "default on purpose: some servers ignore the model field, and "
            "a guessed default would record a wrong model name in the "
            "scan outputs"
        ),
    )
    scan.add_argument(
        "--base-url",
        default=None,
        help=(
            "Endpoint to scan with instead of the hosted API. For "
            "--engine claude: an Anthropic-compatible server, e.g. "
            "http://127.0.0.1:8000. For --engine openai: an "
            "OpenAI-compatible server, e.g. http://127.0.0.1:11434/v1"
        ),
    )
    scan.add_argument(
        "--auth-token",
        default=None,
        help=(
            "Auth token for --base-url (local servers often accept any "
            "value). Command-line arguments are visible in process lists "
            "and shell history; for real credentials prefer the "
            "SAIS_AUTH_TOKEN environment variable instead"
        ),
    )
    scan.add_argument(
        "--structured-output",
        dest="structured_output",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Request schema-constrained output (default: on for the hosted "
            "API, off with --base-url)"
        ),
    )
    scan.add_argument(
        "--language",
        default="en",
        choices=("en", "ja"),
        help="Language for finding descriptions and the report (default: en)",
    )
    scan.add_argument(
        "--context",
        default=None,
        help="Extra security context for the scan (threat model notes, scope)",
    )
    scan.add_argument(
        "--fail-on",
        default="high",
        choices=FAIL_ON_CHOICES,
        help=(
            "Exit with code 1 if a finding at or above this severity exists "
            "(default: high; use 'none' to disable the gate)"
        ),
    )
    scan.add_argument(
        "--format",
        dest="formats",
        action="append",
        choices=OUTPUT_FORMATS,
        default=None,
        help=(
            "Output format; repeatable (default: all of "
            + ", ".join(OUTPUT_FORMATS)
            + ")"
        ),
    )
    scan.add_argument(
        "--max-turns",
        type=int,
        default=100,
        help="Maximum agent turns for the scan (default: 100)",
    )
    scan.add_argument(
        "--max-tokens",
        dest="max_total_tokens",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Total-token budget for the scan (openai engine): stop early "
            "when reached, keep the findings collected so far, and mark "
            "summary.json with stopped=budget_exceeded (default: no cap)"
        ),
    )
    scan.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Stream the agent's progress commentary to stderr",
    )
    scan.add_argument(
        "--json",
        dest="json_summary",
        action="store_true",
        help=(
            "Print the machine-readable scan summary as JSON to stdout "
            "instead of the human-readable one (for agents and scripts)"
        ),
    )

    scan.add_argument(
        "--notify-webhook",
        default=None,
        metavar="URL",
        help=(
            "Webhook URL to POST the run summary to on completion or "
            "failure (or set SAIS_NOTIFY_WEBHOOK; the URL is treated as a "
            "secret and never printed)"
        ),
    )
    scan.add_argument(
        "--notify-format",
        default="generic",
        choices=("generic", "discord", "slack"),
        help=(
            "Webhook payload format: generic JSON, or a Discord/Slack "
            "incoming-webhook message (default: generic)"
        ),
    )

    subparsers.add_parser(
        "mcp",
        help=(
            "Serve the scanner as an MCP server on stdio (requires the "
            "'mcp' extra: pip install 'security-ai-scanner[mcp]')"
        ),
    )
    return parser


def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        target=args.target,
        output_dir=args.output_dir,
        engine=args.engine,
        model=args.model or os.environ.get("SAIS_MODEL") or None,
        language=args.language,
        context=args.context,
        fail_on=args.fail_on,
        formats=tuple(args.formats) if args.formats else OUTPUT_FORMATS,
        max_turns=args.max_turns,
        max_total_tokens=args.max_total_tokens,
        verbose=args.verbose,
        base_url=args.base_url,
        # An explicitly passed --auth-token wins even when it is empty:
        # `--auth-token ""` must not silently fall through to a token in
        # the environment that was meant for a different endpoint.
        auth_token=(
            args.auth_token
            if args.auth_token is not None
            else os.environ.get("SAIS_AUTH_TOKEN") or None
        ),
        structured_output=args.structured_output,
    )


def _print_summary(result, config: ScanConfig) -> None:
    findings = result.output.findings
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = ", ".join(f"{sev}: {n}" for sev, n in counts.items()) or "none"
    print(f"Scan complete: {len(findings)} finding(s) ({breakdown})")
    for path in result.written_files:
        print(f"  wrote {path}")
    # A self-hosted endpoint bills nothing, so reporting the engine's
    # token-derived estimate as a dollar cost would be misleading.
    if result.engine_result.total_cost_usd is not None and not config.base_url:
        print(f"  engine cost: ${result.engine_result.total_cost_usd:.4f}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        from .runner import run_scan

        webhook_url = args.notify_webhook or os.environ.get(
            "SAIS_NOTIFY_WEBHOOK"
        )

        try:
            config = _config_from_args(args)
            result = run_scan(config)
        except (ScannerError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            if webhook_url:
                from .notify import send_notification

                send_notification(
                    webhook_url,
                    args.notify_format,
                    None,
                    error=str(exc),
                    target=str(args.target),
                )
            return EXIT_ERROR
        if webhook_url:
            from .notify import send_notification

            send_notification(webhook_url, args.notify_format, result.summary)
        if args.json_summary:
            print(json.dumps(result.summary, ensure_ascii=False))
        else:
            _print_summary(result, config)
        if result.engine_result.stopped_reason:
            print(
                f"warning: scan stopped early ({result.engine_result.stopped_reason}); "
                "findings may be incomplete.",
                file=sys.stderr,
            )
        if result.gate_failed:
            print(
                f"CI gate: findings at or above '{config.fail_on}' severity "
                "were detected.",
                file=sys.stderr,
            )
            return EXIT_GATE_FAILED
        return EXIT_OK

    if args.command == "mcp":
        try:
            from .mcp_server import main as mcp_main
        except ImportError:
            print(
                "error: the MCP server needs the 'mcp' extra — install with "
                "pip install 'security-ai-scanner[mcp]'",
                file=sys.stderr,
            )
            return EXIT_ERROR
        return mcp_main()

    parser.error(f"Unknown command: {args.command}")  # pragma: no cover
    return EXIT_ERROR  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
