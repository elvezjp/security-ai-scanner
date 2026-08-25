"""Webhook notification for scan results.

Sends the run summary (spec.md §4.2) to a webhook when a scan completes or
fails. Three payload formats:

- ``generic``: the summary object itself (or an error object), as JSON —
  for CI systems and custom receivers
- ``discord``: ``{"content": "<one-line text>"}`` — Discord incoming webhooks
- ``slack``: ``{"text": "<one-line text>"}`` — Slack incoming webhooks

Failure policy: a notification must never break the scan. Errors are
reported as a one-line warning on stderr and swallowed. The webhook URL is
treated as a secret (Discord/Slack URLs embed a token) and is never printed.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any

NOTIFY_FORMATS = ("generic", "discord", "slack")

_TIMEOUT_SECONDS = 10


def _human_line(summary: dict[str, Any]) -> str:
    """One chat-friendly line. Counts only — no finding details, which do
    not belong in a chat channel."""
    counts = summary.get("counts", {})
    total = counts.get("total", 0)
    breakdown = ", ".join(
        f"{sev} {counts[sev]}"
        for sev in ("critical", "high", "medium", "low", "info")
        if counts.get(sev)
    )
    gate = summary.get("gate", {})
    if gate.get("failed"):
        status = f"gate FAILED (fail-on: {gate.get('fail_on')})"
    else:
        status = "gate passed"
    detail = f" ({breakdown})" if breakdown else ""
    subject = summary.get("subject", {})
    target = subject.get("root") or summary.get("target")
    return f"sais scan of {target}: {total} finding(s){detail} — {status}"


def _error_line(target: str, message: str) -> str:
    return f"sais scan of {target}: ERROR — {message}"


def build_payload(
    fmt: str, summary: dict[str, Any] | None, *, error: str | None = None,
    target: str = "",
) -> dict[str, Any]:
    """Build the POST body for one notification.

    Completed runs pass ``summary`` only. Failed runs pass ``error`` and may
    also pass the native error summary when it was successfully published.
    """
    if fmt not in NOTIFY_FORMATS:
        raise ValueError(f"format must be one of {NOTIFY_FORMATS}, got {fmt!r}")
    if error is not None:
        text = _error_line(target, error)
        if fmt == "generic":
            if summary is not None:
                return summary
            return {"tool": "security-ai-scanner", "status": "error",
                    "target": target, "error": error}
    else:
        assert summary is not None
        text = _human_line(summary)
        if fmt == "generic":
            return {"status": "completed", **summary}
    if fmt == "discord":
        return {"content": text}
    return {"text": text}


def send_notification(
    url: str,
    fmt: str,
    summary: dict[str, Any] | None,
    *,
    error: str | None = None,
    target: str = "",
) -> bool:
    """POST one notification. Returns True on success, False otherwise.

    Never raises: the scan result must not depend on webhook availability.
    """
    try:
        payload = build_payload(fmt, summary, error=error, target=target)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS):
            pass
        return True
    except Exception as exc:  # noqa: BLE001 — deliberately broad, see docstring
        # Do not echo the URL: webhook URLs embed access tokens.
        print(
            f"warning: webhook notification failed: {type(exc).__name__}",
            file=sys.stderr,
        )
        return False
