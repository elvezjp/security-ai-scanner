"""Exception types for security-ai-scanner."""

from __future__ import annotations

from typing import Any


_PUBLISHED_SUMMARY = "_sais_published_summary"


def attach_published_summary(
    error: Exception, summary: dict[str, Any]
) -> None:
    """Attach a successfully published error summary without changing type."""
    setattr(error, _PUBLISHED_SUMMARY, summary)


def get_published_summary(error: BaseException) -> dict[str, Any] | None:
    """Return the error summary attached after successful publication."""
    summary = getattr(error, _PUBLISHED_SUMMARY, None)
    return summary if isinstance(summary, dict) else None


class ScannerError(Exception):
    """Base class for all security-ai-scanner errors."""


class TargetError(ScannerError):
    """The scan target is missing or not usable."""


class EngineError(ScannerError):
    """The AI engine failed to run or returned an error."""


class FindingsParseError(ScannerError):
    """The engine output could not be parsed into findings."""


class PublicationError(ScannerError):
    """Scan artifacts could not be safely committed to the output directory."""
