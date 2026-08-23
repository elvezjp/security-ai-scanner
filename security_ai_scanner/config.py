"""Scan configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

#: Severity levels ordered from most to least severe.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Values accepted by --fail-on. "none" disables the CI gate.
FAIL_ON_CHOICES = SEVERITY_ORDER + ("none",)

OUTPUT_FORMATS = ("json", "sarif", "markdown")


@dataclass
class ScanConfig:
    """Configuration for a single scan run.

    CLI options map 1:1 to these fields.
    """

    target: Path
    output_dir: Path = Path("security-scan-results")
    engine: str = "claude"
    model: str | None = None
    max_turns: int = 100
    #: Total-token budget for the scan; None = no cap. Enforced by
    #: engines that account usage per request (the openai engine).
    max_total_tokens: int | None = None
    language: str = "en"
    context: str | None = None
    fail_on: str = "high"
    formats: tuple[str, ...] = OUTPUT_FORMATS
    verbose: bool = False
    #: Base URL of an Anthropic-compatible endpoint (local LLM server).
    base_url: str | None = None
    #: Auth token sent to that endpoint. Local servers usually accept any value.
    auth_token: str | None = None
    #: Request schema-constrained structured output. Disable for backends
    #: that do not support it; the scanner then parses JSON from the text.
    structured_output: bool | None = None

    def use_structured_output(self) -> bool:
        """Whether to request schema-constrained output.

        Defaults to True for the hosted endpoint and False when a custom
        ``base_url`` is set, since local servers rarely implement it.
        """
        if self.structured_output is not None:
            return self.structured_output
        return self.base_url is None

    def validate(self) -> None:
        from .exceptions import TargetError

        if not self.target.exists():
            raise TargetError(f"Scan target does not exist: {self.target}")
        if not self.target.is_dir():
            raise TargetError(f"Scan target must be a directory: {self.target}")
        if self.fail_on not in FAIL_ON_CHOICES:
            raise ValueError(
                f"fail_on must be one of {FAIL_ON_CHOICES}, got {self.fail_on!r}"
            )
        unknown = set(self.formats) - set(OUTPUT_FORMATS)
        if unknown:
            raise ValueError(f"Unknown output formats: {sorted(unknown)}")
        if self.max_turns < 1:
            raise ValueError("max_turns must be >= 1")
        if self.max_total_tokens is not None and self.max_total_tokens < 1:
            raise ValueError("max_total_tokens must be >= 1")
