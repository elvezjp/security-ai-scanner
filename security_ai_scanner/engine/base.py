"""Engine adapter layer.

The scanner core is engine-agnostic: an engine receives a prompt, runs an
agentic analysis over the target directory with read-only tools, and
returns structured findings. New backends (other agent SDKs, local
models) are added by implementing :class:`ScanEngine` and registering it
in :func:`get_engine`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanRequest:
    """Everything an engine needs to run one scan."""

    prompt: str
    system_prompt: str
    cwd: Path
    output_schema: dict[str, Any]
    model: str | None = None
    max_turns: int = 100
    verbose: bool = False
    #: Anthropic-compatible endpoint to talk to instead of the hosted API.
    base_url: str | None = None
    #: Auth token for that endpoint.
    auth_token: str | None = None
    #: Ask the backend for schema-constrained output. When False the engine
    #: returns text and the scanner parses JSON out of it.
    structured_output: bool = True
    #: Total-token budget for the whole scan. Engines that account usage
    #: per request stop early when the budget is reached; None = no cap.
    max_total_tokens: int | None = None


@dataclass
class EngineResult:
    """Raw result returned by an engine."""

    structured_output: Any = None
    text: str = ""
    is_error: bool = False
    error_message: str = ""
    num_turns: int = 0
    duration_ms: int = 0
    total_cost_usd: float | None = None
    #: Total tokens consumed, when the engine can account them (else None).
    total_tokens: int | None = None
    #: Language-neutral reason the scan stopped early (for example,
    #: "budget_exceeded" or "max_turns"), or None for normal completion.
    #: Any non-null value means findings are partial.
    stopped_reason: str | None = None


class ScanEngine(ABC):
    """A backend capable of running an agentic security scan."""

    name: str = "abstract"

    @abstractmethod
    async def run(self, request: ScanRequest) -> EngineResult:
        """Run the scan and return the raw engine result."""


def get_engine(name: str) -> ScanEngine:
    """Look up an engine by name."""
    from .claude import ClaudeAgentEngine
    from .openai import OpenAICompatEngine

    engines: dict[str, type[ScanEngine]] = {
        ClaudeAgentEngine.name: ClaudeAgentEngine,
        OpenAICompatEngine.name: OpenAICompatEngine,
    }
    try:
        return engines[name]()
    except KeyError:
        available = ", ".join(sorted(engines))
        raise ValueError(
            f"Unknown engine {name!r}. Available engines: {available}"
        ) from None
