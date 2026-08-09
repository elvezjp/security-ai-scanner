"""Claude Agent SDK engine.

Runs the scan with Claude's agent harness in read-only mode: the agent
may read, glob, and grep files under the target directory, but write,
edit, shell, and network tools are disallowed.
"""

from __future__ import annotations

import sys

from ..exceptions import EngineError
from .base import EngineResult, ScanEngine, ScanRequest

#: Tools the scan agent is allowed to use (read-only).
READ_ONLY_TOOLS = ["Read", "Glob", "Grep"]

#: Tools explicitly disallowed regardless of harness defaults.
DISALLOWED_TOOLS = [
    "Bash",
    "Write",
    "Edit",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
]


def _build_env(request: ScanRequest) -> dict[str, str]:
    """Environment overrides for the agent subprocess.

    Returns an empty dict for the hosted API. When ``base_url`` is set the
    agent is pointed at an Anthropic-compatible endpoint (for example a
    local inference server) and every model slot is pinned to the
    requested model, since a local server usually serves exactly one.
    """
    if not request.base_url:
        return {}

    env = {
        "ANTHROPIC_BASE_URL": request.base_url,
        "ANTHROPIC_AUTH_TOKEN": request.auth_token or "local",
        # Local endpoints authenticate via the auth token; a hosted API key
        # left in the environment would take precedence and break routing.
        "ANTHROPIC_API_KEY": "",
        "CLAUDE_CODE_OAUTH_TOKEN": "",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    }
    if request.model:
        for slot in (
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            "CLAUDE_CODE_SUBAGENT_MODEL",
        ):
            env[slot] = request.model
    return env


class ClaudeAgentEngine(ScanEngine):
    """Engine backed by the Claude Agent SDK (bundled Claude Code CLI)."""

    name = "claude"

    async def run(self, request: ScanRequest) -> EngineResult:
        try:
            from claude_agent_sdk import (
                AssistantMessage,
                ClaudeAgentOptions,
                ResultMessage,
                TextBlock,
                query,
            )
        except ImportError as exc:  # pragma: no cover - import guard
            raise EngineError(
                "claude-agent-sdk is not installed. "
                "Install it with: pip install claude-agent-sdk"
            ) from exc

        options = ClaudeAgentOptions(
            cwd=str(request.cwd),
            system_prompt=request.system_prompt,
            allowed_tools=READ_ONLY_TOOLS,
            disallowed_tools=DISALLOWED_TOOLS,
            max_turns=request.max_turns,
            model=request.model,
            env=_build_env(request),
        )
        if request.structured_output:
            options.output_format = {
                "type": "json_schema",
                "schema": request.output_schema,
            }

        result = EngineResult()
        try:
            async for message in query(prompt=request.prompt, options=options):
                if isinstance(message, AssistantMessage):
                    if request.verbose:
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                print(block.text, file=sys.stderr)
                elif isinstance(message, ResultMessage):
                    result.structured_output = message.structured_output
                    # Only the agent's final response is trusted as the
                    # findings source. Intermediate assistant text quotes
                    # repository content, which a hostile target could seed
                    # with a fake findings block to bypass the CI gate.
                    result.text = message.result or ""
                    result.is_error = message.is_error
                    result.num_turns = message.num_turns
                    result.duration_ms = message.duration_ms
                    result.total_cost_usd = message.total_cost_usd
                    if message.is_error:
                        result.error_message = message.result or "engine error"
        except Exception as exc:
            raise EngineError(f"Claude Agent SDK failed: {exc}") from exc

        return result
