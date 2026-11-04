"""Claude Agent SDK engine.

Runs the scan with Claude's agent harness in read-only mode: the agent
may read, glob, and grep files under the target directory, but write,
edit, shell, and network tools are disallowed.
"""

from __future__ import annotations

import sys
from itertools import islice
from pathlib import Path

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


def _partial_stop_reason(message) -> str | None:
    """Normalize SDK termination metadata that means partial analysis."""
    terminal_reason = getattr(message, "terminal_reason", None)
    if terminal_reason and terminal_reason != "completed":
        return str(terminal_reason)
    subtype = getattr(message, "subtype", None)
    return {
        "error_max_turns": "max_turns",
        "error_max_budget_usd": "max_budget_usd",
    }.get(subtype)


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


def _content_inspection(block, root: Path) -> bool:
    """Only scoped content reads qualify; filename discovery is not inspection."""
    if not isinstance(block.input, dict):
        return False
    if block.name == "Read":
        path = block.input.get("file_path")
        if not isinstance(path, str) or not path:
            return False
    elif block.name == "Grep" and block.input.get("output_mode") == "content":
        path = block.input.get("path", ".")
        if not isinstance(path, str):
            return False
    else:
        return False
    try:
        target = (root / path).resolve()
        if target != root and root not in target.parents:
            return False
        if block.name == "Read":
            offset = block.input.get("offset", 1)
            limit = block.input.get("limit", 1)
            if (type(offset) is not int or offset < 1
                    or type(limit) is not int or limit < 1 or not target.is_file()):
                return False
            # A successful Read beyond EOF returns a notice, not file content.
            # Check that the requested starting line exists without loading
            # the entire file or depending on the CLI's notice wording.
            with target.open("rb") as stream:
                return next(islice(stream, offset - 1, offset), None) is not None
        return target.exists()
    except (OSError, ValueError, RuntimeError):
        return False


def _has_content(content) -> bool:
    if isinstance(content, str):
        text = content.strip()
    elif isinstance(content, list):
        text = "\n".join(
            item.get("text", "") for item in content
            if isinstance(item, dict) and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        ).strip()
    else:
        return False
    return bool(text) and text.lower() not in {"no matches found", "no matches"}


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
                ToolUseBlock,
                ToolResultBlock,
                UserMessage,
                query,
            )
        except ImportError as exc:  # pragma: no cover - import guard
            raise EngineError(
                "claude-agent-sdk is not installed. "
                "Install the Claude engine with: "
                "pip install 'security-ai-scanner[claude]'"
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

        result = EngineResult(successful_inspections=0)
        pending: set[str] = set()
        root = request.cwd.resolve()
        try:
            async for message in query(prompt=request.prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, ToolUseBlock) and _content_inspection(block, root):
                            pending.add(block.id)
                    if request.verbose:
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                print(block.text, file=sys.stderr)
                elif isinstance(message, UserMessage) and isinstance(message.content, list):
                    for block in message.content:
                        if isinstance(block, ToolResultBlock) and block.tool_use_id in pending:
                            pending.remove(block.tool_use_id)
                            if not block.is_error and _has_content(block.content):
                                result.successful_inspections += 1
                elif isinstance(message, ResultMessage):
                    result.structured_output = message.structured_output
                    # Only the agent's final response is trusted as the
                    # findings source. Intermediate assistant text quotes
                    # repository content, which a hostile target could seed
                    # with a fake findings block to bypass the CI gate.
                    result.text = message.result or ""
                    result.stopped_reason = _partial_stop_reason(message)
                    # SDK limit/cancellation results may carry valid partial
                    # findings. Normalize those as incomplete; the runner still
                    # validates the final payload before accepting it.
                    result.is_error = (
                        message.is_error and result.stopped_reason is None
                    )
                    result.num_turns = message.num_turns
                    result.duration_ms = message.duration_ms
                    result.total_cost_usd = message.total_cost_usd
                    if result.is_error:
                        result.error_message = message.result or "engine error"
        except Exception as exc:
            raise EngineError(f"Claude Agent SDK failed: {exc}") from exc

        if not result.is_error and result.successful_inspections == 0:
            result.is_error = True
            result.structured_output = None
            result.error_message = (
                "model produced a final answer without inspecting any files "
                "successfully (no scoped Read or content Grep completed)"
            )
        return result
