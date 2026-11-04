"""Validate terminal state before accepting OpenAI-compatible model output."""

from typing import Any

from ..exceptions import EngineError


def completion_message(data: dict[str, Any], *, allow_tools: bool) -> dict[str, Any]:
    """Require an unambiguous normal stop or a complete permitted tool request.

    Generation truncation, refusal and missing metadata cannot establish a
    valid final answer, even when the content happens to contain valid JSON.
    Error messages deliberately exclude provider-controlled text.
    """
    choices = data.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise EngineError("Endpoint must return exactly one completion choice")
    choice = choices[0]
    if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
        raise EngineError("Endpoint returned an invalid completion message")
    message = choice["message"]
    if message.get("refusal"):
        raise EngineError("Endpoint refused the request")
    reason = choice.get("finish_reason")
    if reason == "length":
        raise EngineError("Endpoint truncated generation (finish_reason=length)")
    if reason == "content_filter":
        raise EngineError("Endpoint filtered generation (finish_reason=content_filter)")
    if reason not in ("stop", "tool_calls"):
        raise EngineError("Endpoint returned missing or unsupported finish_reason")
    calls = message.get("tool_calls")
    if message.get("function_call"):
        raise EngineError("Endpoint returned an unsupported legacy function call")
    if calls is not None and not isinstance(calls, list):
        raise EngineError("Endpoint returned invalid tool calls")
    if reason == "stop":
        if calls:
            raise EngineError("Endpoint reported stop with unfinished tool calls")
        return message
    if not allow_tools or not calls:
        raise EngineError("Endpoint returned unexpected or empty tool calls")
    for call in calls:
        if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
            raise EngineError("Endpoint returned an invalid tool call")
        function = call["function"]
        if (call.get("type") != "function" or not isinstance(call.get("id"), str)
                or not call["id"] or not isinstance(function.get("name"), str)
                or not function["name"] or not isinstance(function.get("arguments"), str)):
            raise EngineError("Endpoint returned an invalid tool call")
    return message
