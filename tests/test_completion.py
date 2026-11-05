import pytest

from security_ai_scanner.engine.completion import completion_message
from security_ai_scanner.exceptions import EngineError


def response(reason="stop", **message):
    return {"choices": [{"finish_reason": reason, "message": {"content": '{"findings":[]}', **message}}]}


CALL = {"id": "read", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"app.py"}'}}


@pytest.mark.parametrize("reason", ["length", "content_filter", "function_call", "unknown", None])
def test_abnormal_termination_rejects_even_valid_findings_json(reason):
    with pytest.raises(EngineError):
        completion_message(response(reason), allow_tools=True)


def test_missing_termination_metadata_is_not_inferred_from_json():
    data = response()
    del data["choices"][0]["finish_reason"]
    with pytest.raises(EngineError, match="finish_reason"):
        completion_message(data, allow_tools=True)


def test_refusal_is_not_hidden_by_valid_content_or_echoed():
    with pytest.raises(EngineError, match="refused") as error:
        completion_message(response(refusal="private provider text"), allow_tools=True)
    assert "private" not in str(error.value)


@pytest.mark.parametrize("data,allow_tools", [
    ({"choices": []}, True),
    ({"choices": [response()["choices"][0]] * 2}, True),
    (response("stop", tool_calls=[CALL]), True),
    (response("tool_calls", tool_calls=[]), True),
    (response("tool_calls", tool_calls=[CALL]), False),
    (response("tool_calls", tool_calls=["bad"]), True),
    (response("tool_calls", tool_calls=[{"function": {}}]), True),
    (response("stop", function_call={"name": "legacy"}), True),
])
def test_ambiguous_or_inconsistent_completion_is_an_error(data, allow_tools):
    with pytest.raises(EngineError):
        completion_message(data, allow_tools=allow_tools)


def test_normal_stop_and_permitted_tool_call_are_accepted():
    final = response()
    assert completion_message(final, allow_tools=False) == final["choices"][0]["message"]
    intermediate = response("tool_calls", tool_calls=[CALL])
    assert completion_message(intermediate, allow_tools=True) == intermediate["choices"][0]["message"]
