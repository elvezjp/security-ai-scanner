"""Tests for the OpenAI-compatible engine.

The HTTP transport is replaced with a scripted fake so the tests
control exactly what the endpoint returns.
"""

import asyncio
import json
from pathlib import Path

import pytest

from security_ai_scanner.engine import openai as openai_engine
from security_ai_scanner.engine.base import ScanRequest
from security_ai_scanner.engine.openai import OpenAICompatEngine, ReadOnlyTools
from security_ai_scanner.exceptions import EngineError

FINAL_JSON = json.dumps(
    {"findings": [], "summary": "clean", "files_reviewed": 1}
)
FINAL_FENCED = f"```json\n{FINAL_JSON}\n```"


def _response(content=None, tool_calls=None, total_tokens=100):
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"message": message}],
        "usage": {"total_tokens": total_tokens},
    }


def _tool_call(call_id, name, arguments):
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


class _FakeTransport:
    """Scripted stand-in for _request_json."""

    def __init__(self, responses, models=None):
        self.responses = list(responses)
        self.models = models
        self.requests = []

    def __call__(self, url, payload, headers):
        self.requests.append({"url": url, "payload": payload})
        if url.endswith("/models") and payload is None:
            if self.models is None:
                raise EngineError("no models endpoint")
            return {"data": [{"id": name} for name in self.models]}
        return self.responses.pop(0)


def _request(tmp_path, **overrides) -> ScanRequest:
    base = dict(
        prompt="p",
        system_prompt="s",
        cwd=tmp_path,
        output_schema={"type": "object"},
        model="local-model",
        base_url="http://127.0.0.1:8000/v1",
        structured_output=False,
    )
    base.update(overrides)
    return ScanRequest(**base)


def _run(request, transport, monkeypatch):
    monkeypatch.setattr(openai_engine, "_request_json", transport)
    return asyncio.run(OpenAICompatEngine().run(request))


class TestLoop:
    def test_tool_call_then_final(self, tmp_path, monkeypatch):
        (tmp_path / "app.py").write_text("x = 1\n", "utf-8")
        transport = _FakeTransport(
            [
                _response(
                    tool_calls=[_tool_call("c1", "read_file", {"path": "app.py"})]
                ),
                _response(content=FINAL_FENCED),
            ]
        )
        result = _run(_request(tmp_path), transport, monkeypatch)

        assert result.text == FINAL_FENCED
        assert result.is_error is False
        assert result.stopped_reason is None
        assert result.num_turns == 2
        assert result.total_tokens == 200
        # The tool result went back to the endpoint as a numbered read.
        second = transport.requests[1]["payload"]
        tool_msg = second["messages"][-1]
        assert tool_msg["role"] == "tool"
        assert tool_msg["tool_call_id"] == "c1"
        assert "1\tx = 1" in tool_msg["content"]

    def test_structured_output_parses_final_json(self, tmp_path, monkeypatch):
        (tmp_path / "app.py").write_text("x = 1\n", "utf-8")
        transport = _FakeTransport(
            [
                _response(
                    tool_calls=[_tool_call("c1", "read_file", {"path": "app.py"})]
                ),
                _response(content=FINAL_JSON),
            ]
        )
        request = _request(tmp_path, structured_output=True)
        result = _run(request, transport, monkeypatch)

        assert result.structured_output == json.loads(FINAL_JSON)
        payload = transport.requests[0]["payload"]
        assert payload["response_format"]["type"] == "json_schema"

    def test_budget_exceeded_stops_and_finalizes(self, tmp_path, monkeypatch):
        (tmp_path / "app.py").write_text("x = 1\n", "utf-8")
        transport = _FakeTransport(
            [
                # Round 1: under budget, the tool executes normally.
                _response(
                    tool_calls=[_tool_call("c1", "read_file", {"path": "app.py"})],
                    total_tokens=500,
                ),
                # Round 2: budget now exhausted; the pending call is refused.
                _response(
                    tool_calls=[_tool_call("c2", "read_file", {"path": "app.py"})],
                    total_tokens=5000,
                ),
                _response(content=FINAL_FENCED, total_tokens=100),
            ]
        )
        request = _request(tmp_path, max_total_tokens=1000)
        result = _run(request, transport, monkeypatch)

        assert result.stopped_reason == "budget_exceeded"
        assert result.is_error is False  # partial findings are kept
        assert result.text == FINAL_FENCED
        assert result.total_tokens == 5600
        # The pending tool call was answered with a budget notice, not data,
        # and the finalize request carried no tools.
        finalize = transport.requests[2]["payload"]
        assert "tools" not in finalize
        assert "budget exhausted" in finalize["messages"][-1]["content"].lower()

    def test_budget_exhausted_before_any_inspection_is_error(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "app.py").write_text("x = 1\n", "utf-8")
        transport = _FakeTransport(
            [
                _response(
                    tool_calls=[_tool_call("c1", "read_file", {"path": "app.py"})],
                    total_tokens=5000,
                ),
                _response(content=FINAL_FENCED, total_tokens=100),
            ]
        )
        request = _request(tmp_path, max_total_tokens=1000)
        result = _run(request, transport, monkeypatch)

        assert result.is_error is True
        assert "before any file was inspected" in result.error_message

    def test_verdict_without_any_tool_call_is_error(self, tmp_path, monkeypatch):
        # Observed with small models on Ollama: tool calls emitted as plain
        # text the server cannot parse, then an immediate "clean" verdict.
        # That must never pass as a clean scan.
        transport = _FakeTransport([_response(content=FINAL_FENCED)])
        result = _run(_request(tmp_path), transport, monkeypatch)

        assert result.is_error is True
        assert "without inspecting any files" in result.error_message

    def test_verdict_without_tool_call_clears_structured_output(
        self, tmp_path, monkeypatch
    ):
        transport = _FakeTransport([_response(content=FINAL_JSON)])
        request = _request(tmp_path, structured_output=True)
        result = _run(request, transport, monkeypatch)

        # structured_output must not survive, or the runner would trust it.
        assert result.is_error is True
        assert result.structured_output is None

    def test_max_turns_exhausted_finalizes(self, tmp_path, monkeypatch):
        (tmp_path / "app.py").write_text("x = 1\n", "utf-8")
        transport = _FakeTransport(
            [
                _response(
                    tool_calls=[_tool_call("c1", "read_file", {"path": "app.py"})]
                ),
                _response(content=FINAL_FENCED),
            ]
        )
        request = _request(tmp_path, max_turns=1)
        result = _run(request, transport, monkeypatch)

        assert result.stopped_reason == "max_turns"
        assert result.text == FINAL_FENCED
        assert "tools" not in transport.requests[1]["payload"]

    def test_empty_final_output_is_error(self, tmp_path, monkeypatch):
        transport = _FakeTransport([_response(content="")])
        result = _run(_request(tmp_path), transport, monkeypatch)
        assert result.is_error is True


class TestPreflight:
    def test_base_url_required(self, tmp_path, monkeypatch):
        transport = _FakeTransport([])
        with pytest.raises(EngineError, match="--base-url is required"):
            _run(_request(tmp_path, base_url=None), transport, monkeypatch)

    def test_missing_model_lists_server_models(self, tmp_path, monkeypatch):
        transport = _FakeTransport([], models=["qwen2.5-coder:32b", "llama3.3"])
        with pytest.raises(EngineError) as exc:
            _run(_request(tmp_path, model=None), transport, monkeypatch)
        assert "--model is required" in str(exc.value)
        assert "qwen2.5-coder:32b" in str(exc.value)

    def test_missing_model_without_models_endpoint(self, tmp_path, monkeypatch):
        transport = _FakeTransport([])
        with pytest.raises(EngineError, match="--model is required"):
            _run(_request(tmp_path, model=None), transport, monkeypatch)


class TestReadOnlyTools:
    def test_read_file_escape_is_blocked(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (tmp_path / "secret.txt").write_text("secret\n", "utf-8")
        tools = ReadOnlyTools(root)
        out = tools.call("read_file", {"path": "../secret.txt"})
        assert out.startswith("error:")
        assert "secret" not in out.splitlines()[0] or "escapes" in out

    def test_symlink_escape_is_blocked(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (tmp_path / "secret.txt").write_text("TOPSECRET\n", "utf-8")
        (root / "link.txt").symlink_to(tmp_path / "secret.txt")
        tools = ReadOnlyTools(root)
        out = tools.call("read_file", {"path": "link.txt"})
        assert out.startswith("error:")
        assert "TOPSECRET" not in out

    def test_grep_symlink_escape_is_blocked(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (tmp_path / "secret.txt").write_text("TOPSECRET=1\n", "utf-8")
        (root / "leak.txt").symlink_to(tmp_path / "secret.txt")
        (root / "ok.py").write_text("x = 1\n", "utf-8")
        tools = ReadOnlyTools(root)
        found = tools.call("grep", {"pattern": "TOPSECRET"})
        assert "TOPSECRET" not in found
        assert found == "no matches" or found.startswith("error:")

    def test_only_three_tools_exist(self, tmp_path):
        tools = ReadOnlyTools(tmp_path)
        for name in ("bash", "write_file", "edit", "fetch"):
            assert tools.call(name, {}).startswith("error: unknown tool")
        assert len(openai_engine.TOOL_DEFS) == 3

    def test_glob_and_grep(self, tmp_path):
        (tmp_path / "a.py").write_text("password = 'x'\n", "utf-8")
        sub = tmp_path / "pkg"
        sub.mkdir()
        (sub / "b.py").write_text("clean = True\n", "utf-8")
        tools = ReadOnlyTools(tmp_path)

        listed = tools.call("glob", {"pattern": "**/*.py"})
        listed_paths = set(listed.splitlines())
        assert "a.py" in listed_paths
        assert "pkg/b.py" in listed_paths

        found = tools.call("grep", {"pattern": r"password\s*="})
        assert found.startswith("a.py:1:")

        assert tools.call("grep", {"pattern": "("}).startswith(
            "error: invalid regex"
        )

    def test_glob_rejects_escaping_patterns(self, tmp_path):
        tools = ReadOnlyTools(tmp_path)
        assert tools.call("glob", {"pattern": "../*"}).startswith("error:")
        assert tools.call("glob", {"pattern": "/etc/*"}).startswith("error:")

    def test_read_file_rejects_oversized(self, tmp_path):
        fat = tmp_path / "fat.bin"
        fat.write_bytes(b"x" * (openai_engine.MAX_FILE_BYTES + 1))
        tools = ReadOnlyTools(tmp_path)
        out = tools.call("read_file", {"path": "fat.bin"})
        assert out.startswith("error: file too large")

    def test_read_file_offset_and_truncation(self, tmp_path):
        (tmp_path / "f.txt").write_text("\n".join(f"L{i}" for i in range(1, 11)), "utf-8")
        tools = ReadOnlyTools(tmp_path)
        out = tools.call("read_file", {"path": "f.txt", "offset": 3, "limit": 2})
        lines = out.splitlines()
        assert lines[0] == "3\tL3"
        assert lines[1] == "4\tL4"
        assert "truncated" in lines[2]


class TestTransportErrors:
    """Transport failures must surface as EngineError (CLI exit 2), never
    escape as raw exceptions (which would exit 1 — the CI-gate code)."""

    def _engine_error_from(self, monkeypatch, exc):
        def raising_urlopen(*args, **kwargs):
            raise exc

        monkeypatch.setattr(
            openai_engine.urllib.request, "urlopen", raising_urlopen
        )
        with pytest.raises(EngineError) as caught:
            openai_engine._request_json("http://x/v1/chat/completions", {}, {})
        return str(caught.value)

    def test_socket_timeout_is_wrapped(self, monkeypatch):
        message = self._engine_error_from(monkeypatch, TimeoutError("timed out"))
        assert "timed out" in message

    def test_connection_reset_is_wrapped(self, monkeypatch):
        message = self._engine_error_from(
            monkeypatch, ConnectionResetError("peer reset")
        )
        assert "Transport error" in message

    def test_http_protocol_error_is_wrapped(self, monkeypatch):
        import http.client

        message = self._engine_error_from(
            monkeypatch, http.client.BadStatusLine("garbage")
        )
        assert "Transport error" in message
