"""OpenAI-compatible engine: a minimal built-in agent loop.

Speaks the OpenAI Chat Completions API with function calling, so the
scanner connects directly to self-hosted inference servers (vLLM,
Ollama, LM Studio, llama.cpp server) and OpenAI-compatible gateways.

The read-only guarantee is structural: the only tools that exist in
this loop are ``read_file`` / ``glob`` / ``grep``, implemented below in
Python and path-sandboxed to the scan root. There is no shell, write,
or network tool for the model to call.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..exceptions import EngineError
from .base import EngineResult, ScanEngine, ScanRequest

#: Per-request timeout. Local models can be slow; scans are not interactive.
REQUEST_TIMEOUT_SECONDS = 600

#: Caps on tool output, so one tool call cannot flood the context window.
MAX_READ_LINES = 2000
MAX_LINE_CHARS = 500
MAX_GLOB_RESULTS = 200
MAX_GREP_MATCHES = 200
#: Files larger than this are skipped by read_file / grep (binary blobs, bundles).
MAX_FILE_BYTES = 1_000_000

#: OpenAI function-calling schemas for the read-only toolset.
TOOL_DEFS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a text file from the repository. Returns numbered "
                "lines ('<line>\\t<text>')."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to the repository root",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "1-based line number to start from",
                    },
                    "limit": {
                        "type": "integer",
                        "description": f"Maximum lines to return (default {MAX_READ_LINES})",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "glob",
            "description": (
                "List repository files matching a glob pattern, "
                "e.g. '**/*.py' or 'src/**/*.ts'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep",
            "description": (
                "Search file contents with a Python regular expression. "
                "Returns '<path>:<line>: <text>' matches."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression"},
                    "path": {
                        "type": "string",
                        "description": "File or directory to search (default: repository root)",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
]


def _request_json(
    url: str, payload: dict[str, Any] | None, headers: dict[str, str]
) -> dict[str, Any]:
    """POST (or GET when payload is None) and return the parsed JSON body.

    Module-level so tests can monkeypatch the transport.
    """
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise EngineError(
            f"Endpoint returned HTTP {exc.code} for {url}: {body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise EngineError(f"Cannot reach endpoint {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise EngineError(
            f"Request to {url} timed out after {REQUEST_TIMEOUT_SECONDS}s"
        ) from exc
    except (OSError, http.client.HTTPException) as exc:
        # Sockets can fail mid-read with raw OS or http.client errors that
        # urllib does not wrap in URLError; keep the exit-code contract
        # (engine failure = 2, never the CI-gate code 1).
        raise EngineError(f"Transport error for {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise EngineError(f"Endpoint returned invalid JSON: {exc}") from exc


class ReadOnlyTools:
    """The read-only toolset, sandboxed to one directory tree.

    Every path is resolved (following symlinks) and must stay under the
    scan root. Tool errors are returned as strings so the model can
    correct itself instead of aborting the scan.
    """

    def __init__(self, root: Path):
        self.root = root.resolve()

    def call(self, name: str, args: dict[str, Any]) -> str:
        handlers = {
            "read_file": self._read_file,
            "glob": self._glob,
            "grep": self._grep,
        }
        handler = handlers.get(name)
        if handler is None:
            return f"error: unknown tool {name!r}"
        try:
            return handler(**args)
        except TypeError as exc:
            return f"error: bad arguments for {name}: {exc}"
        except Exception as exc:  # tool errors are data, not crashes
            return f"error: {exc}"

    def _resolve(self, rel: str) -> Path:
        path = (self.root / rel).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError(f"path escapes the scan root: {rel}")
        return path

    def _under_root(self, path: Path) -> bool:
        """True when ``path`` (already resolved) stays inside the scan root."""
        return path == self.root or self.root in path.parents

    def _read_file(
        self, path: str, offset: int = 1, limit: int = MAX_READ_LINES
    ) -> str:
        target = self._resolve(path)
        if not target.is_file():
            return f"error: not a file: {path}"
        try:
            size = target.stat().st_size
        except OSError as exc:
            return f"error: {exc}"
        if size > MAX_FILE_BYTES:
            return (
                f"error: file too large ({size} bytes); "
                f"max is {MAX_FILE_BYTES}"
            )
        offset = max(1, int(offset))
        limit = max(1, min(int(limit), MAX_READ_LINES))
        lines = target.read_text("utf-8", errors="replace").splitlines()
        window = lines[offset - 1 : offset - 1 + limit]
        if not window:
            return f"(empty range: file has {len(lines)} lines)"
        numbered = [
            f"{offset + i}\t{line[:MAX_LINE_CHARS]}"
            for i, line in enumerate(window)
        ]
        if offset - 1 + limit < len(lines):
            numbered.append(
                f"(truncated: {len(lines)} lines total; continue with "
                f"offset={offset + limit})"
            )
        return "\n".join(numbered)

    def _glob(self, pattern: str) -> str:
        if pattern.startswith(("/", "~")) or ".." in pattern:
            return "error: pattern must be relative to the repository root"
        matches: list[str] = []
        for path in self.root.glob(pattern):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(self.root)
            except ValueError:
                continue
            if ".git" in rel.parts:
                continue
            # Drop symlinks (and anything else) whose target leaves the root.
            if not self._under_root(path.resolve()):
                continue
            matches.append(rel.as_posix())
        matches.sort()
        if not matches:
            return "no files match"
        clipped = matches[:MAX_GLOB_RESULTS]
        if len(matches) > MAX_GLOB_RESULTS:
            clipped.append(
                f"(truncated: {len(matches)} matches; narrow the pattern)"
            )
        return "\n".join(clipped)

    def _grep(self, pattern: str, path: str = ".") -> str:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return f"error: invalid regex: {exc}"
        base = self._resolve(path)
        matches: list[str] = []
        for file, rel in self._iter_files(base):
            try:
                if file.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = file.read_text("utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    matches.append(f"{rel}:{lineno}: {line.strip()[:200]}")
                    if len(matches) >= MAX_GREP_MATCHES:
                        matches.append("(truncated: narrow the pattern)")
                        return "\n".join(matches)
        return "\n".join(matches) if matches else "no matches"

    def _iter_files(self, base: Path):
        """Yield ``(resolved_file, posix_rel)`` for files that stay under root.

        Symlinks whose targets leave the scan root are skipped, so grep cannot
        exfiltrate contents that ``read_file`` would refuse.
        """
        if base.is_file():
            if self._under_root(base.resolve()):
                yield base, base.relative_to(self.root).as_posix()
            return
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                candidate = Path(dirpath) / name
                try:
                    rel = candidate.relative_to(self.root).as_posix()
                    resolved = candidate.resolve()
                except (OSError, ValueError):
                    continue
                if not self._under_root(resolved):
                    continue
                yield resolved, rel


def _missing_model_error(base_url: str, headers: dict[str, str]) -> EngineError:
    """Build the --model-required error, listing the server's models if we can."""
    message = (
        "--model is required for --engine openai (or set the SAIS_MODEL "
        "environment variable). There is no default: some servers ignore "
        "the model field, which would record a wrong model name in the "
        "scan outputs."
    )
    try:
        data = _request_json(base_url.rstrip("/") + "/models", None, headers)
        names = [
            str(item.get("id"))
            for item in data.get("data", [])
            if isinstance(item, dict) and item.get("id")
        ]
        if names:
            listing = "\n".join(f"  {name}" for name in names[:20])
            message += f"\nModels available at {base_url}:\n{listing}"
    except EngineError:
        pass  # listing is best-effort; the base error stands on its own
    return EngineError(message)


class OpenAICompatEngine(ScanEngine):
    """Engine backed by any OpenAI-compatible Chat Completions endpoint."""

    name = "openai"

    async def run(self, request: ScanRequest) -> EngineResult:
        if not request.base_url:
            raise EngineError(
                "--base-url is required for --engine openai, e.g. "
                "http://127.0.0.1:11434/v1 or https://api.openai.com/v1"
            )
        headers = {
            "Authorization": f"Bearer {request.auth_token or 'local'}",
            "Content-Type": "application/json",
        }
        if not request.model:
            raise _missing_model_error(request.base_url, headers)

        url = request.base_url.rstrip("/") + "/chat/completions"
        tools = ReadOnlyTools(request.cwd)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.prompt},
        ]

        result = EngineResult()
        start = time.monotonic()
        total_tokens = 0
        final_text: str | None = None

        def send(payload_messages, *, with_tools: bool) -> dict[str, Any]:
            nonlocal total_tokens
            payload: dict[str, Any] = {
                "model": request.model,
                "messages": payload_messages,
            }
            if with_tools:
                payload["tools"] = TOOL_DEFS
                payload["tool_choice"] = "auto"
            if request.structured_output:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "scan_findings",
                        "schema": request.output_schema,
                    },
                }
            data = _request_json(url, payload, headers)
            result.num_turns += 1
            usage = data.get("usage") or {}
            total_tokens += int(usage.get("total_tokens") or 0)
            choices = data.get("choices") or []
            return (choices[0].get("message") or {}) if choices else {}

        for _ in range(request.max_turns):
            message = send(messages, with_tools=True)
            tool_calls = message.get("tool_calls")
            if not tool_calls:
                final_text = message.get("content") or ""
                break
            messages.append(message)

            over_budget = (
                request.max_total_tokens is not None
                and total_tokens >= request.max_total_tokens
            )
            for call in tool_calls:
                if over_budget:
                    content = (
                        "Token budget exhausted. Do not call more tools; "
                        "emit your final JSON output now with the findings "
                        "you have so far."
                    )
                else:
                    function = call.get("function") or {}
                    try:
                        args = json.loads(function.get("arguments") or "{}")
                        if not isinstance(args, dict):
                            raise ValueError("arguments must be an object")
                    except (json.JSONDecodeError, ValueError) as exc:
                        content = f"error: invalid tool arguments: {exc}"
                    else:
                        content = tools.call(str(function.get("name", "")), args)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": str(call.get("id", "")),
                        "content": content,
                    }
                )
            if over_budget:
                result.stopped_reason = "budget_exceeded"
                final_text = send(messages, with_tools=False).get("content") or ""
                break
        else:
            # max_turns exhausted without a final answer: one last request,
            # without tools, to collect whatever the model can finalize.
            result.stopped_reason = "max_turns"
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Turn limit reached. Emit your final JSON output "
                        "now with the findings you have so far."
                    ),
                }
            )
            final_text = send(messages, with_tools=False).get("content") or ""

        result.duration_ms = int((time.monotonic() - start) * 1000)
        result.total_tokens = total_tokens
        result.text = final_text or ""
        if request.structured_output and final_text:
            try:
                result.structured_output = json.loads(final_text)
            except json.JSONDecodeError:
                pass  # fall through to the text parser in the runner
        if not result.text and result.structured_output is None:
            result.is_error = True
            result.error_message = "engine returned no final output"
        return result
