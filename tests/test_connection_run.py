"""Connection resolution through the real CLI, engine and publication path."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest

from security_ai_scanner.cli import main

PATCH = '''diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-x = 1
+x = 2
'''


@contextmanager
def endpoint(models=None, response_model="fixture", status=200, reflect=False):
    calls = []
    listed = [{"id":"fixture", "file":"/models/model-q4.gguf", "context_length":8192, "secret_field":"omit"}] if models is None else models
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def reply(self, body):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if status == 302:
                self.send_header("Location", "/redirect-target")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())
        def do_GET(self):
            calls.append(("GET", self.path, self.headers.get("Authorization"), None))
            self.reply({"data":listed, "error":self.headers.get("Authorization")})
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(("POST", self.path, self.headers.get("Authorization"), payload))
            if not any(m["role"] == "tool" for m in payload["messages"]):
                message = {"role":"assistant", "tool_calls":[{"id":"read", "type":"function", "function":{"name":"read_file", "arguments":'{"path":"app.py"}'}}]}
            else:
                summary = self.headers.get("Authorization") if reflect else "clean"
                message = {"content":json.dumps({"findings":[], "summary":summary})}
            self.reply({"model":response_model, "choices":[{"message":message}]})
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", calls
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.fixture
def invocation(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("x = 2\n")
    patch = target / "change.diff"
    patch.write_text(PATCH)
    token = tmp_path / "private-key"
    token.write_text("private-test-token\n")
    token.chmod(0o600)
    config = tmp_path / "machine.toml"
    output = tmp_path / "out"
    monkeypatch.chdir(target)
    for prefix in ("SAIS", "CAIR"):
        for name in ("PROFILE", "CONFIG", "ENGINE", "BASE_URL", "MODEL", "AUTH_TOKEN", "AUTH_TOKEN_FILE"):
            monkeypatch.delenv(prefix + "_" + name, raising=False)
    def run(url, *extra):
        config.write_text('[profiles.local]\nengine="openai"\nmodel="auto"\nbase_url='+json.dumps(url)+'\nauth_token_file='+json.dumps(str(token))+'\n')
        monkeypatch.setenv("SAIS_CONFIG", str(config))
        return main(["scan", str(target), "--profile", "local", "--json", "--format", "json", "-o", str(output), *extra])
    return run, output, token, target


def test_profile_only_run_resolves_model_and_publishes_safe_provenance(invocation, capsys):
    run, output, token, _ = invocation
    with endpoint(reflect=True) as (url, calls):
        assert run(url) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    from jsonschema import Draft202012Validator
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/native-summary-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(summary)
    assert summary["provenance"] == {"engine":"openai", "model_requested":"auto", "model":"fixture", "model_metadata":{"file":"model-q4.gguf", "context_length":8192}}
    assert calls[0][:2] == ("GET", "/v1/models")
    assert all(call[2] == "Bearer private-test-token" for call in calls)
    assert all(call[3]["model"] == "fixture" for call in calls[1:])
    artifacts = captured.out + captured.err + "".join(p.read_text() for p in output.glob("*.json"))
    assert "private-test-token" not in artifacts and str(token) not in artifacts and url not in artifacts
    assert "secret_field" not in artifacts
    assert "[redacted]" in artifacts


@pytest.mark.parametrize("models,expected", [([],"nonempty"), ([{"id":"one"},{"id":"two"}],"one, two"), ([{"wrong":"id"}],"valid"), ([{"id":"fixture","ixv_mode":"beast"}],"beast")])
def test_auto_refuses_ambiguous_invalid_or_beast_models(invocation, capsys, models, expected):
    run, output, _, _ = invocation
    with endpoint(models=models) as (url, calls):
        assert run(url) == 2
    captured = capsys.readouterr()
    assert expected in captured.err
    assert all(c[0] == "GET" for c in calls)
    assert json.loads((output / "summary.json").read_text())["status"] == "error"
    assert not (output / "findings.json").exists()


def test_changed_response_model_fails_closed(invocation, capsys):
    run, output, _, _ = invocation
    with endpoint(response_model="different") as (url, calls):
        assert run(url) == 2
    assert "model changed" in capsys.readouterr().err
    assert json.loads((output / "summary.json").read_text())["status"] == "error"
    assert not (output / "findings.json").exists()


def test_http_error_does_not_echo_credentials(invocation, capsys):
    run, output, token, _ = invocation
    with endpoint(status=401) as (url, _):
        assert run(url) == 2
    captured = capsys.readouterr()
    text = captured.out + captured.err + (output / "summary.json").read_text()
    assert "HTTP 401" in text
    assert "private-test-token" not in text and str(token) not in text and url not in text


def test_cli_token_warns_without_echo_and_overrides_file(invocation, capsys):
    run, _, _, _ = invocation
    with endpoint() as (url, calls):
        assert run(url, "--auth-token", "cli-private-key") == 0
    captured = capsys.readouterr()
    assert "process lists" in captured.err and "cli-private-key" not in captured.err
    assert all(c[2] == "Bearer cli-private-key" for c in calls)


def test_explicit_model_skips_discovery(invocation):
    run, _, _, _ = invocation
    with endpoint() as (url, calls):
        assert run(url, "--model", "fixture") == 0
    assert all(c[0] == "POST" for c in calls)


def test_python_api_uses_only_explicit_config_and_reads_token_at_run_time(tmp_path, monkeypatch):
    from security_ai_scanner.config import ScanConfig
    from security_ai_scanner.engine.base import EngineResult
    from security_ai_scanner.runner import run_scan
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("x = 2\n")
    token = tmp_path / "credential"
    token.write_text("first")
    token.chmod(0o600)
    monkeypatch.setenv("SAIS_PROFILE", "missing")
    monkeypatch.setenv("SAIS_MODEL", "ambient")
    monkeypatch.setenv("SAIS_BASE_URL", "http://untrusted.invalid")
    monkeypatch.setenv("SAIS_AUTH_TOKEN", "ambient-key")
    observed = []
    class Engine:
        async def run(self, request):
            observed.append(request)
            return EngineResult(structured_output={"findings":[],"summary":"clean"})
    monkeypatch.setattr("security_ai_scanner.runner.get_engine", lambda name: Engine())
    config = ScanConfig(target=target, output_dir=tmp_path / "out", auth_token_file=token)
    run_scan(config)
    token.write_text("second")
    run_scan(config)
    assert [r.auth_token for r in observed] == ["first", "second"]
    assert all(r.model is None and r.base_url is None for r in observed)
    assert "second" not in repr(observed[-1]) and str(token) not in repr(config)


def test_redirects_do_not_forward_credentials(invocation, capsys):
    run, _, _, _ = invocation
    with endpoint(status=302) as (url, calls):
        assert run(url) == 2
    assert "HTTP 302" in capsys.readouterr().err
    assert len(calls) == 1 and calls[0][1] == "/v1/models"
