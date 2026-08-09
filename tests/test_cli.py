"""Tests for the CLI."""

import json

import pytest

from security_ai_scanner.cli import (
    EXIT_ERROR,
    EXIT_GATE_FAILED,
    EXIT_OK,
    build_parser,
    main,
)
from security_ai_scanner.engine.base import EngineResult


class TestVersion:
    def test_version_matches_installed_distribution(self):
        # __version__ must come from the distribution metadata
        # (pyproject.toml), not a hard-coded constant that can drift and
        # mislabel provenance in summary.json / findings.json.
        from importlib.metadata import version

        import security_ai_scanner

        assert security_ai_scanner.__version__ == version(
            "security-ai-scanner"
        )


class TestParser:
    def test_scan_defaults(self, tmp_path):
        args = build_parser().parse_args(["scan", str(tmp_path)])
        assert args.command == "scan"
        assert args.engine == "claude"
        assert args.fail_on == "high"
        assert args.language == "en"
        assert args.formats is None

    def test_repeatable_format(self, tmp_path):
        args = build_parser().parse_args(
            ["scan", str(tmp_path), "--format", "sarif", "--format", "json"]
        )
        assert args.formats == ["sarif", "json"]

    def test_version_exits(self, capsys):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--version"])
        assert exc.value.code == 0

    def test_mcp_subcommand_parses(self):
        args = build_parser().parse_args(["mcp"])
        assert args.command == "mcp"


class TestMain:
    @pytest.fixture
    def repo(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        return target

    def _patch_engine(self, monkeypatch, result: EngineResult):
        class Engine:
            name = "claude"

            async def run(self, request):
                return result

        monkeypatch.setattr(
            "security_ai_scanner.runner.get_engine", lambda name: Engine()
        )

    def test_clean_scan_exit_zero(self, repo, tmp_path, monkeypatch, capsys):
        self._patch_engine(
            monkeypatch,
            EngineResult(structured_output={"findings": [], "summary": "ok"}),
        )
        code = main(
            ["scan", str(repo), "--output-dir", str(tmp_path / "out")]
        )
        assert code == EXIT_OK
        assert "Scan complete: 0 finding(s)" in capsys.readouterr().out

    def test_gate_failure_exit_one(self, repo, tmp_path, monkeypatch):
        self._patch_engine(
            monkeypatch,
            EngineResult(
                structured_output={
                    "findings": [
                        {
                            "title": "t",
                            "severity": "critical",
                            "confidence": "high",
                            "file": "a.py",
                            "start_line": 1,
                            "description": "d",
                            "recommendation": "r",
                        }
                    ],
                    "summary": "bad",
                }
            ),
        )
        code = main(["scan", str(repo), "--output-dir", str(tmp_path / "out")])
        assert code == EXIT_GATE_FAILED

    def test_missing_target_exit_two(self, tmp_path, capsys):
        code = main(["scan", str(tmp_path / "nope")])
        assert code == EXIT_ERROR
        assert "error:" in capsys.readouterr().err

    def test_notify_called_on_success(self, repo, tmp_path, monkeypatch):
        self._patch_engine(
            monkeypatch,
            EngineResult(structured_output={"findings": [], "summary": "ok"}),
        )
        calls = []
        monkeypatch.setattr(
            "security_ai_scanner.notify.send_notification",
            lambda *a, **kw: calls.append((a, kw)) or True,
        )
        code = main(
            [
                "scan", str(repo),
                "--output-dir", str(tmp_path / "out"),
                "--notify-webhook", "https://hooks.example/x",
                "--notify-format", "discord",
            ]
        )
        assert code == EXIT_OK
        (args, _kwargs), = calls
        assert args[0] == "https://hooks.example/x"
        assert args[1] == "discord"
        assert args[2]["counts"]["total"] == 0

    def test_notify_called_on_error(self, tmp_path, monkeypatch, capsys):
        calls = []
        monkeypatch.setattr(
            "security_ai_scanner.notify.send_notification",
            lambda *a, **kw: calls.append((a, kw)) or True,
        )
        code = main(
            [
                "scan", str(tmp_path / "nope"),
                "--notify-webhook", "https://hooks.example/x",
            ]
        )
        assert code == EXIT_ERROR
        (args, kwargs), = calls
        assert args[2] is None
        assert "does not exist" in kwargs["error"]

    def test_webhook_url_from_environment(self, repo, tmp_path, monkeypatch):
        self._patch_engine(
            monkeypatch,
            EngineResult(structured_output={"findings": [], "summary": "ok"}),
        )
        monkeypatch.setenv("SAIS_NOTIFY_WEBHOOK", "https://hooks.example/env")
        calls = []
        monkeypatch.setattr(
            "security_ai_scanner.notify.send_notification",
            lambda *a, **kw: calls.append(a) or True,
        )
        code = main(
            ["scan", str(repo), "--output-dir", str(tmp_path / "out")]
        )
        assert code == EXIT_OK
        assert calls[0][0] == "https://hooks.example/env"

    def test_json_flag_prints_machine_summary(
        self, repo, tmp_path, monkeypatch, capsys
    ):
        self._patch_engine(
            monkeypatch,
            EngineResult(structured_output={"findings": [], "summary": "ok"}),
        )
        code = main(
            ["scan", str(repo), "--output-dir", str(tmp_path / "out"), "--json"]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["tool"] == "security-ai-scanner"
        assert payload["exit_code"] == 0
        assert payload["counts"]["total"] == 0
        # stdout is exactly one JSON line, nothing else
        assert len(out.strip().splitlines()) == 1
