"""Tests for scan orchestration with a mock engine."""

import json

import pytest

import security_ai_scanner.engine.base as engine_base
from security_ai_scanner.config import ScanConfig
from security_ai_scanner.engine.base import EngineResult, ScanEngine
from security_ai_scanner.exceptions import EngineError, TargetError
from security_ai_scanner.runner import build_user_prompt, run_scan


class MockEngine(ScanEngine):
    name = "mock"

    def __init__(self, result: EngineResult):
        self._result = result
        self.last_request = None

    async def run(self, request) -> EngineResult:
        self.last_request = request
        return self._result


@pytest.fixture
def repo(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("print('hello')\n")
    return target


@pytest.fixture
def mock_engine(monkeypatch):
    """Install a mock engine; tests set .result before running."""
    holder = {}

    def fake_get_engine(name):
        assert name == "mock"
        engine = MockEngine(holder["result"])
        holder["engine"] = engine
        return engine

    monkeypatch.setattr("security_ai_scanner.runner.get_engine", fake_get_engine)
    return holder


def _structured(findings=None, summary="ok"):
    return EngineResult(
        structured_output={"findings": findings or [], "summary": summary},
        num_turns=3,
    )


def _config(repo, tmp_path, **overrides):
    defaults = dict(
        target=repo,
        output_dir=tmp_path / "out",
        engine="mock",
        fail_on="high",
    )
    defaults.update(overrides)
    return ScanConfig(**defaults)


class TestRunScan:
    def test_clean_scan_writes_outputs(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        result = run_scan(_config(repo, tmp_path))
        assert result.gate_failed is False
        names = {p.name for p in result.written_files}
        assert names == {
            "findings.json",
            "findings.sarif",
            "report.md",
            "summary.json",
        }
        payload = json.loads((tmp_path / "out" / "findings.json").read_text())
        assert payload["tool"] == "security-ai-scanner"
        assert payload["findings"] == []

    def test_gate_fails_on_high_finding(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured(
            findings=[
                {
                    "title": "RCE",
                    "severity": "critical",
                    "confidence": "high",
                    "file": "app.py",
                    "start_line": 1,
                    "description": "d",
                    "recommendation": "r",
                }
            ]
        )
        result = run_scan(_config(repo, tmp_path))
        assert result.gate_failed is True

    def test_gate_disabled_with_none(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured(
            findings=[
                {
                    "title": "RCE",
                    "severity": "critical",
                    "confidence": "high",
                    "file": "app.py",
                    "start_line": 1,
                    "description": "d",
                    "recommendation": "r",
                }
            ]
        )
        result = run_scan(_config(repo, tmp_path, fail_on="none"))
        assert result.gate_failed is False

    def test_text_fallback_parsing(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = EngineResult(
            text='```json\n{"findings": [], "summary": "from text"}\n```'
        )
        result = run_scan(_config(repo, tmp_path))
        assert result.output.summary == "from text"

    def test_engine_error_raises(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = EngineResult(is_error=True, error_message="boom")
        with pytest.raises(EngineError):
            run_scan(_config(repo, tmp_path))

    def test_missing_target_raises(self, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        with pytest.raises(TargetError):
            run_scan(_config(tmp_path / "nope", tmp_path))

    def test_selected_formats_only(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        result = run_scan(_config(repo, tmp_path, formats=("sarif",)))
        # summary.json is always written regardless of --format
        assert [p.name for p in result.written_files] == [
            "findings.sarif",
            "summary.json",
        ]

    def test_request_carries_config(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        run_scan(
            _config(
                repo, tmp_path, language="ja", context="Focus on the API layer"
            )
        )
        request = mock_engine["engine"].last_request
        assert "Japanese" in request.system_prompt
        assert "Focus on the API layer" in request.prompt
        assert request.cwd == repo.resolve()


class TestSummary:
    FINDING = {
        "title": "SQLi",
        "severity": "high",
        "confidence": "high",
        "file": "app.py",
        "start_line": 1,
        "description": "d",
        "recommendation": "r",
    }

    def test_summary_json_written_and_matches_result(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(
            structured_output={
                "findings": [self.FINDING],
                "summary": "one issue",
                "files_reviewed": 5,
            },
            num_turns=3,
            duration_ms=1234,
            total_cost_usd=0.5,
        )
        result = run_scan(_config(repo, tmp_path))
        on_disk = json.loads((tmp_path / "out" / "summary.json").read_text())
        assert on_disk == result.summary
        assert on_disk["counts"] == {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 1,
        }
        assert on_disk["gate"] == {"fail_on": "high", "failed": True}
        assert on_disk["exit_code"] == 1
        assert on_disk["files_reviewed"] == 5
        assert on_disk["duration_ms"] == 1234
        assert on_disk["cost_usd"] == 0.5
        assert set(on_disk["outputs"]) == {
            "findings.json",
            "findings.sarif",
            "report.md",
            "summary.json",
        }

    def test_clean_scan_summary_exit_zero(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        result = run_scan(_config(repo, tmp_path))
        assert result.summary["exit_code"] == 0
        assert result.summary["gate"]["failed"] is False
        assert result.summary["counts"]["total"] == 0

    def test_cost_is_null_for_self_hosted_endpoint(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(
            structured_output={"findings": [], "summary": "ok"},
            total_cost_usd=0.5,
        )
        result = run_scan(
            _config(repo, tmp_path, base_url="http://127.0.0.1:8000")
        )
        assert result.summary["cost_usd"] is None


class TestBuildUserPrompt:
    def test_context_is_wrapped_as_untrusted(self, repo, tmp_path):
        config = ScanConfig(target=repo, context="only scan src/")
        prompt = build_user_prompt(config)
        assert "<user_context>" in prompt
        assert "only scan src/" in prompt

    def test_no_context(self, repo):
        config = ScanConfig(target=repo)
        assert "<user_context>" not in build_user_prompt(config)


class TestEngineRegistry:
    def test_unknown_engine(self):
        with pytest.raises(ValueError, match="Unknown engine"):
            engine_base.get_engine("does-not-exist")

    def test_claude_engine_registered(self):
        engine = engine_base.get_engine("claude")
        assert engine.name == "claude"


class TestSummaryEngineAccounting:
    FINDING = TestSummary.FINDING

    def test_summary_reports_tokens_and_stop_reason(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(
            structured_output={
                "findings": [self.FINDING],
                "summary": "partial",
                "files_reviewed": 2,
            },
            total_tokens=45678,
            stopped_reason="budget_exceeded",
        )
        result = run_scan(_config(repo, tmp_path))
        assert result.summary["total_tokens"] == 45678
        assert result.summary["stopped"] == "budget_exceeded"

    def test_summary_defaults_are_null_for_normal_runs(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(
            structured_output={"findings": [], "summary": "clean"}
        )
        result = run_scan(_config(repo, tmp_path))
        assert result.summary["total_tokens"] is None
        assert result.summary["stopped"] is None
