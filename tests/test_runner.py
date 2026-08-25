"""Tests for scan orchestration with a mock engine."""

import json

import pytest

import security_ai_scanner.engine.base as engine_base
from security_ai_scanner.config import ScanConfig
from security_ai_scanner.engine.base import EngineResult, ScanEngine
from security_ai_scanner.exceptions import (
    EngineError,
    FindingsParseError,
    PublicationError,
    TargetError,
    get_published_summary,
)
from security_ai_scanner.publication import LOCK_NAME, OutputPublication
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
        with pytest.raises(EngineError) as caught:
            run_scan(_config(repo, tmp_path))
        published = get_published_summary(caught.value)
        on_disk = json.loads(
            (tmp_path / "out" / "summary.json").read_text(encoding="utf-8")
        )
        assert published == on_disk
        assert on_disk["status"] == "error"
        assert on_disk["exit_code"] == 2
        assert on_disk["outputs"] == {}
        assert "boom" in on_disk["error"]
        assert not (tmp_path / "out" / LOCK_NAME).exists()

    def test_parse_error_publishes_error_summary(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(text="not findings JSON")

        with pytest.raises(FindingsParseError) as caught:
            run_scan(_config(repo, tmp_path))

        published = get_published_summary(caught.value)
        assert published is not None
        assert published["status"] == "error"
        assert "engine=mock" in published["error"]

    def test_engine_error_with_valid_partial_output_is_still_error(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(
            structured_output={"findings": [], "summary": "partial"},
            is_error=True,
            error_message="turn limit reached",
            stopped_reason="max_turns",
        )

        with pytest.raises(EngineError) as caught:
            run_scan(_config(repo, tmp_path))

        summary = get_published_summary(caught.value)
        assert summary is not None
        assert summary["status"] == "error"

    def test_engine_error_with_output_but_no_partial_reason_is_error(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(
            structured_output={"findings": [], "summary": "untrusted"},
            is_error=True,
            error_message="engine failed",
        )

        with pytest.raises(EngineError) as caught:
            run_scan(_config(repo, tmp_path))

        summary = get_published_summary(caught.value)
        assert summary is not None
        assert summary["status"] == "error"
        assert "engine failed" in summary["error"]

    def test_stale_summary_is_invalidated_before_engine_runs(
        self, repo, tmp_path, mock_engine, monkeypatch
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        summary_path = output_dir / "summary.json"
        summary_path.write_text("old summary\n", encoding="utf-8")
        mock_engine["result"] = _structured()
        original_run = MockEngine.run

        async def inspect_run(engine, request):
            assert not summary_path.exists()
            assert (output_dir / LOCK_NAME).exists()
            return await original_run(engine, request)

        monkeypatch.setattr(MockEngine, "run", inspect_run)
        run_scan(_config(repo, tmp_path))

    def test_existing_writer_is_rejected_before_engine_creation(
        self, repo, tmp_path, mock_engine
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        summary_path = output_dir / "summary.json"
        summary_path.write_text("old summary\n", encoding="utf-8")
        (output_dir / LOCK_NAME).write_text("busy\n", encoding="utf-8")
        mock_engine["result"] = _structured()

        with pytest.raises(PublicationError, match="already in use"):
            run_scan(_config(repo, tmp_path))

        assert summary_path.read_text(encoding="utf-8") == "old summary\n"
        assert "engine" not in mock_engine

    def test_summary_is_published_last(
        self, repo, tmp_path, mock_engine, monkeypatch
    ):
        mock_engine["result"] = _structured()
        order = []
        original_write = OutputPublication.write_text

        def record_write(publication, name, content):
            order.append(name)
            return original_write(publication, name, content)

        monkeypatch.setattr(OutputPublication, "write_text", record_write)
        run_scan(_config(repo, tmp_path))
        assert order == [
            "findings.json",
            "findings.sarif",
            "report.md",
            "summary.json",
        ]

    def test_interruption_cannot_leave_a_completed_marker(
        self, repo, tmp_path, mock_engine, monkeypatch
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        summary_path = output_dir / "summary.json"
        summary_path.write_text("old summary\n", encoding="utf-8")
        mock_engine["result"] = _structured()
        original_write = OutputPublication.write_text

        def interrupt_write(publication, name, content):
            if name == "findings.sarif":
                raise PublicationError("injected interruption")
            return original_write(publication, name, content)

        monkeypatch.setattr(OutputPublication, "write_text", interrupt_write)

        with pytest.raises(PublicationError, match="injected interruption"):
            run_scan(_config(repo, tmp_path))

        error_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        assert error_summary["status"] == "error"
        assert error_summary["outputs"] == {}
        assert (output_dir / "findings.json").exists()
        assert not (output_dir / LOCK_NAME).exists()

    def test_error_summary_publication_is_best_effort(
        self, repo, tmp_path, mock_engine, monkeypatch
    ):
        mock_engine["result"] = _structured()

        def fail_every_write(_publication, _name, _content):
            raise PublicationError("output unavailable")

        monkeypatch.setattr(OutputPublication, "write_text", fail_every_write)

        with pytest.raises(PublicationError) as caught:
            run_scan(_config(repo, tmp_path))

        assert get_published_summary(caught.value) is None
        assert not (tmp_path / "out" / "summary.json").exists()
        assert not (tmp_path / "out" / LOCK_NAME).exists()

    def test_missing_target_raises(self, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        with pytest.raises(TargetError):
            run_scan(_config(tmp_path / "nope", tmp_path))

    def test_selected_formats_only(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        result = run_scan(_config(repo, tmp_path, formats=("sarif",)))
        # Native JSON artifacts are mandatory; --format selects derived output.
        assert [p.name for p in result.written_files] == [
            "findings.json",
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
        }
        assert on_disk["schema_version"] == 1
        assert on_disk["status"] == "completed"
        assert on_disk["subject"]["root"] == str(repo.resolve())

    def test_clean_scan_summary_exit_zero(self, repo, tmp_path, mock_engine):
        mock_engine["result"] = _structured()
        result = run_scan(_config(repo, tmp_path))
        assert result.summary["exit_code"] == 0
        assert result.summary["gate"]["failed"] is False
        assert result.summary["counts"]["total"] == 0

    @pytest.mark.parametrize(
        ("stopped", "has_gate_finding", "expected_status", "expected_exit"),
        [
            (None, False, "completed", 0),
            (None, True, "completed", 1),
            ("max_turns", False, "incomplete", 0),
            ("future_reason", True, "incomplete", 1),
        ],
    )
    def test_status_and_exit_code_matrix(
        self,
        repo,
        tmp_path,
        mock_engine,
        stopped,
        has_gate_finding,
        expected_status,
        expected_exit,
    ):
        findings = [self.FINDING] if has_gate_finding else []
        mock_engine["result"] = EngineResult(
            structured_output={"findings": findings, "summary": "matrix"},
            stopped_reason=stopped,
        )

        result = run_scan(_config(repo, tmp_path))

        assert result.summary["status"] == expected_status
        assert result.summary["exit_code"] == expected_exit

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
        assert result.summary["status"] == "incomplete"

    def test_summary_defaults_are_null_for_normal_runs(
        self, repo, tmp_path, mock_engine
    ):
        mock_engine["result"] = EngineResult(
            structured_output={"findings": [], "summary": "clean"}
        )
        result = run_scan(_config(repo, tmp_path))
        assert result.summary["total_tokens"] is None
        assert result.summary["stopped"] is None
