"""Tests for the MCP server tools (no real MCP client, no real engine)."""

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from security_ai_scanner import mcp_server
from security_ai_scanner.engine.base import EngineResult

FINDINGS = [
    {
        "title": "SQL injection",
        "severity": "high",
        "confidence": "high",
        "file": "app.py",
        "start_line": 3,
        "description": "d",
        "recommendation": "r",
    },
    {
        "title": "Verbose logging",
        "severity": "info",
        "confidence": "medium",
        "file": "log.py",
        "start_line": 9,
        "description": "d",
        "recommendation": "r",
    },
]


@pytest.fixture(autouse=True)
def clean_results():
    mcp_server._RESULTS.clear()
    yield
    mcp_server._RESULTS.clear()


@pytest.fixture
def repo(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    return target


@pytest.fixture
def mock_engine(monkeypatch):
    def install(findings):
        class Engine:
            name = "claude"

            async def run(self, request):
                return EngineResult(
                    structured_output={"findings": findings, "summary": "s"}
                )

        monkeypatch.setattr(
            "security_ai_scanner.runner.get_engine", lambda name: Engine()
        )

    return install


class TestScanRepository:
    def test_returns_summary_with_scan_id(self, repo, mock_engine):
        mock_engine(FINDINGS)
        result = asyncio.run(mcp_server.scan_repository(str(repo)))
        assert result["scan_id"] == "scan-0001"
        assert result["counts"]["high"] == 1
        assert result["counts"]["total"] == 2
        assert result["gate"]["failed"] is True

    def test_outputs_not_written_into_target(self, repo, mock_engine):
        mock_engine([])
        result = asyncio.run(mcp_server.scan_repository(str(repo)))
        assert not (repo / "security-scan-results").exists()
        for descriptor in result["outputs"].values():
            path = Path(descriptor["path"])
            assert not path.is_absolute()
            assert str(repo) not in str(path)

    def test_scan_failure_raises_runtime_error(self, tmp_path, mock_engine):
        mock_engine([])
        with pytest.raises(RuntimeError, match="Scan failed"):
            asyncio.run(mcp_server.scan_repository(str(tmp_path / "nope")))


class TestResultTools:
    def _scan(self, repo):
        return asyncio.run(mcp_server.scan_repository(str(repo)))["scan_id"]

    def test_get_summary_roundtrip(self, repo, mock_engine):
        mock_engine(FINDINGS)
        scan_id = self._scan(repo)
        summary = mcp_server.get_summary(scan_id)
        assert summary["scan_id"] == scan_id
        assert summary["counts"]["total"] == 2

    def test_get_findings_all(self, repo, mock_engine):
        mock_engine(FINDINGS)
        found = mcp_server.get_findings(self._scan(repo))
        assert {f["title"] for f in found} == {
            "SQL injection",
            "Verbose logging",
        }

    def test_get_findings_min_severity(self, repo, mock_engine):
        mock_engine(FINDINGS)
        found = mcp_server.get_findings(self._scan(repo), min_severity="high")
        assert [f["title"] for f in found] == ["SQL injection"]

    def test_get_findings_rejects_bad_severity(self, repo, mock_engine):
        mock_engine(FINDINGS)
        with pytest.raises(ValueError, match="min_severity"):
            mcp_server.get_findings(self._scan(repo), min_severity="urgent")

    def test_unknown_scan_id(self):
        with pytest.raises(ValueError, match="Unknown scan_id"):
            mcp_server.get_summary("scan-9999")


class TestRegistration:
    def test_all_tools_registered(self):
        tools = asyncio.run(mcp_server.server.list_tools())
        assert {t.name for t in tools} == {
            "scan_repository",
            "get_summary",
            "get_findings",
        }
