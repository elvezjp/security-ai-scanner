"""Tests for webhook notification."""

import json

import pytest

from security_ai_scanner.notify import build_payload, send_notification

SUMMARY = {
    "tool": "security-ai-scanner",
    "subject": {"root": "/repo"},
    "counts": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 1,
               "total": 3},
    "gate": {"fail_on": "high", "failed": True},
    "exit_code": 1,
}


class TestBuildPayload:
    def test_generic_completed_embeds_summary(self):
        payload = build_payload("generic", SUMMARY)
        assert payload["status"] == "completed"
        assert payload["counts"]["total"] == 3

    def test_generic_error(self):
        payload = build_payload("generic", None, error="boom", target="/repo")
        assert payload == {
            "tool": "security-ai-scanner",
            "status": "error",
            "target": "/repo",
            "error": "boom",
        }

    def test_generic_error_uses_published_native_summary(self):
        summary = {
            **SUMMARY,
            "status": "error",
            "exit_code": 2,
            "error": "boom",
        }
        payload = build_payload(
            "generic", summary, error="boom", target="/repo"
        )
        assert payload == summary

    def test_discord_message_shape(self):
        payload = build_payload("discord", SUMMARY)
        assert set(payload) == {"content"}
        assert "3 finding(s)" in payload["content"]
        assert "high 2" in payload["content"]
        assert "gate FAILED" in payload["content"]
        assert "/repo" in payload["content"]

    def test_slack_message_shape(self):
        payload = build_payload("slack", SUMMARY)
        assert set(payload) == {"text"}
        assert "gate FAILED" in payload["text"]

    def test_no_finding_details_in_chat_formats(self):
        summary = {**SUMMARY, "summary": "SQLi in app.py line 3"}
        for fmt in ("discord", "slack"):
            text = next(iter(build_payload(fmt, summary).values()))
            assert "app.py" not in text

    def test_unknown_format_rejected(self):
        with pytest.raises(ValueError, match="format"):
            build_payload("teams", SUMMARY)


class TestSendNotification:
    def test_posts_json_body(self, monkeypatch):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["content_type"] = request.get_header("Content-type")
            return FakeResponse()

        monkeypatch.setattr(
            "security_ai_scanner.notify.urllib.request.urlopen", fake_urlopen
        )
        ok = send_notification("https://hooks.example/x", "discord", SUMMARY)
        assert ok is True
        assert captured["url"] == "https://hooks.example/x"
        assert captured["content_type"] == "application/json"
        assert "content" in captured["body"]

    def test_failure_is_swallowed_and_url_not_leaked(
        self, monkeypatch, capsys
    ):
        def fake_urlopen(request, timeout):
            raise OSError("connection refused")

        monkeypatch.setattr(
            "security_ai_scanner.notify.urllib.request.urlopen", fake_urlopen
        )
        secret_url = "https://hooks.example/secret-token-123"
        ok = send_notification(secret_url, "generic", SUMMARY)
        assert ok is False
        err = capsys.readouterr().err
        assert "warning: webhook notification failed" in err
        assert "secret-token-123" not in err


@pytest.mark.parametrize("fmt,key", [("slack", "text"), ("discord", "content")])
@pytest.mark.parametrize("total,failed", [(0, False), (2, False), (2, True)])
@pytest.mark.parametrize("reason", ["max_turns", "budget_exceeded", None])
def test_incomplete_notifications_distinguish_completion_from_threshold(fmt, key, total, failed, reason):
    summary = {**SUMMARY, "status": "incomplete", "stopped": reason,
               "counts": {"total": total}, "gate": {"failed": failed, "fail_on": "high"}}
    text = build_payload(fmt, summary)[key]
    assert "INCOMPLETE" in text
    assert (reason or "unspecified") in text
    assert "local finding threshold" in text
    assert ("FAILED" if failed else "passed") in text
    assert "gate passed" not in text
    assert f"{total} finding(s)" in text
    assert build_payload("generic", summary) == summary


def test_stop_reason_cannot_be_hidden_by_completed_status():
    summary = {**SUMMARY, "status": "completed", "stopped": "max_turns"}
    assert "INCOMPLETE" in build_payload("slack", summary)["text"]


@pytest.mark.parametrize("fmt,key", [("slack", "text"), ("discord", "content")])
def test_completed_and_error_notification_behavior_is_preserved(fmt, key):
    completed = {**SUMMARY, "status": "completed", "stopped": None, "gate": {"failed": False}}
    assert "gate passed" in build_payload(fmt, completed)[key]
    assert "INCOMPLETE" not in build_payload(fmt, completed)[key]
    assert "ERROR" in build_payload(fmt, None, error="engine failed", target="repo")[key]
