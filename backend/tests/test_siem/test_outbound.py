import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("SIEM_OUTBOUND_URL", "https://siem.example.com/webhook")

from app.siem.outbound import push_siem_feedback


def test_push_posts_to_siem_url():
    messages = [{"event_type": "alert", "payload": {"rule": "brute_force"}}]
    resp = MagicMock()
    resp.raise_for_status = lambda: None
    with (
        patch("app.siem.outbound.get_cursor", return_value="0-0"),
        patch("app.siem.outbound.read_batch", return_value=(messages, "1000-0")),
        patch("app.siem.outbound.save_cursor"),
        patch("httpx.post", return_value=resp) as mock_post,
    ):
        push_siem_feedback()
    mock_post.assert_called_once()
    assert "siem.example.com" in mock_post.call_args[0][0]


def test_push_skips_when_no_outbound_url(monkeypatch):
    monkeypatch.delenv("SIEM_OUTBOUND_URL", raising=False)
    with patch("app.siem.outbound.get_cursor", return_value="0-0"):
        with patch("app.siem.outbound.read_batch", return_value=([], "0-0")):
            push_siem_feedback()  # should not raise
