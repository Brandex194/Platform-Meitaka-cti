import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SIEM_INBOUND_KEY", "test-siem-key")

from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app

client = TestClient(app)


def test_missing_api_key_returns_401():
    r = client.post("/api/v1/siem/feedback", json={"event_type": "alert", "payload": {}})
    assert r.status_code == 401


def test_wrong_api_key_returns_401():
    r = client.post(
        "/api/v1/siem/feedback",
        json={"event_type": "alert", "payload": {}},
        headers={"X-SIEM-KEY": "wrong-key"},
    )
    assert r.status_code == 401


def test_valid_key_publishes_to_stream():
    with patch("app.siem.inbound.publish") as mock_pub:
        mock_pub.return_value = "123-0"
        r = client.post(
            "/api/v1/siem/feedback",
            json={"event_type": "alert", "payload": {"rule": "brute_force"}},
            headers={"X-SIEM-KEY": "test-siem-key"},
        )
    assert r.status_code == 200
    mock_pub.assert_called_once()
    call_args = mock_pub.call_args[0]
    assert call_args[0] == "feedback-events"
