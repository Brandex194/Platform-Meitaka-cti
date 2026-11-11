"""Tests for NVD CVE collector."""
import json
from unittest.mock import MagicMock, patch

import fakeredis
import pytest


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _make_response(start: int, count: int, total: int):
    data = {
        "vulnerabilities": [{"cve": {"id": f"CVE-2024-{start + i:05d}"}} for i in range(count)],
        "totalResults": total,
        "resultsPerPage": count,
        "startIndex": start,
    }
    mock = MagicMock()
    mock.json.return_value = data
    mock.raise_for_status.return_value = None
    return mock


def test_nvd_fetch_paginates():
    """fetch_nvd returns total CVE count across all pages."""
    page1 = _make_response(0, 2000, 2500)
    page2 = _make_response(2000, 500, 2500)

    r = fakeredis.FakeRedis()
    with patch("time.sleep"), patch("httpx.get", side_effect=[page1, page2]):
        from app.collectors.nvd import fetch_nvd
        count = fetch_nvd(r=r)

    assert count == 2500


def test_nvd_saves_last_run():
    """After fetch_nvd completes, nvd:last_run key is set in Redis."""
    mock_resp = _make_response(0, 1, 1)
    r = fakeredis.FakeRedis()

    with patch("time.sleep"), patch("httpx.get", return_value=mock_resp):
        from app.collectors.nvd import fetch_nvd, LAST_RUN_KEY
        fetch_nvd(r=r)

    assert r.get(LAST_RUN_KEY) is not None


def test_nvd_http_error_returns_zero():
    """HTTP error from NVD returns 0 without raising."""
    import httpx as _httpx
    r = fakeredis.FakeRedis()

    with patch("time.sleep"), patch("httpx.get", side_effect=_httpx.ConnectError("refused")) as get:
        from app.collectors.nvd import RETRY_ATTEMPTS, fetch_nvd
        assert fetch_nvd(r=r) == 0
    assert get.call_count == RETRY_ATTEMPTS


def test_nvd_retries_timeout_then_succeeds():
    """A read timeout on one page is retried instead of aborting the run."""
    import httpx as _httpx
    r = fakeredis.FakeRedis()

    with patch("time.sleep"), patch(
        "httpx.get", side_effect=[_httpx.ReadTimeout("slow"), _make_response(0, 3, 3)]
    ):
        from app.collectors.nvd import LAST_RUN_KEY, fetch_nvd
        assert fetch_nvd(r=r) == 3
    assert r.get(LAST_RUN_KEY) is not None


def test_fmt_nvd_date_is_iso_with_offset():
    from datetime import datetime, timedelta, timezone

    from app.collectors.nvd import _fmt_nvd_date

    dt = datetime(2026, 8, 11, 16, 28, 15, tzinfo=timezone(timedelta(hours=2)))
    assert _fmt_nvd_date(dt) == "2026-08-11T14:28:15.000+00:00"
