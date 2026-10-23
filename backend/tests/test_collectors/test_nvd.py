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

    with patch("httpx.get", side_effect=_httpx.ConnectError("refused")):
        from app.collectors.nvd import fetch_nvd
        assert fetch_nvd(r=r) == 0
