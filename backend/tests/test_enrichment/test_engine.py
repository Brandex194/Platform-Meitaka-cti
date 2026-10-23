"""Tests for the enrichment engine."""
import uuid
from datetime import date

import fakeredis
import httpx
import pytest

from app.db.models import KevCatalog, Vulnerability
from app.enrichment.engine import enrich_batch
from app.streams.streams import publish


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


def _make_vuln(db_session, cve_id: str) -> Vulnerability:
    v = Vulnerability(id=uuid.uuid4(), cve_id=cve_id)
    db_session.add(v)
    db_session.flush()
    return v


# ---------------------------------------------------------------------------


def test_enrich_batch_empty(db_session, fake_redis):
    assert enrich_batch(db=db_session, r=fake_redis) == 0


def test_enrich_updates_kev(db_session, fake_redis, httpx_mock):
    cve_id = "CVE-2024-KEV1"
    httpx_mock.add_response(json={"data": []})  # empty EPSS — no score set

    v = _make_vuln(db_session, cve_id)
    kev = KevCatalog(id=uuid.uuid4(), cve_id=cve_id, date_added=date(2024, 1, 1))
    db_session.add(kev)
    db_session.flush()

    publish("enriched-entities", {"type": "vulnerability", "cve_id": cve_id}, r=fake_redis)
    count = enrich_batch(db=db_session, r=fake_redis)

    assert count == 1
    db_session.refresh(v)
    assert v.kev_date_added == date(2024, 1, 1)


def test_enrich_epss_set_when_api_succeeds(db_session, fake_redis, httpx_mock):
    cve_id = "CVE-2024-EPSS1"
    httpx_mock.add_response(
        json={"data": [{"cve": cve_id, "epss": "0.12345", "percentile": "0.9"}]}
    )

    v = _make_vuln(db_session, cve_id)
    publish("enriched-entities", {"type": "vulnerability", "cve_id": cve_id}, r=fake_redis)
    count = enrich_batch(db=db_session, r=fake_redis)

    assert count == 1
    db_session.refresh(v)
    assert v.epss_score == pytest.approx(0.12345)


def test_enrich_epss_error_skips(db_session, fake_redis, httpx_mock):
    cve_id = "CVE-2024-EPSS2"
    httpx_mock.add_exception(httpx.ConnectError("EPSS down"))

    v = _make_vuln(db_session, cve_id)
    publish("enriched-entities", {"type": "vulnerability", "cve_id": cve_id}, r=fake_redis)
    count = enrich_batch(db=db_session, r=fake_redis)

    assert count == 1
    db_session.refresh(v)
    assert v.epss_score is None  # EPSS skipped gracefully


def test_enrich_missing_vuln_skips(db_session, fake_redis, httpx_mock):
    # No Vulnerability row in DB — should log warning and skip without error
    publish(
        "enriched-entities",
        {"type": "vulnerability", "cve_id": "CVE-2024-GHOST"},
        r=fake_redis,
    )
    count = enrich_batch(db=db_session, r=fake_redis)
    assert count == 1


def test_kev_read_from_table_not_http(db_session, fake_redis, httpx_mock):
    """KEV data comes from kev_catalog table; no HTTP call to cisa.gov."""
    cve_id = "CVE-2024-CISA1"
    httpx_mock.add_response(json={"data": []})  # EPSS returns empty

    _make_vuln(db_session, cve_id)
    kev = KevCatalog(id=uuid.uuid4(), cve_id=cve_id, date_added=date(2024, 6, 15))
    db_session.add(kev)
    db_session.flush()

    publish("enriched-entities", {"type": "vulnerability", "cve_id": cve_id}, r=fake_redis)
    enrich_batch(db=db_session, r=fake_redis)

    requests = httpx_mock.get_requests()
    assert not any("cisa.gov" in str(r.url) for r in requests)
