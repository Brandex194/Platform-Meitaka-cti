import json
import uuid

import fakeredis
import pytest

from app.db.models import Vulnerability
from app.normalize.engine import normalize_batch
from app.streams.streams import get_cursor, publish


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_normalize_cve_upserts_vulnerability(db_session, fake_redis):
    cve_payload = {
        "id": "CVE-2024-1234",
        "descriptions": [{"value": "A test vulnerability"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
    }
    publish("raw-observations", {"type": "cve", "data": json.dumps(cve_payload)}, r=fake_redis)

    count = normalize_batch(db=db_session, r=fake_redis)

    assert count == 1
    assert db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-1234").count() == 1
    vuln = db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-1234").one()
    assert vuln.cvss_score == 7.5
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_unknown_type_skips(db_session, fake_redis):
    publish("raw-observations", {"type": "unknown_xyz", "data": "{}"}, r=fake_redis)

    count = normalize_batch(db=db_session, r=fake_redis)

    assert count == 1
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_empty_stream_returns_zero(db_session, fake_redis):
    assert normalize_batch(db=db_session, r=fake_redis) == 0


def test_normalize_malformed_message_skips(db_session, fake_redis):
    publish("raw-observations", {"type": "cve", "data": "not-json"}, r=fake_redis)

    count = normalize_batch(db=db_session, r=fake_redis)

    assert count == 1
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_cve_missing_id_skips(db_session, fake_redis):
    """CVE with no 'id' field is skipped; cursor still advances."""
    publish("raw-observations", {"type": "cve", "data": '{"not_id": "blah"}'}, r=fake_redis)

    count = normalize_batch(db=db_session, r=fake_redis)

    assert count == 1
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_cursor_not_advanced_on_exception(db_session, fake_redis, monkeypatch):
    cve_payload = {"id": "CVE-2024-5678", "descriptions": [], "metrics": {}}
    publish("raw-observations", {"type": "cve", "data": json.dumps(cve_payload)}, r=fake_redis)

    import app.normalize.engine as eng

    monkeypatch.setattr(eng, "_upsert_vulnerability", lambda data, db: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        normalize_batch(db=db_session, r=fake_redis)

    assert get_cursor("raw-observations", r=fake_redis) == "0-0"
