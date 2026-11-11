import json
import uuid

import fakeredis
import pytest

from app.db.models import Vulnerability
from app.normalize.engine import OUTPUT_STREAM, normalize_batch
from app.streams.streams import get_cursor, publish, save_cursor


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

    count, last_msg_id, pending = normalize_batch(db=db_session, r=fake_redis)
    # task wrapper publishes then saves cursor after commit; simulate that here
    if last_msg_id:
        save_cursor("raw-observations", last_msg_id, fake_redis)

    assert count == 1
    assert len(pending) == 1
    assert pending[0][0] == OUTPUT_STREAM
    assert db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-1234").count() == 1
    vuln = db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-1234").one()
    assert vuln.cvss_score == 7.5
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_unknown_type_skips(db_session, fake_redis):
    publish("raw-observations", {"type": "unknown_xyz", "data": "{}"}, r=fake_redis)

    count, last_msg_id, _ = normalize_batch(db=db_session, r=fake_redis)
    if last_msg_id:
        save_cursor("raw-observations", last_msg_id, fake_redis)

    assert count == 1
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_empty_stream_returns_zero(db_session, fake_redis):
    count, last_msg_id, pending = normalize_batch(db=db_session, r=fake_redis)
    assert count == 0
    assert last_msg_id is None
    assert pending == []


def test_normalize_malformed_message_skips(db_session, fake_redis):
    publish("raw-observations", {"type": "cve", "data": "not-json"}, r=fake_redis)

    count, last_msg_id, _ = normalize_batch(db=db_session, r=fake_redis)
    if last_msg_id:
        save_cursor("raw-observations", last_msg_id, fake_redis)

    assert count == 1
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_cve_missing_id_skips(db_session, fake_redis):
    """CVE with no 'id' field is skipped; cursor still advances."""
    publish("raw-observations", {"type": "cve", "data": '{"not_id": "blah"}'}, r=fake_redis)

    count, last_msg_id, _ = normalize_batch(db=db_session, r=fake_redis)
    if last_msg_id:
        save_cursor("raw-observations", last_msg_id, fake_redis)

    assert count == 1
    assert get_cursor("raw-observations", r=fake_redis) != "0-0"


def test_normalize_cursor_not_advanced_on_exception(db_session, fake_redis, monkeypatch):
    cve_payload = {"id": "CVE-2024-5678", "descriptions": [], "metrics": {}}
    publish("raw-observations", {"type": "cve", "data": json.dumps(cve_payload)}, r=fake_redis)

    import app.normalize.engine as eng

    monkeypatch.setattr(eng, "_upsert_vulnerability", lambda data, db: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        normalize_batch(db=db_session, r=fake_redis)

    # cursor NOT saved because exception propagated before save_cursor was called
    assert get_cursor("raw-observations", r=fake_redis) == "0-0"


# --- NVD 2.0 record shape: configurations and CVSS fallbacks --------------------
# Structure follows the NVD CVE API 2.0 schema. CVE ids are real; scores, vectors and
# configurations below are test inputs, not a copy of the live NVD records.


def _nvd_record(cve_id, metrics=None, configurations=None):
    return {
        "id": cve_id,
        "descriptions": [{"lang": "es", "value": "otra"}, {"lang": "en", "value": "english text"}],
        "metrics": metrics or {},
        "configurations": configurations or [],
    }


def _normalize_one(record, db_session, fake_redis):
    publish("raw-observations", {"type": "cve", "data": json.dumps(record)}, r=fake_redis)
    normalize_batch(db=db_session, r=fake_redis)
    return db_session.query(Vulnerability).filter_by(cve_id=record["id"]).one()


def test_normalize_stores_vulnerable_cpe_entries(db_session, fake_redis):
    configurations = [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                         "matchCriteriaId": "A"},
                        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                         "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.48",
                         "matchCriteriaId": "B"},
                    ],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
                    ],
                },
            ],
        }
    ]
    vuln = _normalize_one(_nvd_record("CVE-2021-41773", configurations=configurations), db_session, fake_redis)

    assert vuln.cpe_nodes == [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
        {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.48"},
    ]
    assert vuln.description == "english text"


def test_normalize_skips_negated_nodes_and_duplicates(db_session, fake_redis):
    entry = {"vulnerable": True, "criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}
    configurations = [
        {"nodes": [{"negate": False, "cpeMatch": [entry, entry]}]},
        {"nodes": [{"negate": True, "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:v:q:1.0:*:*:*:*:*:*:*"}]}]},
    ]
    vuln = _normalize_one(_nvd_record("CVE-2024-0002", configurations=configurations), db_session, fake_redis)
    assert vuln.cpe_nodes == [{"criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}]


def test_normalize_cvss_prefers_v31_primary(db_session, fake_redis):
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0, "vectorString": "CVSS:3.1/sec"}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/pri"}},
        ],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 4.0}}],
    }
    vuln = _normalize_one(_nvd_record("CVE-2024-0003", metrics=metrics), db_session, fake_redis)
    assert (vuln.cvss_score, vuln.cvss_vector) == (9.8, "CVSS:3.1/pri")


@pytest.mark.parametrize("key", ["cvssMetricV40", "cvssMetricV30", "cvssMetricV2"])
def test_normalize_cvss_falls_back_when_v31_missing(db_session, fake_redis, key):
    metrics = {key: [{"type": "Primary", "cvssData": {"baseScore": 6.1, "vectorString": "V"}}]}
    vuln = _normalize_one(_nvd_record(f"CVE-2024-01{len(key)}", metrics=metrics), db_session, fake_redis)
    assert vuln.cvss_score == 6.1


def test_normalize_without_metrics_or_configurations(db_session, fake_redis):
    vuln = _normalize_one(_nvd_record("CVE-2024-0005"), db_session, fake_redis)
    assert vuln.cvss_score is None
    assert vuln.cpe_nodes == []
