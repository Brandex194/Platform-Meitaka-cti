"""End to end inside the DB: an NVD record goes through normalize and becomes an exposure.

Before 09/11/2026 normalize never stored cpe_nodes, so this chain produced nothing.
"""
import json

import fakeredis

from app.correlation.engine import CorrelationEngine
from app.db.models import CorrelationEvent, ExposureMatch, Software
from app.normalize.engine import normalize_batch
from app.streams.streams import publish

# NVD 2.0 shape; CVE id is real, the configuration below is a test input.
_RECORD = {
    "id": "CVE-2021-41773",
    "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"}],
    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5}}]},
    "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
    ]}]}],
}


def _add_software(db_session, asset, version):
    db_session.add(Software(
        asset_id=asset.id, tenant_id=asset.tenant_id, name="Apache httpd", version=version,
        cpe=f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    ))
    db_session.flush()


def _ingest(db_session):
    r = fakeredis.FakeRedis(decode_responses=True)
    publish("raw-observations", {"type": "cve", "data": json.dumps(_RECORD)}, r=r)
    normalize_batch(db=db_session, r=r)
    return r


def test_affected_version_becomes_exposure(db_session, tenant, asset):
    _add_software(db_session, asset, "2.4.49")
    r = _ingest(db_session)

    created = CorrelationEngine().run_for_tenant(tenant.id, session=db_session, r=r)

    assert created == 1
    event = db_session.query(CorrelationEvent).filter_by(tenant_id=tenant.id).one()
    assert event.rule_name == "vuln_software" and event.asset_id == asset.id
    assert event.s_context == 0.9
    assert db_session.query(ExposureMatch).filter_by(correlation_event_id=event.id).count() == 1


def test_patched_version_is_not_exposed(db_session, tenant, asset):
    _add_software(db_session, asset, "2.4.51")
    r = _ingest(db_session)

    assert CorrelationEngine().run_for_tenant(tenant.id, session=db_session, r=r) == 0
