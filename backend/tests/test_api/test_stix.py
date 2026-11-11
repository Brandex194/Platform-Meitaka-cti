"""STIX import/export routes (passo 9)."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_scoped_db
from app.auth.jwks import decode_token
from app.db.models import Campaign, Indicator, Tenant, ThreatActor
from app.db.session import get_db
from app.main import create_app


def _client(db_session, roles, tenant):
    app = create_app()
    app.dependency_overrides[decode_token] = lambda: {"sub": str(uuid.uuid4()), "roles": roles, "tenant_id": str(tenant.id)}
    app.dependency_overrides[get_scoped_db] = lambda: db_session
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def analyst(db_session, tenant):
    return _client(db_session, ["analyst"], tenant)


def _url(t, what):
    return f"/api/v1/tenants/{t.id}/stix/{what}"


def _bundle(objs):
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def _post(client, tenant, doc):
    return client.post(_url(tenant, "import"), content=json.dumps(doc), headers={"Content-Type": "application/json"})


def test_export_contains_own_and_shared_and_media_type(analyst, db_session, tenant):
    other = Tenant(name="O", slug="o-stix")
    db_session.add(other)
    db_session.flush()
    db_session.add_all([
        Indicator(tenant_id=tenant.id, ioc_type="domain", value="mine.test"),
        Indicator(tenant_id=None, ioc_type="ip", value="198.51.100.7"),
        Indicator(tenant_id=other.id, ioc_type="domain", value="theirs.test"),
        ThreatActor(tenant_id=other.id, name="Foreign actor"),
        Campaign(tenant_id=other.id, name="Foreign campaign"),
    ])
    db_session.flush()
    r = analyst.get(_url(tenant, "export"))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/stix+json")
    assert "attachment" in r.headers["content-disposition"]
    text = r.text
    assert "mine.test" in text and "198.51.100.7" in text
    assert "theirs.test" not in text and "Foreign" not in text
    own = analyst.get(_url(tenant, "export"), params={"own_only": "true"}).text
    assert "mine.test" in own and "198.51.100.7" not in own


def test_export_counts_skipped_indicators(analyst, db_session, tenant):
    db_session.add(Indicator(tenant_id=tenant.id, ioc_type="hash", value="tooshort"))
    db_session.flush()
    r = analyst.get(_url(tenant, "export"))
    assert r.headers["x-stix-skipped"] == "1"


def test_import_creates_records_for_the_importing_tenant(analyst, db_session, tenant):
    aid, cid = f"threat-actor--{uuid.uuid4()}", f"campaign--{uuid.uuid4()}"
    doc = _bundle([
        {"type": "indicator", "id": f"indicator--{uuid.uuid4()}", "pattern": "[domain-name:value = 'Bad.Example']", "pattern_type": "stix", "confidence": 60},
        {"type": "threat-actor", "id": aid, "name": "APT-Z", "aliases": ["Z"]},
        {"type": "campaign", "id": cid, "name": "Op Z"},
        {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", "relationship_type": "attributed-to", "source_ref": cid, "target_ref": aid},
        {"type": "malware", "id": f"malware--{uuid.uuid4()}", "name": "m"},
    ])
    r = _post(analyst, tenant, doc)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] == {"indicators": 1, "threat_actors": 1, "campaigns": 1, "links": 0}
    assert body["duplicates"] == {"indicators": 0, "threat_actors": 0, "campaigns": 0, "links": 0}
    assert body["skipped_total"] == 1 and "not supported" in body["skipped"][0]["reason"]
    ind = db_session.query(Indicator).filter_by(value="bad.example").one()
    assert ind.tenant_id == tenant.id and ind.confidence == pytest.approx(0.6)
    actor = db_session.query(ThreatActor).filter_by(name="APT-Z").one()
    camp = db_session.query(Campaign).filter_by(name="Op Z").one()
    assert actor.tenant_id == tenant.id and camp.tenant_id == tenant.id and camp.threat_actor_id == actor.id


def test_import_twice_is_idempotent(analyst, db_session, tenant):
    doc = _bundle([
        {"type": "indicator", "id": f"indicator--{uuid.uuid4()}", "pattern": "[ipv4-addr:value = '203.0.113.50']", "pattern_type": "stix"},
        {"type": "threat-actor", "id": f"threat-actor--{uuid.uuid4()}", "name": "Dup Actor"},
        {"type": "campaign", "id": f"campaign--{uuid.uuid4()}", "name": "Dup Campaign"},
    ])
    first = _post(analyst, tenant, doc).json()
    second = _post(analyst, tenant, doc).json()
    assert first["created"] == {"indicators": 1, "threat_actors": 1, "campaigns": 1, "links": 0}
    assert second["created"] == {"indicators": 0, "threat_actors": 0, "campaigns": 0, "links": 0}
    assert second["duplicates"] == {"indicators": 1, "threat_actors": 1, "campaigns": 1, "links": 0}
    assert db_session.query(Indicator).filter_by(value="203.0.113.50").count() == 1


def test_import_dedupes_inside_the_bundle_and_against_shared(analyst, db_session, tenant):
    db_session.add_all([Indicator(tenant_id=None, ioc_type="ip", value="198.51.100.9"), ThreatActor(tenant_id=None, name="Shared Actor")])
    db_session.flush()
    mk = lambda p: {"type": "indicator", "id": f"indicator--{uuid.uuid4()}", "pattern": p, "pattern_type": "stix"}  # noqa: E731
    doc = _bundle([
        mk("[ipv4-addr:value = '198.51.100.9']"),
        mk("[ipv4-addr:value = '203.0.113.77']"),
        mk("[ipv4-addr:value = '203.0.113.77']"),
        {"type": "threat-actor", "id": f"threat-actor--{uuid.uuid4()}", "name": "shared actor"},
    ])
    body = _post(analyst, tenant, doc).json()
    assert body["created"]["indicators"] == 1 and body["duplicates"]["indicators"] == 2
    assert body["created"]["threat_actors"] == 0 and body["duplicates"]["threat_actors"] == 1


def test_campaign_links_to_an_existing_actor_in_the_bundle_only(analyst, db_session, tenant):
    aid, cid = f"threat-actor--{uuid.uuid4()}", f"campaign--{uuid.uuid4()}"
    doc = _bundle([
        {"type": "campaign", "id": cid, "name": "Lonely"},
        {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", "relationship_type": "attributed-to", "source_ref": cid, "target_ref": aid},
    ])
    assert _post(analyst, tenant, doc).status_code == 200
    assert db_session.query(Campaign).filter_by(name="Lonely").one().threat_actor_id is None


def test_import_errors(analyst, tenant):
    assert analyst.post(_url(tenant, "import"), content=b"not json").status_code == 400
    r = _post(analyst, tenant, {"type": "indicator"})
    assert r.status_code == 400 and "not a STIX bundle" in r.json()["error"]["message"]
    assert _post(analyst, tenant, [1, 2]).status_code == 400


def test_import_too_large(analyst, tenant, monkeypatch):
    from app.api.v1.routes import stix as route

    monkeypatch.setattr(route, "MAX_BODY_BYTES", 100)
    r = analyst.post(_url(tenant, "import"), content=b"{" + b" " * 200 + b"}")
    assert r.status_code == 413


def test_skipped_list_is_capped_but_total_is_exact(analyst, tenant):
    objs = [{"type": "malware", "id": f"malware--{uuid.uuid4()}", "name": "m"} for _ in range(150)]
    body = _post(analyst, tenant, _bundle(objs)).json()
    assert body["skipped_total"] == 150 and len(body["skipped"]) == 100


def test_roles(db_session, tenant):
    for role in ("viewer",):
        c = _client(db_session, [role], tenant)
        assert c.get(_url(tenant, "export")).status_code == 403
        assert _post(c, tenant, _bundle([])).status_code == 403
    for role in ("analyst", "tenant_admin", "api_user"):
        c = _client(db_session, [role], tenant)
        assert c.get(_url(tenant, "export")).status_code == 200
        assert _post(c, tenant, _bundle([])).status_code == 200


def test_round_trip_export_then_import_into_another_tenant(db_session, tenant, analyst):
    db_session.add_all([
        Indicator(tenant_id=tenant.id, ioc_type="url", value="http://x.test/it's"),
        Indicator(tenant_id=tenant.id, ioc_type="hash", value="b" * 64, confidence=0.5),
    ])
    actor = ThreatActor(tenant_id=tenant.id, name="Round Trip APT", aliases=["RT"])
    db_session.add(actor)
    db_session.flush()
    db_session.add(Campaign(tenant_id=tenant.id, name="Round Trip Op", threat_actor_id=actor.id))
    db_session.flush()
    bundle = analyst.get(_url(tenant, "export"), params={"own_only": "true"}).json()
    other = Tenant(name="Dest", slug="dest-stix")
    db_session.add(other)
    db_session.flush()
    dest = _client(db_session, ["analyst"], other)
    body = _post(dest, other, bundle).json()
    assert body["created"] == {"indicators": 2, "threat_actors": 1, "campaigns": 1, "links": 0} and body["skipped_total"] == 0
    assert db_session.query(Indicator).filter_by(tenant_id=other.id, value="http://x.test/it's").count() == 1
    new_actor = db_session.query(ThreatActor).filter_by(tenant_id=other.id).one()
    assert db_session.query(Campaign).filter_by(tenant_id=other.id).one().threat_actor_id == new_actor.id
    assert new_actor.id != actor.id  # a copy owned by the destination tenant


def test_requires_auth():
    app = create_app()
    c = TestClient(app, raise_server_exceptions=False)
    t = uuid.uuid4()
    assert c.get(f"/api/v1/tenants/{t}/stix/export").status_code == 401
    assert c.post(f"/api/v1/tenants/{t}/stix/import", json={}).status_code == 401
