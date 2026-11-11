"""Knowledge Graph and indicator <-> campaign links (passo 11)."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_scoped_db
from app.auth.jwks import decode_token
from app.db.models import Campaign, CampaignIndicator, Indicator, Tenant, ThreatActor
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


@pytest.fixture
def world(db_session, tenant):
    """own actor + own campaign (attributed), a shared campaign, an own and a shared indicator."""
    actor = ThreatActor(tenant_id=tenant.id, name="APT-G")
    db_session.add(actor)
    db_session.flush()
    camp = Campaign(tenant_id=tenant.id, name="Op G", threat_actor_id=actor.id)
    shared_camp = Campaign(tenant_id=None, name="Shared Op")
    ind = Indicator(tenant_id=tenant.id, ioc_type="domain", value="g.example")
    shared_ind = Indicator(tenant_id=None, ioc_type="ip", value="198.51.100.20")
    db_session.add_all([camp, shared_camp, ind, shared_ind])
    db_session.flush()
    return SimpleNS(actor=actor, camp=camp, shared_camp=shared_camp, ind=ind, shared_ind=shared_ind)


class SimpleNS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _g(t):
    return f"/api/v1/tenants/{t.id}/graph"


def _link_url(t, camp):
    return f"/api/v1/tenants/{t.id}/campaigns/{camp.id}/indicators"


def test_empty_graph(analyst, tenant):
    body = analyst.get(_g(tenant)).json()
    assert body == {"nodes": [], "edges": [], "indicators_total": 0, "truncated": False}


def test_graph_nodes_and_edges(analyst, tenant, world):
    assert analyst.post(_link_url(tenant, world.camp), json={"indicator_id": str(world.ind.id)}).status_code == 201
    assert analyst.post(_link_url(tenant, world.shared_camp), json={"indicator_id": str(world.shared_ind.id)}).status_code == 201
    body = analyst.get(_g(tenant)).json()
    kinds = sorted((n["type"], n["label"], n["own"]) for n in body["nodes"])
    assert kinds == sorted([
        ("threat_actor", "APT-G", True), ("campaign", "Op G", True), ("campaign", "Shared Op", False),
        ("indicator", "g.example", True), ("indicator", "198.51.100.20", False),
    ])
    edges = {(e["type"], e["source"], e["target"]) for e in body["edges"]}
    assert ("attributed-to", str(world.camp.id), str(world.actor.id)) in edges
    assert ("indicates", str(world.ind.id), str(world.camp.id)) in edges
    assert ("indicates", str(world.shared_ind.id), str(world.shared_camp.id)) in edges
    assert body["indicators_total"] == 2 and body["truncated"] is False


def test_unlinked_indicators_are_not_nodes(analyst, tenant, world):
    body = analyst.get(_g(tenant)).json()
    assert all(n["type"] != "indicator" for n in body["nodes"])


def test_link_is_idempotent_and_unlink_works(analyst, db_session, tenant, world):
    url, payload = _link_url(tenant, world.camp), {"indicator_id": str(world.ind.id)}
    first, second = analyst.post(url, json=payload), analyst.post(url, json=payload)
    assert (first.status_code, first.json()["created"]) == (201, True)
    assert (second.status_code, second.json()["created"]) == (200, False)
    assert db_session.query(CampaignIndicator).count() == 1
    assert analyst.delete(f"{url}/{world.ind.id}").status_code == 204
    assert analyst.delete(f"{url}/{world.ind.id}").status_code == 404
    assert db_session.query(CampaignIndicator).count() == 0


def test_cannot_link_what_the_tenant_cannot_see(analyst, db_session, tenant, world):
    other = Tenant(name="O", slug="o-graph")
    db_session.add(other)
    db_session.flush()
    foreign_ind = Indicator(tenant_id=other.id, ioc_type="ip", value="198.51.100.99")
    foreign_camp = Campaign(tenant_id=other.id, name="Foreign Op")
    db_session.add_all([foreign_ind, foreign_camp])
    db_session.flush()
    assert analyst.post(_link_url(tenant, world.camp), json={"indicator_id": str(foreign_ind.id)}).status_code == 404
    assert analyst.post(_link_url(tenant, foreign_camp), json={"indicator_id": str(world.ind.id)}).status_code == 404
    assert analyst.post(_link_url(tenant, world.camp), json={"indicator_id": str(uuid.uuid4())}).status_code == 404
    assert db_session.query(CampaignIndicator).count() == 0


def test_other_tenants_links_and_nodes_never_show(analyst, db_session, tenant, world):
    other = Tenant(name="O2", slug="o2-graph")
    db_session.add(other)
    db_session.flush()
    foreign_actor = ThreatActor(tenant_id=other.id, name="Foreign Actor")
    db_session.add(foreign_actor)
    db_session.flush()
    # the other tenant linked its own indicator to the SHARED campaign
    theirs = Indicator(tenant_id=other.id, ioc_type="ip", value="198.51.100.77")
    db_session.add(theirs)
    db_session.flush()
    db_session.add(CampaignIndicator(tenant_id=other.id, campaign_id=world.shared_camp.id, indicator_id=theirs.id))
    db_session.flush()
    text = json.dumps(analyst.get(_g(tenant)).json())
    assert "Foreign Actor" not in text and "198.51.100.77" not in text


def test_roles(db_session, tenant, world):
    payload = {"indicator_id": str(world.ind.id)}
    for role, code in (("viewer", 403), ("api_user", 403), ("analyst", 201)):
        c = _client(db_session, [role], tenant)
        assert c.post(_link_url(tenant, world.camp), json=payload).status_code == code
        db_session.query(CampaignIndicator).delete()
        db_session.flush()
    assert _client(db_session, ["viewer"], tenant).get(_g(tenant)).status_code == 200  # read open to the tenant


def test_deleting_a_campaign_or_indicator_removes_its_links(analyst, db_session, tenant, world):
    analyst.post(_link_url(tenant, world.camp), json={"indicator_id": str(world.ind.id)})
    assert analyst.delete(f"/api/v1/tenants/{tenant.id}/indicators/{world.ind.id}").status_code == 204
    assert db_session.query(CampaignIndicator).count() == 0
    ind2 = Indicator(tenant_id=tenant.id, ioc_type="ip", value="203.0.113.44")
    db_session.add(ind2)
    db_session.flush()
    analyst.post(_link_url(tenant, world.camp), json={"indicator_id": str(ind2.id)})
    assert analyst.delete(f"/api/v1/tenants/{tenant.id}/campaigns/{world.camp.id}").status_code == 204
    assert db_session.query(CampaignIndicator).count() == 0


def test_truncation_flag(analyst, db_session, tenant, world, monkeypatch):
    from app.api.v1.routes import graph as route

    monkeypatch.setattr(route, "MAX_INDICATOR_NODES", 2)
    for i in range(4):
        ind = Indicator(tenant_id=tenant.id, ioc_type="ip", value=f"203.0.113.{i + 1}")
        db_session.add(ind)
        db_session.flush()
        analyst.post(_link_url(tenant, world.camp), json={"indicator_id": str(ind.id)})
    body = analyst.get(_g(tenant)).json()
    assert body["indicators_total"] == 4 and body["truncated"] is True
    assert sum(1 for n in body["nodes"] if n["type"] == "indicator") == 2
    assert all(e["source"] in {n["id"] for n in body["nodes"]} for e in body["edges"])  # no dangling edge


def test_requires_auth():
    c = TestClient(create_app(), raise_server_exceptions=False)
    assert c.get(f"/api/v1/tenants/{uuid.uuid4()}/graph").status_code == 401


# ----- STIX carries the links ---------------------------------------------------------------


def test_stix_round_trip_keeps_indicates(analyst, db_session, tenant, world):
    analyst.post(_link_url(tenant, world.camp), json={"indicator_id": str(world.ind.id)})
    bundle = analyst.get(f"/api/v1/tenants/{tenant.id}/stix/export", params={"own_only": "true"}).json()
    rels = [o for o in bundle["objects"] if o["type"] == "relationship" and o["relationship_type"] == "indicates"]
    assert len(rels) == 1 and rels[0]["source_ref"] == f"indicator--{world.ind.id}"
    other = Tenant(name="Dest", slug="dest-graph")
    db_session.add(other)
    db_session.flush()
    dest = _client(db_session, ["analyst"], other)
    r = dest.post(f"/api/v1/tenants/{other.id}/stix/import", content=json.dumps(bundle)).json()
    assert r["created"]["links"] == 1 and r["skipped_total"] == 0
    link = db_session.query(CampaignIndicator).filter_by(tenant_id=other.id).one()
    assert db_session.get(Indicator, link.indicator_id).tenant_id == other.id
    again = dest.post(f"/api/v1/tenants/{other.id}/stix/import", content=json.dumps(bundle)).json()
    assert again["created"]["links"] == 0 and again["duplicates"]["links"] == 1


def test_stix_import_reports_a_link_to_something_not_imported(analyst, tenant):
    iid, cid = f"indicator--{uuid.uuid4()}", f"campaign--{uuid.uuid4()}"
    doc = {"type": "bundle", "objects": [
        {"type": "campaign", "id": cid, "name": "Only Campaign"},
        {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", "relationship_type": "indicates", "source_ref": iid, "target_ref": cid},
    ]}
    r = analyst.post(f"/api/v1/tenants/{tenant.id}/stix/import", content=json.dumps(doc)).json()
    assert r["created"]["links"] == 0 and r["skipped_total"] == 1
    assert "not imported" in r["skipped"][0]["reason"]


def test_stix_import_can_link_to_existing_shared_campaign(analyst, db_session, tenant):
    db_session.add(Campaign(tenant_id=None, name="Known Shared"))
    db_session.flush()
    iid, cid = f"indicator--{uuid.uuid4()}", f"campaign--{uuid.uuid4()}"
    doc = {"type": "bundle", "objects": [
        {"type": "indicator", "id": iid, "pattern": "[domain-name:value = 'linked.example']", "pattern_type": "stix"},
        {"type": "campaign", "id": cid, "name": "known shared"},
        {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", "relationship_type": "indicates", "source_ref": iid, "target_ref": cid},
    ]}
    r = analyst.post(f"/api/v1/tenants/{tenant.id}/stix/import", content=json.dumps(doc)).json()
    assert r["created"] == {"indicators": 1, "threat_actors": 0, "campaigns": 0, "links": 1}
    assert db_session.query(Campaign).filter_by(name="Known Shared").count() == 1  # no copy of the shared one
