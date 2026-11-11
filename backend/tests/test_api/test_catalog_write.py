"""Inserting and editing threat actors, campaigns and observables by hand (passo 6)."""
import pytest

from app.db.models import Campaign, Indicator, Tenant, ThreatActor


@pytest.fixture
def other_tenant(db_session):
    t = Tenant(name="Other", slug="other-write")
    db_session.add(t)
    db_session.flush()
    return t


# ---- threat actors ----


def test_actor_crud(analyst_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}/threat-actors"
    r = analyst_client.post(
        base, json={"name": "  FIN7 ", "aliases": ["Carbanak", " ", "Navigator Group"], "description": "financial"}
    )
    assert r.status_code == 201
    actor = r.json()
    assert actor["name"] == "FIN7"
    assert actor["tenant_id"] == str(tenant.id)
    assert actor["aliases"] == ["Carbanak", "Navigator Group"]

    r = analyst_client.patch(f"{base}/{actor['id']}", json={"description": "updated"})
    assert r.status_code == 200 and r.json()["description"] == "updated"
    assert r.json()["name"] == "FIN7"

    listing = analyst_client.get("/api/v1/threat-actors").json()
    assert [a["name"] for a in listing["items"]] == ["FIN7"]

    assert analyst_client.delete(f"{base}/{actor['id']}").status_code == 204
    assert analyst_client.get("/api/v1/threat-actors").json()["total"] == 0


def test_actor_blank_name_or_long_alias_rejected(analyst_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}/threat-actors"
    assert analyst_client.post(base, json={"name": "   "}).status_code == 422
    assert analyst_client.post(base, json={"name": "x", "aliases": ["a" * 101]}).status_code == 422


def test_viewer_cannot_write_catalog(viewer_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}"
    assert viewer_client.post(f"{base}/threat-actors", json={"name": "x"}).status_code == 403
    assert viewer_client.post(f"{base}/campaigns", json={"name": "x"}).status_code == 403
    assert viewer_client.post(f"{base}/indicators", json={"ioc_type": "ip", "value": "1.2.3.4"}).status_code == 403


def test_actor_list_hides_other_tenants_but_shows_shared(viewer_client, db_session, tenant, other_tenant):
    db_session.add_all([
        ThreatActor(name="shared", tenant_id=None),
        ThreatActor(name="mine", tenant_id=tenant.id),
        ThreatActor(name="theirs", tenant_id=other_tenant.id),
    ])
    db_session.flush()
    names = {a["name"] for a in viewer_client.get("/api/v1/threat-actors").json()["items"]}
    assert names == {"shared", "mine"}


def test_shared_and_foreign_actors_are_not_editable(analyst_client, db_session, tenant, other_tenant):
    shared = ThreatActor(name="shared", tenant_id=None)
    foreign = ThreatActor(name="theirs", tenant_id=other_tenant.id)
    db_session.add_all([shared, foreign])
    db_session.flush()
    base = f"/api/v1/tenants/{tenant.id}/threat-actors"
    for actor in (shared, foreign):
        assert analyst_client.patch(f"{base}/{actor.id}", json={"name": "x"}).status_code == 404
        assert analyst_client.delete(f"{base}/{actor.id}").status_code == 404


# ---- campaigns ----


def test_campaign_crud_with_shared_actor(analyst_client, db_session, tenant):
    shared = ThreatActor(name="shared", tenant_id=None)
    db_session.add(shared)
    db_session.flush()
    base = f"/api/v1/tenants/{tenant.id}/campaigns"

    r = analyst_client.post(base, json={"name": "Operazione X", "threat_actor_id": str(shared.id)})
    assert r.status_code == 201
    camp = r.json()
    assert camp["tenant_id"] == str(tenant.id) and camp["threat_actor_id"] == str(shared.id)

    r = analyst_client.patch(f"{base}/{camp['id']}", json={"threat_actor_id": None, "description": "d"})
    assert r.status_code == 200
    assert r.json()["threat_actor_id"] is None and r.json()["description"] == "d"

    assert analyst_client.delete(f"{base}/{camp['id']}").status_code == 204
    assert analyst_client.get("/api/v1/campaigns").json()["total"] == 0


def test_campaign_cannot_use_another_tenants_actor(analyst_client, db_session, tenant, other_tenant):
    foreign = ThreatActor(name="theirs", tenant_id=other_tenant.id)
    db_session.add(foreign)
    db_session.flush()
    base = f"/api/v1/tenants/{tenant.id}/campaigns"
    r = analyst_client.post(base, json={"name": "c", "threat_actor_id": str(foreign.id)})
    assert r.status_code == 404
    mine = analyst_client.post(base, json={"name": "c"}).json()
    r = analyst_client.patch(f"{base}/{mine['id']}", json={"threat_actor_id": str(foreign.id)})
    assert r.status_code == 404


def test_campaign_of_other_tenant_or_shared_is_not_editable(analyst_client, db_session, tenant, other_tenant):
    shared = Campaign(name="shared", tenant_id=None)
    foreign = Campaign(name="theirs", tenant_id=other_tenant.id)
    db_session.add_all([shared, foreign])
    db_session.flush()
    base = f"/api/v1/tenants/{tenant.id}/campaigns"
    for camp in (shared, foreign):
        assert analyst_client.patch(f"{base}/{camp.id}", json={"name": "x"}).status_code == 404
        assert analyst_client.delete(f"{base}/{camp.id}").status_code == 404


def test_deleting_an_actor_keeps_its_campaigns(analyst_client, tenant):
    actors = f"/api/v1/tenants/{tenant.id}/threat-actors"
    camps = f"/api/v1/tenants/{tenant.id}/campaigns"
    actor = analyst_client.post(actors, json={"name": "a"}).json()
    camp = analyst_client.post(camps, json={"name": "c", "threat_actor_id": actor["id"]}).json()
    assert analyst_client.delete(f"{actors}/{actor['id']}").status_code == 204
    items = analyst_client.get("/api/v1/campaigns").json()["items"]
    assert [c["id"] for c in items] == [camp["id"]]
    assert items[0]["threat_actor_id"] is None


# ---- observables ----


def test_indicator_create_list_delete(analyst_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}/indicators"
    r = analyst_client.post(base, json={"ioc_type": "domain", "value": " Evil.Example ", "confidence": 0.8})
    assert r.status_code == 201
    ind = r.json()
    assert ind["value"] == "evil.example" and ind["tenant_id"] == str(tenant.id)

    assert analyst_client.get(f"{base}?ioc_type=domain").json()["total"] == 1
    assert analyst_client.delete(f"{base}/{ind['id']}").status_code == 204
    assert analyst_client.get(base).json()["total"] == 0


def test_indicator_duplicate_is_conflict_case_insensitive_for_domains(analyst_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}/indicators"
    assert analyst_client.post(base, json={"ioc_type": "domain", "value": "evil.example"}).status_code == 201
    assert analyst_client.post(base, json={"ioc_type": "domain", "value": "EVIL.example"}).status_code == 409
    # same text, different type: not a duplicate
    assert analyst_client.post(base, json={"ioc_type": "url", "value": "evil.example"}).status_code == 201


def test_indicator_duplicate_only_within_the_tenant(analyst_client, db_session, tenant, other_tenant):
    db_session.add(Indicator(tenant_id=other_tenant.id, ioc_type="ip", value="203.0.113.7"))
    db_session.flush()
    base = f"/api/v1/tenants/{tenant.id}/indicators"
    assert analyst_client.post(base, json={"ioc_type": "ip", "value": "203.0.113.7"}).status_code == 201


@pytest.mark.parametrize(
    "body",
    [
        {"ioc_type": "banana", "value": "x"},
        {"ioc_type": "ip", "value": "   "},
        {"ioc_type": "ip", "value": "1.2.3.4", "confidence": 1.5},
        {"ioc_type": "ip", "value": "1.2.3.4", "confidence": -0.1},
    ],
)
def test_indicator_invalid_input_rejected(analyst_client, tenant, body):
    assert analyst_client.post(f"/api/v1/tenants/{tenant.id}/indicators", json=body).status_code == 422


def test_shared_and_foreign_indicators_cannot_be_deleted(analyst_client, db_session, tenant, other_tenant):
    shared = Indicator(tenant_id=None, ioc_type="ip", value="198.51.100.1")
    foreign = Indicator(tenant_id=other_tenant.id, ioc_type="ip", value="198.51.100.2")
    db_session.add_all([shared, foreign])
    db_session.flush()
    base = f"/api/v1/tenants/{tenant.id}/indicators"
    for ind in (shared, foreign):
        assert analyst_client.delete(f"{base}/{ind.id}").status_code == 404
