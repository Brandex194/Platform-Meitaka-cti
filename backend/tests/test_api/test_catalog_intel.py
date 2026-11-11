def test_threat_actors_paginated(viewer_client, db_session):
    from app.db.models import ThreatActor

    db_session.add(ThreatActor(name="LockBit", aliases=["LockBit 3.0"]))
    db_session.flush()
    body = viewer_client.get("/api/v1/threat-actors").json()
    assert body["total"] == 1 and body["items"][0]["aliases"] == ["LockBit 3.0"]


def test_campaigns_hide_other_tenants(viewer_client, super_admin_client, db_session, tenant):
    from app.db.models import Campaign, Tenant

    other = Tenant(name="Other", slug="other-camp")
    db_session.add(other)
    db_session.flush()
    db_session.add_all([
        Campaign(name="global", tenant_id=None),
        Campaign(name="mine", tenant_id=tenant.id),
        Campaign(name="theirs", tenant_id=other.id),
    ])
    db_session.flush()

    names = {c["name"] for c in viewer_client.get("/api/v1/campaigns").json()["items"]}
    assert names == {"global", "mine"}
    all_names = {c["name"] for c in super_admin_client.get("/api/v1/campaigns").json()["items"]}
    assert all_names == {"global", "mine", "theirs"}


def test_catalog_requires_auth(client_no_auth):
    assert client_no_auth.get("/api/v1/threat-actors").status_code == 401
    assert client_no_auth.get("/api/v1/campaigns").status_code == 401


def test_indicators_global_and_own_only(viewer_client, db_session, tenant):
    from app.db.models import Indicator, Tenant

    other = Tenant(name="Other", slug="other-ioc")
    db_session.add(other)
    db_session.flush()
    db_session.add_all([
        Indicator(ioc_type="ip", value="203.0.113.10", tenant_id=None),
        Indicator(ioc_type="domain", value="mine.example", tenant_id=tenant.id),
        Indicator(ioc_type="domain", value="theirs.example", tenant_id=other.id),
    ])
    db_session.flush()

    base = f"/api/v1/tenants/{tenant.id}/indicators"
    values = {i["value"] for i in viewer_client.get(base).json()["items"]}
    assert values == {"203.0.113.10", "mine.example"}
    only_ip = viewer_client.get(f"{base}?ioc_type=ip").json()
    assert only_ip["total"] == 1


def test_observations_filtered_by_event_type(viewer_client, db_session, tenant):
    from app.db.models import Observation

    db_session.add_all([
        Observation(tenant_id=tenant.id, event_type="darkweb", payload={"title": "x"}),
        Observation(tenant_id=tenant.id, event_type="cve", payload={}),
    ])
    db_session.flush()
    body = viewer_client.get(f"/api/v1/tenants/{tenant.id}/observations?event_type=darkweb").json()
    assert body["total"] == 1 and body["items"][0]["payload"] == {"title": "x"}


def test_correlation_events_active_filter(viewer_client, db_session, tenant):
    from app.db.models import CorrelationEvent

    db_session.add_all([
        CorrelationEvent(tenant_id=tenant.id, rule_name="a", is_active=True),
        CorrelationEvent(tenant_id=tenant.id, rule_name="b", is_active=False),
    ])
    db_session.flush()
    base = f"/api/v1/tenants/{tenant.id}/correlation-events"
    assert viewer_client.get(base).json()["total"] == 2
    active = viewer_client.get(f"{base}?active=true").json()
    assert [e["rule_name"] for e in active["items"]] == ["a"]


def test_identities(analyst_client, viewer_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}/identities"
    r = analyst_client.post(base, json={"email": "mario.rossi@example.com", "name": "Mario Rossi"})
    assert r.status_code == 201
    assert analyst_client.post(base, json={"email": "not-an-email"}).status_code == 422
    assert viewer_client.post(base, json={"name": "x"}).status_code == 403
    assert viewer_client.get(base).json()["total"] == 1
