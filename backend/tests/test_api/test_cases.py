def test_case_crud(analyst_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}/cases"
    r = analyst_client.post(base, json={"title": "Phishing su HR", "severity": "high"})
    assert r.status_code == 201
    case = r.json()
    assert case["status"] == "open" and case["severity"] == "high"

    r = analyst_client.patch(f"{base}/{case['id']}", json={"status": "closed"})
    assert r.status_code == 200 and r.json()["status"] == "closed"

    listing = analyst_client.get(base).json()
    assert listing["total"] == 1

    assert analyst_client.delete(f"{base}/{case['id']}").status_code == 204
    assert analyst_client.get(base).json()["total"] == 0


def test_viewer_can_read_but_not_write(viewer_client, tenant):
    base = f"/api/v1/tenants/{tenant.id}/cases"
    assert viewer_client.get(base).status_code == 200
    assert viewer_client.post(base, json={"title": "x"}).status_code == 403


def test_invalid_severity_rejected(analyst_client, tenant):
    r = analyst_client.post(f"/api/v1/tenants/{tenant.id}/cases", json={"title": "x", "severity": "urgent"})
    assert r.status_code == 422


def test_case_of_other_tenant_not_found(analyst_client, db_session, tenant):
    from app.db.models import Case, Tenant

    other = Tenant(name="Other", slug="other-c")
    db_session.add(other)
    db_session.flush()
    foreign = Case(tenant_id=other.id, title="secret")
    db_session.add(foreign)
    db_session.flush()
    r = analyst_client.patch(f"/api/v1/tenants/{tenant.id}/cases/{foreign.id}", json={"status": "closed"})
    assert r.status_code == 404
