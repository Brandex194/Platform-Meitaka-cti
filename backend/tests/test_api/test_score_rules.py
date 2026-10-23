def test_create_score_rule_with_super_admin_returns_201(super_admin_client, tenant):
    r = super_admin_client.post(
        f"/api/v1/tenants/{tenant.id}/score-rules",
        json={"weights": {"severity": 0.5, "confidence": 0.2, "recency": 0.2, "epss": 0.1}},
    )
    assert r.status_code == 201
    assert r.json()["version"] == 1


def test_create_score_rule_auto_increments_version(super_admin_client, tenant):
    super_admin_client.post(f"/api/v1/tenants/{tenant.id}/score-rules", json={})
    r = super_admin_client.post(f"/api/v1/tenants/{tenant.id}/score-rules", json={})
    assert r.status_code == 201
    assert r.json()["version"] == 2


def test_create_score_rule_with_analyst_returns_403(analyst_client, tenant):
    r = analyst_client.post(
        f"/api/v1/tenants/{tenant.id}/score-rules",
        json={},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"


def test_create_score_rule_with_viewer_returns_403(viewer_client, tenant):
    r = viewer_client.post(f"/api/v1/tenants/{tenant.id}/score-rules", json={})
    assert r.status_code == 403
