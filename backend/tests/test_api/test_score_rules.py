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


def test_patch_score_rule_with_super_admin_returns_200(super_admin_client, tenant):
    # Create first, then patch
    r = super_admin_client.post(f"/api/v1/tenants/{tenant.id}/score-rules", json={})
    assert r.status_code == 201
    rule_id = r.json()["id"]

    r2 = super_admin_client.patch(
        f"/api/v1/tenants/{tenant.id}/score-rules/{rule_id}",
        json={"weights": {"severity": 0.6, "confidence": 0.2, "recency": 0.1, "epss": 0.1}},
    )
    assert r2.status_code == 200
    assert r2.json()["version"] == 2


def test_patch_score_rule_with_analyst_returns_403(analyst_client, db_session, tenant):
    from app.db.models import ScoreRule
    rule = ScoreRule(tenant_id=tenant.id, version=1)
    db_session.add(rule)
    db_session.flush()

    r = analyst_client.patch(
        f"/api/v1/tenants/{tenant.id}/score-rules/{rule.id}",
        json={"weights": {"severity": 0.5, "confidence": 0.2, "recency": 0.2, "epss": 0.1}},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"
