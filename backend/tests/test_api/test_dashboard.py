import uuid
from datetime import UTC, datetime, timedelta


def test_dashboard_returns_contract(analyst_client, tenant):
    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert body["open_cases"] == 0
    assert body["critical_scores"] == 0
    assert body["active_exposures"] == 0
    assert body["recent_events"] == []
    assert [x["level"] for x in body["scores_by_level"]] == ["critical", "high", "medium", "low"]


def test_open_cases_counts_only_open(analyst_client, db_session, tenant):
    from app.db.models import Case

    db_session.add(Case(tenant_id=tenant.id, title="Open", created_by=uuid.uuid4()))
    db_session.add(Case(tenant_id=tenant.id, title="Closed", status="closed"))
    db_session.flush()

    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/dashboard")
    assert r.json()["open_cases"] == 1


def test_levels_use_latest_score_per_asset(analyst_client, db_session, tenant, asset):
    """An asset that was critical yesterday and is low now counts as low, not critical."""
    from app.db.models import Score

    now = datetime.now(UTC)
    db_session.add(Score(tenant_id=tenant.id, asset_id=asset.id, score_type="asset",
                         value=0.95, level="critical", computed_at=now - timedelta(days=1)))
    db_session.add(Score(tenant_id=tenant.id, asset_id=asset.id, score_type="asset",
                         value=0.1, level="low", computed_at=now))
    db_session.flush()

    body = analyst_client.get(f"/api/v1/tenants/{tenant.id}/dashboard").json()
    assert body["critical_scores"] == 0
    counts = {x["level"]: x["count"] for x in body["scores_by_level"]}
    assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 1}


def test_active_exposures_and_recent_events(analyst_client, db_session, tenant, exposure_match_with_event):
    from app.db.models import ExposureMatch

    db_session.add(ExposureMatch(tenant_id=tenant.id, status="resolved"))
    db_session.flush()

    body = analyst_client.get(f"/api/v1/tenants/{tenant.id}/dashboard").json()
    assert body["active_exposures"] == 1
    assert len(body["recent_events"]) == 1
    assert body["recent_events"][0]["rule_name"] == "test-rule"


def test_dashboard_requires_auth(client_no_auth, tenant):
    r = client_no_auth.get(f"/api/v1/tenants/{tenant.id}/dashboard")
    assert r.status_code == 401


def test_dashboard_cross_tenant_forbidden(client_tenant_a, tenant_b_id):
    r = client_tenant_a.get(f"/api/v1/tenants/{tenant_b_id}/dashboard")
    assert r.status_code == 403
