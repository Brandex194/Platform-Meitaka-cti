import uuid


def test_dashboard_returns_200(analyst_client):
    r = analyst_client.get("/api/v1/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert "open_cases" in body
    assert "top_assets" in body


def test_open_cases_from_cases_table(analyst_client, db_session, tenant):
    from app.db.models import Case

    db_session.add(Case(tenant_id=tenant.id, title="Test Case", created_by=uuid.uuid4()))
    db_session.flush()

    r = analyst_client.get("/api/v1/dashboard")
    assert r.status_code == 200
    assert r.json()["open_cases"] >= 1


def test_dashboard_top_assets_limited_to_5(analyst_client, db_session, tenant):
    from app.db.models import Asset, Score

    # Add 6 assets with scores
    for i in range(6):
        asset = Asset(tenant_id=tenant.id, hostname=f"host-{i}")
        db_session.add(asset)
        db_session.flush()
        db_session.add(Score(
            tenant_id=tenant.id,
            asset_id=asset.id,
            score_type="asset",
            value=float(i) * 0.1,
            level="low",
        ))
    db_session.flush()

    r = analyst_client.get("/api/v1/dashboard")
    assert r.status_code == 200
    assert len(r.json()["top_assets"]) <= 5
