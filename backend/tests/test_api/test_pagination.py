def _make_assets(db_session, tenant, n):
    from app.db.models import Asset

    for i in range(n):
        db_session.add(Asset(tenant_id=tenant.id, hostname=f"host-{i:02d}"))
    db_session.flush()


def test_pages_split_results(analyst_client, db_session, tenant):
    _make_assets(db_session, tenant, 5)
    p1 = analyst_client.get(f"/api/v1/tenants/{tenant.id}/assets?page=1&size=2").json()
    p3 = analyst_client.get(f"/api/v1/tenants/{tenant.id}/assets?page=3&size=2").json()
    assert (p1["total"], p1["page"], p1["size"], len(p1["items"])) == (5, 1, 2, 2)
    assert len(p3["items"]) == 1
    ids = {a["id"] for a in p1["items"]} | {a["id"] for a in p3["items"]}
    assert len(ids) == 3


def test_page_size_is_capped(analyst_client, tenant):
    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/assets?size=1000")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_page_must_be_positive(analyst_client, tenant):
    assert analyst_client.get(f"/api/v1/tenants/{tenant.id}/assets?page=0").status_code == 422
