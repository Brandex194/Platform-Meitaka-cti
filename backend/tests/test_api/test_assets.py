def test_list_assets_returns_200(analyst_client, tenant):
    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/assets")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_create_asset_with_tenant_admin_returns_201(super_admin_client, tenant):
    r = super_admin_client.post(
        f"/api/v1/tenants/{tenant.id}/assets",
        json={"hostname": "web-01", "ip": "10.0.0.1"},
    )
    assert r.status_code == 201
    assert r.json()["hostname"] == "web-01"


def test_create_asset_with_viewer_returns_403(viewer_client, tenant):
    r = viewer_client.post(
        f"/api/v1/tenants/{tenant.id}/assets",
        json={"hostname": "web-02"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"


def test_create_asset_with_analyst_returns_403(analyst_client, tenant):
    r = analyst_client.post(
        f"/api/v1/tenants/{tenant.id}/assets",
        json={"hostname": "web-03"},
    )
    assert r.status_code == 403


def test_unauthenticated_no_override_returns_401(client_no_auth, tenant):
    r = client_no_auth.get(f"/api/v1/tenants/{tenant.id}/assets")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHORIZED"


def test_cross_tenant_returns_403(client_tenant_a, tenant_b_id):
    """Token for tenant A cannot access tenant B's assets."""
    r = client_tenant_a.get(f"/api/v1/tenants/{tenant_b_id}/assets")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"
