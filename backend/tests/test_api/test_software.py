import uuid

CPE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_create_and_list_software(tenant_admin_client, tenant, asset):
    url = f"/api/v1/tenants/{tenant.id}/assets/{asset.id}/software"
    r = tenant_admin_client.post(url, json={"name": "Apache httpd", "version": "2.4.49", "cpe": CPE})
    assert r.status_code == 201
    assert r.json()["cpe"] == CPE
    body = tenant_admin_client.get(url).json()
    assert body["total"] == 1 and body["items"][0]["name"] == "Apache httpd"


def test_invalid_cpe_rejected(tenant_admin_client, tenant, asset):
    r = tenant_admin_client.post(
        f"/api/v1/tenants/{tenant.id}/assets/{asset.id}/software",
        json={"name": "x", "cpe": "apache 2.4.49"},
    )
    assert r.status_code == 422


def test_analyst_cannot_add_software(analyst_client, tenant, asset):
    r = analyst_client.post(
        f"/api/v1/tenants/{tenant.id}/assets/{asset.id}/software", json={"name": "x"}
    )
    assert r.status_code == 403


def test_unknown_asset_returns_404(tenant_admin_client, tenant):
    r = tenant_admin_client.post(
        f"/api/v1/tenants/{tenant.id}/assets/{uuid.uuid4()}/software", json={"name": "x"}
    )
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"


def test_asset_of_other_tenant_returns_404(tenant_admin_client, db_session, tenant):
    """Even with the RLS bypassed in tests, the explicit tenant filter hides other tenants' assets."""
    from app.db.models import Asset, Tenant

    other = Tenant(name="Other", slug="other")
    db_session.add(other)
    db_session.flush()
    foreign = Asset(tenant_id=other.id, hostname="foreign")
    db_session.add(foreign)
    db_session.flush()
    r = tenant_admin_client.get(f"/api/v1/tenants/{tenant.id}/assets/{foreign.id}/software")
    assert r.status_code == 404


def test_delete_software(tenant_admin_client, tenant, software):
    url = f"/api/v1/tenants/{tenant.id}/assets/{software.asset_id}/software/{software.id}"
    assert tenant_admin_client.delete(url).status_code == 204
    assert tenant_admin_client.delete(url).status_code == 404
