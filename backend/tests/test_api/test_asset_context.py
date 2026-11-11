"""Asset §5.2 context: exposure and impact (passo 4, 09/11/2026)."""


def test_create_asset_with_context(tenant_admin_client, tenant):
    r = tenant_admin_client.post(
        f"/api/v1/tenants/{tenant.id}/assets",
        json={"hostname": "web01", "exposure": "internet", "impact": "critical"},
    )
    assert r.status_code == 201
    assert (r.json()["exposure"], r.json()["impact"]) == ("internet", "critical")


def test_asset_without_context_is_unclassified(tenant_admin_client, tenant):
    r = tenant_admin_client.post(f"/api/v1/tenants/{tenant.id}/assets", json={"hostname": "x"})
    assert (r.json()["exposure"], r.json()["impact"]) == (None, None)


def test_invalid_context_rejected(tenant_admin_client, tenant):
    r = tenant_admin_client.post(f"/api/v1/tenants/{tenant.id}/assets", json={"exposure": "cloud"})
    assert r.status_code == 422


def test_patch_changes_only_sent_fields(tenant_admin_client, tenant, asset):
    url = f"/api/v1/tenants/{tenant.id}/assets/{asset.id}"
    r = tenant_admin_client.patch(url, json={"exposure": "dmz"})
    assert r.status_code == 200
    body = r.json()
    assert body["exposure"] == "dmz" and body["impact"] is None and body["hostname"] == asset.hostname
    r = tenant_admin_client.patch(url, json={"exposure": None})
    assert r.json()["exposure"] is None


def test_analyst_cannot_classify(analyst_client, tenant, asset):
    r = analyst_client.patch(f"/api/v1/tenants/{tenant.id}/assets/{asset.id}", json={"impact": "low"})
    assert r.status_code == 403


def test_patch_other_tenant_asset_is_404(tenant_admin_client, db_session, tenant):
    from app.db.models import Asset, Tenant

    other = Tenant(name="Other", slug="other-ctx")
    db_session.add(other)
    db_session.flush()
    foreign = Asset(tenant_id=other.id, hostname="foreign")
    db_session.add(foreign)
    db_session.flush()
    r = tenant_admin_client.patch(f"/api/v1/tenants/{tenant.id}/assets/{foreign.id}", json={"impact": "low"})
    assert r.status_code == 404
