def test_list_exposure_matches_returns_200(analyst_client, tenant):
    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/exposure-matches")
    assert r.status_code == 200
    assert {"items", "total", "page", "size"} <= r.json().keys()


def test_patch_exposure_with_analyst_returns_200(analyst_client, tenant, exposure_match):
    r = analyst_client.patch(
        f"/api/v1/tenants/{tenant.id}/exposure-matches/{exposure_match.id}",
        json={"status": "resolved"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"


def test_patch_exposure_with_viewer_returns_403(viewer_client, tenant, exposure_match):
    r = viewer_client.patch(
        f"/api/v1/tenants/{tenant.id}/exposure-matches/{exposure_match.id}",
        json={"status": "resolved"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"


def test_patch_resolved_deactivates_corr_event(analyst_client, tenant, db_session, exposure_match_with_event):
    match, event = exposure_match_with_event
    r = analyst_client.patch(
        f"/api/v1/tenants/{tenant.id}/exposure-matches/{match.id}",
        json={"status": "resolved"},
    )
    assert r.status_code == 200
    db_session.refresh(event)
    assert event.is_active is False
    assert event.resolved_at is not None
