def test_list_scores_returns_200(analyst_client, tenant):
    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/scores")
    assert r.status_code == 200
    assert {"items", "total", "page", "size"} <= r.json().keys()


def test_compute_scores_with_analyst_returns_200(analyst_client, tenant):
    r = analyst_client.post(f"/api/v1/tenants/{tenant.id}/scores/compute")
    assert r.status_code == 200
    assert "scores_computed" in r.json()


def test_compute_scores_with_viewer_returns_403(viewer_client, tenant):
    r = viewer_client.post(f"/api/v1/tenants/{tenant.id}/scores/compute")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"


def test_score_explanation_endpoint(analyst_client, tenant, asset):
    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/assets/{asset.id}/score-explanation")
    assert r.status_code == 200
    body = r.json()
    assert body["asset_id"] == str(asset.id)
    assert {"formula", "findings", "total", "level", "thresholds", "context_factor"} <= body.keys()


def test_score_explanation_unknown_asset_404(analyst_client, tenant):
    import uuid

    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/assets/{uuid.uuid4()}/score-explanation")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "NOT_FOUND"
