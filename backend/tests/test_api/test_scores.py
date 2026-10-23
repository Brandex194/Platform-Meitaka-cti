def test_list_scores_returns_200(analyst_client, tenant):
    r = analyst_client.get(f"/api/v1/tenants/{tenant.id}/scores")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_compute_scores_with_analyst_returns_200(analyst_client, tenant):
    r = analyst_client.post(f"/api/v1/tenants/{tenant.id}/scores/compute")
    assert r.status_code == 200
    assert "scores_computed" in r.json()


def test_compute_scores_with_viewer_returns_403(viewer_client, tenant):
    r = viewer_client.post(f"/api/v1/tenants/{tenant.id}/scores/compute")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"
