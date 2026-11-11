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


def test_api_rules_are_marked_as_section_5(super_admin_client, tenant):
    r = super_admin_client.post(
        f"/api/v1/tenants/{tenant.id}/score-rules",
        json={"parameters": {"default_exposure": 0.5, "alpha": {"ioc_asset": 0.6}}},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["parameters"]["formula"] == "architettura-5-moltiplicativa-v3"  # the current default
    assert body["parameters"]["default_exposure"] == 0.5
    assert body["weights"] == {"severity": 0.0, "confidence": 0.3, "recency": 0.3, "epss": 0.4}


def test_rule_can_pin_the_additive_formula(super_admin_client, tenant):
    url = f"/api/v1/tenants/{tenant.id}/score-rules"
    r = super_admin_client.post(url, json={"parameters": {"formula": "architettura-5"}})
    assert r.status_code == 201
    assert r.json()["weights"] == {"severity": 0.5, "confidence": 0.3, "recency": 0.2, "epss": 0.0}
    patched = super_admin_client.patch(f"{url}/{r.json()['id']}", json={"parameters": {"default_impact": 0.6}})
    assert patched.json()["parameters"]["formula"] == "architettura-5"  # kept
    assert super_admin_client.post(url, json={"parameters": {"formula": "nuova"}}).status_code == 422


def test_unknown_or_out_of_range_parameters_rejected(super_admin_client, tenant):
    url = f"/api/v1/tenants/{tenant.id}/score-rules"
    assert super_admin_client.post(url, json={"parameters": {"bogus": 1}}).status_code == 422
    assert super_admin_client.post(url, json={"parameters": {"default_impact": 3}}).status_code == 422
    assert super_admin_client.post(url, json={"parameters": {"alpha": {"ioc_asset": "high"}}}).status_code == 422


def test_thresholds_must_be_ordered(super_admin_client, tenant):
    url = f"/api/v1/tenants/{tenant.id}/score-rules"
    assert super_admin_client.post(url, json={"thresholds": {"low": 0.5, "medium": 0.4, "high": 0.7}}).status_code == 422
    assert super_admin_client.post(url, json={"thresholds": {"low": 0.2, "medium": 0.4, "high": 0.7}}).status_code == 201


def test_rule_can_pin_the_previous_multiplicative_formula(super_admin_client, tenant):
    url = f"/api/v1/tenants/{tenant.id}/score-rules"
    r = super_admin_client.post(url, json={"parameters": {"formula": "architettura-5-moltiplicativa"}})
    assert r.status_code == 201
    assert r.json()["parameters"]["formula"] == "architettura-5-moltiplicativa"
