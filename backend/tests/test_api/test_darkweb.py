import hashlib
import uuid

from sqlalchemy import select

from app.db.models import Identity, Leak, Observation


def _url(tenant, tail):
    return f"/api/v1/tenants/{tenant.id}/darkweb/{tail}"


def test_create_and_list_finding(analyst_client, tenant):
    r = analyst_client.post(
        _url(tenant, "findings"),
        json={"source": " forum.onion ", "context": "credentials for sale", "severity": "high"},
    )
    assert r.status_code == 201
    assert r.json()["event_type"] == "darkweb"
    assert r.json()["payload"] == {
        "source": "forum.onion", "context": "credentials for sale", "severity": "high", "status": "new",
    }
    listed = analyst_client.get(f"/api/v1/tenants/{tenant.id}/observations?event_type=darkweb").json()
    assert listed["total"] == 1


def test_finding_validation_and_unknown_asset(analyst_client, tenant):
    assert analyst_client.post(_url(tenant, "findings"), json={"source": "", "context": "x"}).status_code == 422
    assert analyst_client.post(
        _url(tenant, "findings"), json={"source": "s", "context": "c", "severity": "urgent"}
    ).status_code == 422
    r = analyst_client.post(
        _url(tenant, "findings"), json={"source": "s", "context": "c", "asset_id": str(uuid.uuid4())}
    )
    assert r.status_code == 404


def test_viewer_cannot_write(viewer_client, tenant):
    assert viewer_client.post(_url(tenant, "findings"), json={"source": "s", "context": "c"}).status_code == 403
    assert viewer_client.post(_url(tenant, "leaks"), json={"email": "a@b.co", "breach_name": "X"}).status_code == 403


def test_change_status_and_delete_finding(analyst_client, tenant):
    fid = analyst_client.post(_url(tenant, "findings"), json={"source": "s", "context": "c"}).json()["id"]
    r = analyst_client.patch(_url(tenant, f"findings/{fid}"), json={"status": "reviewed"})
    assert r.status_code == 200 and r.json()["payload"]["status"] == "reviewed"
    assert r.json()["payload"]["source"] == "s"
    assert analyst_client.patch(_url(tenant, f"findings/{fid}"), json={"status": "x"}).status_code == 422
    assert analyst_client.delete(_url(tenant, f"findings/{fid}")).status_code == 204
    assert analyst_client.delete(_url(tenant, f"findings/{fid}")).status_code == 404


def test_only_darkweb_observations_are_touched(analyst_client, tenant, db_session):
    other = Observation(tenant_id=tenant.id, event_type="scan", payload={})
    db_session.add(other)
    db_session.flush()
    assert analyst_client.delete(_url(tenant, f"findings/{other.id}")).status_code == 404


def test_leak_is_stored_hashed_and_deduplicated(analyst_client, tenant, db_session):
    body = {"email": " Mario.Rossi@Example.com ", "breach_name": "BigBreach", "pwn_count": 1000}
    r = analyst_client.post(_url(tenant, "leaks"), json=body)
    assert r.status_code == 201
    expected = hashlib.sha256(b"mario.rossi@example.com").hexdigest()
    assert r.json()["email_hash"] == expected
    assert "mario" not in r.text.lower()
    assert analyst_client.post(_url(tenant, "leaks"), json=body).status_code == 409
    stored = db_session.execute(select(Leak)).scalars().all()
    assert [x.email_hash for x in stored] == [expected]
    assert analyst_client.get(_url(tenant, "leaks")).json()["total"] == 1


def test_recorded_leak_matches_identity_in_correlation(analyst_client, tenant, db_session):
    from app.correlation.rules import correlate_leak_identity

    db_session.add(Identity(tenant_id=tenant.id, email="Mario.Rossi@example.com", name="Mario"))
    db_session.flush()
    analyst_client.post(_url(tenant, "leaks"), json={"email": "mario.rossi@example.com", "breach_name": "B"})
    assert len(correlate_leak_identity(db_session, tenant.id)) == 1


def test_delete_leak(analyst_client, tenant):
    lid = analyst_client.post(_url(tenant, "leaks"), json={"email": "a@b.co", "breach_name": "B"}).json()["id"]
    assert analyst_client.delete(_url(tenant, f"leaks/{lid}")).status_code == 204
    assert analyst_client.delete(_url(tenant, f"leaks/{lid}")).status_code == 404


def test_bad_email_rejected(analyst_client, tenant):
    assert analyst_client.post(_url(tenant, "leaks"), json={"email": "nope", "breach_name": "B"}).status_code == 422
