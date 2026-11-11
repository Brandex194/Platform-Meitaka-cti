"""Management (passo 8): API keys, audit log, tenants, API-key authentication."""
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.v1.deps import get_admin_db, get_scoped_db
from app.auth import jwks
from app.auth.api_keys import authenticate_key, generate_key, hash_key, key_status
from app.auth.jwks import decode_token
from app.db.models import ApiKey, AuditLog, Tenant
from app.db.session import get_db
from app.main import create_app


def _client(db_session, roles, tenant, sub=None):
    app = create_app()
    user_id = sub or str(uuid.uuid4())
    app.dependency_overrides[decode_token] = lambda: {
        "sub": user_id, "roles": roles, "tenant_id": str(tenant.id),
    }
    for dep in (get_scoped_db, get_db, get_admin_db):
        app.dependency_overrides[dep] = lambda: db_session
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def admin(db_session, tenant):
    return _client(db_session, ["tenant_admin"], tenant)


@pytest.fixture
def root(db_session, tenant):
    return _client(db_session, ["super_admin"], tenant)


def _keys(t):
    return f"/api/v1/tenants/{t.id}/api-keys"


# ----- key helpers --------------------------------------------------------


def test_generate_key_shape_and_hash():
    raw, prefix, digest = generate_key()
    assert raw.startswith(prefix + "_") and prefix.startswith("mk_")
    assert digest == hash_key(raw) and len(digest) == 64
    assert generate_key()[0] != raw


def test_key_status_rules():
    now = datetime.now(UTC)
    k = ApiKey(name="k", prefix="mk_x", key_hash="h")
    assert key_status(k, now) == "active"
    k.expires_at = now - timedelta(seconds=1)
    assert key_status(k, now) == "expired"
    k.revoked_at = now
    assert key_status(k, now) == "revoked"  # revoked wins over expired


def test_authenticate_key_valid_unknown_expired_revoked(db_session, tenant):
    raw, prefix, digest = generate_key()
    k = ApiKey(tenant_id=tenant.id, name="ci", prefix=prefix, key_hash=digest)
    db_session.add(k)
    db_session.flush()
    payload = authenticate_key(db_session, raw)
    assert payload["tenant_id"] == str(tenant.id) and payload["roles"] == ["api_user"]
    assert k.last_used_at is not None
    assert authenticate_key(db_session, raw + "x") is None
    assert authenticate_key(db_session, "not-a-key") is None
    k.expires_at = datetime.now(UTC) - timedelta(days=1)
    assert authenticate_key(db_session, raw) is None
    k.expires_at = None
    k.revoked_at = datetime.now(UTC)
    assert authenticate_key(db_session, raw) is None


# ----- API key routes ----------------------------------------------------


def test_create_returns_key_once_and_stores_only_hash(admin, db_session, tenant):
    r = admin.post(_keys(tenant), json={"name": "  SIEM export ", "expires_in_days": 30})
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "SIEM export" and body["status"] == "active" and body["key"].startswith("mk_")
    assert body["expires_at"] is not None
    row = db_session.get(ApiKey, uuid.UUID(body["id"]))
    assert row.key_hash == hash_key(body["key"]) and body["key"] not in (row.key_hash, row.prefix)
    listed = admin.get(_keys(tenant)).json()
    assert listed["total"] == 1 and "key" not in listed["items"][0]
    assert listed["items"][0]["prefix"] == body["prefix"]


def test_create_without_expiry_and_validation(admin, tenant):
    assert admin.post(_keys(tenant), json={"name": "forever"}).json()["expires_at"] is None
    assert admin.post(_keys(tenant), json={"name": "   "}).status_code == 422
    assert admin.post(_keys(tenant), json={"name": "x", "expires_in_days": 0}).status_code == 422
    assert admin.post(_keys(tenant), json={"name": "x", "expires_in_days": 9999}).status_code == 422


def test_revoke_keeps_row(admin, db_session, tenant):
    kid = admin.post(_keys(tenant), json={"name": "old"}).json()["id"]
    assert admin.delete(f"{_keys(tenant)}/{kid}").status_code == 204
    assert admin.delete(f"{_keys(tenant)}/{kid}").status_code == 204  # idempotent
    item = admin.get(_keys(tenant)).json()["items"][0]
    assert item["status"] == "revoked" and item["revoked_at"] is not None
    assert admin.delete(f"{_keys(tenant)}/{uuid.uuid4()}").status_code == 404


def test_keys_visible_only_to_admins(db_session, tenant):
    for role in ("analyst", "viewer", "api_user"):
        c = _client(db_session, [role], tenant)
        assert c.get(_keys(tenant)).status_code == 403
        assert c.post(_keys(tenant), json={"name": "x"}).status_code == 403


def test_keys_of_other_tenant_are_not_listed_or_revoked(admin, db_session, tenant):
    other = Tenant(name="Other", slug="other-t")
    db_session.add(other)
    db_session.flush()
    foreign = ApiKey(tenant_id=other.id, name="theirs", prefix="mk_zz", key_hash="f" * 64)
    db_session.add(foreign)
    db_session.flush()
    assert admin.get(_keys(tenant)).json()["total"] == 0
    assert admin.delete(f"{_keys(tenant)}/{foreign.id}").status_code == 404
    assert foreign.revoked_at is None


# ----- decode_token with X-API-Key ---------------------------------------


def _key_client(db_session, tenant, monkeypatch):
    """Real decode_token and real get_scoped_db; only the DB session and the key lookup are swapped."""
    from app.api.v1 import deps

    raw, prefix, digest = generate_key()
    db_session.add(ApiKey(tenant_id=tenant.id, name="k", prefix=prefix, key_hash=digest))
    db_session.flush()
    monkeypatch.setattr(jwks, "_lookup_api_key", lambda r: authenticate_key(db_session, r))
    monkeypatch.setattr(deps, "get_tenant_scoped_db", lambda tid: iter([db_session]))
    return raw, TestClient(create_app(), raise_server_exceptions=False)


def test_decode_token_accepts_api_key(db_session, tenant, monkeypatch):
    raw, c = _key_client(db_session, tenant, monkeypatch)
    url = f"/api/v1/tenants/{tenant.id}/assets"
    assert c.get(url, headers={"X-API-Key": raw}).status_code == 200
    assert c.get(url, headers={"X-API-Key": raw + "0"}).status_code == 401
    assert c.get(url).status_code == 401
    # api_user is not an admin role: it cannot manage keys
    assert c.get(_keys(tenant), headers={"X-API-Key": raw}).status_code == 403


def test_api_key_cannot_reach_another_tenant(db_session, tenant, monkeypatch):
    raw, c = _key_client(db_session, tenant, monkeypatch)
    r = c.get(f"/api/v1/tenants/{uuid.uuid4()}/assets", headers={"X-API-Key": raw})
    assert r.status_code == 403


def test_revoked_key_stops_working(db_session, tenant, monkeypatch):
    raw, c = _key_client(db_session, tenant, monkeypatch)
    db_session.query(ApiKey).update({"revoked_at": datetime.now(UTC)})
    db_session.flush()
    assert c.get(f"/api/v1/tenants/{tenant.id}/assets", headers={"X-API-Key": raw}).status_code == 401


def test_bearer_wins_over_api_key(monkeypatch):
    monkeypatch.setattr(jwks, "_decode_jwt", lambda raw: {"sub": "u", "from": "jwt"})
    monkeypatch.setattr(jwks, "_lookup_api_key", lambda raw: pytest.fail("key must not be looked up"))

    class Req:
        headers = {"X-API-Key": "mk_whatever"}

    class Cred:
        credentials = "tok"

    assert jwks.decode_token(Req(), Cred())["from"] == "jwt"


def test_decode_token_rejects_bad_key_with_401(monkeypatch):
    monkeypatch.setattr(jwks, "_lookup_api_key", lambda raw: None)

    class Req:
        headers = {"X-API-Key": "mk_bad"}

    with pytest.raises(HTTPException) as exc:
        jwks.decode_token(Req(), None)
    assert exc.value.status_code == 401


# ----- audit log ----------------------------------------------------------


def test_audit_list_filter_and_isolation(admin, db_session, tenant):
    other = Tenant(name="Other", slug="other-a")
    db_session.add(other)
    db_session.flush()
    now = datetime.now(UTC)
    db_session.add_all([
        AuditLog(tenant_id=tenant.id, action="POST /x/cases", status_code=201, ip="10.0.0.1", created_at=now),
        AuditLog(tenant_id=tenant.id, action="DELETE /x/assets", status_code=204, created_at=now - timedelta(minutes=1)),
        AuditLog(tenant_id=tenant.id, action="PATCH /x/100%_done", created_at=now - timedelta(minutes=2)),
        AuditLog(tenant_id=other.id, action="POST /secret", created_at=now),
    ])
    db_session.flush()
    url = f"/api/v1/tenants/{tenant.id}/audit-logs"
    body = admin.get(url).json()
    assert body["total"] == 3
    assert [i["action"] for i in body["items"]][:2] == ["POST /x/cases", "DELETE /x/assets"]
    assert body["items"][0]["ip"] == "10.0.0.1" and body["items"][0]["status_code"] == 201
    assert admin.get(url, params={"q": "assets"}).json()["total"] == 1
    assert admin.get(url, params={"q": "%"}).json()["total"] == 1  # wildcard characters are literal
    assert admin.get(url, params={"q": "secret"}).json()["total"] == 0


def test_audit_admin_only(db_session, tenant):
    for role in ("analyst", "viewer", "api_user"):
        assert _client(db_session, [role], tenant).get(f"/api/v1/tenants/{tenant.id}/audit-logs").status_code == 403


# ----- tenants ------------------------------------------------------------


def test_tenants_super_admin_only(admin, db_session, tenant):
    assert admin.get("/api/v1/admin/tenants").status_code == 403
    assert admin.post("/api/v1/admin/tenants", json={"name": "x", "slug": "xx"}).status_code == 403
    assert admin.patch(f"/api/v1/admin/tenants/{tenant.id}", json={"name": "n"}).status_code == 403
    for role in ("analyst", "viewer"):
        assert _client(db_session, [role], tenant).get("/api/v1/admin/tenants").status_code == 403


def test_tenant_create_list_update(root, tenant):
    r = root.post("/api/v1/admin/tenants", json={"name": " Acme Bank ", "slug": "Acme-Bank", "sector": "finance"})
    assert r.status_code == 201
    t = r.json()
    assert t["name"] == "Acme Bank" and t["slug"] == "acme-bank"
    names = [i["name"] for i in root.get("/api/v1/admin/tenants").json()["items"]]
    assert "Acme Bank" in names and "Test Tenant" in names
    up = root.patch(f"/api/v1/admin/tenants/{t['id']}", json={"name": "Acme SpA", "sector": None, "slug": "ignored"})
    assert up.status_code == 200 and up.json()["name"] == "Acme SpA" and up.json()["slug"] == "acme-bank"
    assert up.json()["sector"] is None
    assert root.patch(f"/api/v1/admin/tenants/{uuid.uuid4()}", json={"name": "n"}).status_code == 404


def test_tenant_validation_and_duplicate_slug(root):
    assert root.post("/api/v1/admin/tenants", json={"name": "A", "slug": "bad slug!"}).status_code == 422
    assert root.post("/api/v1/admin/tenants", json={"name": "A", "slug": "-x-"}).status_code == 422
    assert root.post("/api/v1/admin/tenants", json={"name": "  ", "slug": "ok-slug"}).status_code == 422
    assert root.post("/api/v1/admin/tenants", json={"name": "A", "slug": "dup-one"}).status_code == 201
    assert root.post("/api/v1/admin/tenants", json={"name": "B", "slug": "dup-one"}).status_code == 409


def test_audit_action_column_fits_the_longest_route_path():
    """The note-delete path is 130 characters; the column used to be 100 and Postgres dropped the row."""
    longest = f"DELETE /api/v1/tenants/{uuid.uuid4()}/cases/{uuid.uuid4()}/notes/{uuid.uuid4()}"
    assert len(longest) > 100
    assert AuditLog.__table__.c.action.type.length >= len(longest)
