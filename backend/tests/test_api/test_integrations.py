"""Integration keys (write-only) and indicator enrichment routes (passo 10)."""
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.api.v1.deps import get_scoped_db
from app.auth.jwks import decode_token
from app.core import vault
from app.db.models import Indicator, IndicatorEnrichment, IntegrationKey, Tenant
from app.db.session import get_db
from app.integrations import virustotal as vt
from app.main import create_app

KEY = "ab" * 32
KEY2 = "cd" * 32


@pytest.fixture(autouse=True)
def master_key(monkeypatch):
    master = Fernet.generate_key().decode()  # one key for the whole test
    monkeypatch.setattr(vault, "get_settings", lambda: SimpleNamespace(secrets_encryption_key=master))


def _client(db_session, roles, tenant):
    app = create_app()
    app.dependency_overrides[decode_token] = lambda: {"sub": str(uuid.uuid4()), "roles": roles, "tenant_id": str(tenant.id)}
    app.dependency_overrides[get_scoped_db] = lambda: db_session
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def admin(db_session, tenant):
    return _client(db_session, ["tenant_admin"], tenant)


@pytest.fixture
def analyst(db_session, tenant):
    return _client(db_session, ["analyst"], tenant)


def _i(t):
    return f"/api/v1/tenants/{t.id}/integrations"


def _store(admin, tenant, key=KEY):
    return admin.put(f"{_i(tenant)}/virustotal", json={"api_key": key})


# ----- keys are write-only ----------------------------------------------------


def test_list_before_and_after_and_key_never_returned(admin, db_session, tenant):
    first = admin.get(_i(tenant)).json()
    assert first == [{"provider": "virustotal", "label": "VirusTotal", "configured": False, "updated_at": None}]
    r = _store(admin, tenant)
    assert r.status_code == 200 and r.json()["configured"] is True
    assert KEY not in r.text
    listed = admin.get(_i(tenant))
    assert KEY not in listed.text and listed.json()[0]["configured"] is True and listed.json()[0]["updated_at"]
    row = db_session.query(IntegrationKey).one()
    assert KEY not in row.ciphertext and vault.decrypt(row.ciphertext) == KEY


def test_replace_updates_the_same_row(admin, db_session, tenant):
    _store(admin, tenant)
    old = db_session.query(IntegrationKey).one().ciphertext
    assert _store(admin, tenant, KEY2).status_code == 200
    rows = db_session.query(IntegrationKey).all()
    assert len(rows) == 1 and rows[0].ciphertext != old and vault.decrypt(rows[0].ciphertext) == KEY2


def test_delete_is_idempotent(admin, db_session, tenant):
    _store(admin, tenant)
    assert admin.delete(f"{_i(tenant)}/virustotal").status_code == 204
    assert admin.delete(f"{_i(tenant)}/virustotal").status_code == 204
    assert db_session.query(IntegrationKey).count() == 0
    assert admin.get(_i(tenant)).json()[0]["configured"] is False


def test_bad_keys_are_rejected_without_echoing_them(admin):
    secret = "not-a-vt-key-but-secret-looking-value"
    t = SimpleNamespace(id=uuid.uuid4())
    for body in ({"api_key": secret}, {"api_key": "  "}, {}, {"api_key": 123}, {"api_key": KEY[:-1]}):
        r = admin.put(f"{_i(t)}/virustotal", json=body)
        assert r.status_code == 422
        assert secret not in r.text and KEY[:-1] not in r.text
    assert admin.put(f"{_i(t)}/virustotal", content=b"[1,2]", headers={"Content-Type": "application/json"}).status_code == 422


def test_unknown_provider(admin, tenant):
    assert admin.put(f"{_i(tenant)}/shodan", json={"api_key": KEY}).status_code == 404
    assert admin.delete(f"{_i(tenant)}/shodan").status_code == 404


def test_unconfigured_server_answers_503_and_stores_nothing(admin, db_session, tenant, monkeypatch):
    monkeypatch.setattr(vault, "get_settings", lambda: SimpleNamespace(secrets_encryption_key=""))
    r = _store(admin, tenant)
    assert r.status_code == 503 and KEY not in r.text
    assert db_session.query(IntegrationKey).count() == 0


def test_only_admins_manage_keys(db_session, tenant):
    for role in ("analyst", "viewer", "api_user"):
        c = _client(db_session, [role], tenant)
        assert c.get(_i(tenant)).status_code == 403
        assert _store(c, tenant).status_code == 403
        assert c.delete(f"{_i(tenant)}/virustotal").status_code == 403


def test_keys_are_per_tenant(admin, db_session, tenant):
    other = Tenant(name="O", slug="o-int")
    db_session.add(other)
    db_session.flush()
    db_session.add(IntegrationKey(tenant_id=other.id, provider="virustotal", ciphertext=vault.encrypt(KEY2)))
    db_session.flush()
    assert admin.get(_i(tenant)).json()[0]["configured"] is False
    _store(admin, tenant)
    assert db_session.query(IntegrationKey).filter_by(tenant_id=other.id).count() == 1
    assert admin.delete(f"{_i(tenant)}/virustotal").status_code == 204
    assert db_session.query(IntegrationKey).filter_by(tenant_id=other.id).count() == 1  # theirs untouched


# ----- enrichment -----------------------------------------------------------------


@pytest.fixture
def indicator(db_session, tenant):
    i = Indicator(tenant_id=tenant.id, ioc_type="ip", value="203.0.113.5")
    db_session.add(i)
    db_session.flush()
    return i


def _enrich(client, tenant, ind):
    return client.post(f"/api/v1/tenants/{tenant.id}/indicators/{ind.id}/enrich")


def _fake_vt(monkeypatch, result=None, error=None, calls=None):
    def fake(ioc_type, value, api_key, client=None):
        if calls is not None:
            calls.append((ioc_type, value, api_key))
        if error:
            raise error
        return result or vt.VtResult(status="ok", malicious=5, suspicious=1, harmless=50, undetected=10, reputation=-3,
                                     analysis_date=datetime(2026, 11, 9, tzinfo=UTC), permalink="https://www.virustotal.com/gui/ip-address/203.0.113.5")
    monkeypatch.setattr(vt, "lookup", fake)


def test_enrich_uses_the_stored_key_and_saves_the_verdict(admin, analyst, db_session, tenant, indicator, monkeypatch):
    _store(admin, tenant)
    calls = []
    _fake_vt(monkeypatch, calls=calls)
    r = _enrich(analyst, tenant, indicator)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok" and body["malicious"] == 5 and body["indicator_id"] == str(indicator.id)
    assert calls == [("ip", "203.0.113.5", KEY)]  # decrypted for the call...
    assert KEY not in r.text  # ...and never in the answer
    assert db_session.query(IndicatorEnrichment).count() == 1


def test_enrich_twice_updates_one_row(admin, analyst, db_session, tenant, indicator, monkeypatch):
    _store(admin, tenant)
    _fake_vt(monkeypatch)
    _enrich(analyst, tenant, indicator)
    _fake_vt(monkeypatch, result=vt.VtResult(status="ok", malicious=9, permalink="p"))
    r = _enrich(analyst, tenant, indicator)
    assert r.json()["malicious"] == 9 and db_session.query(IndicatorEnrichment).count() == 1


def test_enrich_without_key_is_409(analyst, tenant, indicator, monkeypatch):
    _fake_vt(monkeypatch, error=AssertionError("must not be called"))
    r = _enrich(analyst, tenant, indicator)
    assert r.status_code == 409 and "Management" in r.json()["error"]["message"]


def test_enrich_not_found_at_virustotal_is_saved(admin, analyst, db_session, tenant, indicator, monkeypatch):
    _store(admin, tenant)
    _fake_vt(monkeypatch, result=vt.VtResult(status="not_found", permalink="p"))
    r = _enrich(analyst, tenant, indicator)
    assert r.status_code == 200 and r.json()["status"] == "not_found" and r.json()["malicious"] is None


@pytest.mark.parametrize("status", [409, 429, 502, 422])
def test_upstream_errors_pass_through_with_their_status(admin, analyst, tenant, indicator, monkeypatch, status):
    _store(admin, tenant)
    _fake_vt(monkeypatch, error=vt.VirusTotalError("upstream said no", status))
    r = _enrich(analyst, tenant, indicator)
    assert r.status_code == status and r.json()["error"]["message"] == "upstream said no" and KEY not in r.text


def test_enrich_shared_indicator_ok_foreign_indicator_404(admin, analyst, db_session, tenant, monkeypatch):
    _store(admin, tenant)
    _fake_vt(monkeypatch)
    other = Tenant(name="O", slug="o-enr")
    db_session.add(other)
    db_session.flush()
    shared = Indicator(tenant_id=None, ioc_type="ip", value="198.51.100.1")
    foreign = Indicator(tenant_id=other.id, ioc_type="ip", value="198.51.100.2")
    db_session.add_all([shared, foreign])
    db_session.flush()
    assert _enrich(analyst, tenant, shared).status_code == 200
    assert _enrich(analyst, tenant, foreign).status_code == 404
    assert analyst.post(f"/api/v1/tenants/{tenant.id}/indicators/{uuid.uuid4()}/enrich").status_code == 404


def test_enrich_roles(admin, db_session, tenant, indicator, monkeypatch):
    _store(admin, tenant)
    _fake_vt(monkeypatch)
    for role, code in (("viewer", 403), ("api_user", 403), ("analyst", 200), ("tenant_admin", 200)):
        assert _enrich(_client(db_session, [role], tenant), tenant, indicator).status_code == code


def test_undecryptable_key_asks_for_re_entry(admin, analyst, tenant, indicator, monkeypatch):
    _store(admin, tenant)
    rotated = Fernet.generate_key().decode()
    monkeypatch.setattr(vault, "get_settings", lambda: SimpleNamespace(secrets_encryption_key=rotated))
    r = _enrich(analyst, tenant, indicator)
    assert r.status_code == 409 and "enter it again" in r.json()["error"]["message"]


def test_enrichments_list_is_per_tenant_and_open_to_viewers(admin, analyst, db_session, tenant, indicator, monkeypatch):
    _store(admin, tenant)
    _fake_vt(monkeypatch)
    _enrich(analyst, tenant, indicator)
    other = Tenant(name="O", slug="o-lst")
    db_session.add(other)
    db_session.flush()
    foreign = Indicator(tenant_id=other.id, ioc_type="ip", value="198.51.100.3")
    db_session.add(foreign)
    db_session.flush()
    db_session.add(IndicatorEnrichment(tenant_id=other.id, indicator_id=foreign.id, provider="virustotal", status="ok", malicious=99))
    db_session.flush()
    viewer = _client(db_session, ["viewer"], tenant)
    body = viewer.get(f"/api/v1/tenants/{tenant.id}/enrichments").json()
    assert body["total"] == 1 and body["items"][0]["indicator_id"] == str(indicator.id)
