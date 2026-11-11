"""Vault encryption and the VirusTotal client (no network: httpx.MockTransport)."""
import base64
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet

from app.core import vault
from app.integrations import virustotal as vt

KEY = "ab" * 32  # 64 hex characters, shaped like a VirusTotal key


def _master(monkeypatch, value):
    monkeypatch.setattr(vault, "get_settings", lambda: SimpleNamespace(secrets_encryption_key=value))


def test_round_trip_and_ciphertext_hides_the_key(monkeypatch):
    _master(monkeypatch, Fernet.generate_key().decode())
    token = vault.encrypt(KEY)
    assert KEY not in token and token != KEY
    assert vault.decrypt(token) == KEY
    assert vault.encrypt(KEY) != token  # fresh nonce every time


def test_missing_or_invalid_master_key_is_an_error_not_plaintext(monkeypatch):
    _master(monkeypatch, "")
    with pytest.raises(vault.VaultNotConfigured):
        vault.encrypt(KEY)
    _master(monkeypatch, "not-a-fernet-key")
    with pytest.raises(vault.VaultNotConfigured):
        vault.encrypt(KEY)


def test_rotated_master_key_cannot_decrypt(monkeypatch):
    _master(monkeypatch, Fernet.generate_key().decode())
    token = vault.encrypt(KEY)
    _master(monkeypatch, Fernet.generate_key().decode())  # a different key
    with pytest.raises(vault.VaultDecryptError):
        vault.decrypt(token)


# ----- VirusTotal ------------------------------------------------------------


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok_body(**stats):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20, **stats},
        "reputation": -12, "last_analysis_date": 1762600000}}}


def test_lookup_ok_parses_and_sends_the_key_in_a_header_only():
    seen = {}

    def handler(req: httpx.Request):
        seen["url"], seen["key"] = str(req.url), req.headers.get("x-apikey")
        return httpx.Response(200, json=_ok_body())

    r = vt.lookup("ip", "203.0.113.5", KEY, _client(handler))
    assert (r.status, r.malicious, r.suspicious, r.harmless, r.undetected, r.reputation) == ("ok", 7, 1, 60, 20, -12)
    assert r.analysis_date is not None and r.analysis_date.year == 2025
    assert r.permalink == "https://www.virustotal.com/gui/ip-address/203.0.113.5"
    assert seen["key"] == KEY and KEY not in seen["url"]
    assert seen["url"] == "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.5"


@pytest.mark.parametrize(
    ("ioc_type", "value", "path"),
    [
        ("ip", "2001:db8::1", "/ip_addresses/2001:db8::1"),
        ("domain", "evil.example", "/domains/evil.example"),
        ("hash", "c" * 64, f"/files/{'c' * 64}"),
        ("url", "http://x.test/a?b=1", "/urls/" + base64.urlsafe_b64encode(b"http://x.test/a?b=1").decode().rstrip("=")),
    ],
)
def test_lookup_paths(ioc_type, value, path):
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json=_ok_body())

    vt.lookup(ioc_type, value, KEY, _client(handler))
    assert seen["path"] == "/api/v3" + path


def test_domain_cannot_inject_path_segments():
    seen = {}

    def handler(req):
        seen["raw"] = req.url.raw_path.decode()
        return httpx.Response(404)

    vt.lookup("domain", "evil.example/../../users/me", KEY, _client(handler))
    assert "/../" not in seen["raw"] and seen["raw"].startswith("/api/v3/domains/evil.example%2F")


def test_not_found_is_a_result_not_an_error():
    r = vt.lookup("domain", "unknown.example", KEY, _client(lambda req: httpx.Response(404)))
    assert r.status == "not_found" and r.malicious is None and r.permalink.endswith("/domain/unknown.example")


@pytest.mark.parametrize(("code", "status"), [(401, 409), (403, 409), (429, 429), (500, 502), (503, 502)])
def test_upstream_errors_map_to_safe_messages(code, status):
    with pytest.raises(vt.VirusTotalError) as exc:
        vt.lookup("ip", "203.0.113.5", KEY, _client(lambda req: httpx.Response(code, text=f"secret {KEY}")))
    assert exc.value.status == status and KEY not in exc.value.message


def test_network_failure_and_garbage_answer():
    def boom(req):
        raise httpx.ConnectTimeout("t", request=req)

    with pytest.raises(vt.VirusTotalError) as exc:
        vt.lookup("ip", "203.0.113.5", KEY, _client(boom))
    assert exc.value.status == 502 and KEY not in str(exc.value)
    with pytest.raises(vt.VirusTotalError):
        vt.lookup("ip", "203.0.113.5", KEY, _client(lambda req: httpx.Response(200, json={"oops": 1})))
    with pytest.raises(vt.VirusTotalError):
        vt.lookup("ip", "203.0.113.5", KEY, _client(lambda req: httpx.Response(200, text="<html>")))


def test_invalid_ip_and_unknown_type_never_call_out():
    def never(req):
        pytest.fail("no request expected")

    with pytest.raises(vt.VirusTotalError) as e1:
        vt.lookup("ip", "not-an-ip", KEY, _client(never))
    assert e1.value.status == 422
    with pytest.raises(vt.VirusTotalError):
        vt.lookup("email", "a@b.test", KEY, _client(never))


def test_key_format():
    assert vt.KEY_RE.match(KEY) and vt.KEY_RE.match(KEY.upper())
    assert not vt.KEY_RE.match(KEY[:-1]) and not vt.KEY_RE.match("g" * 64) and not vt.KEY_RE.match(KEY + "0")
