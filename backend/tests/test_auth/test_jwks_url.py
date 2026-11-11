from app.auth.jwks import jwks_url
from app.core.config import get_settings


def _set(monkeypatch, internal: str | None):
    monkeypatch.setenv("KEYCLOAK_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYCLOAK_REALM", "sentinel")
    if internal is None:
        monkeypatch.delenv("KEYCLOAK_INTERNAL_URL", raising=False)
    else:
        monkeypatch.setenv("KEYCLOAK_INTERNAL_URL", internal)
    get_settings.cache_clear()


def test_jwks_url_defaults_to_public_url(monkeypatch):
    _set(monkeypatch, None)
    try:
        assert jwks_url() == "http://localhost:8080/realms/sentinel/protocol/openid-connect/certs"
    finally:
        get_settings.cache_clear()


def test_jwks_url_prefers_internal_url(monkeypatch):
    _set(monkeypatch, "http://keycloak:8080/")
    try:
        assert jwks_url() == "http://keycloak:8080/realms/sentinel/protocol/openid-connect/certs"
    finally:
        get_settings.cache_clear()
