def test_settings_loads_from_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYCLOAK_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYCLOAK_REALM", "sentinel")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "sentinel-ai")
    from app.core.config import get_settings

    get_settings.cache_clear()
    s = get_settings()
    assert s.database_url.startswith("postgresql+psycopg://")


def test_resolve_secret_reads_env(monkeypatch):
    monkeypatch.setenv("TEST_SECRET_XYZ", "myval")
    from app.core.secrets import resolve_secret

    assert resolve_secret("TEST_SECRET_XYZ") == "myval"


def test_resolve_secret_missing_logs_warning_returns_empty(monkeypatch, caplog):
    import logging

    from app.core.secrets import resolve_secret

    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("AWS_SECRET_ARN", raising=False)
    with caplog.at_level(logging.WARNING):
        result = resolve_secret("DEFINITELY_MISSING_KEY_12345")
    assert result == ""
    assert "DEFINITELY_MISSING_KEY_12345" in caplog.text
