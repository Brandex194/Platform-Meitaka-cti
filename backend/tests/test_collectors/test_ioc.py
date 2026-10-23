"""Tests for IoC collector stub."""
from unittest.mock import patch


def test_ioc_disabled_returns_zero():
    """fetch_ioc returns 0 when ioc_collector_enabled is False."""
    from app.core.config import Settings

    mock_settings = Settings.model_construct(
        database_url="sqlite://",
        redis_url="redis://localhost",
        keycloak_url="http://kc",
        keycloak_realm="test",
        keycloak_client_id="test",
        ioc_collector_enabled=False,
    )
    with patch("app.collectors.ioc.get_settings", return_value=mock_settings):
        from app.collectors.ioc import fetch_ioc
        assert fetch_ioc() == 0


def test_ioc_enabled_returns_zero():
    """fetch_ioc returns 0 even when enabled (not yet implemented)."""
    from app.core.config import Settings

    mock_settings = Settings.model_construct(
        database_url="sqlite://",
        redis_url="redis://localhost",
        keycloak_url="http://kc",
        keycloak_realm="test",
        keycloak_client_id="test",
        ioc_collector_enabled=True,
    )
    with patch("app.collectors.ioc.get_settings", return_value=mock_settings):
        from app.collectors.ioc import fetch_ioc
        assert fetch_ioc() == 0
