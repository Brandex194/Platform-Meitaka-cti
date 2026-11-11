"""Test API conftest.

Env vars MUST be set before any app imports so that session.py's module-level
engine creation and pydantic Settings validation succeed.
"""
import os
import uuid

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("KEYCLOAK_URL", "http://localhost:8080")
os.environ.setdefault("KEYCLOAK_REALM", "sentinel")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "sentinel-api")

import pytest
from fastapi.testclient import TestClient

from app.api.v1.deps import get_scoped_db
from app.auth.jwks import decode_token
from app.db.session import get_db
from app.main import create_app


def _client(db_session, roles: list, tenant_id: str) -> TestClient:
    """Create a TestClient with mocked auth (given roles) and mocked DB."""
    app = create_app()
    app.dependency_overrides[decode_token] = lambda: {
        "sub": "testuser",
        "roles": roles,
        "tenant_id": tenant_id,
    }
    app.dependency_overrides[get_scoped_db] = lambda: db_session
    app.dependency_overrides[get_db] = lambda: db_session  # dashboard still uses get_db
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def analyst_client(db_session, tenant):
    return _client(db_session, ["analyst"], str(tenant.id))


@pytest.fixture
def viewer_client(db_session, tenant):
    return _client(db_session, ["viewer"], str(tenant.id))


@pytest.fixture
def tenant_admin_client(db_session, tenant):
    return _client(db_session, ["tenant_admin"], str(tenant.id))


@pytest.fixture
def super_admin_client(db_session, tenant):
    return _client(db_session, ["super_admin"], str(tenant.id))


@pytest.fixture
def client_no_auth(db_session):
    """TestClient with NO auth override — tests that unauthenticated requests get 401.
    decode_token (subdep of get_scoped_db) raises 401 before DB is touched, so no DB override needed.
    """
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client_tenant_a(tenant):
    """TestClient whose token carries tenant A's id but get_scoped_db is NOT bypassed."""
    app = create_app()
    app.dependency_overrides[decode_token] = lambda: {
        "sub": "testuser",
        "roles": ["analyst"],
        "tenant_id": str(tenant.id),
    }
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def tenant_b_id():
    """A random UUID representing a different tenant."""
    return uuid.uuid4()


@pytest.fixture
def exposure_match(db_session, tenant):
    from app.db.models import ExposureMatch

    m = ExposureMatch(tenant_id=tenant.id, status="active")
    db_session.add(m)
    db_session.flush()
    return m


@pytest.fixture
def exposure_match_with_event(db_session, tenant):
    from app.db.models import CorrelationEvent, ExposureMatch

    event = CorrelationEvent(tenant_id=tenant.id, rule_name="test-rule", is_active=True)
    db_session.add(event)
    db_session.flush()

    match = ExposureMatch(
        tenant_id=tenant.id,
        correlation_event_id=event.id,
        status="active",
    )
    db_session.add(match)
    db_session.flush()
    return match, event
