import os

# Set required env vars before any app import — pydantic Settings and
# session.py's module-level engine creation both run at import time.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("KEYCLOAK_URL", "http://localhost:8080")
os.environ.setdefault("KEYCLOAK_REALM", "sentinel")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "sentinel-api")

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base


@pytest.fixture(scope="session")
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture
def db_session(engine):
    conn = engine.connect()
    trans = conn.begin()
    session = Session(conn)
    yield session
    session.close()
    trans.rollback()
    conn.close()


@pytest.fixture
def tenant(db_session):
    from app.db.models import Tenant

    t = Tenant(name="Test Tenant", slug="test", sector="technology")
    db_session.add(t)
    db_session.flush()
    return t


@pytest.fixture
def asset(db_session, tenant):
    from app.db.models import Asset

    a = Asset(tenant_id=tenant.id, hostname="test-host", ip="192.168.1.1")
    db_session.add(a)
    db_session.flush()
    return a


@pytest.fixture
def software(db_session, asset):
    from app.db.models import Software

    s = Software(asset_id=asset.id, tenant_id=asset.tenant_id, name="nginx", version="1.18.0")
    db_session.add(s)
    db_session.flush()
    return s


# ---------------------------------------------------------------------------
# Auth fixtures (Task 5)
# ---------------------------------------------------------------------------


@pytest.fixture
def app_instance():
    return FastAPI()


@pytest.fixture
def client(app_instance):
    return TestClient(app_instance)


@pytest.fixture
def viewer_token():
    return {"sub": "user1", "roles": ["viewer"], "tenant_id": str(uuid.uuid4())}


@pytest.fixture
def analyst_token():
    return {"sub": "user2", "roles": ["analyst"], "tenant_id": str(uuid.uuid4())}


@pytest.fixture
def tenant_admin_token():
    return {"sub": "user3", "roles": ["tenant_admin"], "tenant_id": str(uuid.uuid4())}


@pytest.fixture
def exposure_match_id():
    return uuid.uuid4()
