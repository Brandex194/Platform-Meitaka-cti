def test_health_returns_200(analyst_client):
    r = analyst_client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_health_is_public():
    """Health endpoint needs no auth — test with an app that has no override."""
    import os
    os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
    os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
    os.environ.setdefault("KEYCLOAK_URL", "http://localhost:8080")
    os.environ.setdefault("KEYCLOAK_REALM", "sentinel")
    os.environ.setdefault("KEYCLOAK_CLIENT_ID", "sentinel-api")

    from fastapi.testclient import TestClient
    from app.main import create_app
    client = TestClient(create_app(), raise_server_exceptions=False)
    r = client.get("/api/v1/health")
    assert r.status_code == 200
