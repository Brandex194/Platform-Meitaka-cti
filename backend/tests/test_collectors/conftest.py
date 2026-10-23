"""Test configuration for collector tests.

Sets required env vars before any collector module is imported, so get_settings()
succeeds and app.db.session's eager engine init doesn't blow up.
"""
import os

# Must be set before any collector module (or app.db.session) is imported.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("KEYCLOAK_URL", "http://keycloak:8080")
os.environ.setdefault("KEYCLOAK_REALM", "test")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "test")

import app.db.models  # noqa: F401 — register all ORM models with Base before create_all
