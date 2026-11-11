"""Migration schema-validation tests — no live DB required.

These tests inspect SQLAlchemy metadata to verify the ORM models
match the expected schema that the migrations will create.
"""
import pytest


def test_kev_catalog_in_metadata():
    from app.db.base import Base
    from app.db import models  # noqa: F401

    assert "kev_catalog" in Base.metadata.tables


def test_correlation_events_has_is_active():
    from app.db.base import Base
    from app.db import models  # noqa: F401

    col = Base.metadata.tables["correlation_events"].c["is_active"]
    assert col is not None


def test_leaks_has_tenant_id():
    from app.db.base import Base
    from app.db import models  # noqa: F401

    col = Base.metadata.tables["leaks"].c["tenant_id"]
    assert col is not None


def test_all_27_tables_present():
    from app.db.base import Base
    from app.db import models  # noqa: F401

    expected = {
        "sources", "attack_techniques", "vulnerabilities", "kev_catalog",
        "threat_actors", "tenants", "assets", "identities", "indicators",
        "leaks", "phishing_domains", "cases", "score_rules", "campaigns",
        "audit_logs", "feedback_events", "software", "observations",
        "scores", "correlation_events", "exposure_matches", "case_notes", "case_events", "api_keys", "integration_keys", "indicator_enrichments", "campaign_indicators",
    }
    assert expected == set(Base.metadata.tables.keys())


def test_score_rules_version_column():
    from app.db.base import Base
    from app.db import models  # noqa: F401

    col = Base.metadata.tables["score_rules"].c["version"]
    assert col is not None


def test_correlation_events_resolved_at_nullable():
    from app.db.base import Base
    from app.db import models  # noqa: F401

    col = Base.metadata.tables["correlation_events"].c["resolved_at"]
    assert col.nullable is True


def _get_pg_conn():
    """Return a psycopg connection or None if no Postgres available."""
    import os
    url = os.getenv("MIGRATION_DATABASE_URL", "")
    if not url or "sqlite" in url:
        return None
    try:
        import psycopg
        return psycopg.connect(url)
    except Exception:
        return None


@pytest.mark.integration
def test_rls_on_correlation_events():
    conn = _get_pg_conn()
    if conn is None:
        pytest.skip("No PostgreSQL available (set MIGRATION_DATABASE_URL)")
    with conn:
        cur = conn.execute(
            "SELECT relrowsecurity FROM pg_class WHERE relname='correlation_events'"
        )
        row = cur.fetchone()
    conn.close()
    assert row is not None and row[0] is True


@pytest.mark.integration
def test_no_rls_on_vulnerabilities():
    conn = _get_pg_conn()
    if conn is None:
        pytest.skip("No PostgreSQL available (set MIGRATION_DATABASE_URL)")
    with conn:
        cur = conn.execute(
            "SELECT relrowsecurity FROM pg_class WHERE relname='vulnerabilities'"
        )
        row = cur.fetchone()
    conn.close()
    assert row is not None and row[0] is False
