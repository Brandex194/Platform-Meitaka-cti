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


def test_all_21_tables_present():
    from app.db.base import Base
    from app.db import models  # noqa: F401

    expected = {
        "sources", "attack_techniques", "vulnerabilities", "kev_catalog",
        "threat_actors", "tenants", "assets", "identities", "indicators",
        "leaks", "phishing_domains", "cases", "score_rules", "campaigns",
        "audit_logs", "feedback_events", "software", "observations",
        "scores", "correlation_events", "exposure_matches",
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
