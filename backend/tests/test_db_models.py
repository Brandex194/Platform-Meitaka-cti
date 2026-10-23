"""Tests for all 21 DB models."""


def test_all_21_models_importable():
    from app.db.models import (
        Asset,
        AttackTechnique,
        AuditLog,
        Campaign,
        Case,
        CorrelationEvent,
        ExposureMatch,
        FeedbackEvent,
        Identity,
        Indicator,
        KevCatalog,
        Leak,
        Observation,
        PhishingDomain,
        Score,
        ScoreRule,
        Software,
        Source,
        Tenant,
        ThreatActor,
        Vulnerability,
    )

    tables = {
        m.__tablename__
        for m in [
            Tenant,
            Asset,
            Software,
            Observation,
            Vulnerability,
            Indicator,
            Leak,
            PhishingDomain,
            CorrelationEvent,
            ExposureMatch,
            Score,
            ScoreRule,
            Case,
            Identity,
            ThreatActor,
            Campaign,
            AttackTechnique,
            Source,
            KevCatalog,
            FeedbackEvent,
            AuditLog,
        ]
    }
    assert len(tables) == 21


def test_correlation_event_is_active_defaults_true():
    from app.db.models import CorrelationEvent

    c = CorrelationEvent(rule_name="test", s_context=0.5)
    assert c.is_active is True
    assert c.resolved_at is None


def test_score_rule_weights_default_sums_to_1():
    from app.db.models import ScoreRule

    sr = ScoreRule()
    assert abs(sum(sr.weights.values()) - 1.0) < 0.001


def test_tenant_created(db_session, tenant):
    from app.db.models import Tenant

    result = db_session.get(Tenant, tenant.id)
    assert result is not None
    assert result.slug == "test"


def test_asset_fk(db_session, asset, tenant):
    assert asset.tenant_id == tenant.id


def test_software_fk(db_session, software, asset):
    assert software.asset_id == asset.id
    assert software.name == "nginx"


def test_leak_email_hash(db_session, tenant):
    from app.db.models import Leak

    lk = Leak(
        tenant_id=tenant.id,
        email_hash="a" * 64,
        breach_name="TestBreach",
    )
    db_session.add(lk)
    db_session.flush()
    result = db_session.get(Leak, lk.id)
    assert len(result.email_hash) == 64


def test_case_defaults(db_session, tenant):
    from app.db.models import Case

    c = Case(tenant_id=tenant.id, title="Test Case")
    db_session.add(c)
    db_session.flush()
    result = db_session.get(Case, c.id)
    assert result.status == "open"
    assert result.severity == "medium"


def test_score_rule_thresholds_default(db_session):
    from app.db.models import ScoreRule

    sr = ScoreRule()
    assert sr.thresholds["medium"] == 0.4
