"""Tests for the correlation engine."""
import hashlib
import uuid

import pytest
from sqlalchemy import select

from app.db.models import CorrelationEvent, Identity, Indicator, Leak, Software, Vulnerability
from app.correlation.engine import CorrelationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def software_with_cpe(db_session, asset):
    sw = Software(
        asset_id=asset.id,
        tenant_id=asset.tenant_id,
        name="nginx",
        version="1.18.0",
        cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
    )
    db_session.add(sw)
    db_session.flush()
    return sw


@pytest.fixture
def matching_vulnerability(db_session):
    # criteria has matching vendor+product with no version range => match_cpe returns (True, 0.5)
    v = Vulnerability(
        cve_id="CVE-2024-CORR1",
        cpe_nodes=[{"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}],
    )
    db_session.add(v)
    db_session.flush()
    return v


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_vuln_software_creates_event(db_session, tenant, asset, software_with_cpe, matching_vulnerability):
    CorrelationEngine().run_for_tenant(tenant.id, session=db_session)
    events = db_session.execute(
        select(CorrelationEvent).where(CorrelationEvent.tenant_id == tenant.id)
    ).scalars().all()
    assert len(events) >= 1


def test_new_events_are_active(db_session, tenant, asset, software_with_cpe, matching_vulnerability):
    CorrelationEngine().run_for_tenant(tenant.id, session=db_session)
    inactive = db_session.execute(
        select(CorrelationEvent).where(
            CorrelationEvent.tenant_id == tenant.id,
            CorrelationEvent.is_active == False,  # noqa: E712
        )
    ).scalars().all()
    assert len(inactive) == 0


def test_no_software_no_event(db_session, tenant, matching_vulnerability):
    """No Software rows => no events."""
    count = CorrelationEngine().run_for_tenant(tenant.id, session=db_session)
    assert count == 0


def test_dedup_does_not_double_create(db_session, tenant, asset, software_with_cpe, matching_vulnerability):
    """Running twice for the same tenant creates the event only once."""
    CorrelationEngine().run_for_tenant(tenant.id, session=db_session)
    CorrelationEngine().run_for_tenant(tenant.id, session=db_session)
    events = db_session.execute(
        select(CorrelationEvent).where(CorrelationEvent.tenant_id == tenant.id)
    ).scalars().all()
    assert len(events) == 1


def test_ioc_asset_ip_creates_event(db_session, tenant, asset):
    """IP indicator matching asset IP creates a correlation event."""
    ioc = Indicator(ioc_type="ip", value=asset.ip, confidence=0.8)
    db_session.add(ioc)
    db_session.flush()

    count = CorrelationEngine().run_for_tenant(tenant.id, session=db_session)
    assert count >= 1
    events = db_session.execute(
        select(CorrelationEvent).where(
            CorrelationEvent.tenant_id == tenant.id,
            CorrelationEvent.rule_name == "ioc_asset",
        )
    ).scalars().all()
    assert len(events) == 1


def test_leak_identity_creates_event(db_session, tenant):
    """Leak email_hash matching SHA-256 of identity email creates a correlation event."""
    email = "victim@example.com"
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest()

    identity = Identity(tenant_id=tenant.id, email=email, name="Victim")
    leak = Leak(tenant_id=tenant.id, email_hash=email_hash, breach_name="TestBreach")
    db_session.add_all([identity, leak])
    db_session.flush()

    count = CorrelationEngine().run_for_tenant(tenant.id, session=db_session)
    assert count >= 1
    events = db_session.execute(
        select(CorrelationEvent).where(
            CorrelationEvent.tenant_id == tenant.id,
            CorrelationEvent.rule_name == "leak_identity",
        )
    ).scalars().all()
    assert len(events) == 1
