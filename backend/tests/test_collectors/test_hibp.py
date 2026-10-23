"""Tests for HIBP leak checker."""
import uuid


def test_hibp_skip_when_no_emails(db_session, tenant):
    """fetch_hibp_for_tenant returns 0 when no leak rows exist for tenant."""
    from app.collectors.hibp import fetch_hibp_for_tenant

    count = fetch_hibp_for_tenant(tenant_id=tenant.id, db=db_session)
    assert count == 0


def test_hibp_skip_when_rows_exist(db_session, tenant):
    """fetch_hibp_for_tenant returns 0 (Phase 1 stub) even with stored hashes."""
    from app.db.models import Leak
    from app.collectors.hibp import fetch_hibp_for_tenant

    # Add a stored SHA-256 hash row
    db_session.add(Leak(
        tenant_id=tenant.id,
        email_hash="a" * 64,
        breach_name="TestBreach",
    ))
    db_session.flush()

    count = fetch_hibp_for_tenant(tenant_id=tenant.id, db=db_session)
    # Phase 1: SHA-256→SHA-1 conversion not implemented; always 0
    assert count == 0
