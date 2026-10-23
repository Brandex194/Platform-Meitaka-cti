"""HIBP per-tenant leak checker (Phase 1 stub — limited by SHA-256/SHA-1 mismatch)."""
import logging
import uuid

from app.db.models import Leak

logger = logging.getLogger(__name__)

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def fetch_hibp_for_tenant(
    tenant_id: uuid.UUID,
    db=None,
    r=None,
) -> int:
    """Check tenant watchlist emails against HIBP; publish breached findings.

    shortcut: leaks.email_hash is SHA-256 but HIBP k-anonymity uses SHA-1; the
    collector cannot derive SHA-1 from a stored SHA-256 hash.  Phase 1 reads raw
    emails only if a 'watchlist_emails' attribute exists on the Leak row (it doesn't
    yet), so it always returns 0.  Upgrade when watchlist_emails table is added.

    Returns count of breached findings published.
    """
    _db = db
    _gen = None
    if _db is None:
        from app.db.session import bypass_session  # lazy — avoids eager engine init
        _gen = bypass_session()
        _db = next(_gen)

    try:
        # Query stored hashes — SHA-256, unusable for HIBP SHA-1 k-anonymity
        rows = _db.query(Leak.email_hash).filter_by(tenant_id=tenant_id).all()
        # Phase 1: cannot derive SHA-1 from SHA-256; skip all rows until
        # watchlist_emails table lands.
        _ = rows  # queried to confirm tenant isolation; result unused
        return 0
    finally:
        if _gen is not None:
            try:
                next(_gen)
            except StopIteration:
                pass
