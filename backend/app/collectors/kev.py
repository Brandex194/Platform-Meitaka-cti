"""CISA KEV collector — upserts known-exploited-vulnerabilities catalog."""
import logging
from datetime import date

import httpx

from app.db.models import KevCatalog

logger = logging.getLogger(__name__)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def fetch_kev(db=None, r=None) -> int:
    """Fetch full KEV catalog and upsert into kev_catalog table.

    db: SQLAlchemy session; uses bypass_session() if None (production path, needs PG).
    Returns count of entries processed.
    """
    try:
        resp = httpx.get(KEV_URL, timeout=30)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("KEV HTTP error: %s", exc)
        return 0

    entries = resp.json().get("vulnerabilities", [])

    if db is not None:
        return _upsert(db, entries)

    # Production path: drive the bypass_session generator manually so we can
    # commit on success and rollback on error.
    from app.db.session import bypass_session  # lazy — avoids eager engine init
    gen = bypass_session()
    _db = next(gen)
    try:
        result = _upsert(_db, entries)
        try:
            next(gen)  # resume generator past yield → exits with-begin block → commits
        except StopIteration:
            pass
        return result
    except Exception:
        gen.close()  # throws GeneratorExit → with-begin rolls back
        raise


def _upsert(db, entries: list) -> int:
    count = 0
    for entry in entries:
        cve_id = entry.get("cveID", "")
        if not cve_id:
            continue
        date_str = entry.get("dateAdded", "")
        try:
            date_added = date.fromisoformat(date_str) if date_str else None
        except ValueError:
            date_added = None

        existing = db.query(KevCatalog).filter_by(cve_id=cve_id).first()
        if existing:
            existing.date_added = date_added
        else:
            db.add(KevCatalog(cve_id=cve_id, date_added=date_added))
        count += 1

    db.flush()
    return count
