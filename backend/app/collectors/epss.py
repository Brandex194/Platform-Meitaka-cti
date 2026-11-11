"""EPSS score collector — syncs exploit prediction scores from First.org.

EPSS (Exploit Prediction Scoring System) is a public API requiring no key.
Scores are updated daily; this collector does a full refresh of all CVEs
that already exist in the Vulnerability table.
"""
import logging

import httpx
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.db.models import Vulnerability

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
PAGE_SIZE = 10_000


def fetch_epss(db: Session, r=None) -> int:
    """Fetch all current EPSS scores and update Vulnerability rows. Returns count updated."""
    offset = 0
    total_updated = 0

    while True:
        try:
            resp = httpx.get(
                EPSS_URL,
                params={"limit": PAGE_SIZE, "offset": offset},
                timeout=60,
            )
            resp.raise_for_status()
        except Exception as exc:
            logger.warning("EPSS fetch failed at offset %d: %s", offset, exc)
            break

        payload = resp.json()
        rows = payload.get("data", [])
        if not rows:
            break

        for row in rows:
            cve_id = row.get("cve")
            epss = row.get("epss")
            if not cve_id or epss is None:
                continue
            try:
                epss_float = float(epss)
            except (TypeError, ValueError):
                continue
            result = db.execute(
                update(Vulnerability)
                .where(Vulnerability.cve_id == cve_id)
                .values(epss_score=epss_float)
            )
            total_updated += result.rowcount

        total = payload.get("total", 0)
        offset += len(rows)
        if offset >= total:
            break

    db.flush()
    logger.info("EPSS: updated %d vulnerability rows", total_updated)
    return total_updated
