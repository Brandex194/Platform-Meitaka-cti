"""Enrich engine: consumes enriched-entities, updates EPSS/KEV, publishes correlation-events."""
import logging

import httpx

from app.db.models import KevCatalog, Vulnerability
from app.streams.streams import get_cursor, read_batch, save_cursor

logger = logging.getLogger(__name__)

CURSOR_STREAM = "enriched-entities"
OUTPUT_STREAM = "correlation-events"
BATCH_SIZE = 100


def enrich_batch(db=None, r=None) -> tuple[int, str | None, list]:
    """Read one batch from enriched-entities, enrich vulnerability rows.

    Returns (count, last_msg_id, pending_publishes). Caller must:
      - save cursor AFTER commit
      - publish pending_publishes AFTER commit
    Cursor NOT advanced on exception. Per-message guard covers parse/type errors; DB errors propagate.
    """
    cursor = get_cursor(CURSOR_STREAM, r)
    batch = read_batch(CURSOR_STREAM, cursor, BATCH_SIZE, r)
    if not batch:
        return 0, None, []

    count = 0
    last_msg_id = None
    pending_publishes: list = []
    for msg_id, msg_fields in batch:
        try:
            msg_type = msg_fields.get("type")
            if msg_type == "vulnerability":
                cve_id = msg_fields.get("cve_id")
                if cve_id:
                    payload = _enrich_vulnerability(cve_id, db)
                    if payload:
                        pending_publishes.append((OUTPUT_STREAM, payload))
                else:
                    logger.warning("enrich: missing cve_id in message %s", msg_id)
            else:
                logger.warning("enrich: unknown message type %s, skipping", msg_type)
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            logger.warning("enrich: skipping malformed message %s: %s", msg_id, exc)

        count += 1
        last_msg_id = msg_id

    # cursor and publishes are handled by caller after commit
    return count, last_msg_id, pending_publishes


def _enrich_vulnerability(cve_id: str, db) -> dict | None:
    """Enrich one vulnerability. Returns the publish payload, or None if vuln not found."""
    vuln = db.query(Vulnerability).filter_by(cve_id=cve_id).one_or_none()
    if vuln is None:
        logger.warning("enrich: vulnerability not found: %s", cve_id)
        return None

    # KEV from catalog table — never from HTTP
    kev = db.query(KevCatalog).filter_by(cve_id=cve_id).one_or_none()
    if kev:
        vuln.kev_date_added = kev.date_added

    # EPSS from FIRST.org API — failures are non-fatal
    try:
        resp = httpx.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=10.0
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if data:
            vuln.epss_score = float(data[0]["epss"])
    except Exception as exc:
        logger.warning("enrich: EPSS fetch failed for %s: %s", cve_id, exc)

    db.flush()
    return {
        "type": "vulnerability_enriched",
        "cve_id": cve_id,
        "epss": str(vuln.epss_score or 0),
        "in_kev": str(bool(vuln.kev_date_added)),
    }
