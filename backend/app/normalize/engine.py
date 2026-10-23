"""Normalize engine: consumes raw-observations, upserts catalog entities, publishes enriched-entities."""
import json
import logging
import uuid
from uuid import NAMESPACE_URL

from app.db.models import Indicator, Leak, Vulnerability
from app.streams.streams import get_cursor, publish, read_batch, save_cursor

logger = logging.getLogger(__name__)

CURSOR_STREAM = "raw-observations"
OUTPUT_STREAM = "enriched-entities"
BATCH_SIZE = 100


def normalize_batch(db=None, r=None) -> int:
    """Read one batch from raw-observations, upsert entities, advance cursor on success.

    Returns count of messages processed (including skipped unknown types).
    On exception, cursor is NOT advanced (re-raised to caller).
    """
    cursor = get_cursor(CURSOR_STREAM, r)
    batch = read_batch(CURSOR_STREAM, cursor, BATCH_SIZE, r)
    if not batch:
        return 0

    count = 0
    last_msg_id = None
    for msg_id, msg_fields in batch:
        msg_type = msg_fields.get("type", "")
        if msg_type == "cve":
            data = json.loads(msg_fields["data"])
            cve_id = _upsert_vulnerability(data, db)
            publish(OUTPUT_STREAM, {"type": "vulnerability", "cve_id": cve_id}, r)
        elif msg_type == "leak":
            _upsert_leak(_msg_to_data(msg_fields), db)
        elif msg_type == "indicator":
            _upsert_indicator(_msg_to_data(msg_fields), db)
        else:
            logger.warning("normalize_batch: unknown message type %r — skipping", msg_type)
        count += 1
        last_msg_id = msg_id

    # save_cursor only reached if no exception above
    save_cursor(CURSOR_STREAM, last_msg_id, r)
    # shortcut: flush not commit; caller (daemon) owns the transaction lifecycle
    db.flush()
    return count


def _msg_to_data(msg_fields: dict) -> dict:
    """Return parsed data dict: decode 'data' JSON key if present, else return fields as-is."""
    if "data" in msg_fields:
        return json.loads(msg_fields["data"])
    return dict(msg_fields)


def _upsert_vulnerability(data: dict, db) -> str:
    cve_id = data["id"]
    description = data.get("descriptions", [{}])[0].get("value", "")[:2000]
    cvss_score = (
        data.get("metrics", {})
        .get("cvssMetricV31", [{}])[0]
        .get("cvssData", {})
        .get("baseScore")
    )
    db.merge(
        Vulnerability(
            id=uuid.uuid5(NAMESPACE_URL, cve_id),
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
        )
    )
    return cve_id


def _upsert_leak(data: dict, db) -> None:
    email_hash = data["email_hash"]
    tenant_id = data["tenant_id"]
    source = data.get("source", "unknown")
    db.merge(
        Leak(
            id=uuid.uuid5(NAMESPACE_URL, email_hash + str(tenant_id)),
            email_hash=email_hash,
            # map source → breach_name; Leak model has breach_name NOT NULL, no source column
            breach_name=source,
            tenant_id=uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id,
        )
    )


def _upsert_indicator(data: dict, db) -> None:
    value = data["value"]
    db.merge(
        Indicator(
            id=uuid.uuid5(NAMESPACE_URL, value),
            # model uses ioc_type, not type
            ioc_type=data.get("type", "unknown"),
            value=value,
        )
    )
