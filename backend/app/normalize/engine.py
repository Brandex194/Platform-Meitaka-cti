"""Normalize engine: consumes raw-observations, upserts catalog entities, publishes enriched-entities."""
import json
import logging
import uuid
from uuid import NAMESPACE_URL

from app.db.models import Indicator, Leak, Vulnerability
from app.streams.streams import get_cursor, read_batch, save_cursor

logger = logging.getLogger(__name__)

CURSOR_STREAM = "raw-observations"
OUTPUT_STREAM = "enriched-entities"
BATCH_SIZE = 100


def normalize_batch(db=None, r=None) -> tuple[int, str | None, list]:
    """Read one batch from raw-observations, upsert entities.

    Returns (count, last_msg_id, pending_publishes). Caller must publish THEN save cursor AFTER commit.
    On exception, cursor is NOT advanced (re-raised to caller).
    """
    cursor = get_cursor(CURSOR_STREAM, r)
    batch = read_batch(CURSOR_STREAM, cursor, BATCH_SIZE, r)
    if not batch:
        return 0, None, []

    count = 0
    last_msg_id = None
    pending_publishes: list = []
    for msg_id, msg_fields in batch:
        # Parse + dispatch wrapped together — skip poison pills without blocking the stream.
        # DB errors (IntegrityError, OperationalError) are NOT listed and propagate to halt the batch.
        try:
            msg_type = msg_fields.get("type", "unknown")
            raw_data = msg_fields.get("data", "{}")
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            if not isinstance(data, dict):
                raise ValueError(f"expected dict, got {type(data).__name__}")

            if msg_type == "cve":
                cve_id = _upsert_vulnerability(data, db)
                pending_publishes.append((OUTPUT_STREAM, {"type": "vulnerability", "cve_id": cve_id}))
            elif msg_type == "leak":
                _upsert_leak(data, db)
            elif msg_type == "indicator":
                _upsert_indicator(data, db)
            else:
                logger.warning("normalize: unknown message type %s, skipping", msg_type)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError, AttributeError) as exc:
            logger.warning("normalize: skipping malformed message %s: %s", msg_id, exc)

        # Always advance count/cursor pointer — for both success and skip
        count += 1
        last_msg_id = msg_id

    # flush DB before returning — caller publishes then saves cursor after commit
    db.flush()
    return count, last_msg_id, pending_publishes



def _upsert_vulnerability(data: dict, db) -> str:
    cve_id = data["id"]
    descriptions = data.get("descriptions", [])
    description = (descriptions[0].get("value", "") if descriptions else "")[:2000]
    metrics_v31 = data.get("metrics", {}).get("cvssMetricV31", [])
    cvss_score = metrics_v31[0].get("cvssData", {}).get("baseScore") if metrics_v31 else None
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
