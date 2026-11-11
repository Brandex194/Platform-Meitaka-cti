import logging
import os

import httpx

from app.streams.streams import get_cursor, read_batch, save_cursor

logger = logging.getLogger(__name__)
STREAM = "feedback-events"
CURSOR_KEY = "stream:cursor:feedback-events:siem-out"


def push_siem_feedback() -> None:
    """Read feedback-events stream and POST each message to SIEM_OUTBOUND_URL."""
    url = os.getenv("SIEM_OUTBOUND_URL", "")
    if not url:
        return

    cursor = get_cursor(CURSOR_KEY)
    messages, last_id = read_batch(STREAM, cursor, count=50)
    if not messages:
        return

    for msg in messages:
        try:
            httpx.post(url, json=msg, timeout=10).raise_for_status()
        except Exception as exc:
            logger.warning("SIEM outbound push failed: %s", exc)
            return  # stop; cursor not advanced; retry next run

    save_cursor(CURSOR_KEY, last_id)
