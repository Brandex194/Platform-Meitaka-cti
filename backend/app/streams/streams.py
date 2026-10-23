from __future__ import annotations

import redis

from app.streams.client import get_redis

MAXLEN = 50_000
CURSOR_KEY_PREFIX = "stream:cursor:"


def publish(stream: str, payload: dict, r: redis.Redis | None = None) -> str:
    """Publish payload to stream; returns the new message ID."""
    r = r or get_redis()
    return r.xadd(stream, payload, maxlen=MAXLEN, approximate=True)


def read_batch(
    stream: str,
    cursor: str,
    count: int = 100,
    r: redis.Redis | None = None,
) -> list[tuple[str, dict]]:
    """Read up to *count* messages after *cursor* (exclusive).

    Caller must call save_cursor ONLY after successful processing.
    Do not advance the cursor on exception.
    """
    r = r or get_redis()
    result = r.xread({stream: cursor}, count=count)
    if not result:
        return []
    # result is [(stream_name, [(msg_id, fields), ...])]
    return list(result[0][1])


def save_cursor(stream: str, cursor: str, r: redis.Redis | None = None) -> None:
    """Persist cursor for *stream* to Redis."""
    r = r or get_redis()
    r.set(f"{CURSOR_KEY_PREFIX}{stream}", cursor)


def get_cursor(stream: str, r: redis.Redis | None = None) -> str:
    """Return saved cursor for *stream*, or '0-0' if none."""
    r = r or get_redis()
    return r.get(f"{CURSOR_KEY_PREFIX}{stream}") or "0-0"
