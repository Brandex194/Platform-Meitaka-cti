"""Phishing URL collector — OpenPhish free community feed.

No API key required. Publishes to raw-observations stream as type "phishing_url".
Feed is refreshed every few hours; a Redis key tracks already-seen URLs to avoid
re-publishing on each run (set expires after 48 h so old stale URLs are rechecked).
"""
import json
import logging

import httpx

from app.streams.streams import publish

logger = logging.getLogger(__name__)

OPENPHISH_FEED = "https://openphish.com/feed.txt"
SEEN_KEY_PREFIX = "openphish:seen:"
SEEN_TTL = 48 * 3600  # seconds


def fetch_phishing(r=None) -> int:
    """Fetch OpenPhish feed; publish new phishing URLs to raw-observations. Returns count published."""
    if r is None:
        from app.streams.client import get_redis
        r = get_redis()

    try:
        resp = httpx.get(OPENPHISH_FEED, timeout=30, follow_redirects=True)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("OpenPhish fetch failed: %s", exc)
        return 0

    urls = [line.strip() for line in resp.text.splitlines() if line.strip().startswith("http")]
    count = 0
    pipe = r.pipeline(transaction=False)
    for url in urls:
        seen_key = f"{SEEN_KEY_PREFIX}{hash(url) & 0xFFFFFFFF}"
        if r.exists(seen_key):
            continue
        publish(
            "raw-observations",
            {"type": "phishing_url", "data": json.dumps({"url": url, "source": "openphish"})},
            r=r,
        )
        pipe.setex(seen_key, SEEN_TTL, 1)
        count += 1
    pipe.execute()

    logger.info("OpenPhish: published %d new phishing URLs", count)
    return count
