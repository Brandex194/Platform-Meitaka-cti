"""Ransomware.live collector — recent ransomware attack victims.

Public API, no key required. Publishes to raw-observations stream so the
normalize + correlation pipeline can link victims to tenant assets.
"""
import json
import logging

import httpx

from app.streams.streams import publish

logger = logging.getLogger(__name__)

RANSOMWARE_LIVE_URL = "https://api.ransomware.live/recentvictims"
LAST_RUN_KEY = "ransomware_live:last_run"


def fetch_ransomware_live(r=None) -> int:
    """Fetch recent ransomware victims; publish each to raw-observations. Returns count published."""
    if r is None:
        from app.streams.client import get_redis
        r = get_redis()

    try:
        resp = httpx.get(RANSOMWARE_LIVE_URL, timeout=30, follow_redirects=True)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("ransomware.live fetch failed: %s", exc)
        return 0

    victims = resp.json() if isinstance(resp.json(), list) else resp.json().get("data", [])
    count = 0
    for victim in victims:
        if not isinstance(victim, dict):
            continue
        publish(
            "raw-observations",
            {
                "type": "ransomware_victim",
                "data": json.dumps({
                    "group": victim.get("group_name") or victim.get("group") or "unknown",
                    "victim": victim.get("post_title") or victim.get("victim") or "",
                    "domain": victim.get("website") or victim.get("domain") or "",
                    "published": victim.get("published") or victim.get("date") or "",
                    "country": victim.get("country") or "",
                }),
            },
            r=r,
        )
        count += 1

    logger.info("ransomware.live: published %d victims", count)
    return count
