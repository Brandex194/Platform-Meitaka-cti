"""GreyNoise IP enrichment collector.

Queries GreyNoise Community API for IPs that are internet background noise.
Marks "noise" IPs to reduce false positives in AbuseIPDB/IOC feeds.
Gate: greynoise_enrichment_enabled = true + greynoise_key set (or use community plan).
"""
import json
import logging
import time

import httpx

from app.core.config import get_settings
from app.streams.streams import publish

logger = logging.getLogger(__name__)

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community"
GREYNOISE_ENTERPRISE_URL = "https://api.greynoise.io/v2/experimental/gnql"
RATE_SLEEP = 0.3  # community plan: conservative


def enrich_ip_greynoise(ip: str, r=None) -> dict | None:
    """Query GreyNoise for a single IP. Returns parsed result or None on error."""
    settings = get_settings()
    headers = {}
    if settings.greynoise_key:
        headers["key"] = settings.greynoise_key

    try:
        resp = httpx.get(
            f"{GREYNOISE_COMMUNITY_URL}/{ip}",
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 404:
            return {"ip": ip, "noise": False, "riot": False, "classification": "unknown"}
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("GreyNoise enrich %s failed: %s", ip, exc)
        return None


def fetch_greynoise_for_ips(ips: list[str], r=None) -> int:
    """Enrich a list of IPs and publish noise verdicts to raw-observations. Returns count published."""
    if r is None:
        from app.streams.client import get_redis
        r = get_redis()

    count = 0
    for ip in ips:
        result = enrich_ip_greynoise(ip)
        if result is None:
            continue
        publish(
            "raw-observations",
            {"type": "greynoise_verdict", "data": json.dumps(result)},
            r=r,
        )
        count += 1
        time.sleep(RATE_SLEEP)

    logger.info("GreyNoise: enriched %d IPs", count)
    return count
