"""AbuseIPDB blacklist collector — bulk fetch of reported malicious IPs.

Requires ABUSEIPDB_KEY. Gate: abuseipdb_collector_enabled = true.
Publishes to raw-observations stream as type "malicious_ip".
"""
import json
import logging

import httpx

from app.core.config import get_settings
from app.streams.streams import publish

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"
MIN_CONFIDENCE = 90
LIMIT = 10_000


def fetch_abuseipdb(r=None) -> int:
    """Fetch AbuseIPDB blacklist and publish each IP to raw-observations. Returns count published."""
    settings = get_settings()
    if not settings.abuseipdb_key:
        logger.warning("abuseipdb_key not set; skipping AbuseIPDB collector")
        return 0

    if r is None:
        from app.streams.client import get_redis
        r = get_redis()

    try:
        resp = httpx.get(
            ABUSEIPDB_URL,
            params={"confidenceMinimum": MIN_CONFIDENCE, "limit": LIMIT},
            headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
            timeout=60,
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("AbuseIPDB fetch failed: %s", exc)
        return 0

    data = resp.json().get("data", [])
    count = 0
    for entry in data:
        if not isinstance(entry, dict) or not entry.get("ipAddress"):
            continue
        publish(
            "raw-observations",
            {
                "type": "malicious_ip",
                "data": json.dumps({
                    "ip": entry["ipAddress"],
                    "abuse_confidence": entry.get("abuseConfidenceScore", 0),
                    "country": entry.get("countryCode", ""),
                    "last_reported": entry.get("lastReportedAt", ""),
                    "total_reports": entry.get("totalReports", 0),
                }),
            },
            r=r,
        )
        count += 1

    logger.info("AbuseIPDB: published %d malicious IPs", count)
    return count
