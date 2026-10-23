"""NVD CVE collector — fetches new/modified CVEs since last run."""
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
import redis as _redis

from app.core.config import get_settings
from app.streams.streams import publish

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LAST_RUN_KEY = "nvd:last_run"
PAGE_SIZE = 2000


def fetch_nvd(r: "_redis.Redis | None" = None) -> int:
    """Fetch CVEs modified since last run; publish each to raw-observations stream.

    Returns count of CVEs published.
    """
    settings = get_settings()

    if r is None:
        from app.streams.client import get_redis
        r = get_redis()

    raw = r.get(LAST_RUN_KEY)
    if raw:
        val = raw.decode() if isinstance(raw, bytes) else raw
        start_dt = datetime.fromisoformat(val)
    else:
        start_dt = datetime.now(tz=timezone.utc) - timedelta(days=90)

    end_dt = datetime.now(tz=timezone.utc)

    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    start_index = 0
    total_published = 0

    while True:
        params = {
            "lastModStartDate": _fmt_nvd_date(start_dt),
            "lastModEndDate": _fmt_nvd_date(end_dt),
            "startIndex": start_index,
            "resultsPerPage": PAGE_SIZE,
        }
        try:
            resp = httpx.get(NVD_BASE, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("NVD HTTP error: %s", exc)
            return total_published

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        for item in vulnerabilities:
            cve = item.get("cve", item)
            publish("raw-observations", {"type": "cve", "data": json.dumps(cve)}, r=r)
            total_published += 1

        start_index += len(vulnerabilities)
        if not vulnerabilities or start_index >= total_results:
            break

        time.sleep(0.1 if settings.nvd_api_key else 0.6)

    r.set(LAST_RUN_KEY, end_dt.isoformat())
    return total_published


def _fmt_nvd_date(dt: datetime) -> str:
    # NVD API date format: 2024-01-01T00:00:00.000 UTC+00:00
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000 UTC+00:00")
