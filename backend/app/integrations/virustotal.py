"""VirusTotal API v3: look one indicator up and boil the answer down to a few numbers.

Only the fixed host www.virustotal.com is called; the indicator value goes into the path after
encoding. The key goes in the `x-apikey` header and is never logged.
"""
import base64
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

PROVIDER = "virustotal"
BASE_URL = "https://www.virustotal.com/api/v3"
GUI_URL = "https://www.virustotal.com/gui"
KEY_RE = re.compile(r"^[A-Fa-f0-9]{64}$")  # what a VirusTotal key looks like
TIMEOUT = 10.0


class VirusTotalError(Exception):
    """Base class; `message` is safe to show to the user."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class VtResult:
    status: str  # ok | not_found
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    reputation: int | None = None
    analysis_date: datetime | None = None
    permalink: str | None = None


def _object_path(ioc_type: str, value: str) -> tuple[str, str]:
    """(API path, GUI path) of the VirusTotal object for an indicator."""
    if ioc_type == "ip":
        ip = str(ipaddress.ip_address(value))  # ValueError for junk: never reaches the URL
        return f"/ip_addresses/{ip}", f"/ip-address/{ip}"
    if ioc_type == "domain":
        d = quote(value, safe="")
        return f"/domains/{d}", f"/domain/{d}"
    if ioc_type == "url":
        ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"/urls/{ident}", f"/url/{ident}"
    if ioc_type == "hash":
        h = quote(value, safe="")
        return f"/files/{h}", f"/file/{h}"
    raise VirusTotalError(f"VirusTotal cannot look up '{ioc_type}' indicators", 422)


def lookup(ioc_type: str, value: str, api_key: str, client: httpx.Client | None = None) -> VtResult:
    try:
        api_path, gui_path = _object_path(ioc_type, value)
    except ValueError as exc:
        raise VirusTotalError("this indicator is not a valid value for VirusTotal", 422) from exc

    own = client is None
    http = client or httpx.Client(timeout=TIMEOUT)
    try:
        resp = http.get(BASE_URL + api_path, headers={"x-apikey": api_key, "accept": "application/json"})
    except httpx.HTTPError as exc:
        raise VirusTotalError("VirusTotal could not be reached") from exc
    finally:
        if own:
            http.close()

    if resp.status_code == 404:
        return VtResult(status="not_found", permalink=GUI_URL + gui_path)
    if resp.status_code in (401, 403):
        raise VirusTotalError("VirusTotal rejected the API key", 409)
    if resp.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit reached; free keys allow 4 requests a minute", 429)
    if resp.status_code != 200:
        raise VirusTotalError(f"VirusTotal answered {resp.status_code}")
    try:
        attrs = resp.json()["data"]["attributes"]
    except (ValueError, KeyError, TypeError) as exc:
        raise VirusTotalError("VirusTotal sent an answer this platform cannot read") from exc

    stats = attrs.get("last_analysis_stats") or {}
    ts = attrs.get("last_analysis_date")
    return VtResult(
        status="ok",
        malicious=_int(stats.get("malicious")),
        suspicious=_int(stats.get("suspicious")),
        harmless=_int(stats.get("harmless")),
        undetected=_int(stats.get("undetected")),
        reputation=_int(attrs.get("reputation")),
        analysis_date=datetime.fromtimestamp(ts, UTC) if isinstance(ts, int | float) and ts > 0 else None,
        permalink=GUI_URL + gui_path,
    )


def _int(v: object) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None
