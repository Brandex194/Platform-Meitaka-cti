"""STIX 2.1 indicator patterns <-> (type, value) of our observables.

We write and read only the simplest pattern, a single comparison: `[ipv4-addr:value = '1.2.3.4']`.
Patterns that combine comparisons (AND, OR, FOLLOWEDBY, REPEATS, WITHIN...) or use other operators
are refused with a reason on import, never guessed.
"""
import ipaddress
import re

# our ioc_type -> how the hash type is picked from the length
_HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
_HASH_BY_NAME = {v: k for k, v in _HASH_NAMES.items()}

_SIMPLE = re.compile(
    r"^\s*\[\s*(?P<obj>[a-z0-9-]+):(?P<path>[A-Za-z0-9_.'\"-]+)\s*=\s*'(?P<val>(?:[^'\\]|\\.)*)'\s*\]\s*$"
)
_HASH_PATH = re.compile(r"^hashes\.(?:'(?P<q>[^']+)'|\"(?P<d>[^\"]+)\"|(?P<u>[A-Za-z0-9-]+))$")


class PatternError(ValueError):
    """The pattern is valid STIX but not one this platform can store."""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def _ip_version(value: str) -> int | None:
    try:
        return ipaddress.ip_address(value.strip()).version
    except ValueError:
        return None


def to_pattern(ioc_type: str, value: str) -> str | None:
    """Pattern for one observable, or None when it cannot be expressed (e.g. a hash of odd length)."""
    v = _escape(value)
    if ioc_type == "ip":
        version = _ip_version(value)
        if version is None:
            return None
        return f"[{'ipv6-addr' if version == 6 else 'ipv4-addr'}:value = '{v}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{v}']"
    if ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{v}']"
    if ioc_type == "hash":
        name = _HASH_NAMES.get(len(value))
        return f"[file:hashes.'{name}' = '{v}']" if name else None
    return None


def from_pattern(pattern: str) -> tuple[str, str]:
    """(ioc_type, value) of a single-comparison pattern; PatternError otherwise."""
    m = _SIMPLE.match(pattern or "")
    if not m:
        raise PatternError("pattern is not a single comparison")
    obj, path, value = m.group("obj"), m.group("path"), _unescape(m.group("val"))
    if obj in ("ipv4-addr", "ipv6-addr") and path == "value":
        return "ip", value
    if obj == "domain-name" and path == "value":
        return "domain", value
    if obj == "url" and path == "value":
        return "url", value
    if obj == "email-addr" and path == "value":
        return "email", value
    if obj == "file":
        h = _HASH_PATH.match(path)
        if h:
            name = (h.group("q") or h.group("d") or h.group("u")).upper()
            if name in _HASH_BY_NAME:
                return "hash", value
            raise PatternError(f"hash type {name} not supported")
    raise PatternError(f"{obj}:{path} is not an observable type this platform stores")
