"""CPE version matching for vulnerability enrichment."""
from packaging.version import InvalidVersion, Version


def _parse_ver(s: str | None):
    """Returns Version on success, None on InvalidVersion or None input.

    # shortcut: unparseable NVD bounds are ignored (fail-open); add manual review for OpenSSL-style CVEs
    """
    if s is None:
        return None
    try:
        return Version(s)
    except InvalidVersion:
        return None


def _same_version(a: str, b: str) -> bool:
    if a == b:
        return True
    va, vb = _parse_ver(a), _parse_ver(b)
    return va is not None and vb is not None and va == vb


def match_cpe(software_cpe: str, vuln_configurations: list[dict]) -> tuple[bool, float]:
    """Return (matched, confidence) for a software CPE against CVE configurations.

    Parses vendor/product/version from field 3/4/5 of the CPE string (cpe:2.3:type:vendor:product:version:...).
    Each config dict has 'criteria' (template CPE) and optional version range fields.
    Confidence: 0.9 for exact range match, 0.7 for wildcard version, 0.5 for product-only match.
    """
    if not software_cpe:
        return False, 0.0

    sw_parts = software_cpe.split(":")
    if len(sw_parts) < 6:
        return False, 0.0

    sw_vendor = sw_parts[3]
    sw_product = sw_parts[4]
    sw_version = sw_parts[5]

    for config in vuln_configurations:
        criteria = config.get("criteria", "")
        crit_parts = criteria.split(":")
        if len(crit_parts) < 6:
            continue

        if crit_parts[3] != sw_vendor or crit_parts[4] != sw_product:
            continue

        ver_start = config.get("versionStartIncluding")
        ver_start_excl = config.get("versionStartExcluding")
        ver_end_excl = config.get("versionEndExcluding")
        ver_end_incl = config.get("versionEndIncluding")

        if not any([ver_start, ver_start_excl, ver_end_excl, ver_end_incl]):
            crit_version = crit_parts[5]
            if crit_version in ("*", "-", ""):
                return (True, 0.7) if sw_version == "*" else (True, 0.5)
            # NVD pins a single affected version in the criteria itself (e.g. http_server:2.4.49).
            if sw_version == "*":
                return True, 0.7
            if _same_version(sw_version, crit_version):
                return True, 0.9
            continue

        if sw_version == "*":
            return True, 0.7

        try:
            sv = Version(sw_version)
        except InvalidVersion:
            return False, 0.0  # cannot determine if affected when version is unparseable

        v_start = _parse_ver(ver_start)
        if v_start is not None and not (sv >= v_start):
            continue
        v_start_excl = _parse_ver(ver_start_excl)
        if v_start_excl is not None and not (sv > v_start_excl):
            continue
        v_end_excl = _parse_ver(ver_end_excl)
        if v_end_excl is not None and not (sv < v_end_excl):
            continue
        v_end_incl = _parse_ver(ver_end_incl)
        if v_end_incl is not None and not (sv <= v_end_incl):
            continue

        return True, 0.9

    return False, 0.0
