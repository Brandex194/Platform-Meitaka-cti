"""CPE version matching for vulnerability enrichment."""
from packaging.version import InvalidVersion, Version


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
        ver_end_excl = config.get("versionEndExcluding")
        ver_end_incl = config.get("versionEndIncluding")

        if not any([ver_start, ver_end_excl, ver_end_incl]):
            return (True, 0.7) if sw_version == "*" else (True, 0.5)

        if sw_version == "*":
            return True, 0.7

        try:
            sv = Version(sw_version)
            if ver_start and not (sv >= Version(ver_start)):
                continue
            if ver_end_excl and not (sv < Version(ver_end_excl)):
                continue
            if ver_end_incl and not (sv <= Version(ver_end_incl)):
                continue
        except InvalidVersion:
            # shortcut: string lexicographic comparison for non-PEP-440 versions, may misorder e.g. "10" < "9"
            if ver_start and not (sw_version >= ver_start):
                continue
            if ver_end_excl and not (sw_version < ver_end_excl):
                continue
            if ver_end_incl and not (sw_version <= ver_end_incl):
                continue

        return True, 0.9

    return False, 0.0
