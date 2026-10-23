"""Tests for CPE version matching (brief spec cases + edge cases)."""
import pytest

from app.enrichment.cpe import match_cpe


def _cfg(end_excl=None, end_incl=None, start_incl=None):
    c = {"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}
    if end_excl:
        c["versionEndExcluding"] = end_excl
    if end_incl:
        c["versionEndIncluding"] = end_incl
    if start_incl:
        c["versionStartIncluding"] = start_incl
    return c


# --- Brief spec cases ---------------------------------------------------------


def test_version_end_excluding_match_below():
    configs = [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]
    matched, conf = match_cpe("cpe:2.3:a:v:p:1.9.9:*:*:*:*:*:*:*", configs)
    assert matched is True
    assert conf == 0.9


def test_version_end_excluding_no_match_at_boundary():
    configs = [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]
    matched, _ = match_cpe("cpe:2.3:a:v:p:2.0.0:*:*:*:*:*:*:*", configs)
    assert matched is False


def test_version_end_including_matches_at_boundary():
    configs = [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndIncluding": "2.0.0"}]
    matched, _ = match_cpe("cpe:2.3:a:v:p:2.0.0:*:*:*:*:*:*:*", configs)
    assert matched is True


# --- Additional cases ---------------------------------------------------------


def test_no_version_range_returns_product_match():
    configs = [{"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}]
    matched, conf = match_cpe("cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*", configs)
    assert matched is True
    assert conf == 0.5  # no range → product match confidence


def test_wildcard_sw_version_returns_07():
    configs = [_cfg(end_excl="5.0.0")]
    matched, conf = match_cpe("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", configs)
    assert matched is True
    assert conf == 0.7


def test_vendor_mismatch_returns_false():
    configs = [{"criteria": "cpe:2.3:a:other_vendor:product:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]
    matched, _ = match_cpe("cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", configs)
    assert matched is False


def test_none_software_cpe_returns_false():
    matched, conf = match_cpe(None, [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"}])
    assert matched is False
    assert conf == 0.0


def test_empty_configs_returns_false():
    matched, conf = match_cpe("cpe:2.3:a:v:p:1.0.0:*:*:*:*:*:*:*", [])
    assert matched is False


def test_start_including_out_of_range_returns_false():
    configs = [_cfg(start_incl="2.0.0", end_excl="3.0.0")]
    matched, _ = match_cpe("cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*", configs)
    assert matched is False


def test_match_cpe_unparseable_bound_skips_check():
    """OpenSSL-style bounds like '1.1.1k' (non-PEP-440) are skipped, not raised.

    sw_version "1.1.1" IS valid PEP 440; bound "1.1.1k" is NOT.
    Pre-fix: Version("1.1.1k") raises InvalidVersion → batch abort.
    Post-fix: _parse_ver("1.1.1k") → None → bound skipped → returns (True, 0.9).
    """
    result = match_cpe(
        "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
        [{"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
          "vulnerable": True,
          "versionStartIncluding": "1.0.0",
          "versionEndExcluding": "1.1.1k"}],  # "1.1.1k" is not valid PEP 440
    )
    # versionEndExcluding "1.1.1k" is unparseable → skipped → match is True
    assert result == (True, 0.9)


def test_invalid_version_returns_not_affected():
    # truly unparseable version — cannot determine affected status, treat as not affected
    configs = [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]
    result = match_cpe("cpe:2.3:a:v:p:not-a-version:*:*:*:*:*:*:*", configs)
    assert result == (False, 0.0)
