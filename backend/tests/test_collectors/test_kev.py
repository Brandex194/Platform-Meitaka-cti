"""Tests for CISA KEV collector."""
from unittest.mock import MagicMock, patch

_KEV_PAYLOAD = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "vendorProject": "Apache", "product": "Log4j"},
        {"cveID": "CVE-2022-30190", "dateAdded": "2022-05-31", "vendorProject": "Microsoft", "product": "MSDT"},
        {"cveID": "CVE-2023-23397", "dateAdded": "2023-03-14", "vendorProject": "Microsoft", "product": "Outlook"},
    ]
}


def _mock_resp(payload):
    m = MagicMock()
    m.json.return_value = payload
    m.raise_for_status.return_value = None
    return m


def test_kev_upserts(db_session):
    """fetch_kev returns count of entries and persists them to kev_catalog."""
    with patch("httpx.get", return_value=_mock_resp(_KEV_PAYLOAD)):
        from app.collectors.kev import fetch_kev
        count = fetch_kev(db=db_session)

    assert count == 3

    from app.db.models import KevCatalog
    rows = db_session.query(KevCatalog).all()
    assert len(rows) == 3
    cve_ids = {r.cve_id for r in rows}
    assert "CVE-2021-44228" in cve_ids


def test_kev_upsert_idempotent(db_session):
    """Running fetch_kev twice doesn't duplicate rows."""
    with patch("httpx.get", return_value=_mock_resp(_KEV_PAYLOAD)):
        from app.collectors.kev import fetch_kev
        fetch_kev(db=db_session)

    with patch("httpx.get", return_value=_mock_resp(_KEV_PAYLOAD)):
        from app.collectors.kev import fetch_kev
        count = fetch_kev(db=db_session)

    from app.db.models import KevCatalog
    rows = db_session.query(KevCatalog).all()
    assert len(rows) == 3
    assert count == 3
