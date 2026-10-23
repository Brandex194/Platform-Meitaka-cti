"""MITRE ATT&CK collector — fetches enterprise attack patterns and upserts into DB."""
import logging

import httpx

from app.db.models import AttackTechnique

logger = logging.getLogger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def fetch_attack(db=None) -> int:
    """Fetch MITRE ATT&CK STIX bundle and upsert attack-pattern objects.

    db: SQLAlchemy session; uses bypass_session() if None (production path, needs PG).
    Returns count of techniques upserted.
    """
    try:
        resp = httpx.get(ATTACK_URL, timeout=60)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("ATT&CK HTTP error: %s", exc)
        return 0

    objects = resp.json().get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern"]

    if db is not None:
        return _upsert(db, techniques)

    from app.db.session import bypass_session  # lazy — avoids eager engine init
    gen = bypass_session()
    _db = next(gen)
    try:
        result = _upsert(_db, techniques)
        try:
            next(gen)
        except StopIteration:
            pass
        return result
    except Exception:
        gen.close()
        raise


def _upsert(db, techniques: list) -> int:
    count = 0
    for obj in techniques:
        mitre_id = obj.get("x_mitre_id", "")
        if not mitre_id:
            continue
        name = obj.get("name", "")
        description = (obj.get("description") or "")[:2000]

        existing = db.query(AttackTechnique).filter_by(mitre_id=mitre_id).first()
        if existing:
            existing.name = name
            existing.description = description
        else:
            db.add(AttackTechnique(mitre_id=mitre_id, name=name, description=description))
        count += 1

    db.flush()
    return count
