"""API keys: format, hashing and lookup (passo 8).

A key looks like `mk_<8 chars of prefix>_<32 random chars>`. Only its SHA-256 is stored, so a leaked
database does not leak working keys. A valid key authenticates as role `api_user` of its own tenant.
"""
import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import ApiKey

KEY_PREFIX = "mk_"
API_KEY_HEADER = "X-API-Key"


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Return (raw key, visible prefix, sha-256). The raw key is shown to the user once."""
    visible = secrets.token_hex(4)
    raw = f"{KEY_PREFIX}{visible}_{secrets.token_urlsafe(24)}"
    return raw, f"{KEY_PREFIX}{visible}", hash_key(raw)


def key_status(key: ApiKey, now: datetime | None = None) -> str:
    """active | expired | revoked (revoked wins)."""
    now = now or datetime.now(UTC)
    if key.revoked_at is not None:
        return "revoked"
    expires = _aware(key.expires_at)
    if expires is not None and expires <= now:
        return "expired"
    return "active"


def authenticate_key(db: Session, raw: str, now: datetime | None = None) -> dict | None:
    """Token-like payload for a valid key, or None for an unknown, expired or revoked one."""
    if not raw.startswith(KEY_PREFIX):
        return None
    key = db.execute(select(ApiKey).where(ApiKey.key_hash == hash_key(raw))).scalar_one_or_none()
    now = now or datetime.now(UTC)
    if key is None or key_status(key, now) != "active":
        return None
    key.last_used_at = now
    return {
        "sub": str(key.id),
        "tenant_id": str(key.tenant_id),
        "roles": ["api_user"],
        "auth": "api_key",
        "api_key_id": str(key.id),
    }


def new_id() -> uuid.UUID:
    return uuid.uuid4()
