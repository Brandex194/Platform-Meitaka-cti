"""Encrypt and decrypt the third-party API keys that users store in the platform.

The master key comes from SECRETS_ENCRYPTION_KEY (a Fernet key). Without it nothing can be stored,
and there is no fallback key: a missing configuration is an error, not a silent plaintext.
Ciphertext is the only thing in the database; no route ever returns a key.
"""
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class VaultNotConfigured(RuntimeError):
    """SECRETS_ENCRYPTION_KEY is missing or not a valid Fernet key."""


class VaultDecryptError(RuntimeError):
    """The stored value cannot be decrypted (wrong or rotated master key)."""


def _fernet() -> Fernet:
    key = get_settings().secrets_encryption_key
    if not key:
        raise VaultNotConfigured("SECRETS_ENCRYPTION_KEY is not set")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise VaultNotConfigured("SECRETS_ENCRYPTION_KEY is not a valid Fernet key") from exc


def encrypt(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise VaultDecryptError("stored key cannot be decrypted with the current master key") from exc
