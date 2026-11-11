from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.errors import error_response

_bearer = HTTPBearer(auto_error=False)


class TokenData(BaseModel):
    sub: str
    tenant_id: str | None = None
    roles: list[str] = []


@lru_cache(maxsize=1)
def get_jwks_client() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwks_url())


def jwks_url() -> str:
    """JWKS endpoint; prefers KEYCLOAK_INTERNAL_URL so containers can reach Keycloak
    while the issuer check keeps using the public KEYCLOAK_URL."""
    s = get_settings()
    base = (s.keycloak_internal_url or s.keycloak_url).rstrip("/")
    return f"{base}/realms/{s.keycloak_realm}/protocol/openid-connect/certs"


def _decode_jwt(raw: str) -> dict:
    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(raw)
        settings = get_settings()
        return jwt.decode(
            raw,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.keycloak_client_id,
            issuer=f"{settings.keycloak_url}/realms/{settings.keycloak_realm}",
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail=error_response("UNAUTHORIZED", "Invalid or expired token"),
        ) from exc


def _lookup_api_key(raw: str) -> dict | None:
    """Look the key up in a bypass session: the tenant is not known until the key is found.
    Tests replace this function."""
    from app.auth.api_keys import authenticate_key
    from app.db.session import bypass_session

    gen = bypass_session()
    db = next(gen)
    try:
        payload = authenticate_key(db, raw)
    except Exception:
        gen.close()
        raise
    try:
        next(gen)  # commit last_used_at
    except StopIteration:
        pass
    return payload


def decode_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if credentials is not None:
        return _decode_jwt(credentials.credentials)
    raw_key = request.headers.get("X-API-Key")
    if raw_key:
        payload = _lookup_api_key(raw_key)
        if payload is None:
            raise HTTPException(
                status_code=401,
                detail=error_response("UNAUTHORIZED", "Invalid, expired or revoked API key"),
            )
        return payload
    raise HTTPException(
        status_code=401,
        detail=error_response("UNAUTHORIZED", "Missing or invalid token"),
    )


def verify_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> TokenData:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail=error_response("UNAUTHORIZED", "Missing or invalid token"),
        )
    payload = _decode_jwt(credentials.credentials)
    roles = payload.get("roles") or payload.get("realm_access", {}).get("roles", [])
    return TokenData(sub=payload["sub"], tenant_id=payload.get("tenant_id"), roles=roles)
