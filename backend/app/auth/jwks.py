from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException
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
    s = get_settings()
    url = f"{s.keycloak_url}/realms/{s.keycloak_realm}/protocol/openid-connect/certs"
    return jwt.PyJWKClient(url)


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


def decode_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail=error_response("UNAUTHORIZED", "Missing or invalid token"),
        )
    return _decode_jwt(credentials.credentials)


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
