from functools import lru_cache

import jwt
from fastapi import HTTPException
from pydantic import BaseModel

from app.core.config import get_settings


class TokenData(BaseModel):
    sub: str
    tenant_id: str | None = None
    roles: list[str] = []


@lru_cache(maxsize=1)
def get_jwks_client() -> jwt.PyJWKClient:
    s = get_settings()
    url = f"{s.keycloak_url}/realms/{s.keycloak_realm}/protocol/openid-connect/certs"
    return jwt.PyJWKClient(url)


def decode_token(token: str) -> dict:
    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        settings = get_settings()
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.keycloak_client_id,
            issuer=f"{settings.keycloak_url}/realms/{settings.keycloak_realm}",
        )
    except jwt.PyJWTError as exc:
        from app.core.errors import error_response
        raise HTTPException(
            status_code=401,
            detail=error_response("UNAUTHORIZED", "Invalid or expired token"),
        ) from exc


def verify_token(token: str) -> TokenData:
    payload = decode_token(token)
    roles = payload.get("roles") or payload.get("realm_access", {}).get("roles", [])
    return TokenData(sub=payload["sub"], tenant_id=payload.get("tenant_id"), roles=roles)
