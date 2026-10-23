from functools import lru_cache

import jwt

from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_jwks_client() -> jwt.PyJWKClient:
    s = get_settings()
    url = f"{s.keycloak_url}/realms/{s.keycloak_realm}/protocol/openid-connect/certs"
    return jwt.PyJWKClient(url)


def decode_token(token: str) -> dict:
    s = get_settings()
    client = get_jwks_client()
    signing_key = client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="sentinel-ai",
        issuer=f"{s.keycloak_url}/realms/{s.keycloak_realm}",
    )
