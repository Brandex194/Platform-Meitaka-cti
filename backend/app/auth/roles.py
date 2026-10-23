from enum import Enum

from fastapi import Depends, HTTPException

from app.auth.jwks import decode_token
from app.core.errors import error_response


class Role(str, Enum):
    super_admin = "super_admin"
    tenant_admin = "tenant_admin"
    analyst = "analyst"
    viewer = "viewer"
    api_user = "api_user"


def require_roles(*roles: Role):
    """Returns a FastAPI dependency (or callable for direct test use) that
    verifies the token payload contains at least one of the required roles."""

    def _check(payload: dict = Depends(decode_token)) -> dict:
        token_roles = payload.get("roles") or payload.get("realm_access", {}).get("roles", [])
        if not any(r.value in token_roles for r in roles):
            raise HTTPException(
                status_code=403,
                detail=error_response("FORBIDDEN", "Insufficient permissions"),
            )
        return payload

    return _check
