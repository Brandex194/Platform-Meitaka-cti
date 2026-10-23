"""Tenant-scoped DB dependency with RLS enforcement and commit-on-success."""
import uuid
from typing import Generator

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.jwks import decode_token
from app.auth.roles import Role
from app.core.errors import error_response
from app.db.session import get_tenant_scoped_db


def get_scoped_db(
    tenant_id: uuid.UUID,
    token: dict = Depends(decode_token),
) -> Generator[Session, None, None]:
    """Open a tenant-scoped DB session, enforce tenant match, commit on success."""
    token_roles = token.get("roles") or token.get("realm_access", {}).get("roles", [])
    # super_admin can access any tenant
    if Role.super_admin.value not in token_roles:
        token_tenant = token.get("tenant_id")
        if not token_tenant or str(token_tenant) != str(tenant_id):
            raise HTTPException(
                status_code=403,
                detail=error_response("FORBIDDEN", "Tenant mismatch"),
            )
    gen = get_tenant_scoped_db(str(tenant_id))
    db = next(gen)
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        try:
            next(gen)
        except StopIteration:
            pass
