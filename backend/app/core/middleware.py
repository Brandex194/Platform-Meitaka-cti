import logging
import re
import uuid

import jwt
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
}

_TENANT_PATH_RE = re.compile(r"/tenants/([0-9a-fA-F-]{36})/")
_AUDIT_METHODS = {"POST", "PATCH", "DELETE"}


def _actor_id(request: Request) -> uuid.UUID | None:
    """Who made the call. Only read after the route accepted the request (status < 400), so the
    token has already been verified; the claim is not trusted before that. API keys: no actor."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    try:
        sub = jwt.decode(auth[7:], options={"verify_signature": False}).get("sub")
        return uuid.UUID(str(sub))
    except Exception:
        return None


def _client_ip(request: Request) -> str | None:
    return request.client.host[:45] if request.client else None


def _write_audit_row(
    tenant_id_str: str | None,
    method: str,
    path: str,
    status: int,
    actor_id: uuid.UUID | None = None,
    ip: str | None = None,
    via_api_key: bool = False,
) -> None:
    try:
        from app.core.config import get_settings
        # shortcut: no-op in SQLite test environments; bypass_session uses SET LOCAL (Postgres only)
        if "sqlite" in get_settings().database_url.lower():
            return

        from app.db.models import AuditLog
        from app.db.session import bypass_session

        gen = bypass_session()
        db = next(gen)
        try:
            db.add(AuditLog(
                tenant_id=uuid.UUID(tenant_id_str) if tenant_id_str else None,
                action=f"{method} {path}"[:255],
                actor_id=actor_id,
                ip=ip,
                status_code=status,
                payload={"via": "api_key"} if via_api_key else None,
            ))
            db.flush()
        except Exception as exc:
            logger.warning("audit: write failed: %s", exc)
            try:
                db.rollback()
                next(gen)
            except Exception:
                pass
            return
        try:
            next(gen)  # commit — StopIteration is normal
        except StopIteration:
            pass
    except Exception as exc:
        logger.warning("audit: setup failed: %s", exc)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            response.headers[k] = v
        return response


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if request.method in _AUDIT_METHODS and response.status_code < 400:
            m = _TENANT_PATH_RE.search(request.url.path)
            tenant_id_str = m.group(1) if m else None
            await run_in_threadpool(
                _write_audit_row,
                tenant_id_str,
                request.method,
                request.url.path,
                response.status_code,
                _actor_id(request),
                _client_ip(request),
                "x-api-key" in request.headers,
            )
        return response


def setup_middleware(app: FastAPI) -> None:
    from app.core.config import get_settings  # lazy: avoids Settings() at import time

    settings = get_settings()
    origins = [o.strip() for o in settings.cors_origins.split(",")]

    app.add_middleware(AuditLogMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
