import logging
import re
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
}

_TENANT_PATH_RE = re.compile(r"/tenants/([0-9a-f-]{36})/")
_AUDIT_METHODS = {"POST", "PATCH", "DELETE"}


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
            if m:
                try:
                    from app.db.models import AuditLog
                    from app.db.session import SessionLocal
                    tenant_id = uuid.UUID(m.group(1))
                    with SessionLocal() as session:
                        session.add(AuditLog(
                            tenant_id=tenant_id,
                            action=f"{request.method.lower()}:{request.url.path}",
                        ))
                        session.commit()
                except Exception:
                    # shortcut: best-effort audit; upgrade to reliable store in Phase 3
                    logger.debug("audit log write failed (non-fatal)", exc_info=True)
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
