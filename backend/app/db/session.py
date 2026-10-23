import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings

# Lazy init: engine is created on first session factory call, not at import time,
# so tests that never touch the DB don't need DATABASE_URL set.
_engine = None
_SessionLocal = None


def _get_session_local():
    global _engine, _SessionLocal
    if _SessionLocal is None:
        _engine = create_engine(get_settings().database_url)
        _SessionLocal = sessionmaker(_engine)
    return _SessionLocal


# Module-level aliases for callers that import engine/SessionLocal directly.
# Accessing these triggers lazy init, which is acceptable at route startup.
class _LazyEngine:
    def __getattr__(self, name):
        return getattr(_get_session_local().kw["bind"], name)


engine = _LazyEngine()
SessionLocal = property(_get_session_local)  # shortcut: use _get_session_local() directly


def get_db():
    """Plain session generator for system/background use (no RLS)."""
    Session = _get_session_local()
    with Session() as session:
        yield session


def get_tenant_scoped_db(tenant_id: uuid.UUID):
    """Dependency that yields a session scoped to the given tenant via SET LOCAL."""
    Session = _get_session_local()
    with Session() as session:
        # shortcut: SET LOCAL only works inside a transaction on PostgreSQL;
        # SQLite will error — mock this dependency in unit tests.
        session.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))
        yield session


def bypass_session():
    """Yields a session with RLS bypass flag set."""
    Session = _get_session_local()
    with Session() as session:
        session.execute(text("SET LOCAL app.bypass_tenant_scope = 'on'"))
        yield session
