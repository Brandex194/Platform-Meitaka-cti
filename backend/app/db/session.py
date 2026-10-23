import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings


def _make_engine():
    return create_engine(get_settings().database_url)


engine = _make_engine()
SessionLocal = sessionmaker(engine)


def get_db():
    """Plain session generator for system/background use (no RLS)."""
    with SessionLocal() as session:
        yield session


def get_tenant_scoped_db(tenant_id: uuid.UUID):
    """Dependency yielding a session scoped to the given tenant via SET LOCAL."""
    db = SessionLocal()
    try:
        with db.begin():
            db.execute(text("SELECT set_config('app.current_tenant_id', :tid, true)"), {"tid": str(tenant_id)})
            yield db
    finally:
        db.close()


def bypass_session():
    """Yields a session with RLS bypass flag set."""
    db = SessionLocal()
    try:
        with db.begin():
            db.execute(text("SET LOCAL app.bypass_tenant_scope = 'on'"))
            yield db
    finally:
        db.close()
