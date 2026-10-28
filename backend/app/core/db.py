"""Database engine/session handling.

SQLite by default (file under ``runtime/``). Any SQLAlchemy URL works through
``NTDCP_DATABASE_URL`` (e.g. ``postgresql+psycopg://...``); the models only use
portable column types (JSON is stored with SQLAlchemy's generic JSON type).
Schema creation is done by ``init_db()`` (``Base.metadata.create_all``) – see
docs/ARCHITECTURE.md for the migration path (Alembic) when moving to Postgres.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_env


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal: sessionmaker | None = None


def get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        url = get_env().database_url
        kwargs = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        _engine = create_engine(url, future=True, **kwargs)
        if url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def _pragma(dbapi_conn, _):  # pragma: no cover - trivial
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.close()
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def reset_engine() -> None:
    """Used by tests to point the app at a fresh database."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def init_db() -> None:
    from app import models  # noqa: F401  (registers tables)
    Base.metadata.create_all(get_engine())
    from app.services.settings_service import ensure_defaults
    with session_scope() as s:
        ensure_defaults(s)


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    with session_scope() as s:
        yield s
