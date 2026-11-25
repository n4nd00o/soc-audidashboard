"""Engine/session wiring and programmatic Alembic migrations.

Transaction contract: `get_session` yields a session that NEVER auto-commits. Dependency
teardown may run after the response has been sent, so a commit there could fail after a 2xx.
Handlers/services must call `db.commit()` explicitly before returning; anything uncommitted
is rolled back when the request ends.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from audidash_server.models import Base

PACKAGE_DIR = Path(__file__).parent
MIGRATIONS_DIR = PACKAGE_DIR / "migrations"
ALEMBIC_INI = PACKAGE_DIR / "alembic.ini"


def make_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        engine = create_engine(database_url, connect_args={"check_same_thread": False})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine
    return create_engine(database_url, pool_pre_ping=True)


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(engine: Engine) -> None:
    """create_all convenience for tests/dev; production uses Alembic only."""
    Base.metadata.create_all(engine)


def get_session(request: Request) -> Iterator[Session]:
    """FastAPI dependency: never commits; rolls back anything left uncommitted."""
    factory: sessionmaker[Session] = request.app.state.sessionmaker
    with factory() as session:
        try:
            yield session
        finally:
            session.rollback()


def alembic_config(database_url: str) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["database_url"] = database_url
    return cfg


def run_migrations(database_url: str) -> None:
    command.upgrade(alembic_config(database_url), "head")
