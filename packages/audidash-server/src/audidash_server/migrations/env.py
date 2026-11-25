"""Alembic environment. The URL comes from the caller, AUDIDASH_DATABASE_URL or Settings."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import Engine

from audidash_server.db import make_engine
from audidash_server.models import Base

target_metadata = Base.metadata


def _database_url() -> str:
    url = context.config.attributes.get("database_url") or os.environ.get("AUDIDASH_DATABASE_URL")
    if not url:
        raise RuntimeError("database URL missing: set AUDIDASH_DATABASE_URL")
    return str(url)


def _configure(**kwargs: object) -> None:
    context.configure(
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
        **kwargs,  # type: ignore[arg-type]
    )


def run_migrations_offline() -> None:
    _configure(url=_database_url(), literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine: Engine = make_engine(_database_url())
    with engine.connect() as connection:
        _configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
