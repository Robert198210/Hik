"""SQLite database lifecycle."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from haca.store.models import Base

_SCHEMA_VERSION = 1


class SchemaVersionError(RuntimeError):
    pass


def open_db(path: Path) -> tuple[Engine, sessionmaker[Session]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}", future=True)
    with engine.connect() as conn:
        current = conn.execute(text("PRAGMA user_version")).scalar_one()
    if current == 0:
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            conn.execute(text(f"PRAGMA user_version = {_SCHEMA_VERSION}"))
    elif current != _SCHEMA_VERSION:
        msg = f"unsupported database schema version {current} (expected {_SCHEMA_VERSION})"
        raise SchemaVersionError(msg)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    return engine, factory