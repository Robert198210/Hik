"""SQLite database lifecycle."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from haca.store.models import Base

_SCHEMA_VERSION = 2


class SchemaVersionError(RuntimeError):
    pass


def migrate_v1_to_v2(conn: Connection) -> None:
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS ai_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id VARCHAR(36) NOT NULL,
                model VARCHAR(128) NOT NULL,
                prompt_version VARCHAR(64) NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                total_tokens INTEGER NOT NULL,
                est_cost FLOAT,
                latency_ms INTEGER NOT NULL,
                payload_sha256 VARCHAR(64) NOT NULL,
                status VARCHAR(32) NOT NULL
            )
            """
        )
    )
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ai_calls_run ON ai_calls (run_id)"))
    conn.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS ai_cache (
                cache_key VARCHAR(64) PRIMARY KEY,
                response_json TEXT NOT NULL,
                created_at DATETIME NOT NULL
            )
            """
        )
    )


def open_db(path: Path) -> tuple[Engine, sessionmaker[Session]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}", future=True)
    with engine.connect() as conn:
        current = conn.execute(text("PRAGMA user_version")).scalar_one()
    if current == 0:
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            conn.execute(text(f"PRAGMA user_version = {_SCHEMA_VERSION}"))
    elif current == 1:
        with engine.begin() as conn:
            migrate_v1_to_v2(conn)
            conn.execute(text(f"PRAGMA user_version = {_SCHEMA_VERSION}"))
    elif current != _SCHEMA_VERSION:
        msg = f"unsupported database schema version {current} (expected {_SCHEMA_VERSION})"
        raise SchemaVersionError(msg)
    else:
        Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    return engine, factory