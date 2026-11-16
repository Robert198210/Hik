from __future__ import annotations

import sqlite3
from pathlib import Path

from haca.store.db import open_db


def test_migrate_v1_to_v2(tmp_path: Path) -> None:
    db = tmp_path / "v1.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA user_version = 1")
    conn.execute(
        """
        CREATE TABLE audit_runs (
            id VARCHAR(36) PRIMARY KEY,
            started_at DATETIME,
            finished_at DATETIME,
            simulated INTEGER,
            scenario VARCHAR(64),
            haca_version VARCHAR(32),
            orp_hash VARCHAR(64),
            catalog_version VARCHAR(16),
            status VARCHAR(32),
            kind VARCHAR(16)
        )
        """
    )
    conn.commit()
    conn.close()

    open_db(db)
    conn = sqlite3.connect(db)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    conn.close()
    assert version == 2
    assert "ai_calls" in tables
    assert "ai_cache" in tables