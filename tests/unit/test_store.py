from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from haca.catalog.coverage import CATALOG_VERSION
from haca.collect.runner import run_simulated_collection
from haca.store.db import SchemaVersionError, open_db
from haca.store.repositories import load_run, load_settings, save_collection, save_coverage


def test_round_trip_simulated_collection(tmp_path: Path) -> None:
    result, coverage = run_simulated_collection("clean")
    db = tmp_path / "haca.db"
    _, factory = open_db(db)
    with factory() as session:
        run_id = save_collection(
            session,
            result,
            orp_hash=None,
            catalog_version=CATALOG_VERSION,
            scenario="clean",
        )
        save_coverage(session, run_id, coverage)
        loaded = load_run(session, run_id)
        assert loaded is not None
        settings = load_settings(session, run_id)
        assert settings
        assert len(settings) == sum(len(d.flattened) for d in result.devices)


def test_schema_version_guard(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    db.write_bytes(b"")
    import sqlite3

    conn = sqlite3.connect(db)
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(SchemaVersionError):
        open_db(db)


def test_gzip_body_round_trip_sha256(tmp_path: Path) -> None:
    result, _ = run_simulated_collection("clean")
    db = tmp_path / "haca.db"
    _, factory = open_db(db)
    with factory() as session:
        run_id = save_collection(
            session,
            result,
            orp_hash=None,
            catalog_version=CATALOG_VERSION,
            scenario="clean",
        )
        from sqlalchemy import select

        from haca.store.models import RawResponseRow

        row = session.scalars(
            select(RawResponseRow).where(RawResponseRow.run_id == run_id).limit(1)
        ).first()
        assert row is not None
        assert row.body_gz is not None
        assert row.sha256 is not None
        assert gzip.decompress(row.body_gz)  # must not raise


def test_db_bytes_exclude_simulation_password(tmp_path: Path) -> None:
    result, coverage = run_simulated_collection("clean")
    db = tmp_path / "haca.db"
    _, factory = open_db(db)
    with factory() as session:
        run_id = save_collection(
            session,
            result,
            orp_hash=None,
            catalog_version=CATALOG_VERSION,
            scenario="clean",
        )
        save_coverage(session, run_id, coverage)
    blob = db.read_bytes()
    assert b"synthetic-pass" not in blob