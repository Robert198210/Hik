from __future__ import annotations

from pathlib import Path

from haca.catalog.coverage import CATALOG_VERSION
from haca.collect.runner import run_simulated_collection
from haca.store.db import open_db
from haca.store.diff import diff_runs
from haca.store.repositories import save_collection


def test_diff_conflicts_onvif_ignores_local_time(tmp_path: Path) -> None:
    clean, _ = run_simulated_collection("clean")
    conflicts, _ = run_simulated_collection("conflicts")
    db = tmp_path / "haca.db"
    _, factory = open_db(db)
    with factory() as session:
        run_a = save_collection(
            session,
            clean,
            orp_hash=None,
            catalog_version=CATALOG_VERSION,
            scenario="clean",
        )
        run_b = save_collection(
            session,
            conflicts,
            orp_hash=None,
            catalog_version=CATALOG_VERSION,
            scenario="conflicts",
        )
        diff = diff_runs(session, session, run_a, run_b)
    onvif = [c for c in diff.changed if "proxyProtocol" in c[1]]
    assert onvif
    local_time = [c for c in diff.changed if c[1].endswith("localTime")]
    assert not local_time