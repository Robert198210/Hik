"""Persistence repositories."""

from __future__ import annotations

import gzip
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from haca import __version__
from haca.catalog.coverage import CoverageEntry
from haca.collect.models import CollectionResult
from haca.store.models import AuditRunRow, CoverageRow, RawResponseRow, RunDeviceRow, SettingRow


def save_collection(
    session: Session,
    result: CollectionResult,
    *,
    orp_hash: str | None,
    catalog_version: str,
    scenario: str | None,
) -> str:
    run_id = str(uuid.uuid4())
    session.add(
        AuditRunRow(
            id=run_id,
            started_at=result.run_started,
            finished_at=result.run_finished,
            simulated=1 if result.simulated else 0,
            scenario=scenario,
            haca_version=__version__,
            orp_hash=orp_hash,
            catalog_version=catalog_version,
            status="completed",
            kind="collect",
        )
    )
    for device in result.devices:
        identity = device.identity
        session.add(
            RunDeviceRow(
                run_id=run_id,
                device_id=device.device_id,
                role=device.role,
                model=identity.model if identity else None,
                firmware=identity.firmware_version if identity else None,
                identity_status="IDENTIFIED" if identity else None,
            )
        )
        for ev in device.evidence.values():
            body_gz = gzip.compress(ev.body) if ev.body else None
            session.add(
                RawResponseRow(
                    run_id=run_id,
                    device_id=device.device_id,
                    endpoint_id=ev.endpoint_id,
                    path=ev.path,
                    outcome=ev.outcome.value,
                    http_status=ev.http_status,
                    sub_status_code=ev.sub_status_code,
                    sha256=ev.sha256,
                    body_gz=body_gz,
                    collected_at=ev.collected_at,
                    elapsed_ms=ev.elapsed_ms,
                )
            )
        for flat_key, value in device.flattened.items():
            if ":" not in flat_key:
                continue
            endpoint_id, path = flat_key.split(":", 1)
            session.add(
                SettingRow(
                    run_id=run_id,
                    device_id=device.device_id,
                    endpoint_id=endpoint_id,
                    path=path,
                    value=value,
                )
            )
    session.commit()
    return run_id


def save_coverage(session: Session, run_id: str, entries: list[CoverageEntry]) -> None:
    for entry in entries:
        session.add(
            CoverageRow(
                run_id=run_id,
                device_id=entry.device_id,
                setting_id=entry.setting_id,
                status=entry.status,
                reason=entry.reason,
                evidence_tier=entry.evidence_tier,
                endpoint_id=entry.endpoint_id,
            )
        )
    session.commit()


def list_runs(session: Session, limit: int = 20) -> list[AuditRunRow]:
    stmt = select(AuditRunRow).order_by(AuditRunRow.started_at.desc()).limit(limit)
    return list(session.scalars(stmt))


def load_run(session: Session, run_id: str) -> AuditRunRow | None:
    return session.get(AuditRunRow, run_id)


def load_settings(session: Session, run_id: str) -> dict[tuple[str, str], str]:
    stmt = select(SettingRow).where(SettingRow.run_id == run_id)
    rows = session.scalars(stmt)
    return {(row.device_id, row.path): row.value for row in rows}