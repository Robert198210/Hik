"""ORM models for the SQLite snapshot store."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BLOB, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AuditRunRow(Base):
    __tablename__ = "audit_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    simulated: Mapped[int] = mapped_column(Integer)
    scenario: Mapped[str | None] = mapped_column(String(64), nullable=True)
    haca_version: Mapped[str] = mapped_column(String(32))
    orp_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    catalog_version: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(16))


class RunDeviceRow(Base):
    __tablename__ = "run_devices"
    __table_args__ = (Index("ix_run_devices_run_device", "run_id", "device_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(36))
    device_id: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(16))
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    firmware: Mapped[str | None] = mapped_column(String(128), nullable=True)
    identity_status: Mapped[str | None] = mapped_column(String(32), nullable=True)


class RawResponseRow(Base):
    __tablename__ = "raw_responses"
    __table_args__ = (Index("ix_raw_responses_run_device", "run_id", "device_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(36))
    device_id: Mapped[str] = mapped_column(String(64))
    endpoint_id: Mapped[str] = mapped_column(String(128))
    path: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(String(32))
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sub_status_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    body_gz: Mapped[bytes | None] = mapped_column(BLOB, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    elapsed_ms: Mapped[float] = mapped_column(Float)


class SettingRow(Base):
    __tablename__ = "settings"
    __table_args__ = (Index("ix_settings_run_device", "run_id", "device_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(36))
    device_id: Mapped[str] = mapped_column(String(64))
    endpoint_id: Mapped[str] = mapped_column(String(128))
    path: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)


class CoverageRow(Base):
    __tablename__ = "coverage"
    __table_args__ = (Index("ix_coverage_run_device", "run_id", "device_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(36))
    device_id: Mapped[str] = mapped_column(String(64))
    setting_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_tier: Mapped[str] = mapped_column(String(16))
    endpoint_id: Mapped[str | None] = mapped_column(String(128), nullable=True)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_run", "run_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(36))
    finding_id: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(64))
    classification: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    payload_json: Mapped[str] = mapped_column(Text)


class AiCallRow(Base):
    __tablename__ = "ai_calls"
    __table_args__ = (Index("ix_ai_calls_run", "run_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(36))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64))
    input_tokens: Mapped[int] = mapped_column(Integer)
    output_tokens: Mapped[int] = mapped_column(Integer)
    total_tokens: Mapped[int] = mapped_column(Integer)
    est_cost: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))


class AiCacheRow(Base):
    __tablename__ = "ai_cache"

    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    response_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))