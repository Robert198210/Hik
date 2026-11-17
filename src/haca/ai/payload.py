"""Build redacted audit payloads for Gemini."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from haca.analysis.models import Finding
from haca.catalog.coverage import CoverageEntry, CoverageSummary
from haca.catalog.models import CatalogEntry
from haca.collect.models import CollectionResult
from haca.devices.models import ResolvedDevice
from haca.reports.models import AuditReport
from haca.requirements.models import RequirementsProfile

_NAME_KEYS = frozenset(
    {
        "channelName",
        "ruleName",
        "patrolName",
        "presetName",
        "name",
    }
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SERIAL = re.compile(r"\bSYNTH-[A-Z0-9-]+\b", re.IGNORECASE)
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_DEVICE_ID = re.compile(r"\bdeviceID\b", re.IGNORECASE)
_USERNAME = re.compile(r"\buserName\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class AiPayload:
    data: dict[str, Any]
    json_text: str


def _mask_ip(value: str, subnet: IPv4Network) -> str:
    def repl(match: re.Match[str]) -> str:
        try:
            addr = IPv4Address(match.group(0))
        except ValueError:
            return match.group(0)
        if addr in subnet:
            return f"<subnet>.{int(addr) - int(subnet.network_address)}"
        return f"<subnet>.{addr.packed[-1]}"

    return _IPV4.sub(repl, value)


def _redact_value(key: str | None, value: Any, subnet: IPv4Network) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k in _NAME_KEYS and isinstance(v, str):
                out[k] = f"item-{hash(v) % 10_000:04d}"
                continue
            if k.lower() in ("serialnumber", "serial", "macaddress", "deviceid", "username"):
                continue
            out[k] = _redact_value(k, v, subnet)
        return out
    if isinstance(value, list):
        return [_redact_value(key, item, subnet) for item in value]
    if not isinstance(value, str):
        return value
    text = value
    text = _SERIAL.sub("<serial>", text)
    text = _MAC.sub("<mac>", text)
    text = _mask_ip(text, subnet)
    if key and "username" in key.lower():
        return "<username>"
    return text


def _orp_payload(orp: RequirementsProfile) -> dict[str, Any]:
    return orp.model_dump(mode="json")


def _findings_payload(findings: tuple[Finding, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in findings:
        row: dict[str, Any] = {
            "id": f.id,
            "rule_id": f.rule_id,
            "classification": f.classification.value,
            "severity": f.severity.value,
            "devices": list(f.devices),
            "current_value": f.current_value,
            "recommended_value": f.recommended_value,
            "rationale": f.rationale,
        }
        action = f.recommendation.manual_action if f.recommendation is not None else None
        if action and action != f.rationale:
            row["manual_action"] = action
        rows.append(row)
    return rows


_MAX_LOG_KINDS = 24
_GAP_STATUSES = frozenset({"INACCESSIBLE", "UNSUPPORTED_BY_DEVICE", "NOT_IMPLEMENTED_IN_HACA"})


def _evidence_payload(
    collection: CollectionResult,
    catalog: tuple[CatalogEntry, ...],
    coverage: list[CoverageEntry],
) -> dict[str, Any]:
    return {
        "logs": _log_rows(collection),
        "recordings": _recording_rows(collection),
        "gaps": _gap_rows(catalog, coverage),
    }


def _log_rows(collection: CollectionResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for device in collection.devices:
        view = device.views.log_search
        if view is None:
            continue
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for event in view.events:
            meta = (event.meta_id or "").strip()
            para = (event.para_type or "").strip()
            bucket = groups.setdefault(
                (meta, para),
                {
                    "meta_id": meta or None,
                    "para_type": para or None,
                    "count": 0,
                    "first": None,
                    "last": None,
                },
            )
            bucket["count"] = int(bucket["count"]) + 1
            stamp = event.started_at
            if not stamp:
                continue
            if bucket["first"] is None or stamp < str(bucket["first"]):
                bucket["first"] = stamp
            if bucket["last"] is None or stamp > str(bucket["last"]):
                bucket["last"] = stamp
        kinds = sorted(
            groups.values(),
            key=lambda item: (
                -int(item["count"]),
                str(item["meta_id"] or ""),
                str(item["para_type"] or ""),
            ),
        )
        rows.append(
            {
                "device_id": device.device_id,
                "num_matches": view.num_matches,
                "kinds": kinds[:_MAX_LOG_KINDS],
                "kinds_omitted": max(0, len(kinds) - _MAX_LOG_KINDS),
            }
        )
    return rows


def _recording_rows(collection: CollectionResult) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for device in collection.devices:
        view = device.views.record_search
        if view is None:
            continue
        tracks: dict[str, dict[str, Any]] = {}
        for segment in view.segments:
            track = segment.track_id or "unknown"
            bucket = tracks.setdefault(
                track,
                {
                    "track_id": track,
                    "segments": 0,
                    "first_start": None,
                    "last_end": None,
                    "types": [],
                },
            )
            bucket["segments"] = int(bucket["segments"]) + 1
            if segment.start_time and (
                bucket["first_start"] is None or segment.start_time < str(bucket["first_start"])
            ):
                bucket["first_start"] = segment.start_time
            if segment.end_time and (
                bucket["last_end"] is None or segment.end_time > str(bucket["last_end"])
            ):
                bucket["last_end"] = segment.end_time
            kind = _record_kind(segment.record_type)
            types = bucket["types"]
            if kind and isinstance(types, list) and kind not in types:
                types.append(kind)
        rows.append(
            {
                "device_id": device.device_id,
                "num_matches": view.num_matches,
                "tracks": [tracks[key] for key in sorted(tracks)],
            }
        )
    return rows


def _record_kind(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    text = text[:80]
    return text or None


def _gap_rows(
    catalog: tuple[CatalogEntry, ...],
    coverage: list[CoverageEntry],
) -> list[dict[str, Any]]:
    by_id = {entry.id: entry for entry in catalog}
    rows: list[dict[str, Any]] = []
    for entry in coverage:
        if entry.status not in _GAP_STATUSES:
            continue
        item = by_id.get(entry.setting_id)
        manual_only = bool(
            item and item.sources and all(src.kind == "manual" for src in item.sources)
        )
        if entry.status == "NOT_IMPLEMENTED_IN_HACA" and not manual_only:
            continue
        rows.append(
            {
                "device_id": entry.device_id,
                "setting_id": entry.setting_id,
                "status": "MANUAL_CHECK" if manual_only else entry.status,
                "reason": "manual_check" if manual_only else entry.reason,
            }
        )
    return rows


def _trim_payload(data: dict[str, Any], budget_chars: int) -> dict[str, Any]:
    text = json.dumps(data, separators=(",", ":"))
    if len(text) <= budget_chars:
        return data
    findings = data.get("deterministic_findings")
    if isinstance(findings, list):
        data = {
            **data,
            "deterministic_findings": [f for f in findings if f.get("classification") != "INFO"],
        }
    text = json.dumps(data, separators=(",", ":"))
    if len(text) <= budget_chars:
        return data
    devices = data.get("devices")
    if isinstance(devices, list):
        trimmed_devices = []
        for dev in devices:
            settings = dev.get("settings") or {}
            settings = {
                k: v for k, v in settings.items() if "substream" not in k and "sub_stream" not in k
            }
            trimmed_devices.append({**dev, "settings": settings})
        data = {**data, "devices": trimmed_devices}
    text = json.dumps(data, separators=(",", ":"))
    if len(text) <= budget_chars:
        return data
    if isinstance(devices, list):
        for dev in data["devices"]:
            settings = dev.get("settings") or {}
            settings = {k: v for k, v in settings.items() if "preset" not in k}
            dev["settings"] = settings
    text = json.dumps(data, separators=(",", ":"))
    if len(text) <= budget_chars:
        return data
    evidence = data.get("evidence")
    if isinstance(evidence, dict):
        slim_logs = [
            {
                "device_id": row.get("device_id"),
                "num_matches": row.get("num_matches"),
                "kinds_omitted": len(row.get("kinds") or []),
            }
            for row in evidence.get("logs") or []
            if isinstance(row, dict)
        ]
        data = {**data, "evidence": {**evidence, "logs": slim_logs}}
    return data


def build_payload(
    *,
    report: AuditReport | None,
    collection: CollectionResult,
    devices: list[ResolvedDevice],
    orp: RequirementsProfile,
    catalog: tuple[CatalogEntry, ...],
    coverage: list[CoverageEntry],
    coverage_summary: CoverageSummary,
    findings: tuple[Finding, ...],
    subnet: IPv4Network,
    budget_chars: int,
) -> AiPayload:
    from haca.ai.observed import ObservedIndex

    index = ObservedIndex(catalog, collection, coverage)
    device_rows: list[dict[str, Any]] = []
    for dev in devices:
        dc = next((d for d in collection.devices if d.device_id == dev.id), None)
        settings = index.all_verified_isapi(dev.id)
        settings = {k: _redact_value(k, v, subnet) for k, v in settings.items()}
        firmware = None
        model = dev.expected_model
        if dc and dc.identity:
            firmware = dc.identity.firmware_version
        device_rows.append(
            {
                "device_id": dev.id,
                "role": dev.role,
                "model": model,
                "firmware": firmware,
                "host": f"<subnet>.{int(dev.host.packed[-1])}",
                "settings": settings,
            }
        )
    data: dict[str, Any] = {
        "orp": _redact_value(None, _orp_payload(orp), subnet),
        "coverage_summary": coverage_summary.model_dump(mode="json"),
        "deterministic_findings": _redact_value(None, _findings_payload(findings), subnet),
        "evidence": _redact_value(None, _evidence_payload(collection, catalog, coverage), subnet),
        "devices": _redact_value(None, device_rows, subnet),
    }
    if report is not None:
        data["run_id"] = report.meta.run_id
    data = _trim_payload(data, budget_chars)
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=True)
    scrubbed = _mask_ip(text, subnet)
    scrubbed = _SERIAL.sub("<serial>", scrubbed)
    scrubbed = _MAC.sub("<mac>", scrubbed)
    if _DEVICE_ID.search(scrubbed) or _USERNAME.search(scrubbed):
        msg = "payload leak guard: forbidden identifier field names remain"
        raise ValueError(msg)
    return AiPayload(data=json.loads(scrubbed), json_text=scrubbed)
