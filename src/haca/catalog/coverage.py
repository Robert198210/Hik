"""Setting Catalog coverage computation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from haca.catalog.models import CatalogEntry, IsapiSource, ManualSource
from haca.collect.models import CollectionResult, DeviceCollection, EndpointOutcome
from haca.requirements.models import RequirementsProfile

CATALOG_VERSION = "1"

CoverageStatus = Literal[
    "VERIFIED_ISAPI",
    "VERIFIED_MANUAL",
    "UNSUPPORTED_BY_DEVICE",
    "INACCESSIBLE",
    "NOT_IMPLEMENTED_IN_HACA",
    "NOT_APPLICABLE",
    "NOT_ATTEMPTED",
]

InaccessibleReason = Literal[
    "field_absent",
    "endpoint_not_found",
    "auth_denied",
    "timeout",
    "connection_error",
    "parse_error",
    "blocked_by_policy",
    "device_offline",
]


class CoverageEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: str
    setting_id: str
    status: CoverageStatus
    reason: str | None
    evidence_tier: Literal["isapi", "simulation", "manual", "browser"]
    endpoint_id: str | None


class CoverageSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    catalog_version: str
    per_device: dict[str, dict[str, dict[str, int]]]
    totals: dict[str, int]
    observed_uncataloged: int


def _tier(simulated: bool) -> Literal["isapi", "simulation"]:
    return "simulation" if simulated else "isapi"


def _flatten_keys(device: DeviceCollection, endpoint_id: str) -> dict[str, str]:
    prefix = f"{endpoint_id}:"
    return {
        key[len(prefix) :]: value
        for key, value in device.flattened.items()
        if key.startswith(prefix)
    }


def _field_present(flat: dict[str, str], field: str) -> bool:
    if field in flat:
        return True
    normalized_field = field.replace("[", ".").replace("]", "")
    segments = [segment for segment in normalized_field.split(".") if segment]
    for key in flat:
        if (key.endswith(f".{field}") or key == field.split(".")[-1]) and field in key:
            return True
        normalized = key.replace("[", ".").replace("]", "")
        if all(segment in normalized for segment in segments):
            return True
    if field.startswith("AdminAccessProtocol."):
        parts = field.split(".")
        if len(parts) == 3:
            protocol, leaf = parts[1], parts[2]
            for key in flat:
                if protocol in key and key.endswith(f".{leaf}"):
                    return True
    bracketed = field.replace("[", ".").replace("]", "")
    return any(bracketed in key.replace("[", ".").replace("]", "") for key in flat)


def _outcome_to_coverage(
    outcome: EndpointOutcome,
    *,
    field_ok: bool,
) -> tuple[CoverageStatus, str | None]:
    if outcome == EndpointOutcome.COLLECTED:
        if field_ok:
            return "VERIFIED_ISAPI", None
        return "INACCESSIBLE", "field_absent"
    mapping: dict[EndpointOutcome, tuple[CoverageStatus, str]] = {
        EndpointOutcome.NOT_SUPPORTED: ("UNSUPPORTED_BY_DEVICE", "not_support"),
        EndpointOutcome.SKIPPED_CAPABILITY: ("UNSUPPORTED_BY_DEVICE", "capability_false"),
        EndpointOutcome.ENDPOINT_NOT_FOUND: ("INACCESSIBLE", "endpoint_not_found"),
        EndpointOutcome.AUTH_DENIED: ("INACCESSIBLE", "auth_denied"),
        EndpointOutcome.TIMEOUT: ("INACCESSIBLE", "timeout"),
        EndpointOutcome.CONNECTION_ERROR: ("INACCESSIBLE", "connection_error"),
        EndpointOutcome.PARSE_ERROR: ("INACCESSIBLE", "parse_error"),
        EndpointOutcome.BLOCKED_BY_POLICY: ("INACCESSIBLE", "blocked_by_policy"),
        EndpointOutcome.SKIPPED_DEVICE_OFFLINE: ("INACCESSIBLE", "device_offline"),
    }
    status, reason = mapping.get(outcome, ("INACCESSIBLE", "parse_error"))
    return status, reason


def _applicable(entry: CatalogEntry, device_role: str) -> bool:
    return device_role in entry.device_roles


def _manual_status(
    source: ManualSource,
    device_id: str,
    manual: dict[str, dict[str, object]] | None,
) -> tuple[CoverageStatus, str | None, str | None]:
    if manual and device_id in manual and source.checklist_id in manual[device_id]:
        return "VERIFIED_MANUAL", None, None
    return "NOT_IMPLEMENTED_IN_HACA", None, None


def compute_coverage(
    catalog: tuple[CatalogEntry, ...],
    collection: CollectionResult,
    orp: RequirementsProfile | None,
    *,
    manual: dict[str, dict[str, object]] | None = None,
) -> list[CoverageEntry]:
    _ = orp
    tier = _tier(collection.simulated)
    entries: list[CoverageEntry] = []

    for device in collection.devices:
        for item in catalog:
            if not _applicable(item, device.role):
                entries.append(
                    CoverageEntry(
                        device_id=device.device_id,
                        setting_id=item.id,
                        status="NOT_APPLICABLE",
                        reason="role",
                        evidence_tier=tier,
                        endpoint_id=None,
                    )
                )
                continue

            manual_sources = [s for s in item.sources if isinstance(s, ManualSource)]
            isapi_sources = [s for s in item.sources if isinstance(s, IsapiSource)]

            if manual_sources and not isapi_sources:
                status, reason, endpoint = _manual_status(
                    manual_sources[0], device.device_id, manual
                )
                entries.append(
                    CoverageEntry(
                        device_id=device.device_id,
                        setting_id=item.id,
                        status=status,
                        reason=reason,
                        evidence_tier=tier,
                        endpoint_id=endpoint,
                    )
                )
                continue

            if isapi_sources:
                source = isapi_sources[0]
                ev = device.evidence.get(source.endpoint_id)
                if ev is None:
                    cov_status: CoverageStatus = "NOT_ATTEMPTED"
                    reason = "missing_evidence"
                else:
                    flat = _flatten_keys(device, source.endpoint_id)
                    field_ok = _field_present(flat, source.field)
                    cov_status, reason = _outcome_to_coverage(ev.outcome, field_ok=field_ok)
                entries.append(
                    CoverageEntry(
                        device_id=device.device_id,
                        setting_id=item.id,
                        status=cov_status,
                        reason=reason,
                        evidence_tier=tier,
                        endpoint_id=source.endpoint_id,
                    )
                )
    return entries


def coverage_summary(
    entries: list[CoverageEntry],
    catalog: tuple[CatalogEntry, ...],
    *,
    observed_uncataloged: int = 0,
) -> CoverageSummary:
    category_by_id = {e.id: e.category for e in catalog}
    per_device: dict[str, dict[str, dict[str, int]]] = {}
    totals: dict[str, int] = {}
    for entry in entries:
        category = category_by_id.get(entry.setting_id, "unknown")
        device_bucket = per_device.setdefault(entry.device_id, {})
        counts = device_bucket.setdefault(category, {})
        counts[entry.status] = counts.get(entry.status, 0) + 1
        totals[entry.status] = totals.get(entry.status, 0) + 1
    return CoverageSummary(
        catalog_version=CATALOG_VERSION,
        per_device=per_device,
        totals=totals,
        observed_uncataloged=observed_uncataloged,
    )


def observed_uncataloged_count(collection: CollectionResult) -> int:
    """Approximate uncataloged leaf count from flattened collector output."""
    total_leaves = sum(len(d.flattened) for d in collection.devices)
    extracted = sum(len(d.missing_fields) for d in collection.devices)
    return max(0, total_leaves - extracted)