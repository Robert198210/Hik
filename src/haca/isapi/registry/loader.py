"""Load and validate the ISAPI endpoint registry from packaged YAML."""

from __future__ import annotations

from importlib import resources
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from haca.security.denylist import is_denied_path
from haca.security.endpoint_policy import EndpointPolicy, EndpointRule
from haca.security.errors import PolicyViolation

_REGISTRY_PACKAGE = "haca.isapi.registry"
_REGISTRY_FILE = "endpoints.yaml"

_DeviceRole = Literal["nvr", "ptz", "camera"]
_Verification = Literal["observed_live", "documented", "candidate_unverified"]
_Sensitivity = Literal["normal", "sensitive", "denied"]
_Method = Literal["GET", "POST"]

_DEFAULT_SOURCE = "Hikvision ISAPI generic resource; HACA candidate list v1; verify live"


class RegistryEntry(BaseModel):
    """One registry row with policy and collection metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    path: str
    method: _Method = "GET"
    read_post: bool = False
    post_root_elements: tuple[str, ...] = ()
    device_roles: tuple[_DeviceRole, ...]
    variants: tuple[str, ...] = ()
    capability_gate: str | None = None
    sensitivity: _Sensitivity = "normal"
    redaction_profile: str = "identity"
    verification: _Verification
    source: str
    notes: str = ""

    @field_validator("source")
    @classmethod
    def _source_non_empty(cls, value: str) -> str:
        if not value.strip():
            msg = "registry entry requires a non-empty source"
            raise ValueError(msg)
        return value

    @field_validator("post_root_elements", mode="before")
    @classmethod
    def _coerce_post_roots(cls, value: object) -> object:
        if value is None:
            return ()
        return value


class RegistryValidationError(ValueError):
    """Raised when registry YAML fails lint rules."""


def registry_yaml_bytes() -> bytes:
    ref = resources.files(_REGISTRY_PACKAGE) / _REGISTRY_FILE
    return ref.read_bytes()


def _params_for_template(path_template: str) -> dict[str, int]:
    params: dict[str, int] = {}
    if "{channel}" in path_template:
        params["channel"] = 1
    if "{id}" in path_template:
        params["id"] = 1
    if "{track}" in path_template:
        params["track"] = 1
    return params


def _render_sample_path(path_template: str) -> str:
    """Substitute path placeholders for denylist lint (channel/id/track = 1)."""
    path = path_template
    for name, value in _params_for_template(path_template).items():
        path = path.replace(f"{{{name}}}", str(value))
    return path


def _entry_to_rule(entry: RegistryEntry) -> EndpointRule:
    return EndpointRule(
        id=entry.id,
        path_template=entry.path,
        method=entry.method,
        read_post=entry.read_post,
        allowed_query=frozenset(),
        sensitivity=entry.sensitivity,
        post_root_elements=frozenset(entry.post_root_elements),
    )


def _lint_entry(entry: RegistryEntry, *, policy: EndpointPolicy | None = None) -> None:
    if entry.read_post and not entry.post_root_elements:
        msg = f"{entry.id}: read_post requires post_root_elements"
        raise RegistryValidationError(msg)

    if entry.sensitivity == "denied":
        return

    sample = _render_sample_path(entry.path)
    if is_denied_path(sample):
        msg = f"{entry.id}: primary path {sample!r} matches denylist"
        raise RegistryValidationError(msg)

    for variant in entry.variants:
        variant_sample = _render_sample_path(variant)
        if is_denied_path(variant_sample):
            msg = f"{entry.id}: variant path {variant_sample!r} matches denylist"
            raise RegistryValidationError(msg)

    if policy is not None:
        try:
            policy.render(entry.id, **_params_for_template(entry.path))
        except PolicyViolation as exc:
            msg = f"{entry.id}: policy render failed: {exc}"
            raise RegistryValidationError(msg) from exc


def _parse_raw_entries(raw: Any) -> list[RegistryEntry]:
    if not isinstance(raw, list):
        msg = "endpoints.yaml root must be a sequence"
        raise RegistryValidationError(msg)

    entries: list[RegistryEntry] = []
    errors: list[str] = []
    for index, item in enumerate(raw):
        try:
            entries.append(RegistryEntry.model_validate(item))
        except ValidationError as exc:
            errors.append(f"item {index}: {exc}")
    if errors:
        raise RegistryValidationError("; ".join(errors))
    return entries


def load_registry_entries(*, yaml_bytes: bytes | None = None) -> tuple[RegistryEntry, ...]:
    """Load registry entries from package data or explicit bytes."""
    data = yaml_bytes if yaml_bytes is not None else registry_yaml_bytes()
    raw = yaml.safe_load(data)
    entries = _parse_raw_entries(raw)

    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            msg = f"duplicate registry id {entry.id!r}"
            raise RegistryValidationError(msg)
        seen.add(entry.id)

    rules = [_entry_to_rule(e) for e in entries]
    policy = EndpointPolicy(rules)

    for entry in entries:
        _lint_entry(entry, policy=policy)

    return tuple(entries)


def build_policy(
    entries: tuple[RegistryEntry, ...] | None = None,
) -> EndpointPolicy:
    """Build an allowlist policy from registry entries (includes denied metadata rules)."""
    resolved = entries if entries is not None else load_registry_entries()
    return EndpointPolicy([_entry_to_rule(e) for e in resolved])


def entries_for_role(
    entries: tuple[RegistryEntry, ...],
    role: _DeviceRole,
) -> tuple[RegistryEntry, ...]:
    return tuple(e for e in entries if role in e.device_roles)


def render_endpoint_path(
    entry: RegistryEntry,
    *,
    channel: int = 1,
    id_: int = 1,
    track: int = 1,
) -> str:
    """Render a concrete path for simulation fixtures."""
    path = entry.path
    path = path.replace("{channel}", str(channel))
    path = path.replace("{id}", str(id_))
    path = path.replace("{track}", str(track))
    return path


def all_registry_paths(entries: tuple[RegistryEntry, ...]) -> frozenset[str]:
    """Template paths for static analysis (primary + variants)."""
    paths: set[str] = set()
    for entry in entries:
        paths.add(entry.path)
        paths.update(entry.variants)
    return frozenset(paths)