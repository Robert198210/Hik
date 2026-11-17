"""High-level helpers for collection runs."""

from __future__ import annotations

import time

import httpx

from haca.catalog.coverage import (
    CoverageEntry,
    compute_coverage,
    coverage_summary,
    observed_uncataloged_count,
)
from haca.catalog.loader import load_catalog_entries
from haca.collect.engine import BeforeRead, CollectionEngine, DeviceReady
from haca.collect.models import CollectionResult
from haca.config.models import AppConfig
from haca.devices.models import ResolvedDevice
from haca.devices.network_policy import NetworkPolicy
from haca.isapi.registry.loader import build_collection_policy, load_registry_entries
from haca.security.credentials import CredentialStore
from haca.security.egress import EgressPolicy
from haca.simulation.defaults import (
    build_simulation_network_for_scenario,
    default_resolved_devices,
    simulation_credential_store,
    simulation_timeouts,
)


def run_simulated_collection(scenario: str) -> tuple[CollectionResult, list[CoverageEntry]]:
    registry = load_registry_entries()
    catalog = load_catalog_entries()
    devices = list(default_resolved_devices())
    network = build_simulation_network_for_scenario(scenario)
    transport = network.transport()

    def factory(device: ResolvedDevice) -> object:
        return transport

    engine = CollectionEngine(
        registry,
        build_collection_policy(registry),
        EgressPolicy({device.host for device in devices}),
        simulation_credential_store(),
        simulation_timeouts(),
        factory,  # type: ignore[arg-type]
    )
    result = engine.collect(devices, simulated=True)
    coverage = compute_coverage(catalog, result, None)
    return result, coverage


def run_live_collection(
    app: AppConfig,
    devices: list[ResolvedDevice],
    credentials: CredentialStore,
    *,
    on_device_ready: DeviceReady | None = None,
    on_before_read: BeforeRead | None = None,
) -> tuple[CollectionResult, list[CoverageEntry]]:
    """Read configuration from real devices. No simulation transport."""
    registry = load_registry_entries()
    catalog = load_catalog_entries()

    def factory(_device: ResolvedDevice) -> httpx.BaseTransport:
        return httpx.HTTPTransport(retries=0)

    engine = CollectionEngine(
        registry,
        build_collection_policy(registry),
        EgressPolicy({device.host for device in devices}),
        credentials,
        app.timeouts,
        factory,
        network_policy=NetworkPolicy(app.network.subnet, simulation=False),
        retry_sleep=time.sleep,
    )
    result = engine.collect(
        devices,
        simulated=False,
        on_device_ready=on_device_ready,
        on_before_read=on_before_read,
    )
    coverage = compute_coverage(catalog, result, None)
    return result, coverage


def summarize_collection(
    entries: list[CoverageEntry],
    result: CollectionResult,
) -> object:
    catalog = load_catalog_entries()
    uncataloged = observed_uncataloged_count(result)
    return coverage_summary(entries, catalog, observed_uncataloged=uncataloged)

