from __future__ import annotations

from pydantic import SecretStr

from haca.collect.engine import CollectionEngine
from haca.isapi.registry.loader import build_collection_policy, load_registry_entries
from haca.security.credentials import Credential, DictCredentialStore
from haca.security.egress import EgressPolicy
from haca.simulation.defaults import (
    build_simulation_network_for_scenario,
    default_resolved_devices,
    simulation_timeouts,
)


def test_extract_tolerates_missing_elements() -> None:
    from haca.collect.extract import extract_views
    from haca.isapi.xml import parse_xml

    body = b"""<?xml version="1.0"?>
    <AdminAccessProtocolList xmlns="http://www.hikvision.com/ver20/XMLSchema"/>"""
    doc = parse_xml(body)
    missing: list[str] = []
    views = extract_views("security.admin_accesses", doc, missing)
    assert views.admin_access is not None
    assert "AdminAccessProtocol" in missing


def test_scenario_unsupported_skips_region_entrance_request() -> None:
    registry = load_registry_entries()
    network = build_simulation_network_for_scenario("unsupported")
    devices = list(default_resolved_devices())
    cred = Credential(username="synthetic", password=SecretStr("synthetic-pass"))
    store = DictCredentialStore({d.id: cred for d in devices})
    engine = CollectionEngine(
        registry,
        build_collection_policy(registry),
        EgressPolicy({d.host for d in devices}),
        store,
        simulation_timeouts(),
        lambda _d: network.transport(),
    )
    result = engine.collect(devices, simulated=True)
    cam = next(d for d in result.devices if d.device_id == "cam01")
    assert cam.evidence["smart.region_entrance"].outcome.value == "SKIPPED_CAPABILITY"
    region_paths = [
        path for _dev, _method, path in network.request_log if "regionEntrance" in path
    ]
    assert not region_paths


def test_wrong_password_auth_lockout_limits_requests() -> None:
    registry = load_registry_entries()
    network = build_simulation_network_for_scenario("clean")
    devices = list(default_resolved_devices())
    good = Credential(username="synthetic", password=SecretStr("synthetic-pass"))
    bad = Credential(username="synthetic", password=SecretStr("wrong-pass"))
    store = DictCredentialStore(
        {d.id: (bad if d.id == "nvr01" else good) for d in devices}
    )
    engine = CollectionEngine(
        registry,
        build_collection_policy(registry),
        EgressPolicy({d.host for d in devices}),
        store,
        simulation_timeouts(),
        lambda _d: network.transport(),
    )
    result = engine.collect(devices, simulated=True)
    nvr = next(d for d in result.devices if d.device_id == "nvr01")
    assert all(
        ev.outcome.value == "AUTH_DENIED"
        for eid, ev in nvr.evidence.items()
        if eid != "system.device_info"
    )
    nvr_reqs = [entry for entry in network.request_log if entry[0] == "nvr01"]
    assert len(nvr_reqs) <= 2