from __future__ import annotations

from pydantic import SecretStr

from haca.collect.engine import CollectionEngine
from haca.collect.progress import (
    AI_DONE,
    AI_SEND,
    BEGIN,
    COMPARE,
    SAVING,
    AuditAnnouncer,
)
from haca.isapi.registry.loader import build_collection_policy, load_registry_entries
from haca.security.credentials import Credential, DictCredentialStore
from haca.security.egress import EgressPolicy
from haca.simulation.defaults import (
    build_simulation_network_for_scenario,
    default_resolved_devices,
    simulation_timeouts,
)


def test_announcer_prints_selected_lines_once() -> None:
    lines: list[str] = []
    announcer = AuditAnnouncer(
        {"nvr01": "nvr", "ptz01": "ptz", "cam01": "camera"},
        write=lines.append,
    )
    announcer.begin()
    announcer.device_ready("nvr01")
    announcer.device_ready("nvr01")
    announcer.device_ready("ptz01")
    announcer.device_ready("cam01")
    announcer.before_endpoint("nvr01", "system.time")
    announcer.before_endpoint("ptz01", "system.network.interfaces")
    announcer.before_endpoint("nvr01", "record.tracks")
    announcer.before_endpoint("ptz01", "smart.line_detection")
    announcer.before_endpoint("cam01", "smart.field_detection")
    announcer.before_endpoint("nvr01", "content.log_search")
    announcer.before_endpoint("ptz01", "content.log_search")
    announcer.before_endpoint("nvr01", "content.record_search")
    announcer.compare()
    announcer.sending_summary()
    announcer.gemini_replied()
    announcer.saving_report()
    assert lines == [
        BEGIN,
        "NVR odpowiada",
        "Kamera obrotowa odpowiada",
        "Kamera stała odpowiada",
        "Czytam czas i sieć",
        "Czytam harmonogram nagrywania",
        "Czytam detekcję linii i strefy",
        "Szukam dziennika z ostatnich 24 godzin",
        "Szukam nagrań na torach 101 i 201",
        COMPARE,
        AI_SEND,
        AI_DONE,
        SAVING,
    ]


def test_collection_announces_ready_devices_and_search_reads() -> None:
    registry = load_registry_entries()
    network = build_simulation_network_for_scenario("clean")
    devices = list(default_resolved_devices())
    cred = Credential(username="synthetic", password=SecretStr("synthetic-pass"))
    ready: list[str] = []
    started: list[str] = []
    engine = CollectionEngine(
        registry,
        build_collection_policy(registry),
        EgressPolicy({d.host for d in devices}),
        DictCredentialStore({d.id: cred for d in devices}),
        simulation_timeouts(),
        lambda _d: network.transport(),
    )
    engine.collect(
        devices,
        simulated=True,
        on_device_ready=ready.append,
        on_before_read=lambda _device, endpoint: started.append(endpoint),
    )
    assert ready == ["nvr01", "ptz01", "cam01"]
    assert "record.tracks" in started
    assert "content.log_search" in started
    assert "content.record_search" in started
    assert started.count("content.log_search") == 3
