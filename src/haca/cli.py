"""HACA command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from enum import Enum
from pathlib import Path

from haca import __version__
from haca.collect.identify import IdentificationResult, IdentificationStatus, identify_devices
from haca.config.errors import ConfigError
from haca.config.loader import load_app_config, load_devices
from haca.config.models import AppConfig
from haca.devices.models import ResolvedDevice
from haca.devices.registry import DeviceRegistry
from haca.isapi.client import IsapiClient
from haca.isapi.registry.phase1_endpoints import build_phase1_policy
from haca.requirements.loader import load_requirements, requirements_hash
from haca.requirements.models import DeviceRequirements, RequirementsProfile, SystemRequirements
from haca.security.credentials import CredentialNotFound, CredentialStore, EnvCredentialStore
from haca.security.egress import EgressPolicy
from haca.security.redaction import install_redaction
from haca.simulation.defaults import (
    build_simulation_network,
    simulation_credential,
    simulation_registry,
    simulation_timeouts,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CONFIG = _REPO_ROOT / "config" / "haca.example.yaml"
_DEFAULT_DEVICES = _REPO_ROOT / "config" / "devices.example.yaml"
_SIMULATED_BANNER = "SIMULATED — synthetic fixtures, no real device contacted"


def _safe_terminal_text(value: str) -> str:
    return "".join(ch if 0x20 <= ord(ch) < 0x7F else " " for ch in value)


def _needs_decision_fields(profile: RequirementsProfile) -> list[str]:
    decisions: list[str] = []

    for name in SystemRequirements.model_fields:
        value = getattr(profile.system, name)
        if isinstance(value, Enum) and value.value in ("undecided", "unspecified"):
            decisions.append(f"system.{name}")

    for device_id, device_req in profile.devices.items():
        for name in DeviceRequirements.model_fields:
            value = getattr(device_req, name)
            if isinstance(value, Enum) and value.value in ("undecided", "unspecified"):
                decisions.append(f"{device_id}.{name}")

    return sorted(decisions)


def _print_identify_table(results: list[IdentificationResult]) -> None:
    headers = ("id", "status", "model", "firmware", "serial")
    rows: list[tuple[str, str, str, str, str]] = []
    for item in results:
        identity = item.identity
        rows.append(
            (
                item.device_id,
                item.status.value,
                _safe_terminal_text(identity.model) if identity else "-",
                _safe_terminal_text(identity.firmware_version) if identity else "-",
                identity.serial_masked if identity else "-",
            )
        )
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows))
        for i in range(len(headers))
    ]
    header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(header_line)
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def _build_live_clients(
    registry: DeviceRegistry,
    app: AppConfig,
    store: CredentialStore,
) -> list[tuple[ResolvedDevice, IsapiClient]]:
    policy = build_phase1_policy()
    clients: list[tuple[ResolvedDevice, IsapiClient]] = []
    try:
        for device in registry.all():
            cred = store.get(device.credential_ref)
            client = IsapiClient(
                device,
                cred,
                registry,
                policy,
                EgressPolicy({device.host}),
                app.timeouts,
            )
            clients.append((device, client))
    except CredentialNotFound:
        for _device, client in clients:
            client.close()
        raise
    return clients


def _cmd_identify(args: argparse.Namespace) -> int:
    json_output = bool(args.json)
    if args.simulate:
        banner_stream = sys.stderr if json_output else sys.stdout
        print(_SIMULATED_BANNER, file=banner_stream)
        network = build_simulation_network()
        transport = network.transport()
        registry = simulation_registry()
        credential = simulation_credential()
        policy = build_phase1_policy()
        timeouts = simulation_timeouts()
        client_pairs: list[tuple[ResolvedDevice, IsapiClient]] = []
        for device in registry.all():
            client = IsapiClient(
                device,
                credential,
                registry,
                policy,
                EgressPolicy({device.host}),
                timeouts,
                inner_transport=transport,
            )
            client_pairs.append((device, client))
        try:
            results = identify_devices(client_pairs, simulated=True)
        finally:
            for _device, client in client_pairs:
                client.close()
    else:
        config_path = Path(args.config)
        devices_path = Path(args.devices) if args.devices else _DEFAULT_DEVICES
        app = load_app_config(config_path)
        resolved = load_devices(devices_path, app.network)
        registry = DeviceRegistry.from_config(app, resolved)
        store: CredentialStore = EnvCredentialStore()
        client_pairs = _build_live_clients(registry, app, store)
        try:
            results = identify_devices(client_pairs, simulated=app.simulation)
        finally:
            for _device, client in client_pairs:
                client.close()

    if json_output:
        payload = [result.model_dump(mode="json") for result in results]
        print(json.dumps(payload, indent=2))
    else:
        _print_identify_table(results)

    if any(r.status != IdentificationStatus.IDENTIFIED for r in results):
        return 2
    return 0


def _cmd_requirements_validate(args: argparse.Namespace) -> int:
    requirements_path = Path(args.file)
    devices_path = Path(args.devices) if args.devices else _DEFAULT_DEVICES
    try:
        app = load_app_config(_DEFAULT_CONFIG)
        device_ids = {device.id for device in load_devices(devices_path, app.network)}
        profile = load_requirements(requirements_path, device_ids)
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 1

    print(requirements_hash(profile))
    for field in _needs_decision_fields(profile):
        print(f"needs_decision: {field}")
    return 0


def main(argv: list[str] | None = None) -> None:
    install_redaction()
    parser = argparse.ArgumentParser(prog="haca", description="Hikvision configuration auditor")
    parser.add_argument(
        "--version",
        action="version",
        version=f"haca {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    identify_parser = subparsers.add_parser("identify", help="Identify devices via ISAPI")
    identify_parser.add_argument("--config", default=str(_DEFAULT_CONFIG))
    identify_parser.add_argument("--devices", default=None)
    identify_parser.add_argument("--simulate", action="store_true")
    identify_parser.add_argument("--json", action="store_true")
    identify_parser.set_defaults(func=_cmd_identify)

    requirements_parser = subparsers.add_parser("requirements", help="Requirements profile tools")
    requirements_sub = requirements_parser.add_subparsers(dest="requirements_command")

    validate_parser = requirements_sub.add_parser("validate", help="Validate an ORP file")
    validate_parser.add_argument("--file", required=True)
    validate_parser.add_argument("--devices", default=None)
    validate_parser.set_defaults(func=_cmd_requirements_validate)

    args = parser.parse_args(argv)
    if getattr(args, "func", None) is None:
        parser.print_help()
        sys.exit(0)

    try:
        code = args.func(args)
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
    except CredentialNotFound as exc:
        print(f"{exc.args[0]!r}: credentials not found", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
    sys.exit(code)


if __name__ == "__main__":
    main()