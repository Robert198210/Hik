"""HACA command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from enum import Enum
from pathlib import Path
from typing import cast

import yaml

from haca import __version__
from haca.catalog.coverage import (
    CATALOG_VERSION,
    CoverageEntry,
    compute_coverage,
    coverage_summary,
    observed_uncataloged_count,
)
from haca.catalog.loader import load_catalog_entries
from haca.collect.identify import IdentificationResult, IdentificationStatus, identify_devices
from haca.collect.runner import run_simulated_collection
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
    default_resolved_devices,
    simulation_app_config,
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


def _load_manual_attestation(path: Path | None) -> dict[str, dict[str, object]] | None:
    if path is None:
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    return cast(dict[str, dict[str, object]], data)


def _print_collect_outcomes(result: object) -> None:
    from haca.collect.models import CollectionResult

    if not isinstance(result, CollectionResult):
        return
    print("device  endpoint                         outcome")
    for device in result.devices:
        for endpoint_id, evidence in sorted(device.evidence.items()):
            print(
                f"{device.device_id:<7} {endpoint_id:<32} {evidence.outcome.value}"
            )


def _print_coverage_summary(entries: list[CoverageEntry], result: object) -> None:
    from haca.collect.models import CollectionResult

    catalog = load_catalog_entries()
    if not isinstance(result, CollectionResult):
        return
    summary = coverage_summary(
        entries,
        catalog,
        observed_uncataloged=observed_uncataloged_count(result),
    )
    print(f"coverage catalog_version={summary.catalog_version} totals={summary.totals}")
    print(f"observed_uncataloged={summary.observed_uncataloged}")
    for device_id, categories in summary.per_device.items():
        print(f"  {device_id}: {categories}")


def _resolved_devices(app: AppConfig, devices_path: Path) -> list[ResolvedDevice]:
    from haca.config.loader import load_devices as load_device_file

    resolved = load_device_file(devices_path, app.network)
    return [
        ResolvedDevice(
            id=device.id,
            role=device.role,
            expected_model=device.expected_model,
            host=device.host,
            port=device.port,
            scheme=device.scheme,
            credential_ref=device.credential_ref,
        )
        for device in resolved
        if device.enabled
    ]


def _cmd_collect(args: argparse.Namespace) -> int:
    json_output = bool(args.json)
    if not args.simulate:
        return _cmd_collect_live(args)

    banner_stream = sys.stderr if json_output else sys.stdout
    print(_SIMULATED_BANNER, file=banner_stream)
    scenario = args.scenario or "clean"
    manual = _load_manual_attestation(Path(args.manual)) if args.manual else None
    result, coverage = run_simulated_collection(scenario)
    catalog = load_catalog_entries()
    if manual:
        coverage = compute_coverage(catalog, result, None, manual=manual)

    from haca.store.db import open_db
    from haca.store.repositories import save_collection, save_coverage

    db_path = Path(args.db) if args.db else Path("data/haca-sim.db")
    _, session_factory = open_db(db_path)
    with session_factory() as session:
        run_id = save_collection(
            session,
            result,
            orp_hash=None,
            catalog_version=CATALOG_VERSION,
            scenario=scenario,
        )
        save_coverage(session, run_id, coverage)

    if json_output:
        payload = {
            "run_id": run_id,
            "simulated": True,
            "scenario": scenario,
            "coverage": [e.model_dump() for e in coverage],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_collect_outcomes(result)
        _print_coverage_summary(coverage, result)
        print(f"run_id={run_id}")

    if any(e.status == "INACCESSIBLE" for e in coverage):
        pass
    return 0


def _cmd_collect_live(args: argparse.Namespace) -> int:
    from haca.collect.runner import run_live_collection
    from haca.store.db import open_db
    from haca.store.repositories import save_collection, save_coverage

    config_path = Path(args.config) if args.config else _DEFAULT_CONFIG
    devices_path = Path(args.devices) if args.devices else _DEFAULT_DEVICES
    app = load_app_config(config_path)
    devices = _resolved_devices(app, devices_path)
    manual = _load_manual_attestation(Path(args.manual)) if args.manual else None
    result, coverage = run_live_collection(app, devices, EnvCredentialStore())
    catalog = load_catalog_entries()
    if manual:
        coverage = compute_coverage(catalog, result, None, manual=manual)

    db_path = Path(args.db) if args.db else Path("data/haca.db")
    _, session_factory = open_db(db_path)
    with session_factory() as session:
        run_id = save_collection(
            session,
            result,
            orp_hash=None,
            catalog_version=CATALOG_VERSION,
            scenario=None,
        )
        save_coverage(session, run_id, coverage)

    if args.json:
        payload = {
            "run_id": run_id,
            "simulated": False,
            "coverage": [entry.model_dump() for entry in coverage],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_collect_outcomes(result)
        _print_coverage_summary(coverage, result)
        print(f"run_id={run_id}")
    return 0


def _cmd_runs_list(args: argparse.Namespace) -> int:
    from haca.store.db import open_db
    from haca.store.repositories import list_runs

    db_path = Path(args.db) if args.db else Path("data/haca-sim.db")
    _, session_factory = open_db(db_path)
    with session_factory() as session:
        runs = list_runs(session, limit=args.limit)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": run.id,
                        "started_at": run.started_at.isoformat(),
                        "scenario": run.scenario,
                        "simulated": bool(run.simulated),
                    }
                    for run in runs
                ],
                indent=2,
            )
        )
    else:
        print("run_id                              scenario      started_at")
        for run in runs:
            print(
                f"{run.id}  {str(run.scenario or '-'):<12}  {run.started_at.isoformat()}"
            )
    return 0


def _run_simulated_audit(
    scenario: str,
    requirements_path: Path,
    out_dir: Path,
    db_path: Path | None,
    manual_path: Path | None,
    formats: set[str],
    *,
    use_ai: bool,
    config_path: Path | None,
) -> int:
    from haca.audit import AuditOrchestrator, audit_exit_code
    from haca.reports.html import render_html
    from haca.reports.json_report import write_report_json
    from haca.reports.markdown import render_markdown

    devices = list(default_resolved_devices())
    device_ids = {d.id for d in devices}
    orp = load_requirements(requirements_path, device_ids)
    app = (
        load_app_config(config_path)
        if config_path is not None
        else simulation_app_config()
    )
    manual = _load_manual_attestation(manual_path)
    report = AuditOrchestrator().run_audit(
        app,
        devices,
        orp,
        simulate=True,
        scenario=scenario,
        manual_attestations=manual,
        db_path=db_path,
        use_ai=use_ai,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"haca-audit-{report.meta.run_id}"
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    html_path = base.with_suffix(".html")
    if "json" in formats:
        write_report_json(report, str(json_path))
    if "md" in formats:
        md_path.write_text(render_markdown(report), encoding="utf-8")
    if "html" in formats:
        html_path.write_text(render_html(report), encoding="utf-8")

    print(f"findings={len(report.findings)}")
    for path in (json_path, md_path, html_path):
        if path.exists():
            print(path)
    return audit_exit_code(list(report.findings))


def _cmd_audit(args: argparse.Namespace) -> int:
    if not args.simulate:
        return _run_live_audit(args)
    scenario = args.scenario or "clean"
    default_req = _REPO_ROOT / "config" / "requirements.example.yaml"
    requirements = Path(args.requirements) if args.requirements else default_req
    out_dir = Path(args.out) if args.out else Path("reports")
    db_path = Path(args.db) if args.db else None
    manual_path = Path(args.manual) if args.manual else None
    raw_formats = args.format or "json,md"
    formats = {part.strip().lower() for part in raw_formats.split(",") if part.strip()}
    config_path = Path(args.config) if getattr(args, "config", None) else None
    print(_SIMULATED_BANNER)
    return _run_simulated_audit(
        scenario,
        requirements,
        out_dir,
        db_path,
        manual_path,
        formats,
        use_ai=bool(getattr(args, "ai", False)),
        config_path=config_path,
    )


def _run_live_audit(args: argparse.Namespace) -> int:
    from haca.audit import AuditOrchestrator, audit_exit_code
    from haca.reports.html import render_html
    from haca.reports.json_report import write_report_json
    from haca.reports.markdown import render_markdown

    config_path = Path(args.config) if args.config else _DEFAULT_CONFIG
    devices_path = Path(args.devices) if args.devices else _DEFAULT_DEVICES
    app = load_app_config(config_path)
    devices = _resolved_devices(app, devices_path)
    default_req = _REPO_ROOT / "config" / "requirements.example.yaml"
    requirements = Path(args.requirements) if args.requirements else default_req
    orp = load_requirements(requirements, {device.id for device in devices})
    out_dir = Path(args.out) if args.out else Path("reports")
    db_path = Path(args.db) if args.db else None
    manual_path = Path(args.manual) if args.manual else None
    raw_formats = args.format or "json,md"
    formats = {part.strip().lower() for part in raw_formats.split(",") if part.strip()}
    report = AuditOrchestrator().run_audit(
        app,
        devices,
        orp,
        simulate=False,
        scenario=None,
        manual_attestations=_load_manual_attestation(manual_path),
        db_path=db_path,
        use_ai=bool(getattr(args, "ai", False)),
        credential_store=EnvCredentialStore(),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"haca-audit-{report.meta.run_id}"
    written: list[Path] = []
    if "json" in formats:
        json_path = base.with_suffix(".json")
        write_report_json(report, str(json_path))
        written.append(json_path)
    if "md" in formats:
        md_path = base.with_suffix(".md")
        md_path.write_text(render_markdown(report), encoding="utf-8")
        written.append(md_path)
    if "html" in formats:
        html_path = base.with_suffix(".html")
        html_path.write_text(render_html(report), encoding="utf-8")
        written.append(html_path)
    print(f"findings={len(report.findings)}")
    for path in written:
        print(path)
    return audit_exit_code(list(report.findings))


def _cmd_ai_preview(args: argparse.Namespace) -> int:
    from haca.ai.client import FakeAiClient
    from haca.ai.payload import build_payload
    from haca.audit import AuditOrchestrator
    from haca.catalog.coverage import coverage_summary, observed_uncataloged_count
    from haca.catalog.loader import load_catalog_entries

    scenario = args.scenario or "clean"
    devices = list(default_resolved_devices())
    default_req = _REPO_ROOT / "config" / "requirements.example.yaml"
    requirements = Path(args.requirements) if args.requirements else default_req
    device_ids = {d.id for d in devices}
    orp = load_requirements(requirements, device_ids)
    config_path = Path(args.config) if args.config else _DEFAULT_CONFIG
    app = load_app_config(config_path) if config_path.is_file() else simulation_app_config()
    report = AuditOrchestrator().run_audit(
        app,
        devices,
        orp,
        simulate=True,
        scenario=scenario,
    )
    collection, coverage = run_simulated_collection(scenario)
    catalog = load_catalog_entries()
    summary = coverage_summary(
        coverage,
        catalog,
        observed_uncataloged=observed_uncataloged_count(collection),
    )
    payload = build_payload(
        report=report,
        collection=collection,
        devices=devices,
        orp=orp,
        catalog=catalog,
        coverage=coverage,
        coverage_summary=summary,
        findings=report.findings,
        subnet=app.network.subnet,
        budget_chars=app.ai.budget_chars if app.ai else 200_000,
    )
    from haca.ai.prompts import build_prompt

    fake = FakeAiClient()
    tokens = fake.count_tokens(f"{build_prompt()}\n{payload.json_text}")
    print(payload.json_text)
    print(f"estimated_tokens={tokens}")
    return 0


def _cmd_ai_models(_args: argparse.Namespace) -> int:
    from haca.ai.credentials import load_gemini_api_key

    key = load_gemini_api_key()
    if key is None:
        print(
            "Gemini API key not configured (keyring haca/gemini_api_key or GEMINI_API_KEY)",
            file=sys.stderr,
        )
        return 1
    app = load_app_config(_DEFAULT_CONFIG)
    if app.ai is None:
        print("ai.model is not set in configuration", file=sys.stderr)
        return 1
    try:
        from haca.ai.client import GeminiClient

        client = GeminiClient(key, app.ai.model)
        for name in client.list_models():
            print(name)
    except ImportError:
        print("google-genai optional package is not installed", file=sys.stderr)
        return 1
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    from haca.store.db import open_db
    from haca.store.diff import diff_runs

    db_path = Path(args.db) if args.db else Path("data/haca-sim.db")
    _, session_factory = open_db(db_path)
    with session_factory() as session:
        diff = diff_runs(session, session, args.run_a, args.run_b)
    if args.json:
        print(diff.model_dump_json(indent=2))
    else:
        for device_id, path, old, new in diff.changed[:20]:
            print(f"changed {device_id} {path} {old!r} -> {new!r}")
        if len(diff.changed) > 20:
            print(f"... {len(diff.changed) - 20} more changes")
        for device_id, path, value in diff.added[:10]:
            print(f"added {device_id} {path}={value!r}")
        for device_id, path, value in diff.removed[:10]:
            print(f"removed {device_id} {path}={value!r}")
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

    collect_parser = subparsers.add_parser("collect", help="Collect device configuration")
    collect_parser.add_argument("--simulate", action="store_true")
    collect_parser.add_argument(
        "--scenario",
        choices=["clean", "conflicts", "unsupported"],
        default="clean",
    )
    collect_parser.add_argument("--json", action="store_true")
    collect_parser.add_argument("--db", default=None)
    collect_parser.add_argument("--manual", default=None)
    collect_parser.add_argument("--config", default=str(_DEFAULT_CONFIG))
    collect_parser.add_argument("--devices", default=str(_DEFAULT_DEVICES))
    collect_parser.set_defaults(func=_cmd_collect)

    runs_parser = subparsers.add_parser("runs", help="Persisted audit runs")
    runs_sub = runs_parser.add_subparsers(dest="runs_command")
    runs_list = runs_sub.add_parser("list", help="List recent runs")
    runs_list.add_argument("--db", default=None)
    runs_list.add_argument("--limit", type=int, default=20)
    runs_list.add_argument("--json", action="store_true")
    runs_list.set_defaults(func=_cmd_runs_list)

    diff_parser = subparsers.add_parser("diff", help="Diff settings between runs")
    diff_parser.add_argument("run_a")
    diff_parser.add_argument("run_b")
    diff_parser.add_argument("--db", default=None)
    diff_parser.add_argument("--json", action="store_true")
    diff_parser.set_defaults(func=_cmd_diff)

    audit_parser = subparsers.add_parser("audit", help="Run configuration audit")
    audit_parser.add_argument("--simulate", action="store_true")
    audit_parser.add_argument(
        "--scenario",
        choices=["clean", "conflicts", "unsupported"],
        default="clean",
    )
    audit_parser.add_argument("--requirements", default=None)
    audit_parser.add_argument("--manual", default=None)
    audit_parser.add_argument("--out", default=None)
    audit_parser.add_argument("--format", default="json,md")
    audit_parser.add_argument("--db", default=None)
    audit_parser.add_argument("--ai", action="store_true")
    audit_parser.add_argument("--config", default=str(_DEFAULT_CONFIG))
    audit_parser.add_argument("--devices", default=str(_DEFAULT_DEVICES))
    audit_parser.set_defaults(func=_cmd_audit)

    ai_parser = subparsers.add_parser("ai", help="Gemini analysis tools")
    ai_sub = ai_parser.add_subparsers(dest="ai_command")
    ai_preview = ai_sub.add_parser("preview", help="Print redacted AI payload")
    ai_preview.add_argument("--simulate", action="store_true")
    ai_preview.add_argument(
        "--scenario",
        choices=["clean", "conflicts", "unsupported"],
        default="conflicts",
    )
    ai_preview.add_argument("--requirements", default=None)
    ai_preview.add_argument("--config", default=str(_DEFAULT_CONFIG))
    ai_preview.set_defaults(func=_cmd_ai_preview)
    ai_models = ai_sub.add_parser("models", help="List Gemini models for configured key")
    ai_models.set_defaults(func=_cmd_ai_models)

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