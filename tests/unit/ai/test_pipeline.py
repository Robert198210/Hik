from __future__ import annotations

from pathlib import Path

from haca.ai.client import FakeAiClient
from haca.ai.pipeline import enrich_findings
from haca.ai.schema import AiAnalysis, AiSuggestion
from haca.ai.usage import load_cached_analysis, payload_cache_key
from haca.catalog.coverage import compute_coverage, coverage_summary, observed_uncataloged_count
from haca.catalog.loader import load_catalog_entries
from haca.collect.runner import run_simulated_collection
from haca.config.models import AiConfig, AppConfig
from haca.requirements.loader import load_requirements
from haca.simulation.defaults import default_resolved_devices, simulation_app_config
from haca.store.db import open_db


def _base_app() -> AppConfig:
    return simulation_app_config().model_copy(
        update={
            "ai": AiConfig(model="fake-model", pricing={}),
        }
    )


def test_fake_client_accepts_findings() -> None:
    collection, coverage = run_simulated_collection("clean")
    catalog = load_catalog_entries()
    device_ids = {d.id for d in default_resolved_devices()}
    orp = load_requirements(Path("config/requirements.example.yaml"), device_ids)
    coverage = compute_coverage(catalog, collection, orp)
    summary = coverage_summary(coverage, catalog)
    analysis = AiAnalysis(
        summary="ok",
        suggestions=[
            AiSuggestion(
                device_id="ptz01",
                setting_id="security.http_enabled",
                current_value="true",
                recommended_value="false",
                classification="OPTIMIZATION",
                severity="low",
                rationale="test",
            )
        ],
    )
    client = FakeAiClient(analysis=analysis)
    result = enrich_findings(
        findings=(),
        collection=collection,
        devices=list(default_resolved_devices()),
        orp=orp,
        catalog=catalog,
        coverage=coverage,
        coverage_summary=summary,
        app_config=_base_app(),
        ai_config=_base_app().ai,
        run_id="run-x",
        client=client,
        session=None,
        force_enable=True,
    )
    assert any(f.source.value == "ai_validated" for f in result.findings)
    assert result.ai.status in {"ok", "cached"}


def test_missing_key_skips_without_changing_exit_findings() -> None:
    collection, coverage = run_simulated_collection("clean")
    catalog = load_catalog_entries()
    device_ids = {d.id for d in default_resolved_devices()}
    orp = load_requirements(Path("config/requirements.example.yaml"), device_ids)
    coverage = compute_coverage(catalog, collection, orp)
    summary = coverage_summary(coverage, catalog)
    result = enrich_findings(
        findings=(),
        collection=collection,
        devices=list(default_resolved_devices()),
        orp=orp,
        catalog=catalog,
        coverage=coverage,
        coverage_summary=summary,
        app_config=_base_app(),
        ai_config=_base_app().ai,
        run_id="run-x",
        client=None,
        session=None,
        force_enable=True,
    )
    assert result.ai.status == "skipped"
    assert result.ai.reason == "missing_api_key"


def test_cache_prevents_second_client_call(tmp_path: Path) -> None:
    collection, coverage = run_simulated_collection("clean")
    catalog = load_catalog_entries()
    device_ids = {d.id for d in default_resolved_devices()}
    orp = load_requirements(Path("config/requirements.example.yaml"), device_ids)
    coverage = compute_coverage(catalog, collection, orp)
    summary = coverage_summary(
        coverage,
        catalog,
        observed_uncataloged=observed_uncataloged_count(collection),
    )
    analysis = AiAnalysis(summary="cached", suggestions=[])
    client = FakeAiClient(analysis=analysis)
    app = _base_app()
    db = tmp_path / "ai.db"
    _, factory = open_db(db)
    from haca.ai.payload import build_payload

    payload = build_payload(
        report=None,
        collection=collection,
        devices=list(default_resolved_devices()),
        orp=orp,
        catalog=catalog,
        coverage=coverage,
        coverage_summary=summary,
        findings=(),
        subnet=app.network.subnet,
        budget_chars=200_000,
    )
    key = payload_cache_key(app.ai.model, payload.json_text)  # type: ignore[union-attr]
    with factory() as session:
        enrich_findings(
            findings=(),
            collection=collection,
            devices=list(default_resolved_devices()),
            orp=orp,
            catalog=catalog,
            coverage=coverage,
            coverage_summary=summary,
            app_config=app,
            ai_config=app.ai,
            run_id="run-1",
            client=client,
            session=session,
            force_enable=True,
        )
        assert len(client.calls) == 1
        stored = load_cached_analysis(session, key)
        assert stored is not None
        enrich_findings(
            findings=(),
            collection=collection,
            devices=list(default_resolved_devices()),
            orp=orp,
            catalog=catalog,
            coverage=coverage,
            coverage_summary=summary,
            app_config=app,
            ai_config=app.ai,
            run_id="run-2",
            client=client,
            session=session,
            force_enable=True,
        )
        assert len(client.calls) == 1