# Project Status

Last updated: 2026-11-17

Live handoff for a new chat: [STATUS.md](../STATUS.md). Read it first. Update it when the session changes the live state.

## Phase 4 — Gemini analysis (v0.2)

| Task | Status | Notes |
|---|---|---|
| T4.01 Gemini adapter, payload, validator, HTML | Done | `haca.ai` package, `--ai` audit, `ai preview`/`ai models`, SQLite schema v2 (`ai_calls`/`ai_cache`), HTML report. pytest 1167, ruff/mypy clean. Gate S3 QA not run (developer completion only). |
| Live audit | Done | `haca audit` and `haca collect` without `--simulate` read the configured devices. pytest 1170. |

## Phase 3 — Deterministic audit

| Task | Status | Notes |
|---|---|---|
| T3.01 Rules and correlator | Done | `5fa4c38`, architect fix for `nvr_sync` on `R-TIME-001` |
| T3.02 Audit CLI and reports | Done | `9c14a85`, architect fix `d02951e`: report masking no longer redacts rule ids, models, or `IDENTIFIED` |
| QA Phase 3 / gate S2 | Skipped | QA agent hung at 10:01 with no report and no commit. Do not relaunch that pass. Phase 3 stands on pytest 1159, ruff, mypy, `scenario-clean` exit 0, `scenario-conflicts` exit 3. Next implementation task is T4.01. |

## Phase 2 — Registry + catalog (MVP)

| Task | Status | Notes |
|---|---|---|
| T2.01 Endpoint registry, Setting Catalog, scenario profiles | Done | `endpoints.yaml` (21), `settings.yaml` (41), scenarios `scenario-clean` / `scenario-conflicts` / `scenario-unsupported` for nvr01/ptz01/cam01 |

## Phase 0 — Setup

| Task | Status | Role / routing | Notes |
|---|---|---|---|
| T0.1 Docs + ADR-001..018 | Done | Architect / Claude Opus 5.5 | `docs/*.md`, `README.md` |
| T0.2 Agents + routing verification | Done (picker checks pending, user) | Architect / Claude Opus 5.5 | `.cursor/agents/*`, `.cursor/rules/*`, `AGENTS.md`; Task slugs verified; Auto Cost / Auto Balance picker checks in `agent-workflow.md` §3 |
| T0.3 Security exclusions | Done | Architect | `.gitignore`, `haca/.cursorignore`, workspace `.cursorignore` |
| Repository | Done | Architect | `git init` + initial commit |

## Open decisions (ORP)
- `hik_connect`: undecided
- `ptz01.ptz_mode` (park vs patrol): undecided
- `cam01` requirements: unspecified

## Blocker decisions
See [implementation-plan.md §6](implementation-plan.md). Live testing is deferred to a private Windows 10 PC (B3).
