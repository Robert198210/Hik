# Project Status

Last updated: 2026-11-15

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
