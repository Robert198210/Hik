# HACA — Implementation Plan (v2, approved 2026-11-15)

Architecture: [architecture.md](architecture.md). Decisions: [architecture-decisions.md](architecture-decisions.md).
Workflow and models: [agent-workflow.md](agent-workflow.md). Task specs: [tasks/](tasks/README.md).

## 1. Roadmap

```mermaid
flowchart LR
    P0[P0 Setup] --> P1[P1 Foundation]
    P1 --> P2[P2 Collection + coverage]
    P2 --> P3[P3 Deterministic audit]
    P3 --> P3L["P3L Live validation"]
    P3L --> V02["v0.2 Gemini + HTML"]
    V02 --> V03["v0.3 Dashboard"]
    V03 --> V04["v0.4 Browser optional"]
    V04 --> V10[v1.0 Release]
```

P3L runs on a private Windows 10 PC with authorized network access (B3). Offline development continues
independently; v0.2 work may start before P3L is complete.

## 2. Milestones

| Milestone | Exit criterion |
|---|---|
| M0 | Docs, ADRs, agent definitions, routing verification, security exclusions in place. |
| M1 | `haca identify --simulate` identifies nvr01/ptz01/cam01 from synthetic fixtures; security gate S1 passed. |
| M2 | `haca collect --simulate` writes a snapshot and coverage matrix to SQLite. |
| M3 | `haca audit --simulate` produces JSON + Markdown reports with ORP-aware findings; gate S2 passed. |
| M3L | Live identify/collect/audit on the real devices; registry `verification` updated; Gate L signed. |
| M4 | Gemini analysis with validator and fallback; gate S3 passed. |
| M5 | Local dashboard with history/diff and ORP editing. |
| M6 | Optional browser inspection; gate S4 passed. |
| M7 | v1.0 release on clean Windows 10. |

## 3. Tasks

Specs for Phase 1 are in [tasks/](tasks/README.md). Later phases get specs when the previous phase closes.

### Phase 0 — Setup (Architect)
- T0.1 Repository and architecture documentation, ADR-001..018.
- T0.2 Agent definitions, `AGENTS.md`, routing verification.
- T0.3 Security exclusions (`.gitignore`, `.cursorignore`) and data-handling policy (ADR-017).

### Phase 1 — Foundation
- T1.01 Toolchain: `pyproject.toml`, Python 3.12 via uv, ruff, mypy, pytest.
- T1.02 Config + Operational Requirements Profile.
- T1.03 DeviceRegistry + NetworkPolicy.
- T1.04 Security core: EndpointPolicy, denylist, ReadOnlyTransport, egress guard, SecretRedactor, CredentialStore.
- T1.05 IsapiClient + XML + ResponseStatus.
- T1.06 Synthetic fixtures + provenance + fixture secret scanner (synthetic only, ADR-017).
- T1.07 Mock device simulator (Digest) + fault profiles.
- T1.08 Device identification + `haca identify`.
- T1.09 QA independent verification.
- T1.10 Security gate S1.

### Phase 2 — Collection and coverage
- T2.01 Setting Catalog v1.
- T2.02 Endpoint registry (all entries `candidate_unverified` or `documented` until live).
- T2.03 Capability discovery.
- T2.04 Collection planner + NVR channel expansion.
- T2.05 Normalizer.
- T2.06 Coverage engine.
- T2.07 SQLite store + snapshot diff.
- T2.08 QA.

### Phase 3 — Deterministic audit
- T3.01 Rule framework (`basis`, `requires`, `requires_orp`).
- T3.02 Cross-device correlator.
- T3.03 Initial rules (each rule tested with ORP set-consistent / set-contradicting / unset):
  - `R-VCA-001..003` — VCA rule state, empty targets, missing geometry
  - `R-LINK-001` — notify-center linkage
  - `R-PROTO-001` — camera protocol
  - `R-REC-001` — recording schedule vs ORP
  - `R-TIME-001` — time synchronization
  - `R-FW-001` — firmware consistency
  - `R-STOR-001` — retention estimate
  - `R-PTZ-001` — patrol/tracking vs VCA rules
  - `R-SEC-001..002` — transport/platform services
  - `R-FDET-001` — static-target re-alarm
  - `R-HIKC-001` — Hik-Connect vs ORP
- T3.04 Severity matrix + recommendation schema (`Current → Recommended`).
- T3.05 JSON + Markdown reports.
- T3.06 QA + gate S2.

### Phase 3L — Live validation (private Windows 10 PC)
- T3L.01 Minimal `install.ps1` / `start.ps1`.
- T3L.02 Gate L checklist (account, network, dry-run identify).
- T3L.03 Live identify → collect → audit; compare with synthetic expectations.
- T3L.04 Update registry `verification` and Setting Catalog from live results.

### v0.2 / v0.3 / v0.4 / v1.0
- v0.2: Gemini model selection, payload builder + redaction preview, structured output, validator vs snapshot/capabilities/ORP, usage meter and budget, offline fallback, HTML report, gate S3.
- v0.3: FastAPI dashboard (inventory, connection test, audit control with progress, findings, coverage, history/diff, ORP editor, settings).
- v0.4: HAR capture by user (redacted locally), browser policy, enforcing proxy, Playwright inspector, manual checklist, gate S4.
- v1.0: E2E, clean Win10 validation, troubleshooting guide, packaging tests.

## 4. Definition of Done

Per task:
- [ ] Acceptance criteria in the task spec met.
- [ ] QA ran the tests independently; command + output summary recorded in [test-results.md](test-results.md).
- [ ] `ruff check` and `mypy` clean.
- [ ] Secret / fixture scanner passes.
- [ ] [project-status.md](project-status.md) updated.

MVP:
- [ ] `haca audit` works on the simulator and live; reports contain the coverage matrix.
- [ ] No `CONFIRMED_CONFLICT` without `isapi` evidence and an explicit basis (technical or ORP set) — enforced by test.
- [ ] All security tests pass; Gate L signed in [security-review.md](security-review.md).

v1.0:
- [ ] Gemini analysis with key; deterministic fallback without key.
- [ ] Egress, dependency, and packaging tests pass.
- [ ] Clean Windows 10 x64 install via `install.ps1` in under 10 minutes.

## 5. Risk register

| ID | Risk | Level | Mitigation |
|---|---|---|---|
| R1 | Firmware-specific / undocumented endpoints | High | Registry `verification`, variants, coverage, live validation in P3L |
| R2 | No real data for any device (synthetic only, ADR-017) | High | Clear `synthetic` markers; P3L before claims |
| R3 | False-positive conflicts | High | ORP, `basis`, `needs_decision` |
| R4 | Synthetic fixtures diverge from real firmware | Medium | Namespace-agnostic parser, tolerant normalizer, P3L comparison |
| R5 | Gemini hallucinations | High | Validator; AI cannot confirm conflicts |
| R6 | Private data leak (dev context, logs, AI) | High | ADR-017, `.cursorignore`, redactor, canary tests |
| R7 | Windows 10 end of support | Medium | Python 3.12 + venv; `diagnose.ps1` |
| R8 | Account lockout; admin needed for reads | Medium | No retry on 401; ADR-018 |
| R9 | Device load | Low | Sequential collection, timeouts |
| R10 | Cursor silently substitutes models / no Router | Low | Card verification, documented fallback |
| R11 | Gemini API / pricing / data-terms changes | Medium | Thin adapter, config-driven prices, ADR-016 |
| R12 | Incomplete browser interception for HTTPS | Medium | `reduced_assurance`, optional v0.4 |

## 6. Blocker decisions (2026-11-15)

| ID | Decision |
|---|---|
| B1 | Synthetic data only. No access to private CCTV files, credentials, VPN configs. T1.06 uses synthetic fixtures. Exclusions via `.gitignore` / `.cursorignore` authorized. |
| B2 | Verify routing in T0.2: Opus 5.5 architecture, Auto Cost implementation, Auto Balance QA; document fallback. |
| B3 | Live testing deferred to a private Windows 10 PC with authorized network access. |
| B4 | Design for dedicated minimum-privilege accounts; do not create/modify accounts. |
| B5 | `cam01` uses clearly identified synthetic fixtures. |
| B6 | Gemini billing deferred to v0.2; Gemini is the exclusive runtime AI. |
| B7 | Browser/HAR deferred to v0.4; never collect or upload unredacted tokens or credentials from HAR. |
