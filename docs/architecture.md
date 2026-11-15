# HACA — Architecture

Hikvision AI Configuration Auditor (HACA) is a local, strictly read-only Windows 10 application
that audits the configuration of Hikvision NVRs and IP cameras over ISAPI, evaluates it with
deterministic rules against a user-defined Operational Requirements Profile, optionally enriches
the analysis with Google Gemini, and produces evidence-based reports.

Status: approved plan v2 (2026-11-15). Decisions: [architecture-decisions.md](architecture-decisions.md).

## 1. Two separate AI environments

| Environment | Purpose | AI used |
|---|---|---|
| Development (Cursor) | Design, implement, test, review HACA | Cursor agents (Opus 5.5, Auto Cost, Auto Balance) — see [agent-workflow.md](agent-workflow.md) |
| Runtime (Windows 10) | Audit real devices | **Google Gemini API only**, optional; full deterministic mode without a key |

Runtime HACA has no dependency on Cursor, Claude, Opus, or any development agent (ADR-003).
`.cursor/`, `AGENTS.md`, and `docs/tasks/` are excluded from release artifacts.

## 2. Target devices (initial installation)

| ID | Role | Model | IP |
|---|---|---|---|
| `nvr01` | NVR | DS-7616NXI-K2(D) | `<subnet>.200` |
| `ptz01` | PTZ camera | DS-2DE4425IWG1-E | `<subnet>.201` |
| `cam01` | Fixed camera | DS-2CD2087G3-LI2UY/SL | `<subnet>.202` |

The subnet is configurable. Additional devices are added in `config/devices.yaml`.
No real-device compatibility is claimed until live validation (Phase 3L) is recorded in
[test-results.md](test-results.md).

## 3. Component overview

```mermaid
flowchart TD
    CLI["CLI python -m haca"] --> Orchestrator[AuditOrchestrator]
    UI["Dashboard 127.0.0.1 v0.3"] --> Orchestrator
    Orchestrator --> ORP["Requirements Profile"]
    Orchestrator --> Collector[CollectionEngine]
    Collector --> Client[IsapiClient]
    Client --> Guard["ReadOnlyTransport"]
    Guard --> Devices["NVR PTZ Camera"]
    Guard -.simulation.-> Mock[MockDeviceSimulator]
    Collector --> Catalog["Setting Catalog + Coverage"]
    Catalog --> DB[("SQLite snapshots")]
    Orchestrator --> Rules["RuleEngine technical and requirement"]
    ORP --> Rules
    Rules --> Findings[Findings]
    Orchestrator -.v0.2.-> AI["GeminiAnalyzer"]
    AI --> Validator["AiSuggestionValidator"]
    Validator --> Findings
    Findings --> Reports["Reports JSON MD HTML"]
    Orchestrator -.v0.4.-> Browser["BrowserInspector"]
    Browser --> Proxy["Enforcing proxy"]
    Proxy --> Devices
```

## 4. Python packages (`src/haca/`)

| Package | Responsibility | Release |
|---|---|---|
| `haca.config` | Load and validate `config/haca.yaml`, `config/devices.yaml` (PyYAML `safe_load` + Pydantic). Subnet + suffix → IP. Only `credential_ref`, never secrets. | MVP |
| `haca.requirements` | Operational Requirements Profile (ORP) model, loader, validation. | MVP |
| `haca.devices` | `DeviceRegistry`, `DeviceSpec`, `NetworkPolicy` (RFC1918 + configured subnet; loopback only in simulation). | MVP |
| `haca.security` | `EndpointPolicy`, denylist, `ReadOnlyTransport`, egress guard, `SecretRedactor`, `CredentialStore` (keyring). | MVP |
| `haca.isapi` | `IsapiClient` (httpx + Digest), error taxonomy, XML parsing (defusedxml, namespace-agnostic), `ResponseStatus`, capabilities, endpoint registry loader. | MVP |
| `haca.catalog` | Setting Catalog (`settings.yaml`) and coverage computation. | MVP |
| `haca.collect` | Collection planner, NVR channel expansion, normalizer, raw evidence capture. | MVP |
| `haca.store` | SQLAlchemy 2.0 models, repositories, snapshot diff. | MVP |
| `haca.analysis` | Cross-device correlator, rule engine, rules. | MVP |
| `haca.reports` | JSON (canonical), Markdown, HTML (v0.2). | MVP / v0.2 |
| `haca.ai` | Gemini adapter, payload builder + redactor, suggestion validator, usage meter, knowledge base. | v0.2 |
| `haca.web` | FastAPI app bound to `127.0.0.1`, Jinja2 templates, vendored htmx. | v0.3 |
| `haca.browser` | Optional Playwright inspector, enforcing proxy, session state machine. | v0.4 |

## 5. Audit data flow

1. `identify` — `GET /ISAPI/System/deviceInfo`; compare exact SKU with `expected_model` (`K2(D)` ≠ `K2`).
2. `discover` — capability documents (system, smart, PTZ, event triggers).
3. `collect` — collection plan = endpoint registry × device role × capabilities; NVR channel expansion
   from `InputProxy/channels`.
4. `normalize` — XML → `SettingValue(device_id, setting_path, value, type, endpoint_id, xpath)`.
5. `coverage` — every Setting Catalog entry gets exactly one coverage status (section 7).
6. `snapshot` — raw responses (gzip + sha256) and normalized settings persisted in SQLite.
7. `correlate` — map NVR channels to cameras (IP / serial from `InputProxy`).
8. `rules` — deterministic evaluation with ORP.
9. `ai` (optional, v0.2) — redacted payload → Gemini → validation against snapshot, capabilities, ORP.
10. `report` — JSON → Markdown / HTML.

## 6. Operational Requirements Profile (ORP)

`config/requirements.yaml` states the intended system behaviour, so rules do not report intentional
choices as conflicts (ADR-011). The ORP hash is stored with every audit run.

```yaml
profile_version: 1
system:
  recording_mode: continuous_24_7      # continuous_24_7 | event_only | continuous_plus_event | unspecified
  min_retention_days: null
  analytics_location: camera           # camera | nvr | unspecified
  timeline_markers_required: true
  remote_access: lan_vpn_only          # lan_only | lan_vpn_only | cloud_p2p | unspecified
  hik_connect: undecided               # required | forbidden | undecided
  time_source: nvr_sync                # nvr_sync | ntp | unspecified
  https_required: unspecified
devices:
  ptz01:
    camera_protocol: hikvision         # hikvision | onvif_allowed | unspecified
    ptz_mode: undecided                # static_home_preset | patrol | auto_tracking | manual | undecided
    auto_tracking: forbidden           # required | forbidden | undecided
    required_events: [line_crossing]
    event_targets: [human, vehicle]
    notify_center_required: true
  cam01:
    camera_protocol: unspecified
```

Rule semantics:

- `basis: technical` — intent-independent invariants (trigger references a missing channel, HDD
  status not `ok`, rule enabled while its engine is disabled, firmware mismatch between NVR proxy
  data and camera `deviceInfo`). May produce `CONFIRMED_CONFLICT`.
- `basis: requirement` — compares observation with an explicit ORP value. Explicit contradiction →
  `CONFIRMED_CONFLICT` ("deviation from stated requirement"). ORP `unspecified` / `undecided` →
  at most `INFO` with `needs_decision: true`. Never a conflict.
- Known ambiguous artefacts → `INSUFFICIENT_DATA` plus a manual check item.

## 7. Coverage model (ADR-012)

Coverage is computed per `(device, setting)` against the HACA Setting Catalog, not per endpoint.

| Status | Meaning |
|---|---|
| `VERIFIED_ISAPI` | Value read and parsed from ISAPI. |
| `VERIFIED_BROWSER` | Value read from the web UI (v0.4), screenshot as evidence. |
| `VERIFIED_MANUAL` | User attestation (optional screenshot). |
| `UNSUPPORTED_BY_DEVICE` | Positive evidence only: `subStatusCode=notSupport` or capability explicitly excludes the feature. |
| `INACCESSIBLE` | With reason: `auth_denied`, `endpoint_not_found` (404 / `RequestUrlNotFound` — may be a firmware path variant, **not** "unsupported"), `timeout`, `connection_error`, `parse_error`, `blocked_by_policy`, `device_offline`. |
| `NOT_IMPLEMENTED_IN_HACA` | Known setting without a HACA collector. |
| `NOT_APPLICABLE` | Excluded by device role or ORP. |
| `NOT_ATTEMPTED` | Out of audit scope or audit aborted. |

- `OBSERVED_UNCATALOGED` — count of collected values with no catalog entry (stored raw, not evaluated).
- Evidence tiers: `isapi` > `browser` > `manual` > `simulation`. `CONFIRMED_CONFLICT` requires
  `isapi` or `browser`. `manual` caps at `POTENTIAL_CONFLICT`. `simulation` never counts as live coverage.
- Reports state "Verified X of N settings in HACA catalog vY" and never claim full device coverage.

## 8. Findings model

```
Finding(id, rule_id | "ai", category, classification, severity, basis, devices[],
        evidence[EvidenceRef], evidence_tier, orp_refs[], needs_decision,
        current_value, recommended_value, rationale, source_refs[], source)
classification ∈ {CONFIRMED_CONFLICT, POTENTIAL_CONFLICT, OPTIMIZATION, INFO, INSUFFICIENT_DATA}
severity       ∈ {critical, high, medium, low, info}
source         ∈ {deterministic, ai_validated}
EvidenceRef(snapshot_id, device_id, endpoint_id, xpath, observed_value, raw_sha256, tier)
```

A finding without at least one `EvidenceRef` is invalid (enforced by schema and tests).

## 9. Security architecture (summary)

Detailed gates and checklists: [security-review.md](security-review.md).

| Layer | Control |
|---|---|
| L1 | `IsapiClient.read(endpoint_id, **params)` — no arbitrary URL or method API. |
| L2 | `EndpointPolicy`: registry allowlist + denylist (denylist wins). Only POST: `ContentMgmt/logSearch` with templated body. `configurationData` denied; `picture` denied by default. |
| L3 | `ReadOnlyTransport` (httpx transport wrapper): checks method, exact registered IP (RFC1918), port, path on **every** request including Digest retries; `follow_redirects=False`. |
| L4 | Browser (v0.4): HAR-derived policy, enforcing proxy, Playwright routing, session state machine, minimum-privilege account. |
| L5 | Egress guard: only device IPs and `generativelanguage.googleapis.com`. |

Further rules: secrets only in the OS keyring (Windows Credential Manager); no retry on 401 (account
lockout protection); sequential collection per device; dashboard bound to `127.0.0.1`; reports mask
serial numbers and MAC addresses by default; dedicated minimum-privilege device accounts supported (ADR-018).

## 10. Simulation mode

`--simulate` routes requests to an in-process `httpx.MockTransport` simulator with Digest auth and
fault profiles. Every artefact produced in simulation carries `SIMULATED` markers and never counts
toward live coverage (ADR-008). All fixtures are synthetic until private data processing is
explicitly authorized (ADR-017).

## 11. Release scope

| Release | Scope |
|---|---|
| MVP v0.1 | CLI identify / collect / audit / requirements; ISAPI collection; deterministic rules; ORP; coverage; SQLite + diff; JSON + Markdown reports; minimal Windows install; live validation on a private Windows 10 PC. |
| v0.2 | Gemini analysis (sole runtime AI), HTML report. |
| v0.3 | Local dashboard, history and diff UI, ORP editing. |
| v0.4 | Optional Playwright read-only inspection (HAR-gated). |
| v1.0 | E2E, clean Windows 10 install validation, troubleshooting, packaging. |
