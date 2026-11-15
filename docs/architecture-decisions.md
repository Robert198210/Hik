# Architecture Decision Records

Format: Status / Context / Decision / Consequences. Owner: Lead Architect. Changes to an Accepted ADR
require a new ADR that supersedes it.

---

## ADR-001 Strict read-only v1 with layered enforcement
- **Status:** Accepted (2026-11-15)
- **Context:** Auditing must never alter devices. Some HTTP GET endpoints are not harmless (config export, snapshots).
- **Decision:** No write capability in v1. Enforcement in five independent layers (L1 API surface, L2 EndpointPolicy, L3 ReadOnlyTransport, L4 browser controls, L5 egress guard). Denylist overrides allowlist. Controls do not depend on AI prompts.
- **Consequences:** Some data stays unreachable (reported as coverage). Security tests are mandatory for every change in `haca.security` and `haca.isapi`.

## ADR-002 Endpoint registry in YAML with provenance
- **Status:** Accepted
- **Context:** No complete public ISAPI specification per model/firmware; endpoints must not be fabricated.
- **Decision:** `src/haca/isapi/registry/endpoints.yaml`. Each entry: `id, path, method, device_roles, variants, capability_gate, sensitivity, redaction_profile, verification, source`. `verification ∈ {observed_live, documented, candidate_unverified}`. An entry without `source` fails the lint.
- **Consequences:** Reports distinguish verified from candidate endpoints. Live validation updates `verification`.

## ADR-003 Google Gemini is the only runtime AI provider
- **Status:** Accepted
- **Decision:** Runtime AI uses only `google-genai`. Deterministic audit works without a key. Tests fail if `anthropic`, `openai`, `cursor*`, or `claude*` appear in runtime dependencies or imports. Egress is restricted to device IPs and `generativelanguage.googleapis.com`. Release artifacts exclude `.cursor/`, `AGENTS.md`, `docs/tasks/`.
- **Consequences:** Development agents never become runtime dependencies.

## ADR-004 Secrets in the OS keyring
- **Status:** Accepted
- **Decision:** `keyring` (Windows Credential Manager). Config files contain only `credential_ref`. Dev/test fallback: environment variables. `SecretRedactor` logging filter on all handlers.
- **Consequences:** One extra dependency. No secrets in repo, logs, reports, or AI payloads.

## ADR-005 SQLite without migrations framework
- **Status:** Accepted
- **Decision:** SQLAlchemy 2.0 + SQLite; schema version via `PRAGMA user_version`; forward-only upgrade functions.
- **Consequences:** No Alembic dependency. Schema changes need an explicit upgrade step and test.

## ADR-006 Dashboard stack
- **Status:** Accepted (implementation in v0.3)
- **Decision:** FastAPI + Uvicorn + Jinja2 + vendored htmx (no CDN, no Node). Bind `127.0.0.1` only. CSRF token for POST forms.

## ADR-007 Fixture provenance
- **Status:** Accepted, amended by ADR-017
- **Decision:** Every fixture has `provenance.yaml` (`origin ∈ {synthetic, redacted_capture, live_capture}`, author, date, firmware profile, basis). Fixture secret scanner runs as a test.

## ADR-008 Explicit simulation mode
- **Status:** Accepted
- **Decision:** `--simulate` uses an in-process mock transport. Every simulated artefact carries `SIMULATED`. Simulation never counts as live coverage or device compatibility.

## ADR-009 No PyInstaller in v1
- **Status:** Accepted
- **Decision:** Install via Python 3.12 venv + `pip install --require-hashes -r requirements.lock` + PowerShell scripts.

## ADR-010 Findings model
- **Status:** Accepted
- **Decision:** See [architecture.md §8](architecture.md). Every finding requires at least one `EvidenceRef`. AI cannot produce `CONFIRMED_CONFLICT`.

## ADR-011 Operational Requirements Profile
- **Status:** Accepted
- **Context:** 24/7 recording, ONVIF, Hik-Connect, PTZ patrol/tracking are valid or invalid depending on user intent.
- **Decision:** `config/requirements.yaml`. Rules declare `basis: technical | requirement` and `requires_orp`. Unspecified/undecided intent yields at most `INFO` with `needs_decision`. ORP hash stored per audit. Gemini receives ORP; the validator rejects suggestions contradicting ORP.

## ADR-012 Coverage per setting
- **Status:** Accepted
- **Decision:** Setting Catalog with eight coverage statuses and evidence tiers ([architecture.md §7](architecture.md)). 404 / `RequestUrlNotFound` is `INACCESSIBLE/endpoint_not_found`, never `UNSUPPORTED_BY_DEVICE`.

## ADR-013 MVP-first delivery
- **Status:** Accepted
- **Decision:** MVP = ISAPI collection + deterministic audit + ORP + coverage + JSON/MD reports + live validation. Gemini (v0.2), dashboard (v0.3), browser (v0.4) follow.

## ADR-014 Browser inspection security
- **Status:** Accepted (implementation deferred to v0.4)
- **Context:** Hikvision web login likely uses POST (and a heartbeat, possibly PUT) — unverified. `page.route()` misses redirect hops and Service Worker traffic.
- **Decision:** (1) User-captured HAR first; HAR is redacted locally (cookies, `Authorization`, session tokens, credentials, challenge/nonce values) before any agent sees it; unredacted HAR is never uploaded or committed. (2) Enforcing local proxy for all Chromium traffic. (3) Playwright `context.route`, `service_workers="block"`, no downloads, WebSocket blocked. (4) Session state machine: login exceptions only in `LOGIN` state. (5) Minimum-privilege account. (6) Deterministic page scripts; no generic click/type. HTTPS without MITM → `reduced_assurance`. Live view, PTZ pages, Save/Apply/Test/Format/Upgrade/Reboot, Hik-Connect pages, HDMI-only menus are manual-only.

## ADR-015 Development model routing
- **Status:** Accepted, verification in progress ([agent-workflow.md](agent-workflow.md))
- **Decision:** Picker-first. Architect chat: Claude Opus 5.5. Developer chat: Auto → Optimize For: Cost. QA chat: Auto → Optimize For: Balance. Delegated fallback: developer subagent `composer-2.5`, QA subagent Task model `claude-sonnet-5-5-high`. Never delegate developer/QA with `inherit` from an Opus chat.

## ADR-016 Gemini usage policy
- **Status:** Accepted (implementation in v0.2)
- **Decision:** Billing configuration deferred to v0.2 (B6); recommended paid-tier key for data handling. One aggregated call per audit, token budget in config, cache by `snapshot_sha`, model ID verified with `client.models.list()`.

## ADR-017 Synthetic-only data until authorized (B1)
- **Status:** Accepted (2026-11-15)
- **Context:** Development runs in a corporate environment. Existing private CCTV captures, credentials, and VPN configs exist outside this repo.
- **Decision:** Development uses synthetic fixtures only. Agents must not read, copy, process, sanitize, or upload private CCTV files, credentials, or VPN configurations. Synthetic fixtures are authored from generic ISAPI structure knowledge with fictional values (MAC `00:00:5E:00:53:xx`, IPs in `192.168.250.0/24`, serials `SYNTH-*`). `cam01` fixtures are marked `origin: synthetic`. Private data processing requires explicit written authorization recorded in this file.
- **Consequences:** Realism of fixtures is limited until live validation on the private Windows 10 PC (Phase 3L).

## ADR-018 Dedicated minimum-privilege device accounts (B4)
- **Status:** Accepted (design only)
- **Decision:** Device config supports a per-device `credential_ref` intended for a dedicated low-privilege account. HACA reports `auth_denied` per setting instead of escalating. HACA never creates or modifies device accounts. Whether a non-admin account can read configuration is determined during live validation.
