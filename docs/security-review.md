# Security Review

Gates, checklists, and verdicts. Reviewer role: [haca-security-reviewer](../.cursor/agents/haca-security-reviewer.md).
The Architect records verdicts here.

## Gate overview

| Gate | When | Scope | Status |
|---|---|---|---|
| S0 | Phase 0 | Data-handling exclusions (ADR-017) | **Applied 2026-11-15** (see T0.3) |
| S1 | After Phase 1 | `haca.security`, `haca.isapi.client`, `haca.config`, fixtures | Not started |
| S2 | After Phase 3 | Persistence of raw responses, report masking | Not started |
| L | Before the first live connection (P3L) | Live-device readiness | Not started |
| S3 | v0.2 | Gemini data flow, redaction, validator, egress | Not started |
| S4 | v0.4 | Browser inspection, HAR handling, proxy | Not started |

## S0 / T0.3 — Security exclusions (prepared 2026-11-15)

Status: approved by the user (B1) and **applied 2026-11-15**. All three files below exist on disk.

### `/var/fpwork/ambrosew/.cursorignore` (workspace root — new file)

```gitignore
# HACA / ADR-017: private CCTV data, credentials, VPN configs — never in agent context
skrypty/Hikvision/LOG/
skrypty/Hikvision/dumps/
skrypty/Hikvision/inventory/
**/*.har
**/credentials.env
**/active.env
**/wg-*.conf
**/wireproxy*.conf
```

`skrypty/Hikvision/inventory/` is excluded entirely: it holds device identifiers and the `secrets/`
directory. Notes (`STATUS.md`, `knowledge/`) and public manuals stay readable for the existing
`hikvision-home` skill, but HACA agents are instructed not to use them.

### `skrypty/HIK/haca/.cursorignore`

```gitignore
config/haca.yaml
config/devices.yaml
config/requirements.local.yaml
data/
live-results/
reports/
*.db
*.sqlite*
*.har
*.pcap
secrets/
.env
.env.*
```

### `skrypty/HIK/haca/.gitignore`

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
.mypy_cache/
.ruff_cache/
.pytest_cache/
.coverage
htmlcov/
dist/
build/
*.egg-info/

# Local runtime data — never commit
config/haca.yaml
config/devices.yaml
config/requirements.local.yaml
data/
live-results/
reports/
*.db
*.sqlite*
*.log

# Private data and secrets (ADR-017)
*.har
*.pcap
secrets/
.env
.env.*
credentials.env
*.pem
*.key

# Cursor dev-only artefacts
.cursor/agent-usage.log
```

Example configs (`config/*.example.yaml`) are committed; real configs are not.

## Gate L checklist (live-device readiness) — draft

- [ ] S1 and S2 passed.
- [ ] Runs on the private Windows 10 PC with authorized LAN access; not on the corporate machine.
- [ ] Dedicated minimum-privilege account per device prepared by the user (HACA does not create accounts, ADR-018).
- [ ] Credentials stored in Windows Credential Manager; config contains only `credential_ref`.
- [ ] `config/devices.yaml` lists only the three approved device IPs.
- [ ] Dry run: `haca identify` only. Verify the request log contains only `GET /ISAPI/System/deviceInfo`.
- [ ] Then `haca collect`. Verify the request log: GET only, plus registry-approved `logSearch` POST if enabled.
- [ ] Live outputs stay in `live-results/` on the private PC. Nothing raw is copied to the corporate environment.

## HAR handling (B7, v0.4)

- HAR files are captured by the user on the private PC only.
- Before any agent sees them, a local tool removes cookies, `Authorization` headers, session tokens,
  nonces, challenge values, and credentials, and replaces device identifiers.
- Unredacted HAR files are never committed, uploaded, or pasted into chats.

## Verdict log

| Date | Gate | Verdict | Reviewer | Notes |
|---|---|---|---|---|
| — | — | — | — | — |
