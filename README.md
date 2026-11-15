# HACA — Hikvision AI Configuration Auditor

Local, **strictly read-only** configuration auditor for Hikvision NVRs and IP cameras (Windows 10, Python 3.12).

- Collects configuration over ISAPI (HTTP Digest) using an explicit endpoint allowlist.
- Evaluates it with deterministic rules against your **Operational Requirements Profile**,
  so intentional choices are not reported as conflicts.
- Reports exactly which settings were verified, unsupported, inaccessible, or not yet implemented.
  It never claims full coverage.
- Optional AI analysis uses **Google Gemini API only**. Without a key, a full deterministic audit runs.
- Produces JSON and Markdown reports (HTML from v0.2) and keeps historical snapshots for comparison.

> Status: **Phase 0 — planning and setup.** No application code yet. No real-device compatibility is claimed.

## Documentation
- [Architecture](docs/architecture.md)
- [Architecture decisions](docs/architecture-decisions.md)
- [Implementation plan](docs/implementation-plan.md)
- [Agent workflow (development only)](docs/agent-workflow.md)
- [ISAPI endpoint registry](docs/isapi-endpoint-registry.md)
- [Security review](docs/security-review.md)
- [Test results](docs/test-results.md)
- [Project status](docs/project-status.md)

## Safety
HACA v1 never changes device settings, reboots devices, moves PTZ cameras, formats storage, or manages
accounts. Do not expose cameras or the NVR to the Internet. Use a dedicated minimum-privilege device
account for auditing.

## Development
Development uses Cursor agents (see [agent-workflow.md](docs/agent-workflow.md)). Those agents are not
part of the application and are not required to run it.
