# AGENTS.md — HACA development rules

Development-only file. Not part of the HACA runtime (ADR-003).

## Project
HACA is a strictly read-only Hikvision configuration auditor for Windows 10: Python 3.12, `src/haca`.
Architecture: `docs/architecture.md`. Decisions: `docs/architecture-decisions.md`.
Workflow: `docs/agent-workflow.md`. Tasks: `docs/tasks/`.

## Non-negotiable rules
1. **Read-only.** Never add code that writes device configuration, reboots, resets, upgrades firmware,
   formats storage, moves PTZ, or changes accounts. The only request API is `IsapiClient.read(endpoint_id)`.
2. **No fabricated ISAPI.** Every endpoint and XML field needs a registry `source`. If unknown, use
   `candidate_unverified` or leave it out.
3. **Synthetic data only (ADR-017).** Never open, read, copy, or derive data from
   `/var/fpwork/ambrosew/skrypty/Hikvision/**`, HAR files, or any real device capture. Fixtures use
   `SYNTH-` serials, `00:00:5E:00:53:xx` MACs, and `192.168.250.0/24`.
4. **No secrets** in code, config, tests, logs, reports, or prompts. Credentials come only from
   `CredentialStore` (keyring or env in tests).
5. **Runtime AI = Google Gemini only.** No `anthropic`, `openai`, `cursor*`, or `claude*` runtime dependency.
6. **No real network in tests.** Use `httpx.MockTransport` / `haca.simulation`.
7. **One task at a time.** Implement only the active `docs/tasks/T*.md`. Escalate interface or
   architecture changes to the Architect instead of making them.

## Commands
Environment (dev machine): the shell sets `UV_INDEX` to an internal index and `UV_CACHE_DIR` to a
read-only sandbox path. HACA uses PyPI only:
```
export UV_CACHE_DIR=/var/fpwork/ambrosew/.xdg/cache/uv
unset UV_INDEX
export PATH=/var/fpwork/ambrosew/.xdg/local/bin:$PATH
```
```
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy src
uv run python -m haca --version
```

## Conventions
- Pydantic v2 models: `extra="forbid"`, frozen unless the spec says otherwise.
- Type hints everywhere. `mypy --strict` for `haca.security.*` and `haca.isapi.*`.
- Tests: `tests/unit`, `tests/integration` (marker `simulation`), `tests/security` (marker `security`),
  live tests marker `live` (skipped by default).
- Simulated outputs are always labelled `SIMULATED`.
- English for code, comments, and docs.

## Definition of Done (per task)
Acceptance criteria met; tests, ruff, and mypy green; fixture scanner green; QA result recorded in
`docs/test-results.md`; `docs/project-status.md` updated.
