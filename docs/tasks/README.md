# Task Specs

One file per work package. The developer reads `AGENTS.md` + the task file only.

## Phase 1 order

| Task | Title | Role / routing | Risk | Prerequisites |
|---|---|---|---|---|
| [T1.01](T1.01-toolchain.md) | Toolchain and package skeleton | Developer / Auto Cost | Low | T0.3 applied (git repo, ignore files) |
| [T1.02](T1.02-config-orp.md) | Config + Operational Requirements Profile | Developer / Auto Cost | Low | T1.01 |
| [T1.03](T1.03-device-registry.md) | DeviceRegistry + NetworkPolicy | Developer / Auto Cost | Medium | T1.02 |
| [T1.04](T1.04-security-core.md) | Security core | Developer / Auto Cost + Architect review | **High** | T1.03 |
| [T1.05](T1.05-isapi-client.md) | IsapiClient + XML + ResponseStatus | Developer / Auto Cost + Architect review | **High** | T1.04 |
| [T1.06](T1.06-synthetic-fixtures.md) | Synthetic fixtures + scanner | Developer / Auto Cost | Medium | T1.01 (parallel with T1.02–T1.05) |
| [T1.07](T1.07-simulator.md) | Device simulator with Digest | Developer / Auto Cost | Medium | T1.05, T1.06 |
| [T1.08](T1.08-identify-cli.md) | Identification + CLI | Developer / Auto Cost | Low | T1.07 |
| [T1.09](T1.09-qa-phase1.md) | QA Phase 1 | QA / Auto Balance | — | T1.01–T1.08 |
| [T1.10](T1.10-gate-s1.md) | Security gate S1 | Security / Opus 5.5 | — | T1.09 PASS |

T1.06 may run in parallel with T1.02–T1.05: it only touches `src/haca/simulation/profiles/` and `tools/`.

## Handoff prompt (developer chat, picker: Auto → Cost)

```
Act as @.cursor/agents/haca-developer.md.
Task: @docs/tasks/T1.01-toolchain.md
Follow AGENTS.md. Implement only this task. Finish with the report format from the role file.
```

## Handoff prompt (QA chat, picker: Auto → Balance)

```
Act as @.cursor/agents/haca-qa.md.
Task spec: @docs/tasks/T1.0X-....md
Diff: run `git diff <base>..HEAD` yourself. Do not use the developer's summary.
```

## Common conventions (all tasks)

- Python 3.12, `src/` layout, package `haca`. Type hints everywhere. Pydantic v2 models use
  `model_config = ConfigDict(extra="forbid", frozen=True)` unless the spec says otherwise.
- Test network: `192.168.250.0/24`. Device suffixes: nvr01 `.200`, ptz01 `.201`, cam01 `.202`.
- Synthetic identifiers only: serials `SYNTH-…`, MAC `00:00:5E:00:53:xx`, UUID `00000000-0000-0000-0000-0000000000xx`.
- Tests: `tests/unit/`, `tests/security/` (marker `security`), `tests/integration/` (marker `simulation`).
  Live tests use marker `live` and are skipped by default.
- No network access in tests. Use `httpx.MockTransport` only.
