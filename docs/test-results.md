# Test Results

Simulated and live results are recorded separately. Simulation never implies device compatibility (ADR-008).

## Simulated / offline runs

| Date | Task | Commit | Routing (role / model) | Commands | Passed / Failed | Verdict | Defects |
|---|---|---|---|---|---|---|---|
| 2026-11-15 | T2.01 (registry, catalog, scenario profiles) | _(pending commit)_ | Developer / Composer 2.5 | `uv run ruff check .`; `uv run mypy src`; `uv run pytest -q`; `uv run python tools/scan_fixture_secrets.py src/haca/simulation/profiles tests`; `uv run python tools/registry_report.py --check` | 1129 passed / 0 failed. ruff: clean. mypy: clean. Fixture scanner: 0 findings. Registry doc: current. | PASS (AC 1–5) | — |
| 2026-11-15 | T1.09 (QA of T1.01–T1.08, SIMULATED) | e2a39a5 + QA tests (base diff 8321630..e2a39a5) | QA / Claude Sonnet 5.5 (Task fallback for Auto Balance) | `uv run pytest -q --cov=haca --cov-branch`; `uv run ruff check .`; `uv run mypy src`; `uv run mypy --strict src/haca/{security,isapi,devices}`; `uv run python -m haca --version`; `uv run haca identify --simulate [--json]`; `uv run haca requirements validate --file config/requirements.example.yaml` | Developer suite 177 passed / 0 failed. With QA suite: 969 passed / 0 failed / 29 xfailed (strict, = 16 defects). QA tests alone: 792 passed / 29 xfailed. ruff: clean. mypy: clean (43 files). Coverage 94 % total with QA suite (86 % developer suite only), branch coverage enabled. | PASS (45/45 acceptance criteria met; 16 open defects: 0 High, 4 Medium, 12 Low — Architect to triage the Medium ones before gate S1) | DEF-T1.02-1, DEF-T1.02-2, DEF-T1.04-1 … DEF-T1.04-6, DEF-T1.05-1 … DEF-T1.05-3, DEF-T1.06-1, DEF-T1.07-1, DEF-T1.08-1 … DEF-T1.08-3 |

## Live-device validation (private Windows 10 PC, P3L)

| Date | Device | Model | Firmware | Account type | Command | Result | Notes |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — |

## Defects

| ID | Task | Summary | Severity | Status |
|---|---|---|---|---|
| DEF-T1.02-1 | T1.02 | `DeviceConfig.port` has no range validation: `0`, `-5`, `65536`, `70000` load without `ConfigError` (a bad port only fails later as an `httpx.InvalidURL`). Test: `tests/security/qa/test_qa_config_identify_cli.py::test_device_port_range_validated` | Low | Fixed (f21c9a0) |
| DEF-T1.02-2 | T1.02 | YAML syntax errors are wrapped as `ConfigError("invalid YAML: …")` with PyYAML's snippet, which echoes the raw source line. A secret-looking key with a malformed value therefore leaks its value, against the "never echo raw values of secret-looking keys" rule. Test: `…::test_yaml_syntax_error_does_not_echo_source_line` | Medium | Fixed (f21c9a0) |
| DEF-T1.04-1 | T1.04 | Denylist patterns use `.*` without DOTALL, and path hygiene does not reject control characters. `/ISAPI/PTZCtrl/channels/1%0a/continuous` and `…/1%0d%0a/presets/1/goto` are not matched by the structured PTZ patterns, so a permissive rule would authorise them. The real allowlist still blocks them, so this is a defence-in-depth gap. Test: `tests/security/qa/test_qa_readonly_enforcement.py::test_control_characters_in_path_do_not_bypass_structured_denylist` | Low | Fixed (f21c9a0) |
| DEF-T1.04-2 | T1.04 | `EndpointPolicy.authorize` normalises the method with `str.upper()`, so `"post"` and `"POſT"` (U+017F) are treated as `POST`. httpx normalises first, so this is not currently exploitable. Test: `…::test_policy_rejects_non_ascii_or_lowercase_method_spellings` | Low | Fixed (f21c9a0) |
| DEF-T1.04-3 | T1.04 | `redact_text` misses quoted shapes of unregistered secrets: Digest `response="…"` / `cnonce="…"`, JSON-style `{"password": "…"}`, and quoted values containing spaces (only the first token is masked). Test: `tests/security/qa/test_qa_secrets_redaction.py::test_unregistered_secret_shapes_are_masked` (5 cases) | Medium | Fixed (f21c9a0) |
| DEF-T1.04-4 | T1.04 | `SecretRedactor.filter` rebuilds `record.args` from `tuple(dict)` when args is a mapping (`logger.warning("%(a)s", {"a": 1})`). Log formatting then raises `TypeError` and the message is lost. Test: `…::test_secret_redactor_preserves_mapping_style_args` | Low | Fixed (f21c9a0) |
| DEF-T1.04-5 | T1.04 | `SecretRedactor` only masks `str` args and `msg`. A registered secret reaches the log through non-str args (`logger.warning("%s", exc)`) and through `exc_info` traceback text. Test: `…::test_registered_secret_not_leaked_via_exception_objects[object_arg\|exc_info]` | Medium | Fixed (f21c9a0) |
| DEF-T1.04-6 | T1.04 | `install_redaction()` is guarded by a global flag, so handlers added to the root logger after the first call (for example by `logging.basicConfig` or a file handler) are never filtered. Test: `…::test_install_redaction_covers_handlers_added_later` | Low | Fixed (f21c9a0) |
| DEF-T1.05-1 | T1.05 | Non-taxonomy exceptions escape `IsapiClient.read`: `httpx.ReadError`, `RemoteProtocolError`, `WriteError`, `httpx.ProtocolError` (Digest challenge without nonce), `KeyError` (Digest `algorithm=FOO`). Spec expects `IsapiError` subclasses. `identify` hides it with a generic `except Exception`. Test: `tests/security/qa/test_qa_digest_xml_client.py::test_all_transport_level_failures_map_to_isapi_error` (5 cases) | Low | Fixed (f21c9a0) |
| DEF-T1.05-2 | T1.05 | `XmlParseError` raised from `IsapiClient._build_response` (first `except XmlParseError: raise` branch) carries empty `device_id` / `endpoint_id`. Test: `…::test_xml_parse_error_from_client_is_attributed_to_device_and_endpoint` | Low | Fixed (f21c9a0) |
| DEF-T1.05-3 | T1.05 | `parse_xml` only catches `ParseError, ValueError, TypeError`. A body declaring an unknown encoding (`<?xml version='1.0' encoding='bogus'?>`) raises `LookupError` out of the parser. Test: `…::test_unknown_declared_encoding_raises_xml_parse_error` | Low | Fixed (f21c9a0) |
| DEF-T1.06-1 | T1.06 | Fixture scanner MAC regex only matches colon-separated MACs. A dash-separated real MAC (`44-19-B6-11-22-33`) is not reported. Test: `tests/security/qa/test_qa_static_and_fixtures.py::test_scanner_detects_dash_separated_mac` | Low | Fixed (f21c9a0) |
| DEF-T1.07-1 | T1.07 | Simulator Digest server keeps rotated-out nonces in `valid_nonces` (up to 8), so a stale nonce is still accepted. Spec: "rejects a stale or unknown nonce with 401". Unknown nonces are rejected correctly. Test: `…::test_simulator_rejects_stale_nonce_after_rotation` | Low | Fixed (f21c9a0) |
| DEF-T1.08-1 | T1.08 (cause in T1.05 `xml._preview`) | `XmlParseError` messages embed the first 80 characters of the device body. On a truncated compact `DeviceInfo` this puts the unmasked serial and MAC into `IdentificationResult.message`, which the CLI prints and `--json` dumps, contradicting AC 4 on this path. Test: `tests/security/qa/test_qa_config_identify_cli.py::test_identify_error_message_never_contains_unmasked_serial_or_mac` | Medium | Fixed (f21c9a0) |
| DEF-T1.08-2 | T1.08 | `haca identify` (live path) with missing credentials lets `CredentialNotFound` escape `main()` as an uncaught `KeyError` traceback. Spec: exit code 1 on config error. Already-built clients are not closed. Test: `tests/security/qa/test_qa_secrets_redaction.py::test_cli_live_path_missing_credentials_exits_cleanly_with_code_1` | Low | Fixed (f21c9a0) |
| DEF-T1.08-3 | T1.08 | The identify table prints device-supplied strings (model, firmware) raw, so ANSI/OSC/CR control characters from a hostile device reach the terminal. JSON output is safe (escaped). Test: `tests/security/qa/test_qa_config_identify_cli.py::test_table_output_neutralises_control_characters_from_device` | Low | Fixed (f21c9a0) |

## T1.09 — QA Phase 1 details (2026-11-15, SIMULATED)

Code base: `main` @ `e2a39a5` (T1.08), diff base `8321630` (Phase 0): 104 files, +7073/−32.
Verified independently from the task specs and the code. No developer summary was used.
Private data directory `/var/fpwork/ambrosew/skrypty/Hikvision/**` was not opened (ADR-017).

### Criteria matrix summary

| Task | Criteria | PASS | FAIL | Evidence (developer test → QA addition) |
|---|---|---|---|---|
| T1.01 | 5 | 5 | 0 | `python -m haca --version` = `haca 0.1.0.dev0` exit 0; pytest/ruff/mypy green; Python 3.12.13; no forbidden package in pyproject, `uv.lock`, venv or imports (`test_dependencies.py`, QA `test_lockfile_and_environment_have_no_forbidden_packages`); QA `test_pyproject_matches_t101_spec` |
| T1.02 | 6 | 6 | 0 | `test_example_files_load`, `test_ptz01_resolves_to_expected_host`, `test_rejects_*`, `test_empty_profile_defaults`, `test_requirements_hash_*`; QA adds 14 subnet, 16 timeout, 12 secret-key and 8 ORP rejection variants. AC 6: `haca.config` + `haca.requirements` = 92.0 % (statements + branches) with the developer tests; `haca.config` alone is 88.7 %, `loader.py` 83 % (see observation 5) |
| T1.03 | 5 | 5 | 0 | `test_network_policy.py`, `test_registry.py`; QA adds 32 IPv4 (CGNAT, 172.32, multicast, …) and 10 IPv6/mapped `check_host` variants, 20 strict-literal `match()` variants; `mypy --strict` clean on `haca.devices` |
| T1.04 | 7 | 7 | 0 | `test_endpoint_policy.py`, `test_transport_guard.py`, `test_redaction.py`, `test_credentials.py`, `test_dependencies.py`; QA adds 14 methods, 24 denylist bases x 7 transforms (168 variants, each checked with a permissive rule and with the real policy), 32 traversal/encoding variants, 29 target URLs x 2 gemini settings, canary flow. AC 7: `endpoint_policy.py` branch coverage 57/60 = 95.0 % with developer tests (98 % with QA), `transport_guard.py` 100 % |
| T1.05 | 8 | 8 | 0 | `test_client.py`, `test_xml.py`, `test_response_status.py`; QA adds Digest with/without qop (exactly 2 inner calls), stale 401, Basic challenge never answered, 20 redirect variants, 502/503/504 retry vs other statuses, XXE (8 payloads) / billion laughs / quadratic blowup / BOM / namespace / 5 MB boundary / 50 000-deep nesting, status-body matrix |
| T1.06 | 4 | 4 | 0 | `test_fixtures.py`, `test_scanner.py`; QA adds 15 scanner violation variants, 7 provenance negatives, missing-path handling, element-set and value checks against the spec list |
| T1.07 | 5 | 5 | 0 | `test_simulator.py` (3 devices x Digest, wrong password, 5 fault profiles, GET-only log, 405 on raw PUT); QA adds Digest server checks (wrong user/realm/password, unknown nonce, per-device nonces, non-GET 405 when authenticated) and a fault matrix with isolation. Stale nonce → DEF-T1.07-1 (not one of the 5 criteria) |
| T1.08 | 5 | 5 | 0 | `test_cli_identify.py`, `test_identify.py`; manual runs: `identify --simulate` exit 0 with banner and 3 x IDENTIFIED, `--json` exit 0 (banner on stderr, pure JSON on stdout), `requirements validate` exit 0 listing `system.hik_connect` and `ptz01.ptz_mode`; QA adds model strictness, firmware variants, fault matrix, exit-code and error-path tests |
| **Total** | **45** | **45** | **0** | |

### Fabrication / privacy greps

- ISAPI paths in `src/`: only `/ISAPI/System/deviceInfo` (registry, simulator index, 3 fixtures), the denylist patterns, and two `/ISAPI/Synthetic/*` request URLs inside edge-case fixture bodies. Enforced by QA `test_isapi_paths_in_src_are_registry_or_denylist_only`.
- MACs: only `00:00:5E:00:53:xx` plus `AA:BB:CC:DD:EE:FF` in a scanner negative sample. IPs: only `192.168.250.x` plus documented negative-test addresses. Serials: `SYNTH-…`. UUIDs: `00000000-…-0000000000NN`. XML elements in fixtures are limited to the T1.06 list.
- No file in `src/`, `tests/`, `tools/`, `config/` or `pyproject.toml` references the private data directory. It is named only in rule and doc files as a prohibition: `AGENTS.md`, `.cursor/rules/haca-core.mdc`, `.cursor/agents/*.md`, `docs/security-review.md`, `docs/agent-workflow.md`, `docs/tasks/T1.06*.md`, `docs/tasks/T1.09*.md`.
- AST scan (QA `test_src_has_no_write_capable_http_calls`): no `put/post/delete/patch/head/options/send/stream` call in `src/`; the only `.request(` call is in `isapi/client.py`; the public `IsapiClient` surface is `{read, close}`.

### Observations (not defects; no failing test)

1. Response bodies are fully read and decompressed before the 5 MB check. A 60 MB gzip-decompressed body is held in memory before `XmlParseError`. A hostile LAN device could cause memory pressure.
2. The simulator accepts a legacy (RFC 2069, no `qop`) response even though it advertises `qop="auth"`, and does not enforce `nc` monotonicity or `uri` equality.
3. `identify` does not check that the root element is `DeviceInfo`; any 200 XML whose `<model>` matches is `IDENTIFIED`.
4. `mask_serial` reveals the whole serial when it is exactly 4 characters long.
5. T1.02 AC 6 is met only when `config` and `requirements` are measured together (92.0 %). `loader.py` alone is 83 %.
6. 403/404 with a `ResponseStatus` body lacking `subStatusCode` map to `DeviceReportedError`, not `AuthError` / `EndpointNotFound`. `ConnectTimeout` maps to `DeviceConnectionError`, not `DeviceTimeout`. Both are consistent with the spec as written.
7. `xxe.xml` uses an internal entity, not an external `SYSTEM` entity. External-entity, parameter-entity and external-DTD payloads are covered in memory by QA tests.

### Reproduce

```
export UV_CACHE_DIR=/var/fpwork/ambrosew/.xdg/cache/uv; unset UV_INDEX
export PATH=/var/fpwork/ambrosew/.xdg/local/bin:$PATH
uv run pytest -q --cov=haca --cov-branch      # 969 passed, 29 xfailed
uv run pytest -q tests/security/qa -rxX       # 792 passed, 29 xfailed (defect reproductions)
uv run ruff check . && uv run mypy src
```

Fixing a defect turns its strict xfail into a failure (XPASS). The fixer must then remove the `xfail` marker in the same change.
