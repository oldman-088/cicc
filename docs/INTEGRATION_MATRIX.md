# INTEGRATION MATRIX — four primary agents (owner-confirmed model, 2026-11-06)

Owner: Agent 1 (branch `arena/961971ed-cicc`, PR #4). Statuses marked
**VERIFIED** are backed by a run I executed; **REPORTED** come from another
agent's PR body and are NOT independently verified by me; **BLOCKED** awaits an
owner decision. Master prompt: README.md @ main `ca8f82c` v1.0.

| Agent / domain | Branch | PR | Latest head (2026-11-06 ~08:00Z) | Implementation | Contract | Handler registration | Actual invocation | Frontend consumption | Test evidence | Blockers |
|---|---|---|---|---|---|---|---|---|---|---|
| Agent 1 — coordination + ops/health | arena/961971ed-cicc | #4 | `2d84b34` (M36) → M37 uncommitted | VERIFIED implemented | v1.0 descriptor served at /contract (AMD-001/002/003 pending owner) | n/a (this IS the gateway) | VERIFIED: domain invoke executed in tests + live smoke (fixture handler; real domains NOT mounted) | VERIFIED: own dashboard via BFF (e2e 24/24) | API 241/241, PG 41/41, web 35/35, contract 31/31, trials 23/23 + 32/32 (sandbox-labeled) | AMD decisions; RabbitMQ live (env-blocked); tenant/platform auth (owner) |
| Agent 2 — Threat Intelligence (AVAILABLE) | arena/93315d2c-cicc | #3 | `23715c9` | REPORTED: standalone `apps/threat_intelligence` (Pydantic v2 models/services, osint_sources.py; 41/41 unit tests claimed in PR body — REPORTED, not re-run by me) | REPORTED: INTEGRATION_PREPARATION_REPORT.md in PR #3; no coordination contract confirmation yet | NOT_MOUNTED (no handler in apps/api; gateway mount path ready: POST /domains/{kind}/mount from module, read-only) | NOT EXECUTED — no real TI result has passed the gateway | NOT CONSUMED (Agent 4 pages exist in PR #2 but no live TI data) | PR #3: 1 commit, 1 test file — thin; PR #6 (Agent 6, INACTIVE) has richer TI but is not active | merge order vs main; contract confirmation; P1-05 coordination |
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `222fdfc`, `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `747a86c` | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

## Gateway contract for domain owners (Agent 2 / Replacement Agent 3)

- Mount (read-only, write-token, Agent 1 side): `POST /api/v1/coordination/domains/{kind}/mount` with
  `{module_path, attr, version, source_ref}` — imports a handler `attr(payload, task)` from a server-side
  file WITHOUT modifying the domain package; or register in-process at API startup.
- Handler contract: return `{"result": <json>, "provenance": {"source", "produced_at", ...}}` — include
  confidence / freshness / source timestamps / input fingerprint when the domain has them.
  Handlers MUST be idempotent: the gateway retries with the SAME idempotency_key and guarantees at-most-once
  execution per key at the gateway level (DB-unique).
- Invoke: `POST /api/v1/coordination/domains/{kind}/invoke` (API write-token only — deliberately NOT via the
  browser BFF write path): 201 result+provenance+idempotency_key | 200 duplicate | 409 not mounted |
  502 sanitized error | 422 invalid response. Timeout `CICC_DOMAIN_INVOKE_TIMEOUT_S` (10s), retries
  `CICC_DOMAIN_INVOKE_RETRIES` (1).
- Evidence: `GET /domains`, `GET /domains/{kind}/status`, `GET /health` (domains component) report
  NOT_MOUNTED / MOUNTED / AVAILABLE / EXECUTION_VERIFIED / DEGRADED / FAILED / UNKNOWN from observed invokes only.
- Trace: every invoke creates a task; `GET /tasks/{id}/trace` shows events incl. `domain_result` with
  provenance and the persisted result.

## Honesty rules

- A standalone package or OpenAPI description is NOT a mounted domain (VI: NOT_MOUNTED until a handler is
  registered and invoked — currently true for TI and VI).
- REPORTED statuses from other agents' PR bodies are labeled REPORTED, not VERIFIED, until I execute them.
- All trials are sandbox/fixture-labeled; nothing here is a production claim.
# INTEGRATION MATRIX — four primary agents (owner-confirmed model, 2026-11-06)

Owner: Agent 1 (branch `arena/961971ed-cicc`, PR #4). Statuses marked
**VERIFIED** are backed by a run I executed; **REPORTED** come from another
agent's PR body and are NOT independently verified by me; **BLOCKED** awaits an
owner decision. Master prompt: README.md @ main `ca8f82c` v1.0.

| Agent / domain | Branch | PR | Latest head (2026-11-06 ~08:00Z) | Implementation | Contract | Handler registration | Actual invocation | Frontend consumption | Test evidence | Blockers |
|---|---|---|---|---|---|---|---|---|---|---|
| Agent 1 — coordination + ops/health | arena/961971ed-cicc | #4 | `2d84b34` (M36) → M37 uncommitted | VERIFIED implemented | v1.0 descriptor served at /contract (AMD-001/002/003 pending owner) | n/a (this IS the gateway) | VERIFIED: domain invoke executed in tests + live smoke (fixture handler; real domains NOT mounted) | VERIFIED: own dashboard via BFF (e2e 24/24) | API 241/241, PG 41/41, web 35/35, contract 31/31, trials 23/23 + 32/32 (sandbox-labeled) | AMD decisions; RabbitMQ live (env-blocked); tenant/platform auth (owner) |
| Agent 2 — Threat Intelligence (AVAILABLE) | arena/93315d2c-cicc | #3 | `4f1776f` (confirmed via GitHub API 2026-11-06T07:19Z; earlier record `23715c9` was stale; Agent 2 asked to confirm on PR #4) | REPORTED+READ: standalone `apps/threat_intelligence` incl. `api.py` P1-05 mounting interface at `4f1776f` (192/192 claimed — REPORTED); I READ the PR-head file and executed it read-only via the adapter (see below); `Agent1CoordinationContract.register_domain_gateway` is SIMULATED in their code — not a real mount | REPORTED: INTEGRATION_PREPARATION_REPORT.md in PR #3; no coordination contract confirmation yet | NOT_MOUNTED on main/my branch (file absent until PR #3 merges); VERIFIED READ-ONLY execution of PR-head `api.py` @4f1776f via `domain_adapters/threat_intel_adapter.py` through the gateway: mount 201, invoke 201, provenance.source=`threat_intelligence_api_v1::/api/v1/threat-intelligence/osint-sources`, confidence=1.0, EXPERIMENTAL_DEMO_DATA_ONLY preserved, trace persisted (M40 trial 23/23 @07:52Z, sandbox-labeled) | EXECUTED (read-only, PR-head export, EXPERIMENTAL_DEMO_DATA_ONLY data) via M40 trial; production mount still NOT done (PR #3 unmerged) | NOT CONSUMED (Agent 4 pages exist in PR #2 but no live TI data) | PR #3: 1 commit, 1 test file — thin; PR #6 (Agent 6, INACTIVE) has richer TI but is not active | merge order vs main; contract confirmation; P1-05 coordination |
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `222fdfc`, `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `747a86c` | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

## Gateway contract for domain owners (Agent 2 / Replacement Agent 3)

- Mount (read-only, write-token, Agent 1 side): `POST /api/v1/coordination/domains/{kind}/mount` with
  `{module_path, attr, version, source_ref}` — imports a handler `attr(payload, task)` from a server-side
  file WITHOUT modifying the domain package; or register in-process at API startup.
- Handler contract: return `{"result": <json>, "provenance": {"source", "produced_at", ...}}` — include
  confidence / freshness / source timestamps / input fingerprint when the domain has them.
  Handlers MUST be idempotent: the gateway retries with the SAME idempotency_key and guarantees at-most-once
  execution per key at the gateway level (DB-unique).
- Invoke: `POST /api/v1/coordination/domains/{kind}/invoke` (API write-token only — deliberately NOT via the
  browser BFF write path): 201 result+provenance+idempotency_key | 200 duplicate | 409 not mounted |
  502 sanitized error | 422 invalid response. Timeout `CICC_DOMAIN_INVOKE_TIMEOUT_S` (10s), retries
  `CICC_DOMAIN_INVOKE_RETRIES` (1).
- Evidence: `GET /domains`, `GET /domains/{kind}/status`, `GET /health` (domains component) report
  NOT_MOUNTED / MOUNTED / AVAILABLE / EXECUTION_VERIFIED / DEGRADED / FAILED / UNKNOWN from observed invokes only.
- Trace: every invoke creates a task; `GET /tasks/{id}/trace` shows events incl. `domain_result` with
  provenance and the persisted result.

## Honesty rules

- A standalone package or OpenAPI description is NOT a mounted domain (VI: NOT_MOUNTED until a handler is
  registered and invoked — currently true for TI and VI).
- REPORTED statuses from other agents' PR bodies are labeled REPORTED, not VERIFIED, until I execute them.
- All trials are sandbox/fixture-labeled; nothing here is a production claim.

## M38 addendum (2026-11-06T08:00Z)
- Agent 2 HEAD reconciled: `4f1776f83d929aa7ef951952808fa6d1569a2a1c` (PR #3 head == branch head, GitHub API 07:19Z; commit msg "P1-05 Threat Intelligence API Implementation & Mounting … 192/192"). Confirmation requested from Agent 2 via PR #4 comment.
- Contract comparison (docs/TI_CONTRACT_COMPARISON.md): their `ThreatIntelligenceAPI.invoke_endpoint(path, req) -> {status,data,total_count,has_more,provenance:str,confidence,timestamp,experimental_label}` vs gateway handler contract `{result, provenance:{source,produced_at,...}}` — adapter `apps/api/app/coordination/domain_adapters/threat_intel_adapter.py` maps fields (provenance string -> source, timestamp -> produced_at tz-aware, confidence/freshness_s computed, experimental_label preserved, task+idempotency_key correlation; status=error -> sanitized DomainError). Their `register_domain_gateway` is simulated in their branch — real registration happens via my gateway mount (read-only).
- M40 trial `scripts/m40_integration_trial.py` 23/23 @07:52Z: lifecycle, invoke, provenance, trace, duplicate, retry, timeout, DEGRADED, recovery, 409 honest, health accuracy, BFF frontend reads, deregister, + real TI module read-only execution. All SANDBOX/FIXTURE-labeled.
- Note for Agent 2 (not modified): PR #3 includes committed `__pycache__/*.pyc` files — hygiene suggestion to remove before merge.
# INTEGRATION MATRIX — four primary agents (owner-confirmed model, 2026-11-06)

Owner: Agent 1 (branch `arena/961971ed-cicc`, PR #4). Statuses marked
**VERIFIED** are backed by a run I executed; **REPORTED** come from another
agent's PR body and are NOT independently verified by me; **BLOCKED** awaits an
owner decision. Master prompt: README.md @ main `ca8f82c` v1.0.

| Agent / domain | Branch | PR | Latest head (2026-11-06 ~08:00Z) | Implementation | Contract | Handler registration | Actual invocation | Frontend consumption | Test evidence | Blockers |
|---|---|---|---|---|---|---|---|---|---|---|
| Agent 1 — coordination + ops/health | arena/961971ed-cicc | #4 | `2d84b34` (M36) → M37 uncommitted | VERIFIED implemented | v1.0 descriptor served at /contract (AMD-001/002/003 pending owner) | n/a (this IS the gateway) | VERIFIED: domain invoke executed in tests + live smoke (fixture handler; real domains NOT mounted) | VERIFIED: own dashboard via BFF (e2e 24/24) | API 241/241, PG 41/41, web 35/35, contract 31/31, trials 23/23 + 32/32 (sandbox-labeled) | AMD decisions; RabbitMQ live (env-blocked); tenant/platform auth (owner) |
| Agent 2 — Threat Intelligence (AVAILABLE) | arena/93315d2c-cicc | #3 | `23715c9` | REPORTED: standalone `apps/threat_intelligence` (Pydantic v2 models/services, osint_sources.py; 41/41 unit tests claimed in PR body — REPORTED, not re-run by me) | REPORTED: INTEGRATION_PREPARATION_REPORT.md in PR #3; no coordination contract confirmation yet | NOT_MOUNTED (no handler in apps/api; gateway mount path ready: POST /domains/{kind}/mount from module, read-only) | NOT EXECUTED — no real TI result has passed the gateway | NOT CONSUMED (Agent 4 pages exist in PR #2 but no live TI data) | PR #3: 1 commit, 1 test file — thin; PR #6 (Agent 6, INACTIVE) has richer TI but is not active | merge order vs main; contract confirmation; P1-05 coordination |
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `5215e31` (updated 2026-11-06), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `747a86c` | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

## Gateway contract for domain owners (Agent 2 / Replacement Agent 3)

- Mount (read-only, write-token, Agent 1 side): `POST /api/v1/coordination/domains/{kind}/mount` with
  `{module_path, attr, version, source_ref}` — imports a handler `attr(payload, task)` from a server-side
  file WITHOUT modifying the domain package; or register in-process at API startup.
- Handler contract: return `{"result": <json>, "provenance": {"source", "produced_at", ...}}` — include
  confidence / freshness / source timestamps / input fingerprint when the domain has them.
  Handlers MUST be idempotent: the gateway retries with the SAME idempotency_key and guarantees at-most-once
  execution per key at the gateway level (DB-unique).
- Invoke: `POST /api/v1/coordination/domains/{kind}/invoke` (API write-token only — deliberately NOT via the
  browser BFF write path): 201 result+provenance+idempotency_key | 200 duplicate | 409 not mounted |
  502 sanitized error | 422 invalid response. Timeout `CICC_DOMAIN_INVOKE_TIMEOUT_S` (10s), retries
  `CICC_DOMAIN_INVOKE_RETRIES` (1).
- Evidence: `GET /domains`, `GET /domains/{kind}/status`, `GET /health` (domains component) report
  NOT_MOUNTED / MOUNTED / AVAILABLE / EXECUTION_VERIFIED / DEGRADED / FAILED / UNKNOWN from observed invokes only.
- Trace: every invoke creates a task; `GET /tasks/{id}/trace` shows events incl. `domain_result` with
  provenance and the persisted result.

## Honesty rules

- A standalone package or OpenAPI description is NOT a mounted domain (VI: NOT_MOUNTED until a handler is
  registered and invoked — currently true for TI and VI).
- REPORTED statuses from other agents' PR bodies are labeled REPORTED, not VERIFIED, until I execute them.
- All trials are sandbox/fixture-labeled; nothing here is a production claim.
# INTEGRATION MATRIX — four primary agents (owner-confirmed model, 2026-11-06)

Owner: Agent 1 (branch `arena/961971ed-cicc`, PR #4). Statuses marked
**VERIFIED** are backed by a run I executed; **REPORTED** come from another
agent's PR body and are NOT independently verified by me; **BLOCKED** awaits an
owner decision. Master prompt: README.md @ main `ca8f82c` v1.0.

| Agent / domain | Branch | PR | Latest head (2026-11-06 ~08:00Z) | Implementation | Contract | Handler registration | Actual invocation | Frontend consumption | Test evidence | Blockers |
|---|---|---|---|---|---|---|---|---|---|---|
| Agent 1 — coordination + ops/health | arena/961971ed-cicc | #4 | `2d84b34` (M36) → M37 uncommitted | VERIFIED implemented | v1.0 descriptor served at /contract (AMD-001/002/003 pending owner) | n/a (this IS the gateway) | VERIFIED: domain invoke executed in tests + live smoke (fixture handler; real domains NOT mounted) | VERIFIED: own dashboard via BFF (e2e 24/24) | API 241/241, PG 41/41, web 35/35, contract 31/31, trials 23/23 + 32/32 (sandbox-labeled) | AMD decisions; RabbitMQ live (env-blocked); tenant/platform auth (owner) |
| Agent 2 — Threat Intelligence (AVAILABLE) | arena/93315d2c-cicc | #3 | `4f1776f` (confirmed via GitHub API 2026-11-06T07:19Z; earlier record `23715c9` was stale; Agent 2 asked to confirm on PR #4) | REPORTED+READ: standalone `apps/threat_intelligence` incl. `api.py` P1-05 mounting interface at `4f1776f` (192/192 claimed — REPORTED); I READ the PR-head file and executed it read-only via the adapter (see below); `Agent1CoordinationContract.register_domain_gateway` is SIMULATED in their code — not a real mount | REPORTED: INTEGRATION_PREPARATION_REPORT.md in PR #3; no coordination contract confirmation yet | NOT_MOUNTED on main/my branch (file absent until PR #3 merges); VERIFIED READ-ONLY execution of PR-head `api.py` @4f1776f via `domain_adapters/threat_intel_adapter.py` through the gateway: mount 201, invoke 201, provenance.source=`threat_intelligence_api_v1::/api/v1/threat-intelligence/osint-sources`, confidence=1.0, EXPERIMENTAL_DEMO_DATA_ONLY preserved, trace persisted (M40 trial 23/23 @07:52Z, sandbox-labeled) | EXECUTED (read-only, PR-head export, EXPERIMENTAL_DEMO_DATA_ONLY data) via M40 trial; production mount still NOT done (PR #3 unmerged) | NOT CONSUMED (Agent 4 pages exist in PR #2 but no live TI data) | PR #3: 1 commit, 1 test file — thin; PR #6 (Agent 6, INACTIVE) has richer TI but is not active | merge order vs main; contract confirmation; P1-05 coordination |
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `5215e31` (updated 2026-11-06), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `747a86c` | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

## Gateway contract for domain owners (Agent 2 / Replacement Agent 3)

- Mount (read-only, write-token, Agent 1 side): `POST /api/v1/coordination/domains/{kind}/mount` with
  `{module_path, attr, version, source_ref}` — imports a handler `attr(payload, task)` from a server-side
  file WITHOUT modifying the domain package; or register in-process at API startup.
- Handler contract: return `{"result": <json>, "provenance": {"source", "produced_at", ...}}` — include
  confidence / freshness / source timestamps / input fingerprint when the domain has them.
  Handlers MUST be idempotent: the gateway retries with the SAME idempotency_key and guarantees at-most-once
  execution per key at the gateway level (DB-unique).
- Invoke: `POST /api/v1/coordination/domains/{kind}/invoke` (API write-token only — deliberately NOT via the
  browser BFF write path): 201 result+provenance+idempotency_key | 200 duplicate | 409 not mounted |
  502 sanitized error | 422 invalid response. Timeout `CICC_DOMAIN_INVOKE_TIMEOUT_S` (10s), retries
  `CICC_DOMAIN_INVOKE_RETRIES` (1).
- Evidence: `GET /domains`, `GET /domains/{kind}/status`, `GET /health` (domains component) report
  NOT_MOUNTED / MOUNTED / AVAILABLE / EXECUTION_VERIFIED / DEGRADED / FAILED / UNKNOWN from observed invokes only.
- Trace: every invoke creates a task; `GET /tasks/{id}/trace` shows events incl. `domain_result` with
  provenance and the persisted result.

## Honesty rules

- A standalone package or OpenAPI description is NOT a mounted domain (VI: NOT_MOUNTED until a handler is
  registered and invoked — currently true for TI and VI).
- REPORTED statuses from other agents' PR bodies are labeled REPORTED, not VERIFIED, until I execute them.
- All trials are sandbox/fixture-labeled; nothing here is a production claim.

## M38 addendum (2026-11-06T08:00Z)
- Agent 2 HEAD reconciled: `4f1776f83d929aa7ef951952808fa6d1569a2a1c` (PR #3 head == branch head, GitHub API 07:19Z; commit msg "P1-05 Threat Intelligence API Implementation & Mounting … 192/192"). Confirmation requested from Agent 2 via PR #4 comment.
- Contract comparison (docs/TI_CONTRACT_COMPARISON.md): their `ThreatIntelligenceAPI.invoke_endpoint(path, req) -> {status,data,total_count,has_more,provenance:str,confidence,timestamp,experimental_label}` vs gateway handler contract `{result, provenance:{source,produced_at,...}}` — adapter `apps/api/app/coordination/domain_adapters/threat_intel_adapter.py` maps fields (provenance string -> source, timestamp -> produced_at tz-aware, confidence/freshness_s computed, experimental_label preserved, task+idempotency_key correlation; status=error -> sanitized DomainError). Their `register_domain_gateway` is simulated in their branch — real registration happens via my gateway mount (read-only).
- M40 trial `scripts/m40_integration_trial.py` 23/23 @07:52Z: lifecycle, invoke, provenance, trace, duplicate, retry, timeout, DEGRADED, recovery, 409 honest, health accuracy, BFF frontend reads, deregister, + real TI module read-only execution. All SANDBOX/FIXTURE-labeled.
- Note for Agent 2 (not modified): PR #3 includes committed `__pycache__/*.pyc` files — hygiene suggestion to remove before merge.

## M38-hardening / M39 addendum (2026-11-06T08:25Z)
- Agent 2 HEAD reconfirmed `4f1776f` (PR #3 head unchanged at 07:47Z check). Agent 3 side: PR #8 head moved to `5215e31` (recorded; merge order vs #1 still owner-reserved).
- TI adapter hardened + VI adapter added (`domain_adapters/vuln_intel_adapter.py`): wraps `packages/vuln_intel` READ-ONLY; ops search/health; enum/CveId coercion from JSON; `data_origin` provenance field preserves Origin.is_real (live vs fixture/demo) honesty.
- Gateway hardening: consecutive_failures tracking; hardened response validation (ISO produced_at, confidence in [0,1]); restart persistence of domain stats via coord_domain_stats (`load_persisted_stats` on status/domains/health/mount) — VERIFIED live across a real process restart (08:22Z: after restart+re-mount, threat_intel EXECUTION_VERIFIED invokes=7 succ=5, vuln_intel EXECUTION_VERIFIED invokes=1).
- REAL PR-head modules executed read-only through the gateway (sandbox-labeled, EXPERIMENTAL/demo data only): TI PR #3 @4f1776f (source=threat_intelligence_api_v1::..., label EXPERIMENTAL_DEMO_DATA_ONLY, confidence 1.0) and VI PR #8 @5215e31 via codeload export (search hit CVE-2021-44228, data_origin=non-live:demo; health readiness=not_ready honest). NOT production mounts (PRs unmerged).
- Tests: test_m38b_hardening.py 7/7 (retry exhaustion attempts counted, consecutive timeouts, recovery+reset, restart persistence, hardened validation 422s, secret-leakage regression, concurrent same-key single creator on file-SQLite, deregister-during-inflight safe), test_m39_vi_adapter.py 2/2. API 253/253, PG 41/41.
- M40 trial re-run 23/23 @08:22Z. Live: contract 31/31, e2e 24/24, mvp 23/23, cross-domain 32/32, web 35/35.
