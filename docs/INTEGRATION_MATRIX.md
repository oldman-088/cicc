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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `7f6db2a` (updated 2026-11-06T08:40Z; was 5215e31), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `7f6db2a` (updated 2026-11-06T08:40Z; was 5215e31), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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

## M41 addendum (2026-11-06T08:50Z)
- Heads re-reconciled 08:40Z: PR #3 = 4f1776f (stable), PR #8 = 7f6db2a (entry points unchanged — adapter assumptions hold), PR #2 = d542805, PR #1 = 84fca76. Coordination checklists posted to Agents 2/3/4 on PR #4 (comments 6680890246, 6680890872, 6680891573).
- M41 gateway: stale-data detection (stale=true + domain_stale event + evidence.last_stale/stale_after_s when freshness_s or produced_at age > CICC_DOMAIN_STALE_AFTER_S=3600 default); consecutive_failures persisted (last_stale column); contract descriptor notes the stale field.
- tests test_m41_reliability.py 5/5: stale via freshness_s and via produced_at age, exact lifecycle trace order, 6-thread distinct-key concurrent invokes (invokes counter exact), health worst-status FAILED->degraded + recovery->healthy, PG restart persistence of domain stats. API 253+5=258/258 expected; PG 41+1=42.
- M41 cross-agent trial scripts/m41_cross_agent_trial.py 19/19 @08:43Z (sandbox-labeled): success/provenance/label, trace, duplicate, unmounted 409, invalid mount 409, authz 401, BFF write-boundary block 403 + approved POST /tasks 201, tenant PENDING (no leakage), timeout, retry exhaustion, stale, recovery, health, BFF read path, + REAL unmerged TI (4f1776f) and VI (7f6db2a codeload export) modules via gateway.
- Agent 4 contract published: docs/DOMAIN_STATUS_CONTRACT.md; deployment guide docs/DEPLOYMENT.md (verified commands).
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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `0590d14` (updated 2026-11-06 ~08:40Z; was d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `0590d14` (updated 2026-11-06 ~08:40Z; was d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `414b86e` (updated 2026-11-06 ~09:05Z; was 7f6db2a/5215e31/222fdfc), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `0590d14` (updated 2026-11-06 ~08:40Z; was d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `414b86e` (updated 2026-11-06 ~09:05Z; was 7f6db2a/5215e31/222fdfc), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `0590d14` (updated 2026-11-06 ~08:40Z; was d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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

## M41 addendum (2026-11-06T08:50Z)
- Heads re-reconciled 08:40Z: PR #3 = 4f1776f (stable), PR #8 = 7f6db2a (entry points unchanged — adapter assumptions hold), PR #2 = d542805, PR #1 = 84fca76. Coordination checklists posted to Agents 2/3/4 on PR #4 (comments 6680890246, 6680890872, 6680891573).
- M41 gateway: stale-data detection (stale=true + domain_stale event + evidence.last_stale/stale_after_s when freshness_s or produced_at age > CICC_DOMAIN_STALE_AFTER_S=3600 default); consecutive_failures persisted (last_stale column); contract descriptor notes the stale field.
- tests test_m41_reliability.py 5/5: stale via freshness_s and via produced_at age, exact lifecycle trace order, 6-thread distinct-key concurrent invokes (invokes counter exact), health worst-status FAILED->degraded + recovery->healthy, PG restart persistence of domain stats. API 253+5=258/258 expected; PG 41+1=42.
- M41 cross-agent trial scripts/m41_cross_agent_trial.py 19/19 @08:43Z (sandbox-labeled): success/provenance/label, trace, duplicate, unmounted 409, invalid mount 409, authz 401, BFF write-boundary block 403 + approved POST /tasks 201, tenant PENDING (no leakage), timeout, retry exhaustion, stale, recovery, health, BFF read path, + REAL unmerged TI (4f1776f) and VI (7f6db2a codeload export) modules via gateway.
- Agent 4 contract published: docs/DOMAIN_STATUS_CONTRACT.md; deployment guide docs/DEPLOYMENT.md (verified commands).

## M42 addendum (2026-11-06T09:10Z)
- Heads re-reconciled: PR #3 = `aaacd63` (api.py now imports sibling modules as `apps.threat_intelligence.*` — TI adapter resolves repo roots on import failure, read-only; interface unchanged, EXPERIMENTAL_DEMO_DATA_ONLY intact), PR #8 = `414b86e` (entry points unchanged), PR #2 = `0590d14`, PR #1 = `84fca76`.
- M42 gateway: `analyze_freshness` (basis freshness_s|produced_at|none, clock_skew_s for future timestamps — never silently fresh), malformed freshness_s -> 422, stale recovery resets last_stale, claimed_tenant recorded as UNVERIFIED (no enforcement — owner-reserved), audit events for mount/deregister/invoke (actor label only, no tokens), GET /diagnostics (db_ok/uptime/version/domains, read-gated, no secrets), safe shutdown disposes DB engine. tests test_m42_stale_tenant.py 6/6; API 264/264.
- M42 trial v2 scripts/m42_cross_agent_trial.py 18/18 @09:06Z with evidence classes SANDBOX/FIXTURE + SANDBOX/UNMERGED-BRANCH; MERGED-APPLICATION auto-detected NOT RUN (PRs unmerged); PRODUCTION-VERIFIED never claimed. Real unmerged TI @aaacd63 + VI @414b86e executed via gateway.
- Tenant/auth readiness proposal: docs/TENANT_AUTH_READINESS.md (proposal only; enforcement owner-reserved). DOMAIN_STATUS_CONTRACT.md documents stale/last_stale/stale_after_s semantics.
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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `7f6db2a` (updated 2026-11-06T08:40Z; was 5215e31), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `7f6db2a` (updated 2026-11-06T08:40Z; was 5215e31), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `d542805` (updated 2026-11-06T08:25Z; was 747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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

## M41 addendum (2026-11-06T08:50Z)
- Heads re-reconciled 08:40Z: PR #3 = 4f1776f (stable), PR #8 = 7f6db2a (entry points unchanged — adapter assumptions hold), PR #2 = d542805, PR #1 = 84fca76. Coordination checklists posted to Agents 2/3/4 on PR #4 (comments 6680890246, 6680890872, 6680891573).
- M41 gateway: stale-data detection (stale=true + domain_stale event + evidence.last_stale/stale_after_s when freshness_s or produced_at age > CICC_DOMAIN_STALE_AFTER_S=3600 default); consecutive_failures persisted (last_stale column); contract descriptor notes the stale field.
- tests test_m41_reliability.py 5/5: stale via freshness_s and via produced_at age, exact lifecycle trace order, 6-thread distinct-key concurrent invokes (invokes counter exact), health worst-status FAILED->degraded + recovery->healthy, PG restart persistence of domain stats. API 253+5=258/258 expected; PG 41+1=42.
- M41 cross-agent trial scripts/m41_cross_agent_trial.py 19/19 @08:43Z (sandbox-labeled): success/provenance/label, trace, duplicate, unmounted 409, invalid mount 409, authz 401, BFF write-boundary block 403 + approved POST /tasks 201, tenant PENDING (no leakage), timeout, retry exhaustion, stale, recovery, health, BFF read path, + REAL unmerged TI (4f1776f) and VI (7f6db2a codeload export) modules via gateway.
- Agent 4 contract published: docs/DOMAIN_STATUS_CONTRACT.md; deployment guide docs/DEPLOYMENT.md (verified commands).
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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `9ebee7` (updated ~09:15Z; was 0590d14/d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `9ebee7` (updated ~09:15Z; was 0590d14/d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `700e30f` (updated ~09:15Z; was 414b86e/7f6db2a/5215e31/222fdfc — entry points unchanged), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `9ebee7` (updated ~09:15Z; was 0590d14/d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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
| Replacement Agent 3 — Vulnerability Intelligence | arena/259e5471-cicc (#8), arena/fa0df787-cicc (#1) | #8, #1 | `700e30f` (updated ~09:15Z; was 414b86e/7f6db2a/5215e31/222fdfc — entry points unchanged), `84fca76` | REPORTED: `packages/vuln_intel` standalone package (connectors nvd/osv/ghsa/epss/debian, CycloneDX VEX) — NOT mounted into apps/api | no apps/api surface on either PR (verified via PR file lists) | NOT_MOUNTED (honest: GET /domains empty; invoke → 409) | NOT EXECUTED | NOT CONSUMED | PR #1: 70 commits/65 test files; PR #8: 40 commits/48 test files — counts REPORTED from PR metadata | **PR #8 vs #1 merge order is owner-reserved**; then mount via gateway |
| Agent 4 — Frontend/UI-UX | arena/09952395-cicc | #2 | `9ebee7` (updated ~09:15Z; was 0590d14/d542805/747a86c) | REPORTED: apps/web foundation (accessibility, i18n, pages incl. coordination/system-health) — overlaps PR #7 (Backup Agent 4, INACTIVE) | BFF contract VERIFIED by me: server-side proxy, write path limited to POST /api/v1/coordination/tasks, `x-cicc-idempotency-key` on writes (M33) | n/a | n/a | VERIFIED for Agent-1 dashboard (my apps/web, e2e 24/24); PR #2's own pages REPORTED | my web 35/35 + tsc + build; PR #2 tests REPORTED | PR #2 vs #7 overlap — merge order owner-reserved |

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

## M41 addendum (2026-11-06T08:50Z)
- Heads re-reconciled 08:40Z: PR #3 = 4f1776f (stable), PR #8 = 7f6db2a (entry points unchanged — adapter assumptions hold), PR #2 = d542805, PR #1 = 84fca76. Coordination checklists posted to Agents 2/3/4 on PR #4 (comments 6680890246, 6680890872, 6680891573).
- M41 gateway: stale-data detection (stale=true + domain_stale event + evidence.last_stale/stale_after_s when freshness_s or produced_at age > CICC_DOMAIN_STALE_AFTER_S=3600 default); consecutive_failures persisted (last_stale column); contract descriptor notes the stale field.
- tests test_m41_reliability.py 5/5: stale via freshness_s and via produced_at age, exact lifecycle trace order, 6-thread distinct-key concurrent invokes (invokes counter exact), health worst-status FAILED->degraded + recovery->healthy, PG restart persistence of domain stats. API 253+5=258/258 expected; PG 41+1=42.
- M41 cross-agent trial scripts/m41_cross_agent_trial.py 19/19 @08:43Z (sandbox-labeled): success/provenance/label, trace, duplicate, unmounted 409, invalid mount 409, authz 401, BFF write-boundary block 403 + approved POST /tasks 201, tenant PENDING (no leakage), timeout, retry exhaustion, stale, recovery, health, BFF read path, + REAL unmerged TI (4f1776f) and VI (7f6db2a codeload export) modules via gateway.
- Agent 4 contract published: docs/DOMAIN_STATUS_CONTRACT.md; deployment guide docs/DEPLOYMENT.md (verified commands).

## M42 addendum (2026-11-06T09:10Z)
- Heads re-reconciled: PR #3 = `aaacd63` (api.py now imports sibling modules as `apps.threat_intelligence.*` — TI adapter resolves repo roots on import failure, read-only; interface unchanged, EXPERIMENTAL_DEMO_DATA_ONLY intact), PR #8 = `414b86e` (entry points unchanged), PR #2 = `0590d14`, PR #1 = `84fca76`.
- M42 gateway: `analyze_freshness` (basis freshness_s|produced_at|none, clock_skew_s for future timestamps — never silently fresh), malformed freshness_s -> 422, stale recovery resets last_stale, claimed_tenant recorded as UNVERIFIED (no enforcement — owner-reserved), audit events for mount/deregister/invoke (actor label only, no tokens), GET /diagnostics (db_ok/uptime/version/domains, read-gated, no secrets), safe shutdown disposes DB engine. tests test_m42_stale_tenant.py 6/6; API 264/264.
- M42 trial v2 scripts/m42_cross_agent_trial.py 18/18 @09:06Z with evidence classes SANDBOX/FIXTURE + SANDBOX/UNMERGED-BRANCH; MERGED-APPLICATION auto-detected NOT RUN (PRs unmerged); PRODUCTION-VERIFIED never claimed. Real unmerged TI @aaacd63 + VI @414b86e executed via gateway.
- Tenant/auth readiness proposal: docs/TENANT_AUTH_READINESS.md (proposal only; enforcement owner-reserved). DOMAIN_STATUS_CONTRACT.md documents stale/last_stale/stale_after_s semantics.

## M43 addendum (2026-11-06T09:25Z)
- Heads re-reconciled ~09:15Z: PR #3 = `17e1189` (ThreatIntelligenceAPI/invoke_endpoint/EXPERIMENTAL markers all present), PR #8 = `700e30f` (search/health/schema entry points unchanged), PR #2 = `9ebee7`, PR #1 = `84fca76`. Adapter assumptions hold at all new heads.
- M43 gateway features: circuit breaker (CICC_DOMAIN_CIRCUIT_FAILURES=5 default, CICC_DOMAIN_CIRCUIT_COOLDOWN_S=30; open -> fast 503 domain_circuit_open, sanitized, handler NOT executed; half-open after cooldown; success closes), domain health alerts (ops record_domain_alert, rule=domain_status per kind, critical on FAILED, resolved on EXECUTION_VERIFIED; evaluate_alerts no longer auto-resolves domain_* rules), mount history (mount_count/previous_version + replacement audit event), invoke payload cap 64 KiB -> 413. tests test_m43_circuit_alerts.py 5/5; API 269/269, PG 42/42.
- scripts/m43_trial.py 11/11 @09:19:46Z (SANDBOX/FIXTURE): mount/re-mount history, 3x502 -> circuit open -> 503 fast-reject, alert raised+sanitized, cooldown -> 201 + circuit closed + alert resolved, 413 cap, M42 stale/skew/tenant regressions.
- Contract descriptor documents 503/413. All M42 behavior preserved (regression spot-checks in tests + trial). Live @09:19Z: contract 31/31, e2e 24/24, mvp 23/23, cross-domain 32/32, m42 v2 16/16, web 35/35.

## M44 addendum (2026-11-06T09:50Z)
- Heads re-reconciled @~09:40Z: PR #3 = `5d2ab6b` (entry point re-verified: apps/threat_intelligence/api.py 447 lines, `from apps.threat_intelligence...` imports, EXPERIMENTAL_DEMO_DATA_ONLY intact, imports cleanly from codeload export — SANDBOX/UNMERGED-BRANCH read-only check; still NOT mounted, AMD-003 pending); PR #8 = `3bc6527` **MERGED** into PR #1 branch `arena/fa0df787-cicc` @09:33:29Z (owner-reserved #8-before-#1 order executed by owner side; main still `ca8f82c`, so merged-app surface unchanged); PR #1 = `a56c316` (vuln_intel schema/search/health entry points import OK, non-live origin gate intact); PR #2 = `a765188`.
- M44 domain gateway observability: `GET /api/v1/coordination/domains/metrics` (read token) → per-kind `invokes, successes, failures, success_rate, timeouts, retries, stale_count, skew_count, latency{count,avg_s,max_s,last_s}, circuit{open,opened_at,threshold,cooldown_s,opens,closes}, mount_count, status`; top-level `labels=["kind"]` (bounded cardinality — kinds are server-registered only) and a `note` documenting process-local counters. **No tenant ids, tokens, payload values, or user-controlled label values ever appear** (tested). Latency/retry/stale/skew/circuit-transition counters are PROCESS-LOCAL (a restart resets them; invokes/successes/consecutive_failures persist via `coord_domain_stats`) — documented in DOMAIN_STATUS_CONTRACT.md.
- Alert state/recovery history visible via existing `GET /api/v1/ops/alerts/history?rule=domain_status` (active + resolved rows, sanitized) — verified live.
- Tests: test_m44_observability.py 6/6 (aggregation accuracy after known mix incl. timeout/retries; 8-thread concurrency on file-backed SQLite with per-thread TestClients; sensitive-exclusion; circuit-across-restart process-local documented; concurrent failures open exactly once; concurrent recovery closes exactly once; repeated remounts mount_count; boundary payload sizes at the 16 KiB middleware cap with the 64 KiB router check as second layer). Suites: API 275/275, PG 42/42, web 35/35, contract 31/31, e2e 24/24, mvp 23/23, cross-domain 32/32, m40 19/20 (TI ABSENT — PR#3 unmerged), m41 17/17, m42 v2 16/16, m43 11/11, **m44 17/17 @09:44:12Z (SANDBOX/FIXTURE)**.
- Tenant/auth readiness unchanged: claimed-vs-authenticated distinction kept, no isolation claims, metrics/diagnostics exclude tenant identifiers; remaining cross-tenant/audit-actor/DB-access requirements still owner-reserved (TENANT_AUTH_READINESS.md).


## M45 addendum (2026-11-06T10:35Z)
- Heads re-reconciled @~10:05Z: PR #3 = `f3d3a7f` (entry point re-verified: api.py imports cleanly from codeload export, EXPERIMENTAL_DEMO_DATA_ONLY intact); PR #1 = `f8e96c7` (vuln_intel schema/search/health entry points import OK); PR #2 = `b6cf817`; PR #8 = `3bc6527` (merged into PR #1 branch, not main); main `ca8f82c`.
- M45 changes on PR #4: startup restore of persisted domain stats for ALL kinds (lifespan; unmounted kinds stay honestly NOT_MOUNTED but keep historical counters visible in statuses/metrics); `last_success_at` in status evidence + metrics (process-local); `mounts_total` persisted mount-history count in metrics (audit events); circuit open/close transitions persisted as sanitized audit events; 502 `domain_error` no longer leaks exception class names; m44 trial made rerunnable (delta-based assertions).
- AMD-003 still PENDING: precise reversible plan committed as `docs/M45_AMD003_IMPLEMENTATION_PLAN.md` (exact approval text, additive `extra_json` column proposal for coord_domain_stats with rollback, lifecycle flow, executable verification). No reserved shared changes applied.
- Tests: test_m45_beta_readiness.py 7/7 (restart recovery, persisted circuit audit, mounts_total, auth/tenant boundaries, error isolation, sanitization, lifespan events). Suites: API 282/282, PG 42/42, web 35/35, contract 31/31, e2e 24/24, mvp 23/23, cross-domain 32/32, m40 19/20 fresh (TI ABSENT — PR#3 unmerged), m41 17/17, m42 16/16, m43 11/11, m44 17/17 fresh.
- **scripts/m45_mvp_beta_trial.py --manage-api 26/26 @10:33:17Z** covering the 11 M45 acceptance items incl. REAL PR-head TI `f3d3a7f` + VI `f8e96c7` mounted and invoked through the gateway (SANDBOX/UNMERGED-BRANCH, EXPERIMENTAL label + non-live data_origin preserved), auth/tenant boundaries, provenance/freshness, trace/audit, timeout+circuit recovery with alert history, BFF read-only visibility + browser-write 403, and a SIGKILL restart-recovery pass (persisted counters survive; circuit process-local fail-safe; mounts_total + alert history persist). MERGED-APPLICATION: NOT RUN; PRODUCTION-VERIFIED: never claimed.

## M46 addendum (2026-11-06T12:26Z)

### Exact merge gate and evidence classes

- At the live check (2026-11-06T12:26:21Z), `main` was
  `ca8f82c0500637e22851d7128cddf99081ef3c08`. PR #1 was OPEN/unmerged at head
  `78f869b82f5262ab4cacfb996847173274c259ef`; PR #3 was OPEN/unmerged at head
  `5fec62ef39ab66e6fe36ccc483b302eddb7c5a38`. GitHub's PR API returned
  `merge_commit_sha` values `27626a47c891a6a0dc4a653aa3b736bf1aea4c12` and
  `9a2f6c135afe82d7f13bc9cc386c11f6c64c2314`, respectively, but because both
  PRs were OPEN those are not treated as merged commits. The live compare gate
  confirmed both PR head SHAs were not ancestors of main. PR #2 was also OPEN
  at `e745cc2b8ff995b040896212eab2995607c48963`.
- `scripts/m46_merged_app_acceptance.py` re-queries main and PR metadata,
  checks each merged PR's exact `merge_commit_sha` is reachable from that exact
  main SHA (and records whether the PR head itself is reachable), then exports
  only that immutable main tree. It mounts and invokes TI and VI through the
  host gateway only when PR #1 and PR #3 are merged to `main` and both exact
  merge-result commits pass reachability checks. Open-PR merge candidates,
  package presence, and unmerged branch heads cannot open the gate. Python 3.11
  codeload extraction is path/link/device checked before extraction.
- Live run at 2026-11-06T12:26:21Z: **M46 7/7 PASS** for sandbox operational
  checks; exact result `main=ca8f82c...`, PR #1/#3 still OPEN, heads
  `78f869b82f5262ab4cacfb996847173274c259ef` and
  `5fec62ef39ab66e6fe36ccc483b302eddb7c5a38` both `head_on_main=false`;
  **MERGED-APPLICATION NOT RUN**. No merged integration
  or production result is claimed. Acceptance-gate unit tests cover open PR,
  squash-merge (merge SHA reachable while head is not), unreachable merge SHA,
  and non-main base.
- Final regressions: M46 reliability 9/9 + exact-SHA gate 4/4; focused M43–M46
  reliability/regression set 31/31; API 295/295, PostgreSQL 42/42, web 35/35.

### Read-only current-head trials (not merged integration)

- Latest read-only codeload exports were verified against live PR heads:
  PR #3 TI `5fec62ef39ab66e6fe36ccc483b302eddb7c5a38` and PR #1 VI
  `78f869b82f5262ab4cacfb996847173274c259ef`. At 2026-11-06T12:25:40Z,
  `scripts/m45_mvp_beta_trial.py --manage-api` completed **26/26**. TI mounted
  and invoked at `POST /api/v1/coordination/domains/threat_intel/{mount,invoke}`
  (201/201), preserving `EXPERIMENTAL_DEMO_DATA_ONLY`; VI mounted and invoked
  at `POST /api/v1/coordination/domains/vuln_intel/{mount,invoke}` (201/201),
  `count=1`, with non-live `data_origin`. Trace/audit, auth, UNVERIFIED tenant
  claim, restart persistence, and BFF read-only/browser-write-403 checks passed.
  These are **SANDBOX/UNMERGED-BRANCH** executions using demo/fixture data.
- `scripts/m40_integration_trial.py` at 2026-11-06T12:26:11Z completed
  **23/23** with exact TI SHA `5fec62ef39ab66e6fe36ccc483b302eddb7c5a38`
  supplied via `--ti-sha`; TI provenance preserved the experimental label and
  trace result. VI was honestly reported NOT_MOUNTED on this host branch.
  This is **SANDBOX/UNMERGED-BRANCH** for TI and **SANDBOX/FIXTURE** for the
  remaining checks, not merged application, live ingestion, or production.
- `scripts/m44_observability_trial.py` **17/17** at 12:21:42Z and
  `scripts/m43_trial.py` **11/11** at 12:20:46Z passed as SANDBOX/FIXTURE.
  M44 now captures volatile-metric deltas after remount, so reruns remain valid
  when a non-empty DB contains older process-local observations. `contract_check.py`
  31/31, `e2e_check.py` 24/24, MVP 23/23, cross-domain 32/32, M41 17/17, and
  M42 16/16 passed at 12:20:25–12:20:42Z.

### Stable cross-agent boundary (no agent branch or DTO takeover)

- **Domain status DTO:** routes and state names remain the existing contract in
  this document; M46 changes breaker/probe and alert lifecycle internals and
  preserves process-local counters on equal persisted-stat refreshes. No shared
  DTO/schema change was made.
- **Authentication / tenant propagation:** API read/write ops tokens are the
  current sandbox gate, not platform authentication or a verified principal.
  A body `tenant_id` remains an UNVERIFIED claim only; there is no tenant
  isolation claim or trusted principal-to-tenant resolution.
- **Gateway tracing:** `GET /api/v1/coordination/tasks/{task_id}/trace` returns
  `task_id`, `correlation.idempotency_key`, `correlation.event_id`, and events.
  It does not currently expose a separate `trace_id`; acceptance logs record
  the task ID as the trace handle and the actual correlation fields rather
  than inventing a trace ID.
- **Frontend:** the BFF exposes read-only domain visibility/metrics without a
  browser token. The existing only approved BFF write path remains
  `POST /api/v1/coordination/tasks`; browser domain mount/deregister/invoke
  remain blocked (403).
- **Errors / freshness:** existing sanitized HTTP envelopes remain in force
  (including 401/403/409/413/422/429/502/503); error details expose no
  exception class, payload, tenant identifier, or credential. Freshness
  remains derived from `freshness_s` or `produced_at`; future timestamps are
  flagged as clock skew and stale recovery clears `last_stale`.

Agents 2, 3, and 4 retain ownership of their PRs and specialized implementations.
Only read-only codeload exports were used; no other branch or PR was modified.

## M47 current integration/readiness snapshot (2026-11-06; supersedes older branch-head notes above)

### Host and Agent 1 branch
- Agent 1 branch `arena/961971ed-cicc`; PR #4 head at pre-publication review `4a797f480377bc94fa8eec56ae692a8fc337db5d`, OPEN/CLEAN, no attached checks. Main `ca8f82c0500637e22851d7128cddf99081ef3c08`.
- Agent 1 current domain gateway adapter targets the legacy TI `ThreatIntelligenceAPI` simulated dispatcher and the older `packages/vuln_intel` package. Neither TI nor VI is automatically mounted. Current PR #3 evidence does not validate these adapters against the branch's current TI relationship HTTP API or Replacement Agent 3 VI entry point.
- PR #1 HEAD `a942baabc3260683ec1a2b8c9d953c04dceaae9a` OPEN; PR #2 `e745cc2b8ff995b040896212eab2995607c48963` OPEN; PR #3 `7136538f74ab08b33607774c507785fc0c59cd03` OPEN/Draft. PR #3 currently contains the Agent 2 TI handover and Replacement Agent 3 VI work; this is not evidence that both owners approved a shared adapter.

### Readiness evidence
- Agent 1 local API 309/309; isolated PostgreSQL-selected tests 42/42; web tests 35/35; TypeScript typecheck passed. M47-focused preflight/reliability tests 23/23. These are **SANDBOX/BRANCH** evidence only.
- The M44 fixture trial passed 17/17 on clean and non-empty disposable SQLite with `CICC_DOMAIN_CIRCUIT_FAILURES=3`. The default-threshold run returned 16/17 because the script expects 3 while service default is 5. The successful trials do not mount TI/VI or establish live feeds.
- `scripts/m47_merged_app_acceptance.py` no-manifest preflight is **BLOCKED** (exit 2) before API startup. PR #1/#3 remain open and no owner-approved manifest or tenant driver exists. **MERGED-APPLICATION NOT RUN.**
- PR #3 Agent 2 handover reports a standalone experimental TI relationship host not mounted in Agent 1; host acceptance is **0 executed / 8 skipped**. No actual-host/security/schema approval. Its PostgreSQL CI succeeded on that branch but is not host acceptance.
- Agent 4 PR #2 contains candidate lifecycle/diagnostic decoders and readiness UI. Current checked-out Agent 1 UI does not invoke those domain routes. The candidate surface is not approved; PR #2's body has stale Agent 1/2/3 head references, so refresh before decisions.

### M47 contract/state changes
- Half-open circuit probe ownership is a unique expiring UUID lease; expiration permits a successor and stale callbacks cannot close/re-arm another probe's breaker.
- Per-mount generation guards reject outcomes from callbacks started before replacement/deregistration.
- Coordination `GET /domains`, `/domains/{kind}/status`, `/domains/metrics`, `/diagnostics`, `/health` are checked for no SQL DML; stats restoration is in-memory only. The unrelated `/api/v1/ops/alerts` GET still evaluates and may persist derived state; this is not part of the read-only guarantee.
- Diagnostics include nullable `build_commit`; metrics add `probe_inflight`, `probe_lease_expires_in_s`, `probe_lease_expirations`. No schema change; AMD-003 remains PENDING.
- The exact-revision runner requires exact PR merge results or an owner-approved integration checkout, exact module source/tree identity, approved payload/source/owner manifest, real host execution, and an owner-approved tenant driver. It has not passed against a merged or approved application.

See `docs/M47_CROSS_AGENT_CONTRACT_STATUS.md`, `docs/M47_MERGED_APPLICATION_ACCEPTANCE.md`, and `docs/handover/AGENT1_CENTRAL_COORDINATION_HANDOVER.md` for owner-specific gaps and acceptance evidence. No other agent branch or PR was modified.
