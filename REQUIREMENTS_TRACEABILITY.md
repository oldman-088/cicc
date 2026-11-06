# REQUIREMENTS TRACEABILITY — Agent 1 scope (Security Monitoring / System Health & Operations + Central Coordination)

Owner: Agent 1 (branch arena/961971ed-cicc, PR #4). Whole-product traceability is
coordinated at PR #4; other agents map their own domains. Master prompt ref:
README.md (ULTIMATE MASTER PROMPT v1.0, main@ca8f82c) §12.

| Requirement (master prompt) | Implementation | API / file | Tests | Docs | Status |
|---|---|---|---|---|---|
| Monitoring + health checks (DoD Operations) | ops API health/overview/components/metrics/activity/system + circuit breakers | `/api/v1/ops/*`, apps/api/app/{checks,ops}.py | test_health.py, test_circuit_breaker.py (in 155/155) | MONITORING_CONTRACTS.md | DONE |
| Alerting with escalation/flap/maintenance | rules engine, dedup, escalation, flap, maintenance state, history | `/api/v1/ops/alerts*` | test_alerts.py | MONITORING_CONTRACTS.md § | DONE |
| Worker/task observability | workers register/heartbeat/history, task runs, stats p50/p95/max | `/api/v1/ops/workers`, `/tasks` | milestone4/5 tests | DEVLOG | DONE |
| Retention | purge of ops-owned tables only | ops.retention | retention tests | MONITORING_CONTRACTS | DONE |
| Authentication | read/write tokens, write⊇read, platform-auth adapter (inert, fail-closed) | ratelimit.py, platform_auth.py | auth tests | SECURITY_REVIEW.md, API_REFERENCE.md | DONE (platform auth pending owner) |
| Authorization | approver gate, per-endpoint gates, BFF server-side authz | approvals.py, BFF route | approval/BFF tests | SECURITY_REVIEW.md | DONE |
| Tenant isolation tested (DoD) | NOT implemented — decision doc only | docs/TENANT_ISOLATION_DECISION.md | — | TENANT_ISOLATION_* | BLOCKED on owner |
| Audit logging | every coordination transition audited incl. rejected; ops events | coord_task_events, events | m11/m13 audit tests | COORDINATION_ARCHITECTURE.md | DONE |
| Central agent coordination | registry/webhook/routing/approvals/deliveries/progress/DAG/metrics/sweep + LIVE GitHub + programmatic enqueue | `/api/v1/coordination/*` | m6–m16 suites (155/155) | INTEGRATION_CONTRACTS.md, API_REFERENCE.md | DONE (contract v1.0; agent confirmations pending) |
| Reliable messaging (RabbitMQ) | durable+confirms+DLQ code path; human-assisted honest fallback | handoff.py | unit tests; live broker env-blocked | RABBITMQ_VERIFICATION.md | ENV-BLOCKED |
| Webhook security | HMAC, dedup, rotation, replay detection alert, allowlist, size cap, redaction | webhook.py | m7/m16 tests | SECURITY_REVIEW.md §M14/M16 | DONE |
| BFF (no browser tokens) | server-side proxy + token injection + write block + same-origin | apps/web/app/api/[...path]/route.ts | tests/bff.test.mjs + live | SECURITY_REVIEW.md §M14 | DONE |
| Notifications | disabled adapter, no network path | notifications.py | m13 test | SECURITY_REVIEW.md | DISABLED per owner |
| Frontend (reference dashboard) | apps/web tabs incl. Coordination; EN/AR+RTL; honest states | apps/web | 23/23 + tsc + build | SYSTEM_HEALTH_DASHBOARD.md | DONE (Agent 4 owns final UI) |
| API documentation | docs/API_REFERENCE.md + FastAPI /docs | docs/API_REFERENCE.md | conformance harness | API_REFERENCE.md | DONE |
# REQUIREMENTS TRACEABILITY — Agent 1 scope (Security Monitoring / System Health & Operations + Central Coordination)

Owner: Agent 1 (branch arena/961971ed-cicc, PR #4). Whole-product traceability is
coordinated at PR #4; other agents map their own domains. Master prompt ref:
README.md (ULTIMATE MASTER PROMPT v1.0, main@ca8f82c) §12.

| Requirement (master prompt) | Implementation | API / file | Tests | Docs | Status |
|---|---|---|---|---|---|
| Monitoring + health checks (DoD Operations) | ops API health/overview/components/metrics/activity/system + circuit breakers | `/api/v1/ops/*`, apps/api/app/{checks,ops}.py | test_health.py, test_circuit_breaker.py (in 155/155) | MONITORING_CONTRACTS.md | DONE |
| Alerting with escalation/flap/maintenance | rules engine, dedup, escalation, flap, maintenance state, history | `/api/v1/ops/alerts*` | test_alerts.py | MONITORING_CONTRACTS.md § | DONE |
| Worker/task observability | workers register/heartbeat/history, task runs, stats p50/p95/max | `/api/v1/ops/workers`, `/tasks` | milestone4/5 tests | DEVLOG | DONE |
| Retention | purge of ops-owned tables only | ops.retention | retention tests | MONITORING_CONTRACTS | DONE |
| Authentication | read/write tokens, write⊇read, platform-auth adapter (inert, fail-closed) | ratelimit.py, platform_auth.py | auth tests | SECURITY_REVIEW.md, API_REFERENCE.md | DONE (platform auth pending owner) |
| Authorization | approver gate, per-endpoint gates, BFF server-side authz | approvals.py, BFF route | approval/BFF tests | SECURITY_REVIEW.md | DONE |
| Tenant isolation tested (DoD) | NOT implemented — decision doc only | docs/TENANT_ISOLATION_DECISION.md | — | TENANT_ISOLATION_* | BLOCKED on owner |
| Audit logging | every coordination transition audited incl. rejected; ops events | coord_task_events, events | m11/m13 audit tests | COORDINATION_ARCHITECTURE.md | DONE |
| Central agent coordination | registry/webhook/routing/approvals/deliveries/progress/DAG/metrics/sweep + LIVE GitHub + programmatic enqueue | `/api/v1/coordination/*` | m6–m16 suites (155/155) | INTEGRATION_CONTRACTS.md, API_REFERENCE.md | DONE (contract v1.0; agent confirmations pending) |
| Reliable messaging (RabbitMQ) | durable+confirms+DLQ code path; human-assisted honest fallback | handoff.py | unit tests; live broker env-blocked | RABBITMQ_VERIFICATION.md | ENV-BLOCKED |
| Webhook security | HMAC, dedup, rotation, replay detection alert, allowlist, size cap, redaction | webhook.py | m7/m16 tests | SECURITY_REVIEW.md §M14/M16 | DONE |
| BFF (no browser tokens) | server-side proxy + token injection + write block + same-origin | apps/web/app/api/[...path]/route.ts | tests/bff.test.mjs + live | SECURITY_REVIEW.md §M14 | DONE |
| Notifications | disabled adapter, no network path | notifications.py | m13 test | SECURITY_REVIEW.md | DISABLED per owner |
| Frontend (reference dashboard) | apps/web tabs incl. Coordination; EN/AR+RTL; honest states | apps/web | 23/23 + tsc + build | SYSTEM_HEALTH_DASHBOARD.md | DONE (Agent 4 owns final UI) |
| API documentation | docs/API_REFERENCE.md + FastAPI /docs | docs/API_REFERENCE.md | conformance harness | API_REFERENCE.md | DONE |
| Backup process documented + restore tested (DoD Operations) | scripts/backup_restore.py logical backup/restore/verify (sha256 manifest, sanitized URL, refuse-non-empty) | scripts/backup_restore.py | test_m36_backup_restore.py (SQLite+PG roundtrip 3/3) | docs/DISASTER_RECOVERY.md | DONE (M36) |
| Disaster recovery limitations documented (DoD Operations) | RPO/RTO + limitations incl. webhook dedup, broker state | — | same tests | docs/DISASTER_RECOVERY.md | DONE (M36) |
| Domain integration gateway (coordination) | domains.py registry + GET /domains + POST /domains/{kind}/invoke | apps/api/app/coordination/{domains,router}.py | test_m20 (+2), test_m31_pg (+1) | INTEGRATION_DEPENDENCY_MAP.md M35 addendum | DONE (coordination-side); no real domain mounted — BLOCKED on PR merge order (owner) |

## M47 reliability/acceptance trace (2026-11-06)

| Requirement / control | Implementation | Tests / evidence | Status |
|---|---|---|---|
| Concurrency-safe exact circuit probe lease | `apps/api/app/coordination/domains.py` — unique lease UUID with monotonic expiry, active-lease comparison for callback, successor admission on expiry | `apps/api/tests/test_m47_reliability.py`; full API 309/309; M47 focused suite 23/23 | IMPLEMENTED + LOCAL TESTED (single-process; not distributed breaker) |
| Reject stale results after mount replacement/deregister | mount generation UUID captured by invoke and compared before outcome affects active domain state | `apps/api/tests/test_m47_reliability.py` | IMPLEMENTED + TESTED |
| Read-only status/diagnostics with persistence restored at startup | Domain GETs and diagnostics do not issue SQL DML; persisted stats load in-memory; idempotent repeated restore | `apps/api/tests/test_m47_reliability.py`, `test_m46_ops_reliability.py`; PostgreSQL-selected 42/42 | IMPLEMENTED + TESTED; `/api/v1/ops/alerts` GET is explicitly outside this guarantee |
| Probe/build diagnostics | optional `CICC_BUILD_SHA` -> nullable `build_commit`; metric fields `probe_inflight`, `probe_lease_expires_in_s`, `probe_lease_expirations` | API schema/route tests and M47 reliability tests | IMPLEMENTED + TESTED; frontend contract approval pending |
| Exact merged-application acceptance | `scripts/m47_merged_app_acceptance.py`, `apps/api/tests/test_m47_acceptance_preflight.py`, `docs/M47_MERGED_APPLICATION_ACCEPTANCE.md` | No-manifest preflight BLOCKED before app startup; requires exact source/tree identity and owner-approved manifest/tenant driver | IMPLEMENTED; MERGED-APPLICATION NOT RUN |
| TI/VI trusted host integration | Agent 2/Replacement Agent 3 contract and exact source owners required; Agent 1 adapters remain legacy candidates | PR #3 reports actual-host tests 0 executed / 8 skipped; no approved manifest/host/pool/audit driver | BLOCKED; no integration approval or production claim |
| Master Prompt source alignment | `README.md` v1.0 reread; SHA-256 `6249373bd3c19602b4a92f217afa3236ad18b5b51feea188bf1b791fbbb611d1`; original unchanged | `docs/MASTER_PROMPT_ALIGNMENT.md`; full technical mapping in `docs/handover/AGENT1_CENTRAL_COORDINATION_HANDOVER.md` | DOCUMENTED; production DoD remains unmet |

## M48 whole-product acceptance status (2026-11-06)

| Master Prompt / acceptance item | Current evidence | Status / boundary |
|---|---|---|
| Agent 1 API, PostgreSQL and Web regression checks | API 309/309; PostgreSQL-selected 42/42; Web 35/35; typecheck/build PASS; PR #4 CI `42246801975` 3/3 jobs | PASS on Agent 1 branch `157645e9`; not merged/deployed product acceptance |
| Exact-revision merged application | `scripts/m47_merged_app_acceptance.py --checkout .` exited 2 because no owner-approved revision/module/host/tenant manifest; app did not start | BLOCKED / NOT RUN |
| TI actual Agent 1 host | PR #3 CI explicitly excludes actual-host tests; handover 0/8 | BLOCKED; no integration credit |
| VI actual Agent 1 host | PR #1 handover claims 6/6; all six workflow jobs succeeded, but raw log/count unavailable to this audit and no mounted route exists | Candidate evidence only; not merged-app acceptance |
| Production authentication and tenant isolation (§10, §17) | No principal-bound tenant data pools, RLS or cross-tenant acceptance; AMD-003 pending | NOT IMPLEMENTED/VERIFIED; tenant-isolation acceptance 0% |
| Product-wide core modules, graph, source integrations, AI, 3D, localization and deployment (§4–§9, §17) | Candidate branches and documentation are tracked separately; no integrated acceptance evidence for full scope | INCOMPLETE; see `docs/handover/CICC_PROJECT_COMPLETION_STATUS.md` |
