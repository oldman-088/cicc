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
