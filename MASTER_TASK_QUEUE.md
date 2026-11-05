# MASTER TASK QUEUE — Agent 1 section (Central Coordination + System Health & Operations)

> Ownership note: this file is maintained by Agent 1 for the coordination/ops
> domain. Other agents keep their own sections/files; merge must reconcile
> without overwriting (see docs/APPS_INTEGRATION_STRATEGY.md).

Branch: `arena/961971ed-cicc` · PR: #4 (OPEN, never self-merged)

## Done (M1–M8, commits …→89e3a3c + M8 commit)
- Ops API v0.3.0+: health/overview/components/metrics/activity/dependencies/tasks/workers/alerts/broker/system; failure isolation; cache; 429; tokens; 413.
- Alerts: rules, dedup, ack/resolve/assign/owner, escalation (occurrence+time+per-rule), flap detection, maintenance state + suppression, recovery events, per-component history. Notifications DISABLED by design.
- Workers: register + heartbeat + history (throttled), stalled detection; task runs w/ attempts; failures analytics; stats w/ p50/p95/max, per-min, retry_rate.
- Maintenance windows CRUD + cancel; retention purge (own tables only, OPS_RETENTION_DAYS).
- Coordination: GitHub webhook (HMAC, replay dedup, allowlist, size cap, secret redaction) + LIVE GitHub API sync (api.github.com); task registry (14 states, audited transitions, deps, timeouts, TTL, cancel/retry, idempotency, dead-letter); agent registry; workload-aware explainable routing; approvals (approver-gated, expiry); delivery records (publisher confirms on real broker; honest human-assisted otherwise); progress reports; DAG; sweep.
- Dashboard: 8 tabs incl. Coordination (agents, tasks, GitHub live panel); EN/AR 174 keys; a11y.
- Platform-auth adapter (inert, fail-closed) matching verified contract on arena/da631853-cicc; tenant-isolation PLAN (not enabled).
- Tooling: bench_scale.py, verify_rabbitmq.py (mgmt + AMQP roundtrip), ops_client.py, check_no_secrets.sh, docker-compose.verify.yml, validate_compose.sh (VERIFY_RABBITMQ=1).

## Done — M11 (integration & reliability proof)
- M11-01 lifecycle integration tests (9 scenarios) green at HTTP boundary; 2 real fixes: EXPIRED from CREATED/VALIDATING, deps→409.
- M11-02 contract v1.0 (25 endpoints) + Agent 4 dashboard contract; PR #4 comment requesting confirmation.
- M11-04 GitHub reliability: pagination, transient retry, full-body reads (live-caught truncation bug).
- M11-05 tenant-isolation decision doc (options A–D, rec: B) — awaiting owner.
- M11-06 dashboard: broker chip + delivery channel split + honest unavailable states.
- API 135/135 (7 real-PG + 1 live-GitHub); web 17/17 + tsc + build; i18n 188/188.

## Done — M12 (cross-agent integration & readiness)
- Contract adoption record w/ per-agent evidence (docs/CONTRACT_ADOPTION.md);
  v1.0 unchanged; PR #4 comments to Agents 2/3/4 (incl. Agent 4 visual verification).
- E2E integration tests: threat-intel flow (submit→route→handoff→ack→progress→
  complete→audit), vuln task depends_on threat (409 until done), dashboard payload
  shapes. Simulated agents explicitly labeled; no Arena-session claims.
- Reliability tests: stale agents, approval expiry (410/409), dead-letter filter +
  audit, restart recovery, timeout, duplicates. API 142/142 (7 real-PG + 1 live-GitHub).
- Live smoke: E2E on :8000, dashboard :3000 page 200, LIVE github via proxy ok.
- Security review M12 section w/ unresolved owner decisions; tenant isolation still
  pending; notifications disabled.

## Done — M13 (integration stabilization)
- Agent 4's 4 blockers answered on PR #4; docs/API_REFERENCE.md (read-side
  contract: DTOs, error codes, cache semantics); path inconsistency fixed.
  Agents 2/3 still silent — agreement NOT assumed; v1.0 unchanged.
- Boundary tests (8): uniform errors, auth gates, cross-domain routing
  isolation, webhook->dashboard read chain, audit completeness, idempotency,
  no-network notifications, secret redaction. Fixes: report 409 on
  non-applicable state; /events task_id. API 150/150.
- Tenant isolation still pending owner (M13-04); notifications disabled;
  RabbitMQ deprioritized per owner (M13-05) — human-assisted delivery kept.

## Done — M14 (integration closure)
- BFF server-side token injection implemented + tested + live-verified
  (apps/web/app/api/[...path]/route.ts, lib/bff.mjs): no token in browser JS,
  client auth headers stripped, writes 403, optional same-origin enforcement,
  no token logging. web 23/23.
- Webhook security findings documented (SECURITY_REVIEW.md §M14): real
  protections + honest no-signed-timestamp limitation + remaining replay
  risk + safe mitigations.
- Adoption record split accepted/rejected/pending (CONTRACT_ADOPTION.md);
  Agents 2/3 PENDING (not assumed); Agent 4 visual QA requested on PR #4.
- Regression: API 150/150 (7 real-PG + 1 live-GitHub); web 23/23 + tsc + build.

## In progress / next (priority)
1. Real RabbitMQ verification + broker delivery loop — environment-blocked here (no Docker; egress allowlist); run `VERIFY_RABBITMQ=1 bash scripts/validate_compose.sh` where Docker exists; attach evidence to PR #4.
2. Agent 4 heartbeat/task contract confirmation (PR #4 comment + issue #5).
3. Tenant isolation execution after owner DB-model decision (docs/TENANT_ISOLATION_PLAN.md).
4. Retry backoff policy (CICC_COORD_RETRY_BACKOFF_S) + prefetch=1 runbook note.
5. Webhook secret rotation + timestamp freshness check.
6. Merge-time apps/ops/* reorg per strategy doc.

## Blocked / needs owner
- Outbound notification channels (owner authorization required; adapters disabled).
- Shared DB vs read-only replica for platform auth (owner decision; recommendation in TENANT_ISOLATION_PLAN.md).
- Destructive/shared migrations: never without approval.
