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
