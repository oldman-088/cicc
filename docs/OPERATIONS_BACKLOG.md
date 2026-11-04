# System Health & Operations — engineering backlog

Owner: Lead System Health & Operations Engineer. Updated at each milestone.

## Done this milestone (PR #4 update)

- Live probes: `/live`, `/ready` (503 when DB down), `/health` with real DB round trip.
- Dependency components: `rabbitmq` (management API, 2 s timeout, creds never
  leaked), `platform_api` (env-configured probe), `workers` (derived from real
  task runs only; explicit "RabbitMQ does NOT control Arena sessions" note).
- Endpoints: `/api/v1/ops/{overview,components,metrics,metrics/history,activity,dependencies,tasks/stats}` + `POST /api/v1/ops/tasks` (token-gated when configured).
- Failure isolation (a down component never breaks the overview), 2 s overview
  cache, sliding-window rate limit (429) with probes exempt.
- Real metric snapshots (≤1/min) + history endpoint for trends.
- Dashboard: tab navigation (Overview/Components/Metrics & Trends/Activity/
  Dependencies), alerts banner (down/degraded only), SVG trend charts,
  dependency graph with RTL-aware arrows, activity level filter + search,
  task stats, aria-live/roles/keyboard-accessible tabs, EN/AR parity.
- Tests: API 29 passed (incl. failure isolation, 429, ready-503, no-secret-leak,
  history, tasks, token auth); web 15 node tests + tsc + next build.
- Live smoke: all endpoints direct (:8000) and via web proxy (:3000).

## Done — Milestone 3

- Alert engine: 6 rules with env thresholds, dedup by (rule, component),
  active/acknowledged/resolved states, occurrences, history, audit events,
  REST endpoints + dashboard Alerts tab with ack/resolve actions.
- Worker observability: POST /workers/heartbeat contract, workers list with
  heartbeat age + stalled flag + 24h task stats; stalled-worker alerts.
- RabbitMQ deep metrics when configured: queue totals, queue count,
  consumer count, dead-letter queue count, broker history snapshots;
  circuit breakers on all external probes (stale/unknown, never false ok).
- Security: optional read-token gate, 413 body limit, generic 500 (no
  internal leakage), host-only probe details, credential-leak tests.
- REAL disposable PostgreSQL integration tests via pgserver (5 tests).
- System capacity: real process metrics endpoint + dashboard cards.
- Dashboard v3: 7 tabs (Overview/Components/Metrics/Activity/Dependencies/
  Alerts/Workers & Queues), component diagnostics <details>, 129-key EN/AR
  parity.
- Perf (measured): overview uncached p50 5.6ms/p95 8.3ms; cached ~0ms;
  metrics p50 1.5ms; HTTP via proxy p50 6ms.
- API tests: 56 passed. Web tests: 17 passed; tsc clean; next build OK.

## Next priorities (P1)

1. PostgreSQL integration test against a real disposable Postgres (CI or
   local) — `psycopg2-binary` already in dev requirements.
2. RabbitMQ integration test with a real broker (management API) where
   available; until then the adapter reports `not_configured` honestly.
3. Docker/Compose verification via `scripts/validate_compose.sh` where Docker
   exists (NOT available in the Arena sandbox — limitation documented).
4. Auth on monitoring endpoints once the platform API (da631853 branch)
   fronts them; tenant-scoped metrics.
5. Worker heartbeats + stalled-worker detection via task_runs freshness.
6. Alert notifications (email/webhook) with rate-limited dispatch.
7. Longer retention + downsampling for metric_snapshots.

## Known limitations (honest)

- Docker not available in sandbox → images/compose unbuilt here.
- No RabbitMQ reachable in sandbox → broker check untested against real broker.
- SQLite default; Postgres path coded + driver installed, not yet exercised.
- Single-tenant dev API; no auth on reads yet (contract in MONITORING_CONTRACTS.md §7).
- Branch `arena/da631853-cicc` defines its own `apps/` paths — merge
  coordination required (both trees touch `apps/`).


## Done — Milestone 4 (PR #4 update)

- Maintenance windows: create/cancel/list, rule-scoped + component-scoped
  suppression of alert firing, 422 validation, write-token gated, 404/409
  semantics, recovery ("alert resolved") events preserved.
- Task observability: GET /tasks (worker/queue/status filters), GET
  /tasks/failures (grouped by worker+error), worker heartbeat history with
  60s throttled sampling.
- Retention: throttled purge of ops-owned tables only (OPS_RETENTION_DAYS=30);
  retention events logged. No destructive migrations.
- Auth fix: write token now also satisfies the read gate (single-header writer
  clients); covered by test.
- Perf: idempotent additive indexes; scale benchmark with real seeded data
  (numbers in MONITORING_CONTRACTS §9).
- Verification tooling: scripts/bench_scale.py, scripts/verify_rabbitmq.py
  (REAL broker check, never mocked), docker-compose.verify.yml
  (rabbitmq:3.13-management overlay), scripts/check_no_secrets.sh wired into
  validate_compose.sh (VERIFY_RABBITMQ=1 for live broker verification).
  Docker itself is NOT available in the Arena sandbox — compose validation
  remains an external-verification procedure, executed where Docker exists.
- Dashboard: Workers tab now shows recent task runs (latest 25) + top failure
  groups (24h), EN/AR keys added (141 keys each).
- Tests: API 65 passed (incl. 7 real-Postgres: 80-row concurrent write
  integrity, dead-engine → component "down"); web 17 passed, tsc clean,
  next build OK.
- Live smoke (uvicorn :8000 + next :3000): all new endpoints verified direct
  and via web proxy, incl. 401/404/409/422 paths and suppression behavior.

## Next (backlog, priority order)

1. Real RabbitMQ live verification where Docker exists
   (`VERIFY_RABBITMQ=1 bash scripts/validate_compose.sh`) — record evidence.
2. Cross-agent heartbeat-contract coordination issue (see GitHub issue on
   oldman-088/cicc) — align on POST /workers/heartbeat payload.
3. apps/ integration strategy doc (docs/APPS_INTEGRATION_STRATEGY.md) —
   propose domain subdirs under apps/ to avoid merge conflicts with PR #2
   (apps/web) and arena/da631853 (apps/api+apps/web).
4. Alerting escalation policies + notification channels — NOTIFY DISABLED
   until owner authorizes outbound notifications/costs.
5. RLS/tenant isolation — only against the VERIFIED platform auth contract.


## Done — Milestone 5 (PR #4 update)

- Alerting: severity escalation on occurrences (OPS_ALERT_ESCALATE_OCCURRENCES),
  flap detection (OPS_ALERT_FLAP_WINDOW_S), both event-logged; notifications
  still DISABLED. Additive dialect-aware alert columns (escalated/flapping).
- Perf: task stats via SQL aggregation — 20k-row window p50 224ms → 21ms.
- Auth: platform-auth adapter (verified contract from arena/da631853-cicc),
  inert unless enabled, fail-closed, role allow-lists; static tokens fallback.
  Tenant-isolation PLAN written (docs/TENANT_ISOLATION_PLAN.md); scoping NOT
  enabled (shared-contract decision pending).
- RabbitMQ: verify_rabbitmq.py extended with REAL AMQP 0-9-1 roundtrip (pika);
  management parsing covered by labeled fixture tests; live broker run is
  blocked in the Arena sandbox (no Docker, egress allowlist) — exact external
  procedure in docs/RABBITMQ_VERIFICATION.md.
- Integration: scripts/ops_client.py reference client; issue #5 updated with
  the final contract proposal for Agent 4.
- Tests: API 73/73 (incl. 7 real-PG); web 17/17, tsc clean; dashboard shows
  escalated/flapping chips (EN/AR 143 keys).

## Next (backlog, priority order)

1. Execute RabbitMQ live verification where Docker/broker is reachable; attach
   real evidence to PR #4 / RABBITMQ_VERIFICATION.md.
2. Issue #5: get Agent 4's confirmation on heartbeat/task contract; implement
   compatibility only after agreement.
3. Tenant isolation: execute docs/TENANT_ISOLATION_PLAN.md after owner decides
   shared DB vs read-only replica + ops read roles per tenant.
4. Alerting: escalation policies per rule (multi-level), notification channels
   — still DISABLED until owner authorizes outbound notifications/costs.
5. Per-tenant rate limiting on ops endpoints; ops audit events into platform
   audit table via adapter port.
6. Merge-time apps/ reorganization per APPS_INTEGRATION_STRATEGY.md.


## Done — Milestone 6 (PR #4 update)

- Ops: MAINTENANCE health state; escalation policy engine (occurrence + time
  based, per-rule overrides); alert ownership/assign; worker registry
  (register endpoint, merged into /workers); task attempts; tasks_per_min;
  per-principal write rate limiting (sha256-keyed, auth-before-429);
  notifications adapter registry (disabled, suppression events only).
- Coordination (new, docs/COORDINATION_ARCHITECTURE.md): signed GitHub webhook
  ingestion (HMAC sha256, fail-closed, replay dedup, secrets stripped,
  provenance kept) → durable task registry (10 validated states + audit
  history) → routing engine (DB rules + specialization defaults, unmatched →
  BLOCKED) → delivery (real RabbitMQ durable publish when RABBITMQ_AMQP_URL
  set, else copy-ready human-assisted handoff; dead broker → RETRYING, never
  false delivery) → agent ack/complete/fail reporting. Dashboard Coordination
  tab (EN/AR 161 keys).
- Tests: API 93/93 (incl. 7 real-PG); web 17/17, tsc clean, build OK.
- Live smoke (:8000/:3000): webhook bad-sig 401 → good-sig ingest → replay
  dedup → route → human-assisted deliver → secret-stripped payload → events;
  maintenance state on overview; register; attempts; stats per_min; proxy+page.
- Bench: task_stats p50 ~33ms @20k rows (incl. per_min query), overview 7.6ms.

## Next (backlog, priority order)

1. Real RabbitMQ delivery/ack loop for coordination + broker verification where
   Docker exists (blocked in sandbox; procedure in RABBITMQ_VERIFICATION.md).
2. Agent 4 contract confirmation (PR #4 comment / issue #5).
3. Coordination: workload-aware routing, WAITING_FOR_APPROVAL flow, CI event
   routing, webhook secret rotation doc.
4. Tenant isolation execution after owner decides DB model
   (docs/TENANT_ISOLATION_PLAN.md); per-tenant rate buckets; ops audit adapter.
5. Notification channel adapters — only after explicit owner authorization.


## Done — Milestone 7 (PR #4 update)

- Coordination v2: agent registry + lifecycle, workload-aware explainable
  routing (scoring + reasons, eligibility excludes stale/offline/draining and
  capability-mismatched agents), task lifecycle v2 (14 canonical states +
  legacy aliases, explicit transition policy with audited rejections,
  dependencies gating delivery, timeouts/TTL sweep, cancel/retry,
  idempotency-key dedup, dead-letter after max attempts), approval workflow
  (approver-gated 403, expiry, 409 while waiting, audited), delivery records
  with publisher confirms on real broker / honest human-assisted otherwise,
  webhook allowlist + 413 cap + object validation.
- Ops: per-component alert history endpoint; task stats latency p50/p95/max +
  retry_rate.
- Dashboard: agent registry table, routing explanations (EN/AR 168 keys).
- Tests: API 107/107 (incl. 7 real-PG); web 17/17 + tsc + build.
- Live smoke: full webhook→approval→route→deliver→ack/start/complete + sweep.

## Next (backlog, priority order)

1. Real broker delivery + consumer ack loop when a Docker/broker environment
   is available (environment-blocked here; procedure committed).
2. Agent 4 contract confirmation (PR #4 comment / issue #5); then wire ops
   client into their worker lifecycle.
3. Coordination: progress reports (structured), cross-domain task refs,
   PR/CI joins on the dashboard, dependency DAG endpoint.
4. Tenant isolation execution after owner DB-model decision; per-tenant rate
   buckets; ops audit adapter into platform audit table.
5. Notification channel adapters — only after explicit owner authorization.


## Done — Milestone 8 (PR #4 update)

- LIVE GitHub API integration (api.github.com reachable from sandbox — real,
  not mocked): repo status probe + sync creating tasks from failed CI on
  arena branches and open PRs; idempotent; rate-limit + CB guarded; token
  header-only. Live-verified: probe ok (PRs #1–4, 20 check runs), sync
  created 4 tasks; suite has a live test (skips honestly if unreachable).
- Progress reports (audited, 0–100), dependency DAG endpoint, OSS research
  decisions doc, security review doc, root deliverables
  (MASTER_TASK_QUEUE.md / DEVELOPMENT_LOG.md / PROJECT_STATE.json, Agent-1
  scoped with merge-coordination note).
- Dashboard: live GitHub panel in Coordination tab (EN/AR 174 keys).
- Tests: API 112/112 (7 real-PG + 1 live-GitHub); web 17/17 + tsc + build.

## Next (backlog, priority order)

1. Real RabbitMQ verification + broker delivery loop where Docker exists
   (env-blocked here; procedure committed; attach evidence to PR #4).
2. Agent 4 contract confirmation (PR #4 comment / issue #5) -> wire ops_client.
3. Retry backoff (CICC_COORD_RETRY_BACKOFF_S), prefetch=1 runbook, webhook
   secret rotation + timestamp freshness.
4. Tenant isolation execution after owner DB-model decision; per-tenant rate
   buckets; ops audit adapter.
5. Notification adapters only after explicit owner authorization.
