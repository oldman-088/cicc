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
