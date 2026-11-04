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
