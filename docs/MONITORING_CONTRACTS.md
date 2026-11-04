# CICC Monitoring Contracts — System Health & Operations subsystem

Owner: Lead System Health & Operations Engineer (branch `arena/961971ed-cicc`, PR #4).
These contracts are the integration surface between the monitoring
subsystem and every other CICC subsystem. Other agents must not redefine
them; propose changes via PR review.

## 1. Health states (closed vocabulary)

`ok` · `degraded` · `down` · `not_implemented` · `not_configured` · `unknown`

- `ok` — a REAL check passed (e.g. DB round trip, HTTP 2xx probe). Never set
  merely because a monitoring endpoint responds.
- `degraded` — reachable but impaired (non-2xx, high latency).
- `down` — real check failed.
- `not_implemented` — module does not exist in this build.
- `not_configured` — optional integration not enabled via env var.
- `unknown` — check itself failed unexpectedly.

Overall status aggregation: any `down` → `down`; else any non-`ok` →
`degraded`; else `ok`; empty → `unknown`.

## 2. Component identifiers

Services: `api`, `database`, `rabbitmq`, `platform_api`, `workers`, `web`
(web is added client-side by the dashboard).
Modules: `threat_intelligence`, `vulnerability_intelligence`,
`command_theater_3d`, `investigations`, `ingestion_pipeline`,
`system_health_ops`.

## 3. Endpoint contracts (FastAPI ops API, base `/`)

| Method | Path | Notes |
|---|---|---|
| GET | `/live` | Liveness. Always 200 while process runs. Never rate limited. |
| GET | `/ready` | Readiness. 200 only if DB check passes, else 503. Never rate limited. |
| GET | `/health` | Liveness + check details (DB round trip). |
| GET | `/api/v1/ops/overview` | Cached ≤2 s. Rate limited (429 beyond `OPS_RATE_LIMIT`/min, default 120). |
| GET | `/api/v1/ops/components` | services + modules with live statuses. |
| GET | `/api/v1/ops/metrics` | Real counters. |
| GET | `/api/v1/ops/metrics/history?hours=1..168` | Real snapshots (recorded ≤1/min). |
| GET | `/api/v1/ops/activity?limit=1..200` | Real events, newest first. |
| GET | `/api/v1/ops/dependencies` | `{nodes: ComponentInfo[], edges: [{from,to,label}]}`. |
| GET | `/api/v1/ops/tasks/stats?hours=1..168` | Aggregates over real task runs. |
| POST | `/api/v1/ops/tasks` | Worker task-run ingestion (see §5). 201 `{id}`. |

ComponentInfo schema:
`{key, kind: "service"|"module", name, status, detail, last_check_at, check?}`

Overview adds: `{generated_at, overall_status, metrics, activity, data_source}`
where `data_source` is always `live-ops-database`.


## 3b. Milestone-3 endpoints (ops API)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/ops/alerts?state=active|acknowledged|resolved|all&limit=` | Evaluates rules, then lists. |
| POST | `/api/v1/ops/alerts/{id}/ack` body `{acked_by?}` | 200 / 404 / 409 (resolved). |
| POST | `/api/v1/ops/alerts/{id}/resolve` | 200 / 404 / 409. |
| GET | `/api/v1/ops/workers` | Real heartbeats + per-worker 24h task stats + stalled flag. |
| POST | `/api/v1/ops/workers/heartbeat` body `{worker, details?}` | Write-token gated like /tasks. Local worker liveness ONLY. |
| GET | `/api/v1/ops/broker/history?hours=` | Real broker-total snapshots (recorded only on successful checks). |
| GET | `/api/v1/ops/system` | Real process metrics (RSS/CPU/threads/pid/uptime) of the API process. |

Alert rules (thresholds via env): `component_down` (critical),
`component_degraded` (warning), `database_slow` (> `OPS_DB_LATENCY_WARN_MS`, 1000),
`worker_stalled` (heartbeat older than `OPS_WORKER_STALL_S`, 120s),
`task_failures` (>= `OPS_TASK_FAIL_THRESHOLD`, 5/hour),
`queue_backlog` (`messages_ready` > `OPS_QUEUE_BACKLOG_THRESHOLD`, 1000).
Dedup by (rule, component_key): open alerts update occurrences; cleared
conditions resolve and keep history. Ack/resolve are audited in events.

Circuit breakers: external probes (`rabbitmq`, `CICC_PLATFORM_API_URL`) are
wrapped per-probe; after `OPS_CB_FAILURES` (3) consecutive failures the probe
is skipped for `OPS_CB_COOLDOWN_S` (30s) and reports `status=unknown,
stale=true` with the last observed status — never a false `ok`.

Security additions: `CICC_OPS_READ_TOKEN` (optional Bearer gate on ops GETs;
probes /live /ready /health stay open for orchestrators), 413 body limit
(16 KiB) on writes, generic 500 (`internal_error`, details logged server-side
only), host-only probe details, `hide_password` on DB URLs.

PostgreSQL: integration-tested against a REAL disposable PostgreSQL
(pgserver/pypi) — see apps/api/tests/test_postgres_integration.py.

## 4. Configuration (env)

- `DATABASE_URL` — default `sqlite:///./data/ops.db`; PostgreSQL via
  `postgresql+psycopg://…`. Passwords are never rendered in responses
  (`render_as_string(hide_password=True)` + host-only URLs for probes).
- `CORS_ORIGINS` — comma-separated allowed origins.
- `RABBITMQ_MANAGEMENT_URL` (+ optional `RABBITMQ_USER`/`RABBITMQ_PASS`) —
  enables the RabbitMQ broker check against the management API
  (`GET {base}/api/overview`, 2 s timeout). Reports broker availability and
  queue totals (`messages_ready`, `messages_unacknowledged`, `queues`).
- `CICC_PLATFORM_API_URL` — enables probing the integration/platform API
  (`GET {base}/health`, 2 s timeout) as dependency `platform_api`.
- `CICC_OPS_WRITE_TOKEN` — if set, `POST /api/v1/ops/tasks` requires
  `Authorization: Bearer <token>`. Production MUST set it; without it the
  endpoint is open (trusted-network/dev only).
- `OPS_RATE_LIMIT` — per-client ops-endpoint limit per minute (default 120).

## 5. Worker / task contract

Workers report task executions via `POST /api/v1/ops/tasks`:

```json
{"worker": "w1", "queue": "arena-tasks", "status": "success|failed|running",
 "started_at": "…", "finished_at": "…", "duration_ms": 42, "error": "…"}
```

This records **task execution only**. It is NOT evidence that RabbitMQ
controls Arena agent sessions — that integration is not implemented or
verified, and the API explicitly says so in the `workers` component detail.

## 6. RabbitMQ boundary statement

- Monitored: broker reachability + queue totals via the management API.
- NOT monitored/claimed: consumer counts per Arena agent, agent heartbeats,
  Arena session control. A reachable queue does NOT mean an Arena agent is
  operational.
- Distinction maintained everywhere: RabbitMQ availability ≠ local worker
  availability ≠ task execution success ≠ Arena agent activity.

## 7. Integration points with other subsystems (contracts to fulfill)

| Subsystem | Contract expected from owner | Monitoring side |
|---|---|---|
| Threat Intelligence module | expose `GET /health` when deployed; register component `threat_intelligence` | shows `not_implemented` until then |
| Vulnerability Intelligence | same, component `vulnerability_intelligence` | `not_implemented` |
| 3D Command Theater | same, component `command_theater_3d` | `not_implemented` |
| Investigations | same, component `investigations` | `not_implemented` |
| Ingestion pipeline | report sync attempts via `sync_attempts` (API: record through ops service) | `not_configured`; last successful sync shown truthfully as *never* |
| Platform API (branch `arena/da631853-cicc`) | deploy with `/health`; set `CICC_PLATFORM_API_URL` | `platform_api` dependency probe |
| AuthN/AuthZ, tenants, audit | monitoring endpoints must inherit auth when the platform API fronts them; tenant scope for all future multi-tenant metrics | currently single-tenant dev API, documented |

## 8. Security & privacy boundaries for monitoring data

- No secrets, credentials, internal hostnames beyond configured probe hosts,
  or tenant data in any dashboard response or log line.
- Error details are exception type names, never raw connection strings.
- Rate limiting on ops endpoints; probes exempt for orchestrators.
- Write endpoint (`POST /tasks`) token-gated when `CICC_OPS_WRITE_TOKEN` set.


## 9. Milestone-4 endpoints & contracts (ops API, all under read-token gate)

Read gate: `CICC_OPS_READ_TOKEN` (when set) protects ALL ops endpoints. Write
gate: `CICC_OPS_WRITE_TOKEN` (when set) protects mutations. **When both are
set, the write token also satisfies the read gate** (write ⊇ read), so a
single `Authorization: Bearer <write>` header authorizes writer clients.

| Endpoint | Method | Notes |
|---|---|---|
| `/api/v1/ops/tasks?worker&queue&status&limit` | GET | `status` in running\|success\|failed, `limit` ≤ 500; rows: id/worker/queue/status/started_at/finished_at/duration_ms/error/created_at |
| `/api/v1/ops/tasks/failures?hours&limit` | GET | failed runs grouped by (worker, error): count + last_seen |
| `/api/v1/ops/workers/history?worker&hours` | GET | sampled heartbeat history, `sample_interval_s=60` (throttled writes) |
| `/api/v1/ops/maintenance?active=` | GET | list maintenance windows (active-only filter) |
| `/api/v1/ops/maintenance` | POST | 201; 422 if `ends_at <= starts_at`; write token |
| `/api/v1/ops/maintenance/{id}/cancel` | POST | 200; 404 unknown; 409 already cancelled/ended |

Maintenance-window alert suppression: an ACTIVE window suppresses firing of
alerts whose rule matches `window.rule`, or — when `window.rule` is null — all
rules (optionally narrowed by `component_keys`). Suppressed OPEN alerts are
intentionally NOT auto-resolved (they resolve only on real recovery), so the
alert history remains truthful. Cancelled windows re-enable firing.

Retention: `build_overview` triggers a throttled (≥1h apart) `purge_old_data()`
that deletes rows older than `OPS_RETENTION_DAYS` (default 30) from ONLY the
ops-owned tables `metric_snapshots`, `broker_snapshots`,
`worker_heartbeat_history`, `events` — never platform tables, and never a
destructive migration. A `retention` event is logged for each purge.

Performance: idempotent `CREATE INDEX IF NOT EXISTS` on task_runs(created_at,
worker), events(ts), metric_snapshots(ts), worker_heartbeat_history(worker,ts),
alerts(status) — additive only, safe on live DBs.

Scale benchmark (scripts/bench_scale.py, real seeded data, SQLite):
20k task runs / 5k events / 2k snapshots / 1k heartbeat samples →
task list (limit 100) p50 1.6ms; failures(24h) p50 7.5ms; activity p50 1.2ms;
history(168h) p50 19.5ms; worker history p50 8.0ms; evaluate_alerts p50 4.9ms;
full overview p50 8.2ms; retention purge p50 0.9ms. task stats over the full
20k-row window p50 ~224ms (documented; not on the overview hot path).


## 10. Milestone-5 contracts & behaviors

- **Alert escalation**: when an open alert reaches `OPS_ALERT_ESCALATE_OCCURRENCES`
  (default 10) occurrences, severity bumps one level (info→warning→critical),
  `escalated=true`, and an `alerts` event is logged. Outbound notifications
  remain DISABLED (no notify path exists; policy-gated).
- **Flap detection**: if a (rule, component) alert resolves and the same key
  resolves again within `OPS_ALERT_FLAP_WINDOW_S` (default 300s), the alert is
  marked `flapping=true` and re-fires inherit the flag. Event logged.
- Alert objects now expose `escalated` and `flapping` (additive columns via
  dialect-aware, non-destructive ADD COLUMN — SQLite + PostgreSQL).
- **Task stats** computed via SQL aggregation (was row-materializing;
  20k-row window p50 224ms → 21ms, scripts/bench_scale.py).
- **Platform auth adapter** (`app/platform_auth.py`, INERT unless
  `CICC_OPS_USE_PLATFORM_AUTH=1` + `CICC_PLATFORM_DB_URL`): verifies bearer
  sha256 digest against the VERIFIED platform schema (`auth_sessions`⋈`users`),
  fails closed; role allow-lists `CICC_OPS_READ_ROLES` / `CICC_OPS_WRITE_ROLES`.
  Static env tokens remain the fallback for non-platform deployments.
  Tenant scoping of ops data: plan only — docs/TENANT_ISOLATION_PLAN.md.
- **RabbitMQ verification**: scripts/verify_rabbitmq.py performs REAL
  management-API + AMQP 0-9-1 roundtrip checks (never mocked);
  docs/RABBITMQ_VERIFICATION.md records the sandbox limitation and the exact
  external procedure. Management parsing covered by labeled fixture tests.
- **Reference ops client** for integration agents: scripts/ops_client.py
  (heartbeat/task senders, --dry-run). Contract unchanged from §5/§9.
