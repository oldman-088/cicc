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
