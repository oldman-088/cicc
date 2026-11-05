# CICC API Reference — M13 (read-side contract for the dashboard / Agent 4)

Base URLs (verified against `app/main.py`):
- Operations: `/api/v1/ops/...` (`app/routers/ops.py`, prefix `/api/v1/ops`)
- Coordination: `/api/v1/coordination/...` (`app/coordination/router.py`, prefix `/api/v1/coordination`)
- Health: `/`, `/health`, `/ready`

The Next.js dashboard proxies **server-side via the BFF** (M14):
browser calls relative `/api/...` with **no token**; the route handler
`app/api/[...path]/route.ts` forwards to `API_INTERNAL_URL` and injects
`Authorization: Bearer $WEB_BFF_API_TOKEN` (server env only). Client
`Authorization`/`Cookie`/`x-cicc-*` headers are stripped; writes return 403
unless `WEB_BFF_ALLOW_WRITES=1`; `WEB_BFF_ENFORCE_SAME_ORIGIN=1` rejects
cross-site browser requests. Logs contain only method/path/status.
**No browser-held static token is introduced; nothing secret is stored in
web storage.**

## Authentication & errors (applies to both families)

| Code | Meaning |
|---|---|
| 200/201 | success |
| 400 | missing header (e.g. `X-GitHub-Delivery`) |
| 401 | missing/invalid read token (reads) or write token (writes); webhook: bad/absent HMAC or secret not configured (fail-closed) |
| 403 | authenticated but not allowed (e.g. non-approver on approve/reject) |
| 404 | unknown task/agent id |
| 409 | illegal state transition / deliver while WAITING_FOR_APPROVAL / depends_on unmet / no pending approval |
| 410 | approval expired (decided after TTL, before sweep) |
| 413 | body too large (16 KiB API, 256 KiB webhook) |
| 422 | schema validation (FastAPI) |
| 429 | rate limited (global read limiter; per-principal write limiter) |

Write token implies read (`require_write_token` also satisfies read gate).
Env: `CICC_OPS_READ_TOKEN`, `CICC_OPS_WRITE_TOKEN`, `CICC_GH_WEBHOOK_SECRET`
(+ `CICC_GH_WEBHOOK_SECRET_PREVIOUS` during rotation).

## Coordination GET DTOs (dashboard reads)

- `GET /api/v1/coordination/agents` → `{agents: [{agent, specialization, capabilities[], status, stale, last_seen, active_tasks, completed_tasks, failed_tasks, ...}]}` — `stale` computed vs `CICC_AGENT_STALE_S` (300s).
- `GET /api/v1/coordination/tasks?state=&agent=&kind=&dead_letter=&limit=` → `{tasks: [{task_id, event_id, source, kind, agent, state, priority, repo, pr_ref, branch_ref, title, attempts, result, owner, depends_on[], timeout_s, expires_at, dead_letter, routing_explanation, progress, next_retry_at, payload, handoff, created_at, updated_at}]}` — `state` is one of the 14 canonical states.
- `GET /api/v1/coordination/tasks/dag?limit=` → `{nodes: [{task_id, kind, state, agent, priority}], edges: [{from, to}], known_ids[]}`.
- `GET /api/v1/coordination/metrics` → `{tasks_total, by_state{}, by_kind{}, active_by_agent{}, avg_progress_active, dead_lettered, deliveries_total, deliveries_by_outcome{}, approvals_pending, agents_registered, agents_online}` — honest DB counts; no fabrication.
- `GET /api/v1/coordination/events?limit=` → `{events: [{delivery_id, event, received_at, action, repo, sender, task_id, normalized?}]}` — webhook-ingested events with provenance.
- `GET /api/v1/coordination/tasks/{id}`, `/events`, `/deliveries`, `/approval` — per-task detail; `deliveries[]` has `channel` (`rabbitmq`|`human_assisted`) and `status` (`published`|`confirmed`|`failed`); `confirmed` only with real broker publisher-confirm.
- `GET /api/v1/coordination/github/status` → **LIVE** api.github.com probe: `{status, repo, open_prs[], open_issues[], check_runs[], rate_limit?}`; non-ok when unreachable (circuit-breaker guarded) — the UI shows "unavailable", never fabricated data.
- `GET /api/v1/coordination/rules` → routing rules.

## Ops GETs

- `GET /api/v1/ops/overview` → `OverviewResponse {generated_at, overall_status, services[], modules[], metrics, activity[], data_source, cached}` — short-TTL cache (`OVERVIEW_CACHE_TTL_S=2.0`), `cached:true` when served from cache; `data_source` labels real vs unavailable.
- Also: `/components`, `/metrics`, `/metrics/history`, `/activity`, `/dependencies`, `/tasks`, `/workers`, `/alerts`, `/alerts/history`, `/broker/history`, `/system`, `/maintenance`.

## Task states (14 canonical)
CREATED, VALIDATING, QUEUED, ASSIGNED, DELIVERING, ACKNOWLEDGED, RUNNING,
WAITING_FOR_APPROVAL, COMPLETED, FAILED, RETRYING, BLOCKED, CANCELLED, EXPIRED.
Legacy aliases accepted on input, normalized. Every transition (incl. rejected)
is in `GET /tasks/{id}/events`.

## Tenancy
Single-tenant trusted deployment only. Ops/coordination tables have **no
`tenant_id`**; tenant isolation is a documented owner decision
(`docs/TENANT_ISOLATION_DECISION.md`) and is NOT production-claimed.
