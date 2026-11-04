# System Health & Operations Dashboard

Operational health dashboard for the CICC platform (Agent 1 assignment).
Provides a real-time overview of platform services, module health,
operational metrics and a system activity timeline, in English and Arabic
(with RTL support).

## Architecture

```
apps/api   FastAPI operations service  (real health checks + ops DB)
apps/web   Next.js 14 dashboard         (/api/* proxied server-side to the API)
```

- `GET /live` — liveness (always 200 while the process runs; not rate limited).
- `GET /ready` — readiness: 200 only if the **real** DB check passes, else 503.
- `GET /health` (API) — liveness + a **real** database round trip (`SELECT 1`).
- `GET /api/health` (web route) — web UI status + proxied backend check.
- `GET /api/v1/ops/overview` — services, modules, metrics, recent activity (cached ≤2 s).
- `GET /api/v1/ops/components` — component registry with live, truthful statuses.
- `GET /api/v1/ops/metrics` — real counters (COUNT/MAX on the ops database).
- `GET /api/v1/ops/metrics/history?hours=1..168` — real recorded snapshots for trends.
- `GET /api/v1/ops/activity?limit=N` — real recorded events, newest first.
- `GET /api/v1/ops/dependencies` — service dependency graph with live node statuses.
- `GET /api/v1/ops/tasks/stats?hours=N` — stats over real worker-reported task runs.
- `POST /api/v1/ops/tasks` — worker task-run ingestion (token-gated when
  `CICC_OPS_WRITE_TOKEN` is set). See `docs/MONITORING_CONTRACTS.md`.

Ops endpoints are rate limited per client (default 120/min, `OPS_RATE_LIMIT`,
429 beyond); `/live`, `/ready`, `/health` are exempt for orchestrators.
RabbitMQ is monitored via `RABBITMQ_MANAGEMENT_URL` (broker + queue totals
only — never credentials, and never any claim about Arena session control).

## Data honesty rules

- No service is reported healthy without an actual check.
- Metrics are real database counts. On a fresh database they are **0** —
  that is the truthful value, not a placeholder.
- Modules not implemented in this build are reported as `not_implemented`.
- No synthetic/demo/mock data is presented as live intelligence. The
  `data_source` field of the overview states `live-ops-database`.
- No CVEs, campaigns or events are fabricated; the API records only its
  own real events (e.g. service start).

## Run locally

```bash
# API
cd apps/api
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                      # tests
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Web (separate terminal)
cd apps/web
npm ci
npm test                                 # node --test (i18n + status logic)
npm run typecheck                        # tsc --noEmit
npm run build                            # production build
API_INTERNAL_URL=http://127.0.0.1:8000 npm run dev   # http://localhost:3000
```

Or with Docker (compose files provided; image builds were NOT executed in
the development sandbox — validate where Docker is available):

```bash
docker compose up --build    # web on :3000, api on :8000
```

Configuration via environment variables — see `.env.example`.

## Known limitations / outstanding integrations

- Threat Intelligence, Vulnerability Intelligence, 3D Command Theater and
  Investigations modules are not implemented in this build and are shown as
  `not_implemented`.
- No external intelligence source is connected (sandbox outbound access is
  limited to package registries and GitHub), so sync history is empty and
  "last successful sync" is reported as *never*.
- SQLite is the default datastore; PostgreSQL via `DATABASE_URL` is
  supported by the code but was not exercised against a live server here.
- Docker/Compose images are untested in this environment.
- Future integration: this dashboard lives alongside the work on branch
  `arena/da631853-cicc` (which has its own `apps/web` demo shell and API).
  Merging the two trees will require coordination because both define
  `apps/` paths — to be resolved by the lead architect via PR review.
