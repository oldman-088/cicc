# DEPLOYMENT — Agent 1 services (verified commands, M41, 2026-11-06)

Verified by actually running these commands in this workspace (sandbox).
**Not a production deployment** — no production credentials exist here; see
RELEASE_READINESS.md for the honest readiness statement.

## API (coordination + ops)

```bash
cd apps/api
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt        # if present, else: pip install fastapi uvicorn sqlalchemy pydantic psycopg2-binary pgserver httpx
cat > .env.local  # NEVER committed: tokens below are sandbox examples only
# CICC_OPS_READ_TOKEN=...  CICC_OPS_WRITE_TOKEN=...  (write implies read)
# CICC_COORD_APPROVERS=owner
# CICC_GH_WEBHOOK_SECRET=...            (fail-closed when unset)
# DATABASE_URL=sqlite:////tmp/cicc.db   (PostgreSQL: postgresql+psycopg2://...)
# CICC_BUILD_SHA=<immutable deployed Git commit> (optional; returned by coordination diagnostics)
# CICC_DOMAIN_INVOKE_TIMEOUT_S=10  CICC_DOMAIN_INVOKE_RETRIES=1  CICC_DOMAIN_STALE_AFTER_S=3600
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# checks: curl -s localhost:8000/health ; /ready ; /docs (OpenAPI)
```

## Web dashboard + BFF

```bash
cd apps/web
npm ci && npm run build
# server env only: API_INTERNAL_URL=http://127.0.0.1:8000  WEB_BFF_API_TOKEN=<read token>
# WEB_BFF_ALLOW_WRITES=1 (default) — write allowlist is still ONLY POST /api/v1/coordination/tasks
# WEB_BFF_ENFORCE_SAME_ORIGIN=1
npm run start -- -p 3000
```

## Tests / verification (all sandbox-labeled)

```bash
cd apps/api && . .venv/bin/activate
python -m pytest -q -p no:cacheprovider                 # API suite (SQLite)
python -m pytest -q -p no:cacheprovider -k "postgres or pg"   # real-PG suite (pgserver)
cd ../web && npm test                                     # BFF/dashboard unit tests
# live trials (need API :8000 + WEB :3000):
API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 WRITE_TOKEN=... READ_TOKEN=... \
  python3 scripts/{contract_check,e2e_check,mvp_sandbox_trial,cross_domain_trial,m40_integration_trial,m41_cross_agent_trial}.py
```

## Backup / restore (M36, tested)

```bash
python3 scripts/backup_restore.py backup  --db-url "$DATABASE_URL" --out backups/cicc-$(date -u +%Y%m%dT%H%M%SZ).json
python3 scripts/backup_restore.py verify  --db-url "$DATABASE_URL" --from backups/cicc-....json
python3 scripts/backup_restore.py restore --db-url "$DATABASE_URL" --from backups/cicc-....json [--force]
```

## Not included (blocked/owner-reserved)

RabbitMQ live broker verification (env-blocked; procedure in
docs/RABBITMQ_VERIFICATION.md), tenant isolation/RLS, platform auth,
outbound notifications, production credentials/deploy — all owner-reserved.
