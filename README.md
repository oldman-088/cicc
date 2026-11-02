# Cyber Intelligence Command Center (CICC)

Early, **not production-ready** foundation. The current application is a read-only synthetic demonstration, not a security product. The default demo has no authentication, tenant isolation, persistence, live feeds or operational integrations. An experimental, opt-in authenticated API exists but is not production-ready or connected to the UI. Never expose it publicly or enter sensitive data.

## Run locally

Requires Python 3.11+ and Node.js 20.9+. In one terminal:

```sh
cd apps/api
python -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements.lock
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
cd apps/web
npm ci
npm run dev
```

Open http://localhost:3000. The browser calls the same-origin Next.js route; `API_INTERNAL_URL` sets its server-side backend destination at runtime. API documentation is at http://localhost:8000/docs. All records are fictional and clearly labeled. Source labels in this demo do not reflect experimental connector status.

## Checks

```sh
cd apps/api && pip install --require-hashes -r requirements-dev.lock && python -m pytest
cd apps/web && npm run typecheck && npm test && npm run build
```

See `PROJECT_STATE.json`, `MASTER_TASK_QUEUE.md`, and `BLOCKERS.md` for recovery and scope; `RELEASE_READINESS.md` records production gaps.

## Draft database migrations

The draft schema is not connected to the demo API. To apply its initial migration to a **dedicated database**, from `apps/api` set `DATABASE_URL` to a SQLAlchemy URL such as `postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME` through a secret manager or protected environment, then run `alembic upgrade head`. Never put credentials in source control or shell history. Back up and verify recovery before migrations; `alembic downgrade base` destroys these tables and their data. Migrations have been tested on disposable PostgreSQL 16.2 and SQLite, not a production deployment.

Migration tests use temporary SQLite by default. To test PostgreSQL, set `TEST_DATABASE_URL` to a dedicated, **empty disposable** database; the tests create and drop tables. Never use an existing or production database. CI is configured with a disposable PostgreSQL service, but has not yet run on GitHub.

### Experimental offline bootstrap

After applying migrations to an isolated test database, an authorized database operator can create a **new** tenant and its first administrator using `python -m app.bootstrap --tenant-name "Example" --username admin --confirm-new-tenant`. Set `DATABASE_URL` securely first; the command requires an interactive terminal and prompts twice for a password (12–1024 characters). It creates a new tenant on every successful invocation and cannot add an administrator to an existing tenant. It records a bootstrap event atomically; it does not start a login endpoint. Never use this experimental path for real data until the security controls and PostgreSQL tests are complete. Do not place passwords in command arguments or logs.

### Experimental authenticated API

Disabled by default. Opt-in requires `CICC_EXPERIMENTAL_AUTH=true`, a migrated PostgreSQL `DATABASE_URL`, and `CICC_RATE_LIMIT_KEY_BASE64` containing at least 32 random bytes encoded in standard base64. Do not use example credentials. The API expects HTTPS in the ASGI scope and must receive a trustworthy client address: never trust arbitrary forwarded headers, and configure any reverse proxy and Uvicorn proxy trust explicitly. Do not expose this experimental API publicly or use real data. Selected API and isolation tests passed on disposable PostgreSQL 16.2; real TLS, proxy configuration and production deployment remain unverified. Login uses JSON and returns a bearer token; logout revokes it. `/api/v1/secure/entities` derives the tenant from the session and records an audit event. Administrator-only account creation, role change and disable routes, and a manual intelligence creation endpoint for analysts and administrators, are also available when enabled. The web UI does not use these routes. See API_DOCUMENTATION.md and SECURITY_STATUS.md for limitations.

### Optional disposable PostgreSQL test harness

On a trusted Linux development machine, install the optional test-only package `pip install pgserver==0.1.4`, then run `python scripts/test_postgres.py` from the repository root using the API virtual environment. It starts an isolated temporary PostgreSQL instance on a private Unix socket with local trust authentication, runs the API suite, stops the server and removes its temporary data. Never use this test setup for production or sensitive data. CI instead uses a disposable PostgreSQL service.

### Experimental rate-limit maintenance (manual)
After migrating the experimental PostgreSQL database and verifying its identity and synchronized system clock, an authorized database operator may run from `apps/api`: `python -m app.maintenance --confirm-cleanup --batch-size 1000` with `DATABASE_URL` set. This deletes at most one batch of rate-limit buckets older than 24 hours, leaving potentially active windows. Repeat manually if necessary. It does not schedule work, record operator identity, enforce single-operator execution, clean audit logs, or replace ingress rate limits. Do not run against an unverified database.

### Experimental manual CISA KEV sync
An authorized operator may, from `apps/api`, run `python -m app.connectors.cisa_cli --confirm-live-fetch` with the correct migrated PostgreSQL `DATABASE_URL`. It requires an interactive terminal and prompts without echo for an existing administrator bearer session; the token determines the tenant. This makes a real request to the fixed CISA endpoint, not a synthetic demo; provider terms, permissions and network policy must be checked first. No test here contacted CISA. The fetch enforces a 60-second elapsed budget at request/stream/retry/parse checkpoints and bounds individual HTTP timeouts, and import checks a 120-second budget between records and before commit. Neither is a hard deadline: blocked operations, parsing, rollback and commit are not forcibly interrupted. No scheduler starts. A crash or interruption can leave a `running` attempt; inspect experimental admin status and explicitly abandon only after deciding the worker should no longer import. Abandonment prevents late import but does not stop the worker. Do not use with sensitive data or deploy publicly until security and operational gates pass.

The same offline command supports `--kind expired-sessions`, for example `python -m app.maintenance --confirm-cleanup --kind expired-sessions --batch-size 1000`. It deletes at most one batch of sessions expired for more than 24 hours, including expired revoked sessions; it does not delete audit events. The same clock, database identity and operator-control cautions apply.

### Python dependency locks
`apps/api/requirements.txt` and `requirements-dev.txt` define direct pins; hash-locked runtime and test dependency sets are generated for Python 3.11. Docker installs the runtime lock and CI uses the dev lock. When updating dependencies, from the repository root use Python 3.11 with `pip-tools==7.5.3`: `python -m piptools compile --generate-hashes --strip-extras --output-file=apps/api/requirements.lock apps/api/requirements.txt` and similarly compile `apps/api/requirements-dev.txt` to `apps/api/requirements-dev.lock`. Run `python scripts/check_python_locks.py`, install both locks with `--require-hashes` into fresh environments, run tests and audit both locks. The checker verifies direct pins and agreement between runtime/dev versions, not complete resolver correctness. Regenerate and test separately for other Python/platform targets.

The synthetic demo has a partial English/Arabic/Persian selector for the heading, safety notice, illustrative navigation, dashboard labels, error/loading text and exact-match synthetic fixture text; other interface text and unrecognized records may remain in English. The preference is stored in browser local storage when available. Arabic/Persian selections switch the demo shell to RTL and isolate some mixed-direction text; navigation entries remain nonfunctional. Full localization, broad RTL and screen-reader validation remain incomplete. Web unit tests require Node 22 with TypeScript stripping support. On Linux, `cd apps/web && npm ci && npm run build && npm run test:browser` runs limited synthetic Chromium smoke tests (requires `tar`); the bundled browser runs without a sandbox, so use only isolated synthetic data. GitHub CI is configured but not verified.

The public demo overview proxy accepts only a bounded, explicitly synthetic response contract. Unexpected fields, non-synthetic records or source status changes cause an unavailable error rather than being relabeled. This checks the upstream assertion and shape, not the actual provenance of its data; coordinate schema changes.
