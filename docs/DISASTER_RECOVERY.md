# DISASTER RECOVERY & BACKUP — Agent 1 scope (M36, 2026-11-06)

Labels: restore procedure is **VERIFIED by automated tests** against SQLite AND
real PostgreSQL (`apps/api/tests/test_m36_backup_restore.py`, 3/3 — roundtrip
preserves row counts, task state, event order, and the UNIQUE idempotency_key
constraint; restore refuses non-empty targets; `verify` detects drift; manifest
contains no credentials). This is a **logical** backup, not a production
deployment procedure; the product is **NOT production-ready** (see
RELEASE_READINESS.md).

## Backup (logical, DB-agnostic)

```bash
cd apps/api && . .venv/bin/activate
python ../../scripts/backup_restore.py backup \
  --db-url "$DATABASE_URL" --out "backups/cicc-$(date -u +%Y%m%dT%H%M%SZ).json"
```

- Exports every table of `app.models.Base.metadata` (ops + coordination) to one
  JSON file; manifest records sha256, per-table row counts, UTC timestamp, and a
  **sanitized** DB URL (password stripped).
- Recommended cadence: before every migration/upgrade and at least daily; keep
  the last N manifests. Store backups outside the app host.

## Restore (tested procedure)

```bash
python ../../scripts/backup_restore.py restore --db-url "$DATABASE_URL" --from backups/cicc-....json
# refuses a non-empty target unless --force (reverse-FK-order delete first)
python ../../scripts/backup_restore.py verify  --db-url "$DATABASE_URL" --from backups/cicc-....json
```

`verify` re-exports the live DB and compares per-table counts with the manifest
(exit 1 on any mismatch — detects silent drift/corruption).

## RPO / RTO (logical backup)

- **RPO** = time since the last backup file (events/tasks after the backup are
  lost on restore). **RTO** ≈ minutes: schema recreate + row re-insert + app
  restart; measured locally in tests (<1 s for small DBs), scale-tested only at
  fixture sizes — see `scripts/bench_scale.py` for the tested ceiling.

## Known limitations (honest)

- Logical backup of a **live** DB is not a transactional snapshot for SQLite
  file-copy semantics; for exact point-in-time on PG use `pg_dump`/WAL archiving
  at infra level (owner/infra scope, not implemented here).
- Webhook dedup state (`coord_github_events`) lives in the DB: restoring an
  older backup can re-accept a redelivered GitHub event after the backup point —
  mitigated by HMAC + delivery-id logging and by the replay alert; documented in
  SECURITY_REVIEW.md §M14.
- RabbitMQ broker state is NOT backed up (env-blocked here; see
  RABBITMQ_VERIFICATION.md) — redelivery after broker loss relies on the DB
  delivery records.
- No off-site replication, no automated restore drill in CI — manual procedure
  only, verified by tests above.
