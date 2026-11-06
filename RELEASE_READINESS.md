# RELEASE READINESS — Agent 1 scope (updated 2026-11-06, M36) — NOT production-ready product-wide

Per master prompt DoD (README.md §17, main@ca8f82c), the project must not be called
production-ready until all items verified. Agent 1 scope status:

- Automated tests passing: YES (API 234/234 incl. real-PG races + 1 live-GitHub; PG suite 41/41; web 35/35 + tsc + build).
- Monitoring/health checks: YES (ops API, live-smoked).
- Authentication/authorization verified: YES for token model + BFF; platform auth + tenant isolation NOT enabled (owner decision pending) → DoD security item unmet.
- Audit logging: YES (coordination transitions audited).
- API documentation: YES (docs/API_REFERENCE.md + /docs).
- Deployment instructions: PARTIAL (docker-compose.verify.yml for RabbitMQ verification; no full deployment guide — DEPLOYMENT_GUIDE.md not created, infra scope).
- Backup/restore/DR: DONE (M36) — scripts/backup_restore.py logical backup/restore/verify, TESTED vs SQLite + real PG (test_m36_backup_restore.py 3/3); docs/DISASTER_RECOVERY.md with RPO/RTO + limitations (webhook dedup state loss on restore of an old backup — SECURITY_REVIEW §M14).
- Requirements traceability: Agent-1 scope in REQUIREMENTS_TRACEABILITY.md; product-wide pending other agents.
- Known limitations: RabbitMQ live verification env-blocked; notifications disabled; tenant isolation pending; agent contract confirmations pending.

## M36 update (2026-11-06)
- Backup/restore/verify implemented + tested (SQLite & PG roundtrip, refuse-non-empty, drift detection, unique-key preserved, API smoke on restored DB); DR doc with honest limitations.
- Domain gateway (M35) added; no domain mounted yet (honest 409); AMD-002 pending.
- Four-role arrangement: Agent 6 INACTIVE (not a TI backup); Agent 2 TI pending explicit availability; Agent 5/Backup Agent 4 inactive.
- Still NOT production-ready: tenant isolation, platform auth, notifications, RabbitMQ live verification, real domain mounting, product-wide DoD items owned by other agents.
