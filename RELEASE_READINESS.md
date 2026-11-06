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

## M48 whole-product recheck (2026-11-06) — **NOT BETA-ACCEPTED / NOT PRODUCTION-READY**

- Agent 1 PR #4 is OPEN/CLEAN at product-code baseline `157645e9d46bef4c120ff46fc3028320971fe286`. The new Agent 1 CI passed all API, PostgreSQL-selected, and Web/typecheck/build jobs on both the PR and push events. Local evidence: API 309/309, PostgreSQL-selected 42/42, Web 35/35, typecheck and production build PASS.
- The exact-revision merged-app gate is still **BLOCKED** (exit 2, no app started) because no owner-approved manifest/module/host/tenant contract is available. PR #1 and #3 remain open; PR #3 actual-host tests remain 0/8.
- PR #1's six-job CI and its handover's 6/6 actual-host claim are candidate-branch evidence; the raw host test count was not independently retrievable here. No VI/TI route is mounted in Agent 1's current host.
- Production authentication/authorization, tenant isolation/RLS, AMD-003 and migration approval, connected TI/VI, full prompt modules and verified deployment remain unmet. Overall weighted integrated Beta estimate: **29%**; tenant-isolation acceptance: **0%**. Scoring method and evidence are in `docs/handover/CICC_PROJECT_COMPLETION_STATUS.md`.
