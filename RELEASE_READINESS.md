# RELEASE READINESS — Agent 1 scope (updated 2026-11-06, M50) — NOT production-ready product-wide

Per Master Prompt DoD (repository `README.md` §17, v1.0), do not call the project
production-ready until every applicable item is verified. Current Agent 1 branch evidence:

- Automated checks: API **311/311**, PostgreSQL-selected **42/42** (269 deselected), Web **40/40**, typecheck/build and disposable API-to-production-BFF smoke **PASS** locally; hosted M50 PR/push runs `42297518074` and `42297508625` each pass all three jobs.
- Monitoring/health checks: Ops API and gateway lifecycle/metrics available in Agent 1 branch; M49 panel exposes gateway evidence only and no TI/VI feed. M50 successful database health details expose only the driver/dialect, not the connection target/path.
- Authentication/authorization: branch token gates, BFF, and same-origin tests pass; **production identity, tenant-bound authorization, and tenant isolation are NOT verified** → DoD security item unmet.
- Audit logging: coordination transitions and Ops events are audited; trusted actor identity and cross-domain data-access audit are not established.
- API documentation: `docs/API_REFERENCE.md` + FastAPI `/docs` cover Agent 1 APIs.
- Deployment instructions: PARTIAL (`docs/DEPLOYMENT.md` and RabbitMQ verification tooling exist); no verified intended-production deployment guide/run.
- Backup/restore/DR: Agent 1 logical backup/restore/verify is tested vs SQLite and PostgreSQL; `docs/DISASTER_RECOVERY.md` records limitations. No intended-production recovery drill.
- Requirements traceability: Agent 1 scope in `REQUIREMENTS_TRACEABILITY.md`; full prompt map in `docs/M49_MASTER_PROMPT_REQUIREMENT_STATUS.md`; whole product remains incomplete.
- Known limitations: owner-approved host/source/tenant manifest and executable harness absent; AMD-003 and migration 0043 approval pending; PR #3 actual-host tests 0/8; no mounted TI/VI; tenant-isolation acceptance 0%; RabbitMQ verification is optional/unverified for autonomous delivery; notifications disabled.

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

## M49 release gate update (2026-11-06) — **NOT BETA-ACCEPTED / NOT PRODUCTION-READY**

- Current Agent 1 code baseline is `e1122bd3aed644af8607bd0873f1863a2a2edf94` on `arena/961971ed-cicc`, PR #4. Local evidence: API **309/309**, PostgreSQL-selected **42/42**, Web **40/40**, typecheck/build **PASS**. GitHub PR run [42252536511](https://github.com/oldman-088/cicc/actions/runs/42252536511) and push run [42252527313](https://github.com/oldman-088/cicc/actions/runs/42252527313) each passed API, PostgreSQL-selected, and Web/typecheck/build jobs.
- The M49 disposable production-BFF smoke also passed in both hosted runs. It proves only the tested Agent 1 branch behavior: direct unauthenticated API reads deny, the server-side BFF serves the read-only gateway status without browser credentials, cross-site GET/POST are denied, and no TI/VI handler is mounted. It does not prove production identity, tenant isolation, or a live intelligence path.
- The exact-revision merged-app gate remains **BLOCKED** until an owner approves the pinned application/source/module/host/tenant/auth/DB/audit/trace manifest and executable isolated host harness. PR #3 actual-host suite remains 0/8; PR #1's 6/6 candidate host-test claim is not mounted-app acceptance. Migration 0043 remains unapplied/unapproved despite the PR body discrepancy.
- M49 is a gateway status-display milestone only. Overall integrated Beta remains **29%** (approximate, not an acceptance result); tenant-isolation acceptance remains **0%**. Do not release or describe the product as Beta-accepted/production-ready.
- Detailed Master Prompt status: `docs/M49_MASTER_PROMPT_REQUIREMENT_STATUS.md`; cross-agent/host/migration evidence: `docs/M49_CROSS_AGENT_INTEGRATION_REVIEW.md`; current full-product score and blockers: `docs/handover/CICC_PROJECT_COMPLETION_STATUS.md`.

## M50 security-hardening snapshot (2026-11-06)

- PR #4 code commit `d7bc7625dd52f38bd65185a117e87baafc18944d` removes DB connection targets from successful health details; only the SQLAlchemy dialect/driver and fixed verification text are returned. Endpoint/helper regression tests prove DB path/name do not appear.
- Local API **311 passed**; PostgreSQL-selected **42 passed / 269 deselected**. GitHub PR run `42297518074` and push run `42297508625` each passed all three CI jobs, including BFF smoke. This is branch-level evidence only.
- No migration/schema change. The merged-app manifest/host harness, production identity, tenant-bound authorization, cross-tenant tests, AMD-003 and migration approval remain blockers. Tenant-isolation acceptance **0%**; integrated-Beta estimate **29%**. **NOT BETA-ACCEPTED / NOT PRODUCTION-READY.**
