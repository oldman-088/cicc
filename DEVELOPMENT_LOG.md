# Development log

## 2026-11-02
- Inspected clean branch `arena/da631853-cicc` at `c6ef133`; only README existed.
- Added FastAPI read-only synthetic overview and health endpoints, Next.js dashboard with loading/error states, record detail and clearly unconfigured source status, local Dockerfiles and Compose, tests and project recovery documentation.
- API: 3 tests passed using `python -m pytest -q`; initial direct `pytest` invocation failed to import the app, then corrected invocation succeeded. Web typecheck and production build passed after upgrading Next and lucide and enabling `skipLibCheck` for upstream declaration incompatibility. Build had CSS autoprefixer warnings; test emitted an upstream deprecation warning.
- Not tested: Docker, browser E2E, accessibility, real sources, security, database or restore. No commit created in this session at time of writing. Next: implement P0-03 authentication, authorization and tenant security before storing any real data, then P0-04 schema/migrations.
- Verified the running Next proxy returned the API's `synthetic-demo` response with four records. `npm audit --omit=dev --audit-level=high` failed with three findings (two high), including PostCSS and sharp; remediation is outstanding.
- Created foundation commit `243016c`; subsequent recovery-file housekeeping is recorded separately. No push performed.

## 2026-11-02 continuation
- Upgraded Next.js to 16.4.4 and updated transitive dependencies. `npm audit --omit=dev --audit-level=high` reports zero findings. Clean build and typecheck succeeded. An initial build while an old development server was running produced an incomplete route manifest; stopped the server, removed `.next`, rebuilt and confirmed `/` is present.
- Added standalone Argon2id, fail-closed RBAC and tenant-filtered read primitives, and draft SQLAlchemy models with composite tenant-bound relationship foreign keys. Six API tests pass, including SQLite tenant isolation tests. These are not wired to the API and do not implement authentication or production isolation. Added CI workflow (not run on GitHub). No PostgreSQL, Docker, browser, real source, or restore tests performed.
- Next: implement authenticated sessions and API enforcement, real PostgreSQL migrations and integration tests, audit, and secure deployment.

## 2026-11-02 migration and proxy continuation
- Added Alembic migration with PostgreSQL JSONB variant and SQLite support, explicit DATABASE_URL requirement, tests for upgrade/downgrade, missing config and cross-tenant FK rejection. Added a disposable PostgreSQL CI service and optional test. Local API tests: 9 passed, 1 skipped (PostgreSQL not available); one upstream deprecation warning. PostgreSQL and GitHub CI are not verified.
- Replaced build-time rewrite with a fixed runtime same-origin overview route, so Compose runtime API_INTERNAL_URL works as intended; forwards only the demo GET endpoint, disables cache and reports upstream failures. Clean web build, typecheck, npm production audit (zero findings), production HTTP smoke test and API proxy smoke test passed. Docker not tested.
- Next: authentication and session lifecycle, API/service enforcement, audit, real PostgreSQL validation and schema completeness.
- Confirmed the production route returns HTTP 503 and an explicit unavailable message when its configured API is unreachable.

## 2026-11-02 identity continuation
- Added tenant-scoped users and session models, Alembic revision 0002, and internal opaque-token session primitives with digest-only storage, 8-hour expiration, revocation, role refresh and active-account checks. Session issuance is deliberately not exposed: rate limiting, audit and secure provisioning are prerequisites.
- API tests: 13 passed, 1 skipped (PostgreSQL unavailable), including SQLite identity migration rollback and session lifecycle. Web typecheck/build and npm production audit passed; one upstream test deprecation warning remains. PostgreSQL, CI, frontend auth and production security are unverified.
- Next: implement rate limiting and auditable login before exposing authentication; integrate API authorization and test using PostgreSQL.

## 2026-11-02 audit and rate-limit continuation
- Added tenant-scoped minimal audit events with enum allowlist, admin-only tenant-filtered reads, and tenant-constrained actor references. Added HMAC-keyed fixed-window database counters using atomic upsert and migration 0003. Both are standalone, not connected to login. Rate-limit transactions must be committed for failures; fixed-window bursts, key management, cleanup, global/IP limits and audit tamper-resistance require further work.
- API tests: 17 passed, 1 PostgreSQL test skipped; SQLite migration rollback, counter and audit tests pass. Web typecheck/build and production npm audit pass. PostgreSQL concurrency, CI, endpoint integration and production security remain unverified.
- Next: orchestrate audited login with independently committed throttling, secure provisioning and API authorization, then validate on PostgreSQL.

## 2026-11-02 internal login continuation
- Added unexposed login/logout orchestration with committed global/source/account rate limits, session and audit atomicity, trusted-source IP validation and fail-closed audit failure. Unknown tenants have no tenant-scoped audit event. Fixed windows can burst at boundaries; global throttling can affect all tenants.
- Added concurrent SQLite tests, including against migrated schema, plus optional PostgreSQL variant. API: 23 passed, 2 PostgreSQL cases skipped; one third-party warning. Web typecheck, build and npm production audit passed. PostgreSQL CI, production hardening, account provisioning, browser login and tenant API enforcement remain unverified or unimplemented.
- Next: secure provisioning and protected API transport, after resolving key management, proxy trust, audit and PostgreSQL concurrency.

## 2026-11-02 account administration continuation
- Added internal administrator-authenticated account creation, role changes, deactivation and session revocation with tenant checks and atomic target audit; no bootstrap or HTTP routes. Added migration 0004 for audit target FK, and user row locking for session issuance.
- Final API tests: 28 passed, 3 PostgreSQL variants skipped; web typecheck/build and npm production audit passed. An initial new migration test failed due to a missing test import; fixed and reran successfully. PostgreSQL locking, CI, browser workflow and production security remain unverified. Audit does not yet record before/after roles.
- Next: secure first-admin provisioning, durable audit detail, API authentication/authorization, then PostgreSQL integration and concurrency verification.

## 2026-11-02 offline bootstrap continuation
- Added an offline new-tenant/initial-admin bootstrap service and CLI with explicit confirmation, interactive password and confirmation, no default password and atomic tenant/user/audit creation. It cannot add users to existing tenants. SQLite foreign keys are enabled by the CLI. Operator identity is not recorded, and CLI is not a substitute for production provisioning controls.
- API tests: 35 passed, 4 PostgreSQL variants skipped; CLI terminal interactions mocked. Web typecheck/build and npm production audit passed. Real TTY, PostgreSQL, CI and production deployment not verified.
- Next: audit attribution/retention, secure HTTP authentication transport and tenant enforcement, and PostgreSQL isolation/concurrency validation.

## 2026-11-02 experimental protected API continuation
- Added default-off PostgreSQL-configured experimental bearer login/logout and bounded tenant-derived entity reads with TLS scope enforcement, audit, throttling, no-store and redacted validation errors. No browser UI or account administration routes. Configuration fails closed without an explicit database and sufficiently long base64 key.
- API tests: 43 passed, 5 PostgreSQL variants skipped, one upstream deprecation warning. Web typecheck/build and npm production audit passed. Tests use SQLite and simulated HTTPS; no real PostgreSQL, TLS/proxy, browser or CI verification.
- Next: verify PostgreSQL and real transport, protect audit and key management, add authorized account workflows and complete core intelligence model.

## 2026-11-02 account API continuation
- Added opt-in administrator-only account creation, role change and disable endpoints with tenant-derived scope and prior/new role audit fields (migration 0005). No browser integration. Authorization is checked before password hashing and again in the service mutation transaction.
- API: 46 passed, 5 PostgreSQL cases skipped. An initial new test expected 422 but bearer validation correctly returned 401; fixed the test to supply a bearer header and reran successfully. Web typecheck, build and npm production audit passed. No Docker or PostgreSQL binary found. PostgreSQL, real TLS/proxy, browser and CI remain unverified.
- Next: verify PostgreSQL/TLS, audit integrity and retention, key management and real product workflows.

## 2026-11-02 manual intelligence continuation
- Added default-off experimental analyst/admin create endpoint, tenant-derived creator, source/reference, bounded optional confidence and unverified status; added tenant-scoped audit target and migration 0006. Source references are inert. List endpoint now returns these fields. No real integration, full evidence model or UI.
- API 50 passed, 5 PostgreSQL variants skipped, one upstream warning. SQLite tests include tenant and role denial, DB constraints, audit rollback and migration rollback. Web typecheck/build and production npm audit passed. PostgreSQL, TLS, browser and CI remain unverified.
- Next: complete provenance/evidence and tenant-scoped intelligence workflow; validate PostgreSQL and production security.

## 2026-11-02 evidence-reference continuation
- Added experimental tenant-scoped analyst-entered evidence reference create/list endpoints with actor/source/time and optional asserted SHA-256, tenant-bound FKs, audit and migration 0007. References are inert; no files are uploaded or hash-verified.
- API 53 passed, 5 PostgreSQL variants skipped, with one upstream deprecation warning. No browser, PostgreSQL, TLS, CI or Docker validation.
- Next: verify PostgreSQL/transport and implement real provenance and evidence lifecycle; avoid sensitive data until security is validated.

## 2026-11-02 rate-limit maintenance continuation
- Added an explicit rate-limit cleanup primitive that keeps any window potentially active within the maximum configured 24-hour window. It requires caller commit and a synchronized clock. No scheduler or deployment integration has been added.
- API: 55 passed, 5 PostgreSQL cases skipped; web typecheck/build and npm production audit passed. PostgreSQL, browser, CI, Docker and deployment remain unverified.
- Next: wire controlled operational maintenance, build evidence provenance/history, and verify PostgreSQL/transport.

## 2026-11-02 PostgreSQL verification continuation
- Installed optional pgserver 0.1.4 in the temporary venv; ran a disposable PostgreSQL 16.2 server on a private local Unix socket. The first full run found 4 fixture errors: downgrade left an empty Alembic version table and blocked subsequent PostgreSQL cases. Fixed fixture to require a completely empty disposable DB and remove only its own version table after downgrade. Added schema parity and cross-tenant evidence FK tests.
- Reran full suite using scripts/test_postgres.py: 64 passed with one upstream warning; additionally `alembic check` passed on PostgreSQL. Server stopped and temporary data removed. An earlier exploratory server was explicitly stopped after finding it had outlived its temporary directory; the new script cleans up before directory removal. Tests are not a production security review.
- Next: continue audit/evidence provenance and production controls; verify real TLS/proxy, deployments and restore.

## 2026-11-02 provenance continuation
- Added migration 0008 and API-read-only provenance events for manual entity creation and evidence references. Events contain actor, timestamp and limited source snapshot; tenant/entity/evidence composite FK prevents mismatched references. Earlier records are not backfilled and API warns history may be incomplete. Database-level tamper resistance remains absent.
- Full suite with disposable PostgreSQL 16.2: 68 passed, one upstream deprecation warning. Web typecheck/build and production npm audit passed. Real TLS/proxy, browser and deployment remain unverified.
- Next: implement verified provenance enrichment and evidence lifecycle, and strengthen operational security; no real data until release gates pass.

## 2026-11-02 audit API continuation
- Added tenant-scoped, administrator-only experimental audit read endpoint; access is itself audited and the response explicitly notes its 100-record cap and missing pagination/tamper protection.
- Full API suite using disposable PostgreSQL 16.2: 69 passed, one upstream deprecation warning. SQLite tests check unauthorized, non-admin and cross-tenant behavior; migrated PostgreSQL API smoke test includes audit access. No browser or actual TLS verification.
- Next: address production audit integrity and retention; continue core intelligence and source connectors without claiming live integrations.

## 2026-11-02 entity update continuation
- Added tenant-scoped experimental title/confidence update with optimistic versioning, reset to unverified, atomic audit and before/after provenance. Migration 0009 adds version 1 for existing records. Sources and other fields remain immutable through this endpoint.
- Full API suite using disposable PostgreSQL 16.2: 73 passed, 1 skipped (SQLite variant of PostgreSQL-only concurrency test), one upstream warning. Concurrent edits on PostgreSQL produced one success and one conflict. Web typecheck/build and npm audit passed. Real TLS, production security, UI and complete lifecycle remain unverified.
- Next: continue highest-priority security and evidence lifecycle, including audit retention and operational controls.

## 2026-11-02 request size hardening continuation
- Added an ASGI request-body size guard for experimental routes, with declared/streamed size checks, invalid content-length rejection, and explicit no-store errors. This does not replace proxy limits or request timeouts.
- Initial integration test failed because the middleware had been imported but not registered; registered it and reran. Full API suite on disposable PostgreSQL 16.2: 77 passed, 1 SQLite variant skipped (PostgreSQL-only concurrency), one upstream warning. Web typecheck/build and npm production audit passed.
- Next: continue audit integrity/retention, intelligence graph workflows, and actual TLS/proxy validation.

## 2026-11-02 relationship graph continuation
- Added experimental analyst-authored relationship assertions with source, optional confidence and subject-bound evidence; enforced tenant/actor/evidence foreign keys, audit and provenance. API lists inbound/outbound relationships and labels new assertions unverified. Migration 0010 tested. No automatic correlation, full relationship lifecycle or UI.
- Full suite on disposable PostgreSQL 16.2: 82 passed, 1 skipped (SQLite variant of PostgreSQL-only concurrency test), one upstream warning. Web typecheck/build and npm production audit passed. No production TLS, GitHub CI, browser or deployment testing.
- Next: complete security/operational gates, evidence lifecycle and frontend workflows; maintain truthful source status.

## 2026-11-02 CISA adapter continuation
- Added a standalone CISA KEV fixed-URL fetch/normalization adapter with bounded size, no redirects/environment proxy, timestamps, schema and CVE validation, duplicate rejection, sanitized errors and bounded retry handling that does not retry before long Retry-After. Test fixtures are synthetic; no live source request, persistent ingestion, status tracking, scheduling or UI integration exists.
- Full API suite with disposable PostgreSQL 16.2: 96 passed, 1 skipped (SQLite variant of PostgreSQL-only concurrency), one upstream warning. Prior web typecheck/build and npm production audit passed. Network policy prevents live source verification.
- Next: add tenant-scoped source persistence, deduplication and truthful synchronization status before any connector exposure; independently continue security gates.

## 2026-11-02 CISA snapshot import continuation
- Added migration 0011 and internal admin-only tenant-scoped CISA snapshot import linked to unified vulnerability entities, with source observations, timestamps, atomic audit and provenance. PostgreSQL tenant row locking serializes imports; stale snapshots are rejected, existing analyst entity edits are not overwritten, and absent entries are retained without assuming remediation. Snapshot state tracks successes only. No network-to-import orchestration, attempt/error status, API, scheduler or UI exists.
- Full suite on disposable PostgreSQL 16.2: 101 passed, 2 skipped (SQLite variants of PostgreSQL concurrency tests), one upstream warning. Web typecheck/build and npm production audit passed. All imported test data is synthetic; CISA not contacted.
- Next: design safe sync orchestration with truthful attempt/error states, permissions and bounded scheduling; separately close security and production gates.

## 2026-11-02 CISA sync coordination continuation
- Added migration 0012 and internal admin-only CISA sync coordinator with persisted attempt statuses, sanitized failures, atomic snapshot import/success, tenant row locking, explicit abandon, late-result refusal and audited status. Fetch occurs outside DB transactions. Crashes can leave running attempts until explicitly abandoned; no automatic scheduler, API or UI.
- Full API suite using disposable PostgreSQL 16.2: 108 passed, 3 skipped (SQLite variants of PostgreSQL-only concurrency tests); one upstream warning. Synthetic-only fetches. Web typecheck/build and production npm audit passed. No live CISA access attempted.
- Next: safely expose source status/control when security gates permit, handle operational recovery, and verify provider contract in an authorized network environment. Continue other security and frontend work independently.

## 2026-11-02 CISA status and recovery API continuation
- Added opt-in administrator-only tenant-scoped CISA status and attempt-abandon endpoints. Status includes recorded attempt ID and clearly states no live verification; abandonment prevents late import but cannot terminate an already running worker. No endpoint starts network sync and no scheduler/UI exists.
- Full suite using disposable PostgreSQL 16.2: 109 passed, 3 skipped (SQLite variants of PostgreSQL-only concurrency cases), one upstream warning. Web typecheck/build and npm production audit passed. CISA not contacted.
- Next: address production security/operational controls and a safe start-sync mechanism; do not describe source as live until actually verified.

## 2026-11-02 entity pagination continuation
- Added tenant-scoped UUID keyset pagination to experimental entity listing. A next cursor is returned only if more results exist; each page is authenticated and audited. This is not a consistent snapshot and other list endpoints still lack pagination.
- Full suite on disposable PostgreSQL 16.2: 112 passed, 3 skipped (SQLite variants of PostgreSQL-only concurrency cases), one upstream warning. Migrated SQLite and PostgreSQL page tests pass.
- Next: paginate audit and other record lists, continue security gates and source orchestration.

## 2026-11-02 audit pagination continuation
- Added admin-only tenant-scoped timestamp/UUID keyset pagination for audit history and migration 0013 composite index. Page access is audited; foreign or missing cursor is rejected without cross-tenant details. Traversal is not a snapshot and audit storage is not tamper-resistant.
- Full API suite using disposable PostgreSQL 16.2: 116 passed, 3 skipped (SQLite variants of PostgreSQL-only concurrency), one upstream warning. Web typecheck/build and npm production audit passed. No real TLS or browser testing.
- Next: paginate evidence/provenance/relationship lists and continue audit durability, retention, source integration and security gates.

## 2026-11-02 graph pagination continuation
- Added keyset pagination for evidence references, provenance and inbound/outbound relationships. Each page retains authorization, entity/tenant scope and read audit. Added provenance/relationship indexes in migration 0014. UUID and chronological traversals are not consistent snapshots.
- Disposable PostgreSQL/SQLite suite: 118 passed, 3 SQLite-only concurrency variants skipped, one upstream warning. Migration upgrade/downgrade and parity exercised; synthetic records only. Web was not changed since last successful checks.
- Next: review remaining security and operational gates, add bounded source orchestration only after considering deployment trust and authorization.

## 2026-11-02 protected response hardening
- Enforced no-store and nosniff on experimental-prefix responses including 404/405, deliberately conflicting cache headers, and sanitized pre-response unhandled 500s. Exceptions still propagate for server logging; no claim of log redaction or proxy verification.
- API suite: 119 passed, 3 SQLite variants skipped, disposable PostgreSQL 16.2; one upstream warning.
- Next: examine session revocation concurrency and enforce fail-closed authorization on protected mutations.

## 2026-11-02 authorization lock recheck
- Protected requests, account management, logout and CISA admin/import operations now lock and re-read user/session state in the transaction. Prevents a pending request from proceeding on stale pre-lock role or a session revoked while waiting. The initial lookup is only a lock-target hint; expiry checked after lock. Existing operations that lock first may finish before revocation.
- Forced PostgreSQL demotion/revocation lock-wait tests deny mutation; complete suite 121 passed, 5 SQLite variants skipped, one upstream warning. SQLite row locks, full deadlock and load/security verification remain absent; requests serialize per user.
- Next: inspect and address lock-order deadlock risks (especially CISA tenant locking vs audit foreign-key writes); implement focused PostgreSQL concurrency tests.

## 2026-11-02 CISA tenant lock refinement
- Changed CISA tenant serialization to PostgreSQL FOR NO KEY UPDATE: concurrent source operations still conflict, while tenant foreign-key checks for audit rows can proceed. Added deterministic PostgreSQL test holding actor lock while source operation holds tenant lock and waits, then writing an audit row.
- Full suite: 122 passed, 6 SQLite variants skipped, one upstream warning. Other lock orders, mutual admin changes, PostgreSQL deployment and load behavior still need review.
- Next: avoid mutual administrator account-update lock cycles by consistently ordering actor/target user locks; add PostgreSQL concurrency coverage.

## 2026-11-02 account mutation lock ordering
- Admin role/disable operations acquire actor and target rows in deterministic UUID order, then recheck session and permissions. Preliminary role check avoids needless locks for obvious non-admin requests. Same-tenant and no-self restrictions preserved.
- PostgreSQL concurrent mutual-demotion test synchronizes at lock acquisition; one succeeds and one is denied. Full API suite: 123 passed, 7 SQLite variants skipped, one upstream warning. No guarantee against all deadlocks; throughput untested.
- Next: review and harden login input, rate limits and per-user serialization against resource exhaustion; continue source orchestration and production gates.

## 2026-11-02 rate-limit allocation hardening
- Broader login limit denials no longer allocate source/account buckets for attacker-chosen identifiers; counter values saturate at limit+1 to avoid overflow. Stable policy limits during each window are required; exact excess counts are not retained.
- Migrated PostgreSQL and SQLite tests cover allocation and saturation; full suite 126 passed, 7 SQLite variants skipped, one upstream warning. This does not solve global fairness, audit growth, fixed-window bursts, cleanup scheduling or DDoS.
- Next: review rate-limit cleanup scheduling/operations or independent CISA sync execution interface, without implying production readiness or live-source validation.

## 2026-11-02 bounded rate-limit maintenance
- Added indexed, transaction-bound batch cleanup and an explicit-confirmation offline PostgreSQL maintenance command. One invocation deletes at most the specified batch of windows older than 24 hours; no scheduler, operator audit, single-operator enforcement or clock verification. This is not audit retention.
- Full disposable PostgreSQL/SQLite suite 129 passed, 7 SQLite variants skipped, one upstream warning; test includes CLI call against migrated disposable PostgreSQL and rollback/cutoff checks.
- Next: consider safe administrative manual CISA synchronization with explicit runtime limits and source authorization; no live verification possible here.

## 2026-11-02 manual CISA operator command
- Added explicit-confirmation, interactive, PostgreSQL-only single sync command. Admin bearer token entered via getpass; no token arguments or custom URL. Authorization precedes fetching and failures are sanitized. No scheduler or start-sync API. Process interruption may leave a running attempt; no strict overall deadline.
- Full suite: 132 passed, 8 skipped (SQLite variants of PostgreSQL-only cases); one upstream warning. PostgreSQL CLI test uses synthetic fixture and simulated terminal; non-admin denied before fetching. No CISA request, provider-terms review or real TTY test.
- Next: implement a bounded end-to-end fetch deadline and test slow streaming; source live verification remains blocked. Continue security gates independently.

## 2026-11-02 CISA fetch time budget
- Fetch uses 60-second monotonic elapsed budget checked around attempts, streamed chunks, retries and parsing; per-operation timeouts capped by remaining budget. Retry-After is never shortened. Blocked operations, DNS, parsing and database import are not forcibly interrupted, so this is not a hard end-to-end deadline.
- Full suite 133 passed, 8 SQLite variants skipped; synthetic slow-stream and retry budget tests pass. No live CISA fetch or provider contract verification.
- Next: review source import resource limits and operational cancellation; independently continue production security and deployment validation.

## 2026-11-02 CISA import budget
- Added 120-second monotonic import budget checked per record and before transaction return. On expiry the transaction rolls back; coordinator failure handling records sanitized import failure when available. Blocking SQL, rollback and commit are not forcibly interrupted.
- Full suite 136 passed, 8 SQLite variants skipped; synthetic fixture tests force expiration after partial insertion and verify rollback on migrated PostgreSQL and SQLite. No real feed or strict end-to-end deadline.
- Next: inspect retention and expired-session storage; continue deployment and security verification independently.

## 2026-11-02 expired-session maintenance
- Added indexed bounded cleanup of sessions expired over 24 hours, available as explicit offline maintenance command kind. Active and recently expired/revoked sessions and audit records remain untouched. Requires synchronized clock and operator safeguards; no scheduler, operator audit or single-operator enforcement.
- Full suite 138 passed, 8 SQLite variants skipped, one upstream warning; migrated PostgreSQL and SQLite cleanup, rollback, cutoff and CLI tests pass.
- Next: inspect release/deployment controls and independent security tests; remaining product modules and operational gates are incomplete.

## 2026-11-02 demo detail modal keyboard handling
- Detail modal now focuses its close button, contains Tab focus for its single control, supports Escape, restores prior focus on close and associates its description. This is partial accessibility only; no browser or screen reader verification and no translations/RTL.
- Web typecheck, production build and npm production audit passed (zero findings). No browser executable detected.
- Next: extend accessibility and localization for the demo or continue independent security/deployment work; perform browser E2E when browser environment is available.

## 2026-11-02 account creation preflight
- Prevented invalid or non-admin sessions from causing Argon2 work during account creation; preflight role/session validation occurs before hashing, with full locked recheck before transaction writes. Legitimate authenticated users can still incur hashing; no complete DoS controls.
- API suite 142 passed, 8 SQLite variants skipped; revoked-during-hash denial tested on SQLite and PostgreSQL, plus unauthorized hash prevention.
- Next: inspect source sync error and status paths, operational security and broader rate limits; continue feature work independently.

## 2026-11-02 truthful demo source labels
- Scoped dashboard source and authentication statements to the synthetic demo, and removed the unsupported global claim that no synchronization has been attempted. Demo does not display experimental connector status; no live source was contacted.
- Web typecheck/build and npm production audit passed; no browser E2E.
- Next: continue unfinished features, localization and security gates; review user-facing source status and real source contract only when authorized network access exists.

## 2026-11-02 Python dependency security review
- pip-audit initially reported 16 advisory entries in pytest 8.3.5 and Starlette 0.46.2. Upgraded FastAPI 0.162.0, explicitly pinned Starlette 1.10.0 and pytest 9.0.3. pip-audit against resolved requirements and pip check pass. Configured pip-audit in CI; not run on GitHub. No Python transitive lockfile, and future resolver results/advisories may differ.
- Full API suite 142 passed, 8 SQLite PostgreSQL-only variants skipped; Starlette TestClient httpx integration deprecation warning. No Docker, real TLS, browser or independent security review.
- Next: review unpinned transitive Python dependencies and isolate runtime/test dependencies; ensure reproducible security scanning and verify CI locally as feasible.

## 2026-11-02 Python runtime/test dependency separation
- Moved pytest to requirements-dev.txt; Docker continues to install runtime requirements only. CI installs and audits development requirements including runtime dependencies; it has not run on GitHub. Corrected README test setup and demo source wording. Transitive dependencies remain unlocked.
- Full suite 142 passed, 8 SQLite variants skipped, one Starlette TestClient warning; pip-audit on dev requirements returned no known vulnerabilities. Docker not tested.
- Next: implement reproducible Python dependency locking and test a clean environment, or continue independent security and localization work.

## 2026-11-02 Python dependency hash locks
- Generated Python 3.11 hash-locked runtime/dev sets, updated Dockerfile and CI to install locked dependencies, and added direct-pin/runtime-dev consistency checker with negative tests. Checker is not a full resolver or supply-chain provenance proof. Optional pgserver and audit tool are separately installed.
- Fresh Linux/Python 3.11 environments installed locks with --require-hashes; runtime import passed with pytest absent. Disposable PostgreSQL suite 143 passed, 8 SQLite variants skipped, one upstream TestClient warning; both lockfiles passed pip-audit. Docker, other platforms and GitHub CI not verified.
- Next: continue localization/accessibility and remaining operational/security gates; browser executable and live source verification remain blocked.

## 2026-11-02 experimental investigation foundation
- Added migration 0017 and experimental case create/list, versioned open/closed status, paginated case history, tenant/actor database constraints and transactional generic security audit. Audit does not identify case, case history is not tamper-resistant, and pagination is not a snapshot. No evidence linkage, assignment, reporting, UI or operational readiness.
- Full locked API suite: 148 passed, 9 SQLite PostgreSQL-only variants skipped, one upstream warning. SQLite/PostgreSQL isolation, FK, rollback, pagination and PostgreSQL concurrent status conflict tests pass; no browser or real TLS.
- Next: add case IDs to security audit with tenant-enforced foreign key and tests, then implement same-tenant case/entity links before evidence lifecycle.

## 2026-11-02 investigation-targeted security audit
- Migration 0018 adds optional tenant-scoped case target FK to security audit. Case creation, status changes and event reads record targets; list reads remain untargeted. Existing audit events are preserved but not backfilled. Audit is not immutable.
- Full locked API suite: 151 passed, 9 SQLite variants skipped; PostgreSQL and SQLite FK/endpoint tests and SQLite targeted upgrade/downgrade data preservation pass; one upstream TestClient warning.
- Next: implement same-tenant case/entity linking with atomic case history/audit, tenant FKs, pagination, RBAC and PostgreSQL tests.

## 2026-11-02 investigation/entity associations
- Migration 0019 adds same-tenant case/entity links, scoped uniqueness and actor FKs; experimental API supports analyst/admin create in open cases and reader pagination. Case history and audit with both target IDs commit atomically; associations are explicitly unverified and are not evidence. No unlink, case assignment or UI.
- Locked API suite 156 passed, 10 SQLite concurrency variants skipped, one upstream warning. Migrated PostgreSQL/SQLite tenant isolation, FK, rollback, pagination and PostgreSQL lock-wait on closed case tested. No real TLS or production readiness.
- Next: implement audited, authorized unlink with case history, carefully define closed-case rules; then expand case evidence workflows and independent security gates.

## 2026-11-02 investigation entity unlink
- Added analyst/admin unlink of a case/entity association only while case open; same-tenant scope, case row locking, transactional history and targeted audit. Unlink removes current association but preserves event history; relink gets a new ID. Associations remain unverified.
- Locked API suite 159 passed, 11 SQLite concurrency variants skipped, one upstream TestClient warning. SQLite/PostgreSQL authorization, rollback, cross-tenant, status and history tests plus forced PostgreSQL close-vs-link/unlink interleavings pass.
- Next: add investigation evidence-reference associations without implying verified files or chain of custody; maintain tenant constraints, lifecycle and tests.

## 2026-11-02 investigation evidence-reference associations
- Migration 0020 and experimental API link/list/unlink unverified evidence references for entities already linked to an open case. Composite foreign keys enforce case/entity/reference tenant and subject boundaries; entity unlink requires evidence associations removed first. Case history and case/entity-targeted audit commit atomically. No file upload, hashing, verification or chain of custody.
- Locked API suite 163 passed, 11 SQLite concurrency variants skipped, one upstream TestClient warning. Migrated PostgreSQL/SQLite auth, tenant, FK, pagination, rollback, duplicate and lifecycle tests pass. No browser or real TLS.
- Next: add PostgreSQL race test for case evidence link/unlink vs case closure and parent unlink; continue case management and security gates.

## 2026-11-02 investigation evidence concurrency
- Added deterministic PostgreSQL case-lock interleavings: pending evidence link/unlink after case closure is rejected; linking after parent entity association removal is rejected. Existing data remains consistent.
- Locked API suite 166 passed, 14 SQLite PostgreSQL-only variants skipped, one upstream TestClient warning. Broader deadlock and load behavior remain unverified.
- Next: add case assignment and role-scoped audit with tenant FK and tests, or continue independent security/localization tasks.

## 2026-11-02 investigation assignment
- Migration 0021 adds same-tenant assignee; admin-only assignment/clear requires an open case and expected version, active analyst/admin at assignment time, deterministic user locks and rechecked session. Case history and targeted audit are atomic; assignment grants no extra access. Disabling/demoting an assignee later does not clear existing assignments.
- Locked suite 170 passed, 15 SQLite PostgreSQL-only variants skipped, one upstream TestClient warning. PostgreSQL forced disable-before-lock, authorization, FK, rollback and SQLite migration preservation tests passed.
- Next: handle previously assigned users who become ineligible, defining safe operational visibility and lifecycle; continue localization and deployment gates.

## 2026-11-02 stale case-assignee visibility
- Case list reports query-time assignee eligibility using a tenant-scoped user join. Unassigned, active analyst/admin and ineligible states are distinct. This does not automatically clear assignments or guarantee future eligibility; case assignment grants no permissions.
- Locked suite 172 passed, 15 SQLite variants skipped, one upstream warning. Migrated SQLite/PostgreSQL tests exercise demotion, restoration and disable.
- Next: improve case discovery/detail, then localization and broader security/deployment gates; browser, live sources and production readiness remain unverified.

## 2026-11-02 investigation detail and discovery
- Added tenant-scoped, case-target-audited detail endpoint and optional status/assignee filters on paginated case listing; all readers remain role-checked. Eligibility is query-time only, cursors are not snapshots.
- Locked API suite 174 passed, 15 SQLite concurrency variants skipped; one upstream TestClient warning. SQLite/PostgreSQL authorization, detail, filter and targeted audit tests pass.
- Next: add case notes with actor/time, tenant constraints, transactional audit/history, pagination and versioning considerations; continue localization/deployment work.

## 2026-11-02 investigation notes
- Added migration 0022 and experimental analyst-authored case notes, create only in open cases and chronological paginated read. Tenant/actor FKs, case history and case-targeted audit are transactional. Notes are unverified, immutable only through API, not tamper-resistant or evidence; text requires escaping in any UI.
- Locked suite 179 passed, 16 SQLite PostgreSQL-only variants skipped; one upstream TestClient warning. SQLite/PostgreSQL scope, rollback, redacted validation and tie pagination plus PostgreSQL close-before-note interleaving pass.
- Next: continue case workflow (search/reporting and stricter audit target precision), localization and production security gates; no UI login, live source or validated TLS.

## 2026-11-02 note detail and audit target
- Migration 0023 adds case/tenant constrained note IDs to security audit and check that note target requires case. New note creation and single-note reads are targeted; old audit records are not backfilled. Added tenant-scoped note detail endpoint.
- Locked API suite 181 passed, 16 SQLite variants skipped, one upstream warning; migrated SQLite/PostgreSQL scope, FK, check and targeted audit tests pass. Audit is not tamper-resistant.
- Next: review audit event filtering and case discovery or implement source/locale/UI gaps, while preserving tenant boundaries and safe operational status.

## 2026-11-02 case audit filters
- Added admin-only audit filtering by case and supported event type, filter-scoped cursor validation, and migration 0024 case/time index. Foreign case IDs produce empty results. Existing audit events lacking historical case targets cannot be recovered by this filter.
- Locked suite 183 passed, 16 SQLite variants skipped, one upstream TestClient warning; migrated SQLite/PostgreSQL role, scope, filter and pagination tests pass. Audit remains mutable and without retention/export.
- Next: proceed with localization, protected UI and operational security; ensure source status remains factual.

## 2026-11-02 partial demo localization
- Added a persisted EN/AR/FA selector for demo heading and synthetic-data safety notice, with scoped language/direction metadata and explicit disclosure that remaining UI and records remain English. No full-page RTL or protected UI. Storage failure falls back to in-memory preference.
- Initial web typecheck failed due to TypeScript extension import setting; enabled no-emit TypeScript import support. Locale unit test, typecheck, production build and npm production audit pass. Node emits module-type warning; no browser, screen reader or native-speaker translation review performed. GitHub CI configured to run test, not executed.
- Next: extend translation coverage to all demo content, data labels and full RTL, test keyboard/persistence in a real browser; continue independent protected workflow and security work.

## 2026-11-02 demo navigation localization
- Translated illustrative navigation groups/items and accessible navigation label into EN/AR/FA with scoped RTL alignment. Navigation is still nonfunctional; other UI and records remain English and the page says language support is partial.
- Web typecheck, two dictionary unit tests, build and npm production audit pass; Node module-type warning remains. No browser, screen reader or native-speaker review.
- Next: translate dashboard panels and synthetic data labels, preserve truthful synthetic status and accessibility; then full RTL/browser validation when available.

## 2026-11-02 selected dashboard panel translations
- Added EN/AR/FA strings for selected demo panel headings, explanatory text and source disclaimer with per-span language/direction. Remaining labels and synthetic records stay English; explicit partial-support notice remains.
- Web typecheck, three dictionary tests, production build and npm production audit pass; Node module-type warning. No browser, screen reader or native-speaker review.
- Next: translate remaining metrics, table labels, modal and synthetic records while keeping unrecognized backend text tagged English and source claims truthful.

## 2026-11-02 metrics, detail and synthetic fixture translations
- Added EN/AR/FA labels for selected metrics, tables and detail fields and exact-match translations for known explicitly synthetic fixture text. Unknown or non-synthetic source text remains unchanged; prototype keys safely fall back. Partial support notice remains; other text is English.
- An initial replacement script stopped on unmatched footer text; fixed and reran. Web typecheck, five dictionary tests, production build and npm production audit pass; Node module-type warning. No browser, screen reader, RTL or native-speaker review.
- Next: translate remaining demo labels/error/loading states, assess full layout direction, then perform browser and accessibility testing when available.

## 2026-11-02 demo error/status localization
- Extended demo translations to loading/errors, remaining navigation context, source status, modal headings and localized date formatting; unknown source status remains unchanged. Language support remains explicitly partial, layout is not fully RTL and navigation is nonfunctional.
- Two scripted replacements initially stopped on unmatched embedded JSX, then corrected. Web typecheck, six locale tests, build and npm production audit pass; Node module-type warning. No browser, assistive technology or native-speaker review.
- Next: implement full RTL layout with bidi-safe handling and verify persistence, dynamic data, mobile and accessibility in a real browser when available; continue protected UI/security independently.

## 2026-11-02 demo RTL shell
- Enabled demo-shell RTL for Arabic/Persian, added RTL-specific borders, alignment, directional icons and bidi isolation for source names/ISO dates. Translations remain partial; protected UI absent.
- Web typecheck, six locale tests, production build and npm production audit passed. No browser executable found; layout, mobile, focus, persistence, bidi and screen reader behavior are not verified.
- Next: add browser-based E2E and accessibility checks when a supported browser environment is available; independently continue protected product workflows and security gates.

## 2026-11-02 remove third-party font request
- Removed Google Fonts stylesheet import and use system fonts to avoid an unnecessary third-party browser request. Actual glyph rendering on Arabic/Persian platforms is unverified; no broader network/CSP audit is claimed.
- Six web unit tests, typecheck, build and npm production audit pass; browser unavailable.
- Next: continue security and protected investigation workflows; verify RTL, language rendering, browser accessibility and privacy in a supported browser.

## 2026-11-02 synthetic browser smoke and RTL fixes
- Local production build hydrates; a pre-existing dev server on port 3000 did not hydrate and showed HMR errors after build activity; its cause was not established. A separate production server and test server were stopped after use.
- Corrected demo badge styling that inadvertently styled translated text as the status dot, and constrained narrow-screen breadcrumbs. Added three automated synthetic Chromium tests for selected AR/FA direction, Arabic persistence, modal keyboard focus/Escape, 390px overflow and API failure; the main successful flow rejects external requests. Chromium runs without sandbox, for synthetic test use only; no browser security conclusion.
- Fresh npm ci, web typecheck, six locale unit tests, build, three browser tests and full npm audit passed locally. Browser tests added to CI but GitHub execution unverified. No native-speaker, screen-reader, other-browser or comprehensive accessibility review.
- Next: extend accessibility and error coverage, then continue protected investigation/security workflows; real sources, restore, TLS and production gates remain open.

## 2026-11-02 synthetic overview contract hardening
- Added strict bounded synthetic-only response validation at the proxy and client, rejecting unknown fields, non-synthetic records, non-demo mode, unexpected source status, duplicate IDs and malformed values. The proxy caps streamed response at 256 KiB, fails closed and marks errors no-store. This validates assertions and shape, not the factual provenance of upstream content; strict schema changes require coordination.
- Web typecheck, seven unit tests, build, five Chromium/proxy tests and full npm audit passed; actual Python demo fixture accepted. Proxy tests include malformed JSON, oversized and unauthorized-shape responses, and browser test confirms an invalid 200 response shows an error. CI remains unverified.
- Next: extend accessibility and negative-path browser coverage, then continue protected investigation and security work.

## 2026-11-02 demo dialog accessibility increment
- Marked background shell sections inert while the detail dialog is open, and exposed error/loading states as alert/status. Headless Chromium tests cover inert behavior, Tab/Shift+Tab, Escape and focus restoration. A test initially matched Next's own alert too; selector was corrected and rerun.
- Web typecheck, seven unit tests, production build and five synthetic browser/proxy tests pass locally. This is not screen-reader, cross-browser or comprehensive accessibility verification.
- Next: inspect protected investigation workflows/tests (in protected_api.py and test_migrations.py) and implement an independent authorization-preserving increment; then continue broader product and security work.

## 2026-11-02 experimental case details update
- Added analyst/admin tenant-scoped open-case title/description update with strict version, current user/session authorization, PostgreSQL case row locking, and atomic previous/current case history plus targeted audit. Closed, stale, foreign and unauthorized requests are denied. This is an experimental API, not a protected UI or a verified evidence lifecycle.
- SQLite test initially used a string UUID in a direct ORM query and failed; corrected it. Locked API suite on migrated SQLite and disposable PostgreSQL: 187 passed, 18 intentionally skipped SQLite variants of PostgreSQL-only tests. PostgreSQL forced lock waits cover close and competing version change. One upstream TestClient warning remains.
- Next: inspect validation/history rendering and select the next tenant-scoped investigation workflow; continue independent security and product tasks.

## 2026-11-02 case list cursor scope
- Case-list continuation now requires an existing anchor in the caller tenant matching current status/assignee filters; foreign, missing and mismatched anchors return 404. This is not a signed filter-bound token; changed cases can invalidate a cursor, and traversal is not a snapshot.
- Locked API suite on migrated SQLite and disposable PostgreSQL: 187 passed, 18 SQLite PostgreSQL-only variants skipped, one upstream TestClient warning.
- Next: review other list cursor scoping and concurrent change behavior, then continue independent tenant-scoped workflows and security tasks.

## 2026-11-02 case link cursor scope
- Case entity/evidence link lists now require an existing same-tenant, same-case link as the UUID continuation anchor. Missing or mismatched anchors return 404; unlinking an anchor invalidates it and pagination remains non-snapshot.
- Locked API suite: 187 passed, 18 skipped SQLite variants of PostgreSQL-only tests; migrated SQLite/PostgreSQL tests cover multi-page, invalid and cross-case anchors. One upstream TestClient warning.
- Next: inspect entity and evidence list cursor scoping; continue security and tenant-isolated investigation workflows.

## 2026-11-02 intelligence and evidence cursor scope
- Entity list UUID continuation requires an existing same-tenant entity; evidence list continuation requires an existing reference for the same entity and tenant. Missing, foreign and mismatched anchors return 404. Corrected obsolete pagination comment. Existing UUID anchors can be invalidated by deletion and are not snapshots.
- Locked API suite: 187 passed, 18 skipped SQLite variants of PostgreSQL-only tests, one upstream TestClient warning; negative cursor scope and multi-page tests pass on migrated SQLite/PostgreSQL.
- Next: implement another eligible tenant-scoped investigation/security improvement; preserve isolation and atomic audit and test PostgreSQL behavior.

## 2026-11-02 synthetic isolated logical restore drill
- Added an opt-in developer-only drill using two disposable local-trust PostgreSQL servers, synthetic fixtures, bundled pg_dump/pg_restore, Alembic schema parity and selected restored rows plus one composite tenant-constraint check. It accepts no external URLs or real data and removes temporary data after stopping servers.
- Local drill passed; optional pgserver remains separately installed and unlocked. This does not validate encryption, off-site backups, actual deployment, production restore, RPO/RTO, roles or recovery procedures.
- Next: continue independent tenant-scoped investigation/security work and operational backup design; real restore remains an open release gate.

## 2026-11-02 admin session revocation
- Added experimental admin-only same-tenant endpoint to revoke existing sessions for another account, under UUID-ordered user locks with rechecked authorization and atomic target audit. Self and foreign targets are denied; zero-session requests are audited. This does not disable accounts, change passwords or prevent later login; expired but unrevoked sessions are included in the count.
- Locked migrated SQLite/disposable PostgreSQL suite: 190 passed, 19 SQLite variants of PostgreSQL-only tests skipped, one upstream warning. Tests cover role/tenant denial, audit rollback, target isolation, old/new sessions and forced PostgreSQL concurrent session issuance.
- Next: inspect additional identity/security incident-response controls; keep the production release blocked on missing credential recovery, MFA, TLS and security review.

## 2026-11-02 experimental self password change
- Added current-password-verified self-change with a committed per-account fixed-window attempt limit before Argon2 verification, a locked recheck of session and original hash, atomic credential replacement, revocation of all own sessions and non-secret audit. This is not forgotten-password recovery; no MFA, reuse/breach checks or failed-change audit exists. Fixed-window and ingress/global abuse limitations remain.
- Locked migrated SQLite/disposable PostgreSQL suite: 196 passed, 19 SQLite variants of PostgreSQL-only tests skipped, one upstream warning. Tests cover redacted responses, authorization, throttling before hash verification, rollback, token invalidation, login with old/new passwords, and preflight revocation/hash-change rechecks. Actual proxy/TLS remains unverified.
- Next: exercise forced PostgreSQL concurrent password-change races and continue independent identity/security and investigation workflows.

## 2026-11-02 password change failure audit and concurrency
- Audit failed current-password and throttled attempts after initial token check, without passwords or request bodies; rate-limit consumption remains committed independently. Audit failure fails closed. Attribution reflects preflight authentication, not a locked final authorization; blocked-attempt audit growth remains an operational concern.
- PostgreSQL barrier test forces two valid concurrent password changes; one commits and the other is denied, with one audit event and both old sessions revoked. Locked API suite: 197 passed, 20 SQLite variants of PostgreSQL-only tests skipped, one upstream warning.
- Next: continue tenant-scoped identity/security and investigation workflows with rollback and concurrency tests; actual TLS and security review remain unverified.

## 2026-11-02 protected current-user identity
- Added experimental bearer-only `GET /api/v1/secure/me`, returning only current tenant, user ID, username and freshly rechecked role, with tenant-targeted self-read audit in the same transaction. No login UI, cookie session or production transport is implied.
- Locked API suite: 199 passed, 20 SQLite variants of PostgreSQL-only tests skipped, one upstream warning. Migrated SQLite/PostgreSQL tests verify anonymous denial, per-tenant identity, role updates, deactivation, no-store and fail-closed audit reads.
- Next: continue secure tenant-scoped workflows and design an operational UI without persistent bearer-token storage; actual TLS and production review remain open.

## 2026-11-02 tenant user directory
- Added experimental administrator-only tenant-scoped user list with bounded UUID cursor, current locked role/session authorization and atomic directory-read audit. It returns only ID, username, role and active state; no password hash or sessions. Missing/foreign anchors return 404; pagination is not snapshot-consistent.
- Locked migrated SQLite/PostgreSQL API suite: 201 passed, 20 SQLite PostgreSQL-only variants skipped, one upstream warning. Tests cover multi-page traversal, scope, role demotion, no-store and audit failure. No operational UI or production transport is claimed.
- Next: continue tenant-scoped identity/investigation workflows, concurrency verification and secure operational UI design.

## 2026-11-02 verification and next recovery step
- After identity changes, isolated synthetic restore drill, web typecheck, seven unit tests, production build, five browser/proxy smoke tests and full npm audit passed locally. API suite remains 201 passed, 20 SQLite variants of PostgreSQL-only tests skipped; CI, real restore and real transport unverified.
- Next: inspect session model/audit/locking and design tenant-scoped session-specific audit targets before implementing per-session controls; do not store browser bearer tokens persistently. Continue independent investigation/security tasks.

## 2026-11-02 experimental self session management
- Added tenant/user-scoped session list and individual session revocation (including current session), locked reauthentication and atomic audit; results expose UUID metadata, never token or digest. List includes expired/revoked sessions pending cleanup. Migration 0025 stores a session UUID audit snapshot and enforces user target but deliberately has no session FK so cleanup can proceed; association is checked in application, not DB, and old audits are not backfilled.
- Locked API suite: 207 passed, 21 SQLite PostgreSQL-only variants skipped; one upstream TestClient warning. Tests cover tenant/user denial, pagination, audit failure rollback, self-revocation, retained audit after cleanup, data-preserving migration downgrade/upgrade and a forced PostgreSQL concurrent revoke. Synthetic restore drill passed after migration.
- Next: expand PostgreSQL authorization/disable races for session routes; continue other tenant-scoped investigation and security work. Real TLS, MFA, production review and audit tamper resistance remain missing.

## 2026-11-02 session disable interleavings
- Forced PostgreSQL row-lock tests demonstrate both self-session list and individual revoke deny requests after the account is disabled while they wait; no unintended revocation or corresponding success audit occurs. These are selected interleavings, not comprehensive concurrency verification.
- Locked API suite: 209 passed, 23 intentionally skipped SQLite variants of PostgreSQL-only tests, one upstream warning.
- Next: inspect tenant-scoped investigation workflows for another independently implementable product increment while keeping audit, authorization and concurrency tests.

## 2026-11-02 protected entity detail
- Added tenant-scoped entity detail with locked reauthentication and targeted transactional read audit, sharing the existing list projection and explicitly warning that entity metadata and references are unverified. Internal properties are not included.
- Locked migrated SQLite/PostgreSQL suite: 211 passed, 23 SQLite variants of PostgreSQL-only tests skipped, one upstream warning. Tests cover viewer access, foreign and anonymous denial, list/detail consistency, no-store and audit fail-closed.
- Next: continue protected intelligence/investigation workflows and secure UI design; live sources, verified evidence and production controls remain incomplete.

## 2026-11-02 entity kind filtering
- Entity list accepts a validated kind filter and requires continuation anchors to match that filter and tenant; migration 0026 adds a tenant/kind/ID index. Cursors are unsigned UUID anchors, not filter-bound tokens or snapshots; changes can invalidate them.
- Locked API suite: 211 passed, 23 SQLite PostgreSQL-only variants skipped, one upstream warning; SQLite/PostgreSQL filter and pagination tests, schema parity and isolated synthetic restore pass. Index performance on production data is unmeasured.
- Next: inspect evidence-reference detail and targeted audit for a tenant-scoped increment, then continue independent investigation/security tasks.

## 2026-11-02 evidence reference detail and scoped audit target
- Added tenant/entity-scoped single evidence-reference detail and targeted create/read audit. Migration 0027 enforces the evidence target belongs to the audit tenant and entity; earlier audit events are not backfilled. The FK can block reference deletion and requires an eventual retention/deletion policy. References, digests and files are not verified.
- Locked API suite: 214 passed, 23 SQLite PostgreSQL-only variants skipped, one upstream warning. Tests cover viewer access, tenant/entity mismatches, targeted audit, audit failure, FK constraints and migration data preservation; synthetic PostgreSQL restore and schema parity passed.
- Next: extend evidence-target audit to investigation link/unlink and relevant audit filters, maintaining transactional scope and tests; production controls and verified evidence remain open.

## 2026-11-02 case evidence audit targets and filter
- Case evidence link/unlink now record evidence as well as case/entity targets; admin audit supports an evidence-ID filter and filter-matching cursor anchor. Migration 0028 indexes tenant/evidence/time traversal. Historical events remain without backfill; filtering is not snapshot-consistent, and the evidence FK can inhibit deletion.
- A first test run failed because the test referenced a nonexistent fixture name; fixed and reran. Locked API suite: 216 passed, 23 SQLite PostgreSQL-only variants skipped, one upstream warning. Migrated SQLite/PostgreSQL tests cover rollback, filtered multi-page traversal and tenant/cursor scope; schema parity and synthetic restore passed.
- Next: continue evidence lifecycle and investigation/security work; real file verification, retention, tamper protection, production TLS and operational UI are still missing.

## 2026-11-02 case evidence-link detail
- Added tenant/case-scoped single evidence association read, with current locked session authorization and case/entity/evidence targeted read audit in one transaction. Returns only association metadata and explicitly labels it unverified; no file or digest is validated. A concurrent unlink may occur after the read, so it is not a durable snapshot.
- Locked migrated SQLite/PostgreSQL API suite: 218 passed, 23 SQLite PostgreSQL-only variants skipped, one upstream warning. Tests cover viewer, anonymous, cross-case and cross-tenant behavior, list/detail consistency and audit failure.
- Next: continue independent investigation/evidence security work; verified files, chain of custody, production security and UI remain absent.

## 2026-11-02 case entity-link detail
- Added tenant/case-scoped single entity association read with locked session recheck and atomic case/entity-targeted audit. Association is explicitly unverified and is not evidence of involvement; a later unlink can make the response stale.
- Locked migrated SQLite/PostgreSQL API suite: 218 passed, 23 SQLite PostgreSQL-only variants skipped, one upstream warning. Tests cover viewer, anonymous, cross-case/tenant denial, list/detail consistency and audit failure.
- Next: continue protected investigations, identity/security and safe operational UI design; production gates remain unmet.

## 2026-11-02 entity-filtered audit
- Admin audit now supports an entity-ID filter alongside existing case/evidence/event filters, scoped to the caller tenant and checked against continuation anchors; migration 0029 adds tenant/entity/time indexing. Older events without entity targets do not appear, pagination is not a snapshot and production-scale performance is unmeasured.
- API suite 218 passed, 23 SQLite PostgreSQL-only variants skipped, one upstream warning. Migrated SQLite/PostgreSQL tests exercise multi-page filtered results and foreign/mismatched anchors; synthetic restore and Alembic schema parity passed.
- Next: continue protected product workflows, security and operational UI work. Production transport and verified evidence remain open.

## 2026-11-02 login/password lock interleaving
- Added a forced PostgreSQL interleaving proving a login that has read an old password but waits on the user row verifies the newly committed password hash and denies the old password; no session is issued. This is one selected race, not complete identity security verification.
- Locked API suite: 219 passed, 24 SQLite variants of PostgreSQL-only tests skipped, one upstream warning.
- Next: continue implementing bounded tenant-scoped product features and secure evidence lifecycle; operational UI, live sources and production gates remain incomplete.

## 2026-11-02 user-target audit filter
- Added administrator-only user-target filter to tenant audit with current filter-scoped cursor validation and migration 0030 index. Events without target-user IDs are excluded; this is not a snapshot or a production-scale performance claim.
- Locked API suite: 221 passed, 24 SQLite variants of PostgreSQL-only tests skipped, one upstream warning. Cross-tenant IDs return empty results; viewer denial, mismatched cursor and multi-page traversal tested. Synthetic restore and Alembic schema parity passed.
- Next: continue independent investigation, evidence and operational security work; production gates remain open.

## 2026-11-02 literal intelligence title search
- Added bounded, literal case-insensitive title substring search to tenant entity listing, combinable with kind and constrained continuation anchors. SQL wildcard and escape characters are treated literally; audit records a list read without recording the query. Search may scan a tenant's data, case handling depends on database/collation, query strings may be logged by infrastructure, and cursors are not snapshots.
- Locked API suite: 223 passed, 24 SQLite variants of PostgreSQL-only tests skipped, one upstream warning. Migrated SQLite/PostgreSQL tests cover tenant isolation, multi-page filter matching, wildcard escaping and invalid input. Production-scale performance and non-ASCII collation behavior are unverified.
- Next: continue tenant-scoped investigation and evidence workflow, operational security and UI work.

## 2026-11-02 investigation title search and test boundary fix
- Added bounded literal case-title substring search, combinable with status/assignee and checked against tenant/filter-scoped continuation anchors; no query text is placed in security audit. Search may scan data, case behavior depends on collation, query URLs may be logged and pagination is not a snapshot.
- One full-suite run crossed a fixed-window boundary and failed the existing login throttle test (six requests legitimately straddled windows). Fixed tests to use a controlled counter clock; added an explicit boundary-burst test and also fixed the analogous password-change throttle test. This does not change or improve the real fixed-window policy.
- Locked API suite rerun: 226 passed, 24 SQLite PostgreSQL-only variants skipped, one upstream warning. Migrated SQLite/PostgreSQL case-search tests cover literal wildcards, tenant isolation, filters and cursors; production performance and Unicode behavior remain unverified.
- Next: continue tenant-scoped product/security workflows and safe evidence/UI design.

## 2026-11-02 secure-prefix framing defense
- Reject requests at the secure ASGI prefix when both Content-Length and Transfer-Encoding reach the application, including case-insensitive header names; error is generic, no-store and nosniff. This cannot correct parsing disagreements upstream and is not a request-smuggling security review or replacement for trusted proxy/server controls.
- Locked API suite: 226 passed, 24 SQLite PostgreSQL-only variants skipped, one upstream warning; five targeted request-limit tests passed after expanding header assertions. No real reverse-proxy/TLS test was performed.
- Next: continue independently eligible protected investigation/security and evidence work; keep production release blocked.

## 2026-11-02 restored checkout and NVD fixture adapter
- Session checkout started at original `c6ef133` with the prior workspace files untracked/modified and previous conversation commit objects unavailable. Preserved the existing workspace in snapshot commit `a822bab`; this does not reconstruct the prior Git history. Recreated Python 3.11 locked dev environment and separately installed optional pgserver.
- Added standalone fixed-URL NVD single-CVE lookup parser/fetch with synthetic tests, bounded response, sanitized errors, no redirects, one request and a checkpointed time budget. It preserves source timestamps and multilingual descriptions, does not infer confidence and returns no record on an empty valid response. It has no importer, scheduler, UI, API key or shared rate limit; provider terms and actual NVD compatibility/live availability remain unverified. Blocking I/O is not hard-cancelled.
- API suite: 237 passed, 24 SQLite PostgreSQL-only variants skipped, one upstream TestClient warning; isolated synthetic PostgreSQL restore passed. Fresh npm ci, web typecheck, 7 unit tests, build, 5 browser/proxy smoke tests and npm audit passed. GitHub CI and Docker not verified.
- Next: build and test tenant-authorized NVD import with explicit provenance/audit and SQLite/PostgreSQL isolation; do not make live requests or claim live integration without verification.

## 2026-11-02 NVD tenant-scoped internal import
- Added migration 0031, source-specific NVD observation storage, tenant-scoped admin import, source attribution and transactional audit/provenance. Validated adapter records are revalidated; observations remain unverified. Identical observations are idempotent, older collection timestamps and same-time conflicts are rejected, and analyst edits are not overwritten. Ordering is by caller-provided collection time, not NVD modification timestamp; CISA and NVD observations are not fused. No external NVD import/read endpoint, scheduler, UI, live fetch, global rate limit or API key support.
- Migrated SQLite/PostgreSQL tests cover roles, cross-tenant FK, idempotency, rollback, stale/conflicting observations, provenance and concurrent PostgreSQL deduplication. 243 passed, 25 intentional SQLite skips of PostgreSQL-only cases; schema parity and synthetic disposable restore passed. One upstream TestClient deprecation warning. Restore does not specifically validate NVD record contents or production backup.
- Next: expose an audited tenant-scoped NVD observation read path; retain unverified status and no implied live health.

## 2026-11-02 protected NVD observation read
- Added `GET /api/v1/secure/sources/nvd/cves/{cve_id}` to the default-off experimental API. It requires an authenticated reader, scopes lookup by tenant, audits successful reads against the entity atomically, emits no-store, and explicitly labels observations unverified and timestamps not proof of live health. Invalid IDs return generic 422; missing and cross-tenant observations return 404. Collection timestamps are normalized to UTC; source timestamps are left as received.
- Migrated SQLite/PostgreSQL tests cover viewer access, unauthenticated and foreign-tenant denial, invalid/missing IDs, audit failure and targeted audit filter. API suite 245 passed, 25 intentional SQLite skips of PostgreSQL-only cases; synthetic PostgreSQL restore and schema parity passed, one upstream warning. No NVD sync API, CLI, UI, scheduler, global rate limit or live verification.

## 2026-11-02 synthetic NVD restore coverage
- Expanded disposable PostgreSQL logical restore drill with a synthetic NVD observation, checked its entity link, JSON and collection timestamps after restore, and verified the restored NVD composite tenant/entity FK rejects a foreign entity. Drill and Alembic parity passed locally. This does not verify real data recovery, backups, encryption, off-site durability, PITR or RPO/RTO.

## 2026-11-02 NVD manual synchronization coordinator
- Added migration 0032 and internal manual single-CVE coordination with authorized admin preflight/recheck, one running attempt per tenant (tenant lock plus partial unique DB index), persisted sanitized success/not-found/failure/abandonment and audited status. Import, provenance, success status and audit commit atomically. Fetch outside transactions; explicitly abandoned work cannot later import or update status. A no-result response does not delete records or prove safety.
- Synthetic/mock fetch tests only: migrated SQLite/PostgreSQL tests include role and tenant scoping, rollback, concurrent PostgreSQL starts, uniqueness, errors and late completion after abandonment. Locked API 258 passed, 26 intentional SQLite PostgreSQL-only skips, one upstream warning; schema parity and synthetic restore passed. Provider terms/schema/live availability unverified, no shared provider-wide limiter, scheduler, CLI, public sync or status API, UI or hard cancellation; crashed attempts require explicit abandonment.

## 2026-11-02 NVD status and recovery endpoints
- Added admin-only, tenant-scoped `GET /api/v1/secure/sources/nvd/status` and `POST /api/v1/secure/sources/nvd/attempts/{id}/abandon` to the default-off experimental API, with transactional audit, generic errors, no-store, UTC timestamps and explicit notice that recorded results do not establish live health. Abandonment does not stop fetch but prevents late import.
- Migrated SQLite/PostgreSQL tests cover role/tenant denial, audit-failure rollback, no-store and successful recovery; API suite 260 passed, 26 intentional SQLite PostgreSQL-only skips, one upstream warning. Parity and synthetic restore passed. No sync-start API, CLI, scheduler, real provider verification or global provider rate limiter.

## 2026-11-02 interactive manual NVD CLI
- Added an explicit single-CVE manual CLI requiring fixed CVE validation, configured PostgreSQL, explicit live-fetch confirmation, interactive token input, and admin authorization before fetch. It does not accept URLs or bearer tokens as arguments; output distinguishes imported unverified, no-record and failure, and redacts exceptions. No network request was made in tests.
- Initial full test run exposed a test teardown bug: the test changed DATABASE_URL beyond the scoped monkeypatch, so Alembic used a non-existent test URL. Removed the override and reran successfully. API 263 passed, 27 intentional SQLite PostgreSQL-only skips, one upstream warning; synthetic restore and schema parity passed. CLI uses simulated TTY/mock fetch on disposable PostgreSQL, not verified with a real terminal or NVD; no scheduler, shared provider rate limiter, start-sync API or hard deadline.

## 2026-11-02 forced NVD authorization interleavings
- Added six forced PostgreSQL lock-wait cases: admin demotion, disable or session revocation during an in-flight mocked fetch, for both found and missing responses. Pending import/not-found completion is denied, no NVD record/success/not-found audit commits and the attempt records sanitized import failure. This exercises selected races, not comprehensive concurrency or deployment security.
- Full API suite 269 passed, 33 intentionally skipped SQLite variants for PostgreSQL-only tests, one upstream TestClient warning. Schema parity and disposable synthetic restore passed; no live requests.
