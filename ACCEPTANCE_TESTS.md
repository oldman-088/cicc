# Acceptance tests

Executed: API `python -m pytest -q`: 3 passed (synthetic labels, unavailable sources, read-only endpoint, health); web `npm run typecheck` passed and `npm run build` passed. Build issued CSS autoprefixer warnings. API test emitted a third-party deprecation warning. No browser, accessibility, Docker, live source, database, security or restore tests executed.

Release gates: validate authentication, session revocation, cross-tenant reads/writes, audit, migrations against PostgreSQL, connector contracts and failures, evidence integrity, end-to-end workflows, all three locales and RTL, accessibility, secure file quarantine, monitoring and a verified backup restore. Detailed feature acceptance criteria are in MASTER_TASK_QUEUE.md. None of these gates is satisfied by the demo tests.

2026-11-02 continuation: 6 API tests passed, including Argon2id verification, RBAC denial, tenant-filtered reads and cross-tenant relationship rejection with SQLite foreign keys enabled. Clean Next.js 16 build and typecheck passed; production npm audit reported zero findings. PostgreSQL, authenticated API, browser and CI remain untested.

2026-11-02: API suite 9 passed, 1 PostgreSQL case skipped (no test database). SQLite migration upgrade, downgrade, missing URL fail-closed, and tenant FK constraint passed. Web typecheck, build, production npm audit (zero findings), and production server HTTP smoke test for `/` and the runtime API route passed. CI and PostgreSQL remain unverified.
- Production proxy failure smoke test: unreachable API returned HTTP 503 with an explicit unavailable message.

2026-11-02 session continuation: 13 API tests passed, 1 PostgreSQL test skipped. SQLite tests cover session issuance, invalid credentials, tenant mismatch, stored token digests, role changes, deactivation, revocation, expiry, invalid roles, session FK isolation and identity migration rollback. Web typecheck/build and production npm audit passed. There is no end-to-end login test because no login endpoint is exposed.

2026-11-02 audit continuation: 17 API tests passed, 1 PostgreSQL test skipped. SQLite tests cover scoped audit reads, permission denial, allowed event types, fixed-window counters, key hashing, transaction rollback and migration rollback. Web typecheck/build and npm production audit passed. No concurrent PostgreSQL rate-limit test or login integration was executed.

2026-11-02 login-service continuation: API 23 passed, 2 PostgreSQL cases skipped. SQLite tests include concurrent login rate limits on both metadata-created and migrated databases, durable failed-attempt counts, audit/session atomicity, audit failure rollback, logout and invalid source handling. Web typecheck/build and production npm audit passed. The CI PostgreSQL concurrency case is configured but not run.

2026-11-02 account continuation: API 28 passed and 3 PostgreSQL tests skipped. SQLite tests cover admin-only account creation, target audit, role refresh, revocation on disable, cross-tenant and self-operation denial, duplicate username, audit rollback, and migration upgrade/downgrade. Web typecheck/build and production npm audit passed. PostgreSQL and HTTP account workflows remain unverified.

2026-11-02 bootstrap continuation: API 35 passed, 4 PostgreSQL cases skipped. SQLite tests cover new-tenant bootstrap, password hash, audit rollback, invalid input, CLI confirmation/TTY checks and mocked successful password prompts. Typecheck, web build and production npm audit passed. Real terminal interaction and PostgreSQL remain unverified.

2026-11-02 protected API continuation: API 43 passed, 5 PostgreSQL cases skipped. SQLite/TestClient tests cover opt-in fail-closed config, HTTPS scope, login/logout, rate limiting, tenant-derived reads, invalid tokens, audit failure and redacted validation errors. A migrated PostgreSQL API test is configured but not run. Web typecheck/build and production npm audit passed; no real TLS or browser testing.

2026-11-02 account API continuation: API 46 passed, 5 PostgreSQL variants skipped. SQLite/TestClient tests cover admin account creation, duplicate detection, role change, disable, cross-tenant denial, redaction, old/new role audit and migration rollback. Migrated PostgreSQL API/account variant configured but not run. Web typecheck/build and production npm audit passed.

2026-11-02 intelligence continuation: API 50 passed, 5 PostgreSQL cases skipped. SQLite tests cover manual creation, analyst/viewer permissions, tenant spoofing rejection, creator and confidence constraints, source fields, unverified status, audit rollback and migration rollback. Web typecheck/build and npm production audit passed. PostgreSQL, live source and browser workflow tests not run.

2026-11-02 evidence continuation: API 53 passed, 5 PostgreSQL cases skipped; SQLite/TestClient tests cover tenant isolation, read/write permissions, input validation, audit rollback, unverified labeling and migration rollback for evidence references. No real files, digest verification or PostgreSQL test executed.

2026-11-02 rate-limit cleanup continuation: 55 API tests passed, 5 PostgreSQL cases skipped; SQLite tests cover safe retention threshold and transactional rollback. Web typecheck/build and production npm audit passed. No scheduled cleanup or PostgreSQL verification.

2026-11-02 PostgreSQL continuation: 64 API tests passed on a disposable PostgreSQL 16.2 instance via a private Unix socket (including 7 PostgreSQL variants), plus SQLite. Verified migration upgrade/downgrade, Alembic schema parity, selected cross-tenant foreign keys, concurrent login limits, bootstrap and experimental API workflows using simulated HTTPS. First run exposed an Alembic version-table fixture cleanup bug (56 passed, 4 errors); fixed and reran successfully. No production TLS, comprehensive race testing, GitHub CI, deployment or restore verification.

2026-11-02 provenance continuation: 68 API tests passed with disposable PostgreSQL 16.2, including SQLite/PostgreSQL migration and schema parity, exact evidence/entity FK mismatch rejection, API provenance events and history warning. Web typecheck/build and production npm audit passed. No real TLS, production audit protection, UI or complete history verification.

2026-11-02 audit API continuation: 69 API tests passed with disposable PostgreSQL 16.2; tested administrator-only audit access, cross-tenant exclusion and auditing of access with SQLite, plus PostgreSQL migrated API smoke test. Real TLS and production audit guarantees remain unverified.

2026-11-02 entity update continuation: API suite 73 passed, 1 SQLite variant skipped because the test specifically targets PostgreSQL concurrency. Tested optimistic conflicts, tenant and role denial, audit rollback, before/after provenance, targeted SQLite migration rollback and concurrent PostgreSQL edits. Web typecheck/build and production npm audit passed.

2026-11-02 request body continuation: 77 API tests passed, 1 SQLite variant skipped (PostgreSQL concurrency-only test). Tests cover declared and streamed request limits, malformed/duplicate content length, default demo isolation and middleware registration. Web typecheck/build and npm production audit passed; real reverse-proxy behavior remains untested.

2026-11-02 graph continuation: 82 API tests passed, 1 SQLite case skipped because it targets PostgreSQL concurrency. SQLite and disposable PostgreSQL 16.2 tests cover relationship creation/list, unverified labels, tenant/evidence constraints, authorization, audit rollback, migration rollback and schema parity. Web typecheck/build and production npm audit passed. No production TLS, graph UI or automatic correlation verified.

2026-11-02 CISA adapter continuation: 96 API tests passed, 1 SQLite variant skipped (PostgreSQL-only concurrency). Synthetic MockTransport tests cover fixed URL, validation, duplicate CVE rejection, no redirects, retry limits, timeouts, source failures and decoded size limits. No live CISA request or provider terms verification performed. Web typecheck/build and npm production audit passed on preceding run.

2026-11-02 CISA import continuation: API suite 101 passed, 2 SQLite variants skipped (PostgreSQL-specific concurrency cases). Synthetic fixture tests cover tenant separation, successful import metadata, deduplication, stale rejection, audit rollback, preserving analyst edits, no implicit deletion and PostgreSQL concurrent imports. Web typecheck/build and npm production audit passed. No real feed request, operational synchronization or source health verification.

2026-11-02 source sync continuation: 108 API tests passed, 3 SQLite variants skipped (PostgreSQL-only concurrency cases). Synthetic fixtures cover success, failure, preservation of last imported snapshot on failure, admin/tenant isolation, concurrency, explicit abandonment and late-result refusal, audit rollback and migration rollback. Web typecheck/build and npm production audit passed. No live CISA request, scheduler, UI or production verification.

2026-11-02 CISA status API continuation: 109 API tests passed, 3 SQLite variants skipped (PostgreSQL-only concurrency cases); tested status authorization, tenant isolation, abandonment, missing start-sync endpoint, and PostgreSQL-backed status smoke test. Web typecheck/build and npm production audit passed. No live CISA access, production TLS or browser verification.

2026-11-02 entity pagination continuation: 112 API tests passed, 3 SQLite PostgreSQL-only variants skipped. SQLite and migrated PostgreSQL tests verify multi-page cursor iteration, no duplicate IDs and tenant isolation; pagination is not a snapshot.

2026-11-02 audit pagination continuation: 116 API tests passed, 3 SQLite variants skipped (PostgreSQL-only concurrency). Tests cover multi-page audit traversal, timestamp ties, tenant-scoped cursors, denial for foreign cursors, audit of access, index migration rollback and SQLite/PostgreSQL schema parity. Web typecheck/build and npm production audit passed.

2026-11-02 graph pagination continuation: 118 API tests passed, 3 SQLite variants skipped. Migrated SQLite and PostgreSQL tests verify multi-page evidence, provenance, relationship lists, timestamp ties and rejection of unrelated timeline/relationship cursors; schema parity checks cover new indexes.

2026-11-02 response hardening: 119 API tests passed, 3 SQLite variants skipped. Covered non-cacheable secure success, 404, 405 and generic 500, and preservation of demo-route behavior. Real reverse proxy, server logging and browser behavior remain unverified.

2026-11-02 concurrent authorization: 121 passed, 5 skipped (SQLite variants of PostgreSQL concurrency tests). PostgreSQL lock-wait tests demote/revoke an actor before its pending entity mutation acquires the user lock; mutation is rejected. Full security, deadlock, and load testing remain open.

2026-11-02 source tenant lock test: 122 passed, 6 skipped (SQLite variants of PostgreSQL concurrency tests). Tested actor-lock/source-lock/audit FK interleaving and existing source concurrency tests; other deadlock and availability cases remain open.

2026-11-02 administrator lock ordering: 123 API tests passed, 7 skipped (SQLite variants of PostgreSQL concurrency tests). Two simultaneous administrators attempting mutual demotion serialize; one succeeds and the other is denied. Broader deadlock and performance testing remains open.

2026-11-02 login throttle allocation: 126 API tests passed, 7 skipped (SQLite variants of PostgreSQL concurrency tests). Synthetic tests on migrated PostgreSQL and SQLite verify no narrower buckets created after a broader denial and counter saturation. DoS, cleanup scheduling and global fairness remain unresolved.

2026-11-02 bounded maintenance: 129 API tests passed, 7 SQLite variants skipped. Migrated PostgreSQL and SQLite tests exercise bounded cleanup, rollback and cutoff; the operator command was exercised on disposable PostgreSQL and rejects SQLite. Real operator environment and scheduling remain unverified.

2026-11-02 CISA operator CLI: 132 API tests passed, 8 skipped. Disposable migrated PostgreSQL test uses synthetic fixture and simulated interactive terminal, verifies admin import and viewer denial before fetch; no live CISA request or real TTY test.

2026-11-02 CISA fetch time budget: 133 API tests passed, 8 skipped. Synthetic mocked slow stream exceeds checkpointed deadline and Retry-After beyond remaining budget fails without retrying early. It is not a hard cancellation mechanism; no live fetch.

2026-11-02 CISA import time budget: 136 API tests passed, 8 skipped. Synthetic SQLite and migrated PostgreSQL tests force expiration after a partial record and verify atomic rollback. No real feed, hard cancellation or database timeout is verified.

2026-11-02 expired-session maintenance: 138 API tests passed, 8 SQLite variants skipped. SQLite and migrated PostgreSQL verify bounded deletion, 24-hour cutoff, rollback, audit preservation; operator command exercised against disposable PostgreSQL. Actual production operator environment remains unverified.

2026-11-02 demo modal accessibility: web typecheck/build and production npm audit passed after adding keyboard dismissal and focus handling. Browser keyboard and assistive technology tests could not be performed; no browser executable is installed.

2026-11-02 account creation resource hardening: 142 API tests passed, 8 SQLite variants skipped. Tests verify invalid/viewer sessions do not invoke password hashing and revocation during hashing prevents creation on SQLite and migrated PostgreSQL. This is not a full DoS defense.

2026-11-02 demo status labeling: web typecheck, production build and production dependency audit passed; dashboard explicitly scopes source status to demo and does not claim knowledge of experimental sync attempts. Browser E2E untested.

2026-11-02 Python dependency remediation: pip-audit initially identified 16 vulnerability entries in pytest and Starlette; after version upgrades pip-audit returned no known vulnerabilities on the resolved requirements and pip check passed. Full API suite: 142 passed, 8 SQLite variants skipped, one Starlette TestClient deprecation warning. GitHub CI, Docker and real transport remain unverified.

2026-11-02 Python dependency split: 142 API tests passed, 8 SQLite variants skipped; pip-audit dev requirements reported no known vulnerabilities. Docker and GitHub CI remain unverified.

2026-11-02 Python hash locks: clean Python 3.11 Linux virtual environments installed runtime and dev locks using --require-hashes; runtime imported and pytest absent; full disposable PostgreSQL suite 143 passed, 8 skipped; both locks pip-audit clean at test time. Lock consistency checker drift/duplicate tests pass. Docker and GitHub CI not run.

2026-11-02 investigation foundation: 148 API tests passed, 9 SQLite variants skipped. Migrated SQLite/PostgreSQL cover authorization, tenant isolation, composite FK, case/event pagination, atomic rollback and optimistic version conflicts; PostgreSQL concurrent status changes produce one success and one conflict. Full case lifecycle, UI and production security remain unverified.

2026-11-02 case audit targeting: 151 API tests passed, 9 SQLite variants skipped. Migrated SQLite/PostgreSQL verify case audit targets, cross-tenant FK rejection and migration parity; SQLite targeted upgrade/downgrade preserves prior audit rows. No historical backfill or immutable audit.

2026-11-02 case/entity links: 156 locked API tests passed, 10 SQLite variants skipped. Migrated SQLite/PostgreSQL tests cover tenant foreign keys, role denial, duplicates, closed cases, pagination, history/audit and rollback. Forced PostgreSQL close-before-link lock wait returns 409. No real data, UI or full lifecycle.

2026-11-02 investigation entity unlink: 159 locked API tests passed, 11 SQLite variants skipped. Migrated SQLite/PostgreSQL tests verify RBAC, tenant isolation, atomic rollback, closed-case denial, preserved history/audit and relinking. PostgreSQL forced lock-wait tests verify link and unlink are denied after case closes.

2026-11-02 case evidence references: 163 locked API tests passed, 11 SQLite variants skipped. Migrated SQLite/PostgreSQL tests cover RBAC, scope, composite FK mismatch, parent requirement, duplicates, pagination, rollback, closed cases and history/audit. No file handling or evidence validation.

2026-11-02 case evidence concurrency: 166 API tests passed, 14 SQLite variants skipped. PostgreSQL forced case-lock interleavings confirm link/unlink reject a closed case and link rejects a removed parent. Full deadlock or load verification remains open.

2026-11-02 case assignment: 170 locked API tests passed, 15 SQLite variants skipped. SQLite/PostgreSQL tests cover admin-only assignment, eligibility, tenant FK, version conflict, closed cases, history/audit and rollback; forced PostgreSQL disable-before-lock case is rejected. SQLite targeted migration upgrade/downgrade preserves case and event rows.

2026-11-02 assignment eligibility visibility: 172 locked API tests passed, 15 SQLite variants skipped. Migrated SQLite/PostgreSQL tests cover unassigned, eligible, demoted, restored and disabled states. Status is query-time, not a guarantee or automatic reassignment.

2026-11-02 case detail and filters: 174 locked API tests passed, 15 SQLite variants skipped. Migrated SQLite/PostgreSQL tests cover tenant-scoped detail, targeted audit, status/assignee filters and invalid input. Pagination remains non-snapshot.

2026-11-02 case notes: 179 locked API tests passed, 16 SQLite variants skipped. Migrated SQLite/PostgreSQL tests cover authorization, tenant FK, rollback, redacted validation, timestamp-tie pagination and history/audit; PostgreSQL close-before-note lock wait rejects write. No browser or tamper resistance.

2026-11-02 note detail and audit precision: 181 locked API tests passed, 16 SQLite variants skipped. Migrated SQLite/PostgreSQL verify note detail authorization, tenant/case mismatch denial, audit target FK and null-case check; old events are not backfilled.

2026-11-02 audit filtering: 183 locked API tests passed, 16 SQLite PostgreSQL-only variants skipped. Migrated SQLite/PostgreSQL tests cover admin-only filters, case tenant scope, cursor scope, timestamp ties and pagination; no backfill, immutable audit or production security verification.

2026-11-02 partial demo localization: locale dictionary unit test, web typecheck/build and production npm audit passed. Initial typecheck found TypeScript extension import configuration missing; corrected. Node emits module-type warning. Browser RTL, persistence, screen reader and native-speaker translation review not verified.

2026-11-02 demo navigation localization: two web unit tests pass, typecheck/build and production npm audit pass. Labels and scoped RTL rules are implemented, but navigation remains illustrative; no browser, screen reader or native-speaker review.

2026-11-02 partial panel localization: three locale dictionary tests, web typecheck/build and npm production audit passed. Selected dashboard panel text is translated; other interface text and data remain English. Browser, assistive technology and native-speaker review remain unverified.

2026-11-02 expanded demo translations: five locale unit tests, web typecheck/build and npm production audit passed. Exact known fixture text translates only when explicitly synthetic; unknown/non-synthetic text remains unchanged. Initial text-replacement script stopped on a nonmatching footer and was corrected before verification. Browser, full RTL, accessibility and native-speaker translation review remain unverified.

2026-11-02 further demo translations: six locale unit tests, web typecheck/build and npm production audit passed. Dates use selected locale and UTC, error/loading text is translated. Replacement scripts required correction on embedded JSX text. No browser, assistive technology, layout RTL or native-speaker review was performed.

2026-11-02 demo RTL shell: six locale tests, web typecheck/build and npm production audit passed. RTL direction and mixed-direction isolation are implemented, but no browser executable was found; layout, responsive behavior, bidi correctness and assistive technology remain unverified.

2026-11-02 font privacy: web typecheck, six locale tests, build and production npm audit passed after removing external Google Fonts import. Actual browser network and glyph rendering unverified.
