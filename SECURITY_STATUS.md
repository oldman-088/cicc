# Security status

**Not production ready.** The default dashboard and its demo API are unauthenticated and serve only synthetic data. Do not deploy publicly or process real data.

A separate, disabled-by-default experimental API provides opaque bearer sessions, Argon2id password verification, tenant-scoped entity and evidence access, administrator account management, fixed-window account/source/global throttling and audit events. SQLite and disposable PostgreSQL 16.2 tests exercise migrations, selected tenant constraints, API workflows and concurrent login throttling. These tests are not an independent security assessment, do not cover all isolation or race scenarios, and use simulated HTTPS. Evidence references are unverified metadata, not uploads or verified hashes.

Missing or unverified: actual TLS and trusted proxy/client-IP configuration; tamper-resistant audit, retention and global audit for unknown tenants; MFA and recovery; password reset; production key management and automatic rate-limit cleanup; operator attribution for offline bootstrap; real browser login; uploads and quarantine; security headers and comprehensive SSRF/CSRF/XSS defenses; PostgreSQL deployment hardening and comprehensive concurrency testing. Default demo and experimental API must not be treated as secure production systems.

`npm audit --omit=dev --audit-level=high` last returned zero findings on 2026-11-02. This is not a full security assessment. See SECURITY.md and P0-03/05.

Experimental API requests have a 16 KiB ASGI body limit that checks declared and streamed sizes; it is not a substitute for reverse-proxy request limits, timeouts or a production security review. The default demo route is unaffected.

The CISA adapter uses a fixed endpoint, disables redirects and environment proxies, limits decoded response size and sanitizes transport errors; it is not exposed or scheduled. This is not a general-purpose SSRF defense or a verified operational integration.

Internal CISA snapshot import is tenant-scoped and audited, uses PostgreSQL tenant locking and does not expose an endpoint or fetch live data. Snapshot objects must come from the validating parser; no generic untrusted object ingestion is supported. SQLite does not provide equivalent concurrent row locking.

CISA synchronization itself remains an internal admin-only coordinator, not a start-sync network endpoint or scheduled process. Experimental administrator-only status and abandonment endpoints are exposed only when the experimental API is enabled. Attempts have sanitized failure codes, and late results cannot commit after explicit abandonment. A process crash may leave a running attempt until an authorized operator abandons it. PostgreSQL concurrent-start tests use synthetic data; no live source verification has occurred.

Experimental-prefix responses are forced to `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` by ASGI middleware, including framework errors and generic unhandled 500 responses. Exceptions are re-raised for server logging; production log redaction and proxy behavior still require review. This does not replace TLS, secure client storage, or proxy-side limits.

Protected requests and account operations lock and re-read the acting user and session within their transaction (user before session). PostgreSQL tests force a lock wait, then demote or revoke the actor and verify an intelligence mutation is denied. Operations that already acquired locks may complete before revocation; SQLite has no comparable row-lock guarantee. This serializes requests per user and can reduce throughput; deadlock/availability and complete concurrency review remain open. CISA imports additionally lock tenant first.

CISA tenant serialization uses PostgreSQL `FOR NO KEY UPDATE`, allowing foreign-key `KEY SHARE` while still serializing same-tenant source work. One forced actor-lock/audit insertion interleaving is tested; other lock cycles and performance are not comprehensively tested.

Account role changes and disable operations lock actor and target user rows in UUID order before rechecking authorization; one PostgreSQL simultaneous mutual-demotion case is tested. This does not prove absence of other deadlocks or address throughput.

Login rate limiting stops allocating narrower buckets when a global or source limit already rejects the request; counters saturate at limit + 1. Limits should remain stable through a window, because saturation loses exact excess counts. This is not a complete DoS defense: fixed-window boundary bursts, global denial of service, audit growth on throttling, database contention and unscheduled cleanup remain.

A bounded, explicitly confirmed offline PostgreSQL maintenance command can delete one batch of old rate-limit buckets. It requires operator-verified database identity, permissions and synchronized clock; no scheduler, single-operator enforcement or operator audit is provided. Audit log retention is separate and unimplemented.

CISA fetching checks a monotonic 60-second elapsed budget around network attempts, streamed chunks, retries and parsing, with per-operation timeout bounded by remaining budget. It is not a hard deadline: a blocked operation, name resolution, parsing or database import cannot be immediately interrupted. Live provider behavior is unverified.

CISA imports additionally check a 120-second monotonic budget between records and before returning from the transaction; expiration rolls back the import and the coordinator records a sanitized failure when possible. This is not a hard deadline or database statement timeout; blocking SQL, rollback and commit may exceed it.

The manual maintenance command also supports bounded deletion of sessions expired for more than 24 hours. It does not alter active sessions or audit events. Clock synchronization, operator authorization and concurrent invocation are operational responsibilities; no scheduler or operator identity audit is implemented.

Account creation performs a cheap session/role preflight before expensive Argon2 hashing, then rechecks authorization under locks before writing. This prevents unauthenticated requests from directly triggering account-creation hashing, but authenticated abuse, concurrent work, global login throttling and ingress DoS protections remain unresolved.

2026-11-02: Python dependency audit initially reported advisories affecting pytest 8.3.5 and Starlette 0.46.2. Updated FastAPI to 0.162.0, pinned Starlette 1.10.0 and pytest 9.0.3. `pip-audit -r apps/api/requirements.txt` now reports no known vulnerabilities for the resolved set; `pip check` passes. CI is configured to audit but has not run on GitHub. At the time of that audit transitive Python dependencies were not lockfile-pinned; the later Python 3.11 lock work is recorded below. Audit is time-dependent and not a security review. Full API suite passed on disposable PostgreSQL/SQLite; Starlette TestClient warns about its httpx integration.

The API Dockerfile installs runtime requirements only; pytest is in `requirements-dev.txt`, which is also audited in CI. Runtime and test transitive dependencies were initially unlocked; subsequent hash-lock work is recorded below. Actual Docker build remains unverified.

Python 3.11 runtime/dev dependency sets are now hash locked. A clean Linux/Python 3.11 environment installed each lock with `--require-hashes`; runtime import and full test suite succeeded, and both lockfiles passed pip-audit. A consistency checker covers direct pins and shared package versions but is not a full resolver or provenance verification. Docker builds, other platforms and GitHub CI remain unverified; optional pgserver and audit tooling are separately installed.

Security audit now supports a tenant-enforced investigation target for case creation, status changes and case event reads. Case-list reads have no individual case target; records before this feature are not backfilled. Audit and case history remain mutable at database level and retention is absent.

Note creation and individual note reads record a case- and tenant-scoped note target in security audit. A composite FK and check constraint prevent mismatched notes or a note target without a case. Older audit events are not backfilled, and audit remains mutable at the database level.

Tenant admin audit listing supports case and allowed event-type filtering; cursor anchors are checked within the selected scope. The feature is not a complete search/export, and audit integrity and retention remain unresolved.

The demo stylesheet no longer imports third-party hosted fonts; it uses system fonts instead. This removes that particular browser request but is not a complete CSP, privacy or network security review.

- Experimental secure-prefix body guard also rejects forwarded Content-Length plus Transfer-Encoding; this is defense in depth only and cannot resolve upstream HTTP parser discrepancies. Trusted proxy framing, request-size limits and real TLS remain unverified.

Experimental local quarantine staging and SHA-256 utilities are standalone and synthetic-tested only. They do not implement tenant isolation, trusted custody, malware scanning, encryption, crash cleanup or upload APIs and must not be used for real evidence. Directory ancestor trust, ACLs and same-UID threats require deployment-specific design and review.

2026-11-03: pip check passed; pip-audit `--disable-pip --no-deps` reported no known vulnerabilities for runtime and dev lock entries, and npm audit reported zero findings. These time-dependent advisory checks do not assess code, configuration, or separately installed optional test/audit tools.
