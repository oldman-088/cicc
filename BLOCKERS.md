# Blockers and limitations

- Production release blocked: experimental authenticated APIs are disabled by default and lack comprehensive PostgreSQL isolation verification, real TLS/proxy configuration, security review, durable audit protections, retention and key management. The default dashboard remains an unauthenticated synthetic demo.
- CISA KEV adapter, snapshot persistence and internal sync coordinator are tested only with synthetic fixtures; a new interactive admin-session CLI can invoke one sync, but they have no start-sync API, scheduler or UI and are not live-verified; an experimental admin-only status/recovery API exists. This environment restricts outbound access to package registries and GitHub. NVD has an experimental fixture-only adapter and internal importer; other external connectors are not implemented.
- Docker/Compose, PostgreSQL deployment hardening and broader isolation coverage, production restoration, comprehensive browser E2E, accessibility and GitHub CI are unverified (limited synthetic Chromium smoke tests pass locally).
- Manual intelligence supports create/list, limited title/confidence edits and analyst-entered evidence references only. Limited provenance and analyst-authored relationship assertions exist for new manual writes only; no file upload, digest verification, complete provenance, complete investigation lifecycle, full editing, deduplication or connected UI exists.
- Audit tamper resistance, retention, global audit for unknown tenants, automated rate-limit cleanup (a bounded manual command exists), bootstrap operator attribution, MFA and recovery are missing.
- Arabic/Persian localization is partial (selected demo interface strings and exact-match synthetic fixture text only); comprehensive RTL browser and native-speaker validation, 3D interactions, AI, most modules and enterprise extensions remain unimplemented.
- No external scheduler or authorized mechanism for starting another Arena session was provided; no autonomous continuation runs after this session.
- Protected operations now serialize on acting-user/session rows on PostgreSQL; throughput, deadlock behavior and full concurrent authorization coverage remain unverified. SQLite cannot enforce this concurrency guarantee.
- Rate limits can suffer global denial-of-service, boundary bursts and audit/database growth under floods; cleanup is manual and production ingress protections are unverified. Saturated counters require stable limits during a window.
- Manual CISA CLI has no strict end-to-end runtime deadline (fetch and import use checkpointed elapsed budgets but blocking work and commit are not forcibly interrupted); real terminal behavior, provider terms, live access and source compatibility remain unverified. A crash may leave a running attempt.
- Experimental investigations support create/list, versioned open/closed status, admin assignment, unverified notes, change history and unverified entity/evidence-reference associations with link/unlink only. No verified files, chain of custody, reporting or UI; disabled/demoted assignees are not automatically cleared (case list reports query-time eligibility); case history and audit are not tamper-resistant; historical audit records were not backfilled with case IDs.

- Demo response contract fails closed on unknown fields and explicit non-synthetic data, but cannot prove an upstream claim of synthetic provenance; backend and frontend schema changes require coordination.

- Only a disposable synthetic logical dump/restore drill has passed; no deployed backups, encryption, off-site recovery, production restoration or RPO/RTO validation exist.

- Admin target-session revocation is not credential recovery: the account remains active and later logins can issue new sessions; self password change requires the existing password; forgotten-password recovery and MFA are not implemented.

- Self password change has a per-account fixed-window limit but no global ingress protection, breach/reuse checks or forgotten-password recovery. Failed and throttled attempts are audited after preflight authentication, which can grow storage; broader concurrency and production proxy/TLS behavior need review.

- Session-target audit stores an application-scoped UUID snapshot without an FK so cleanup can delete sessions; the database cannot independently enforce the session/user association, and audit remains mutable and incomplete for older events.

- Evidence-target audit is FK-constrained to tenant/entity/reference and is not historically backfilled; its FK can prevent deletion. Evidence records, supplied hashes and file contents remain unverified.

- Experimental entity and investigation title search is a bounded literal substring scan; production performance, Unicode/collation semantics and intermediary URL-log privacy are unverified.

- NVD adapter is fixture-tested only; real endpoint/schema/provider policy, API key handling and coordinated rate limits are unverified; no NVD exposed read/sync API, scheduler, status API or UI. Its fetch budget is checkpointed, not a hard cancellation deadline.
- This session checkout did not contain the prior conversation commit objects; restored workspace was preserved as snapshot commit `a822bab`, rather than claiming those historical commits exist locally.

- NVD import accepts internal observations after structural validation but cannot establish their authenticity; collection time is caller-provided and ordering does not compare provider modification times. CISA and NVD currently create separate source-specific entities without fusion.
