# SECURITY STATUS — Agent 1 scope (2026-11-05)

Full review: docs/SECURITY_REVIEW.md (controls table w/ test evidence, findings,
M14 webhook findings, M15 session-architecture note). API reference: docs/API_REFERENCE.md.

- Authn: read/write tokens (write⊇read); webhook HMAC fail-closed + rotation; BFF server-side token injection (no browser tokens). Platform auth adapter inert until owner enables it.
- Authz: per-endpoint gates; approver allowlist (403); BFF writes 403; same-origin enforcement available.
- Rate limits: global read limiter + per-principal write limiter (429) on all writes incl. coordination.
- Audit: every coordination transition (incl. rejected) recorded; ops events; replay-detection alert (M16).
- Secrets: never logged/returned (GH token header-only; webhook payload redaction tested; check_no_secrets.sh).
- Tenant isolation: NOT implemented — pending owner decision; not claimed ready.
- Notifications: disabled (no network path).
- Known limitations: webhook has no signed timestamp (GitHub limitation; detection-only mitigation); dedup-state loss on DB restore until secret rotation.
