# Tenant Isolation & Authentication Plan — Ops Subsystem

Status: PLAN + inert adapter implemented (M5). Tenant scoping of ops data is
**not** enabled; it requires a shared-contract decision (see "Open decisions").

## 1. Verified platform auth contract (inspected read-only, 2026-11-04)

Source: branch `arena/da631853-cicc`, `apps/api/app/{sessions,security,login_service}.py`.

- Login is orchestrated internally (not an HTTP endpoint there); rate-limited
  per global/source/account; fail-closed; audited per tenant.
- Sessions: opaque bearer token (`secrets.token_urlsafe(32)`, ≤128 chars,
  ASCII). Server stores **only `sha256(token)`** in `auth_sessions.token_digest`
  (unique), joined to `users` on `(tenant_id, user_id)`; `expires_at` (8 h),
  `revoked_at`; raw tokens never logged/persisted.
- `users`: `id`, `tenant_id` (FK `tenants.id`), `role` ∈ admin|analyst|viewer,
  `active`. Roles→permissions map in `security.py`; `authorize()` **fails
  closed** on cross-tenant or unknown role.
- DB tables: `tenants`, `users`, `auth_sessions`, `security_audit_events`,
  `rate_limit_buckets`.

## 2. What the ops subsystem implements now (M5)

`apps/api/app/platform_auth.py` — **inert unless** `CICC_OPS_USE_PLATFORM_AUTH=1`
AND `CICC_PLATFORM_DB_URL` is set:

- `resolve_principal(Authorization)` verifies the bearer digest against the
  platform DB (own read-only engine, `pool_pre_ping`), enforces
  not-revoked / not-expired / active / known-role. **Fails closed on any
  error** (DB down → 401, never bypass). Raw tokens never logged.
- `read_allowed` / `write_allowed`: role allow-lists via env
  `CICC_OPS_READ_ROLES` (default `admin,analyst,viewer`),
  `CICC_OPS_WRITE_ROLES` (default `admin`).
- `ratelimit.read_token_dependency` / `require_write_token`: when platform auth
  is enabled they use the platform session gate; otherwise the existing static
  env-token gates (`CICC_OPS_READ_TOKEN` / `CICC_OPS_WRITE_TOKEN`, write ⊇ read).
  Both modes covered by tests (73/73 API suite).

Conformance tests use a **fixture DB mirroring the verified platform schema**
(labeled as such — not a live platform).

## 3. Remaining authorization gaps (honest list)

1. Ops-owned tables have **no `tenant_id`** — today ops data is global; a valid
   platform token from ANY tenant can read ops metrics. Acceptable only for a
   single-tenant deployment.
2. No per-tenant rate limiting on ops endpoints (current limiter is global).
3. No audit trail of ops reads/writes tied to platform `security_audit_events`.
4. Web proxy: `Authorization` header passes through Next rewrites unchanged —
   verified by design of `next.config` rewrites; add a regression test when
   platform auth is enabled end-to-end.
5. `CICC_OPS_READ/WRITE_TOKEN` static tokens remain as fallback for
   non-platform deployments (documented, single-tenant/dev only).

## 4. Safe implementation plan for tenant isolation (NOT yet executed)

1. **Additive columns** on ops tables (`tenant_id` nullable) via the same
   additive-only migration helper (`_ensure_*_columns`, inspector-based,
   PG+SQLite safe). Non-destructive; existing rows get NULL = "legacy/global".
2. **Write path**: when platform auth enabled, stamp `tenant_id` from the
   principal on writes (heartbeats, task runs, maintenance windows, alerts).
3. **Read path**: filter all ops queries by principal tenant; NULL rows
   visible only to a configured `CICC_OPS_LEGACY_TENANT_ID` (or admin).
4. **Per-tenant rate limit buckets** keyed by `tenant_id` (same pattern as the
   platform's `rate_limit_buckets`).
5. **Audit**: mirror ops write events into the platform `security_audit_events`
   via an adapter port (host-supplied), never importing platform code.
6. **RLS**: NOT used — SQLite has none and PG RLS would be a speculative
   shared-infra change; enforce in queries (fail-closed), escalate to owner
   before any DB-level RLS.

## 5. Open decisions (need owner / shared-contract approval)

- Does the ops DB live in the SAME database as the platform (shared
  `auth_sessions`), or a separate DB reached read-only? Current adapter assumes
  separate DB + read-only URL (`CICC_PLATFORM_DB_URL`).
- Which roles may read ops data in multi-tenant deployments?
- Should ops alerts/events be tenant-scoped or global (SRE-style)?
