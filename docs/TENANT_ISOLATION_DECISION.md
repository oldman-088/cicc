# Tenant Isolation — Decision Document (M11-05)

Status: **DECISION REQUIRED FROM OWNER**. Nothing here is implemented beyond
the inert, fail-closed platform-auth adapter. No speculative RLS. Outbound
notifications remain disabled.

## Verified platform contract (from `arena/da631853-cicc`, read-only)
`users.tenant_id`, `users.role` (admin/analyst/viewer), `users.active`,
`auth_sessions` (sha256 digests), `tenants`, `security_audit_events`,
`rate_limit_buckets`. Fail-closed authorize in the platform API.

## Options

| Model | What it means for CICC ops/coordination data | Migration | Trade-offs |
|---|---|---|---|
| A. Shared tables + app-level `tenant_id` filter on every query | One DB, filter in ops layer | Add `tenant_id` columns + backfill; every read/write path touched (risk of misses) | Simplest infra; weakest isolation (bug = cross-tenant leak); audit must log tenant per event |
| B. Schema-per-tenant (PostgreSQL schemas) | `SET search_path` per request after auth | New schema per tenant; migrations run per schema (tooling: use Alembic per-schema or search_path-aware runner) | Strong isolation; operational complexity; SQLite dev unaffected |
| C. Row-Level Security (PostgreSQL RLS) | Policies `USING (tenant_id = current_setting('app.tenant_id'))` | Enable RLS + policies + `SET LOCAL app.tenant_id` per transaction | Strong, DB-enforced; requires PG (not SQLite), careful with superuser/bypass roles, and migrations must not disable RLS |
| D. Separate database per tenant | Connection routing per tenant | Most ops (backups, migrations per tenant) | Strongest; highest cost; overkill at current scale |

## Recommendation
**B (schema-per-tenant) on PostgreSQL in production**, with A-style
`tenant_id` columns kept in every ops/coordination table so that:
- SQLite dev and tests keep working unchanged (filter is a no-op when
  `CICC_TENANT_ID` unset → single-tenant dev mode, fail-closed auth still applies);
- migrating to C (RLS) later is additive (policies enforce what the app already filters);
- the platform's `users.tenant_id` becomes the source of truth, mapped at the
  auth adapter boundary (`platform_auth.py`, currently inert).

## Security notes
- Never log raw tokens (already enforced; `check_no_secrets.sh`).
- Rate-limit buckets should be per (tenant, principal) once multi-tenant.
- Audit events must carry tenant_id; ops audit adapter into
  `security_audit_events` is backlog.
- Until the owner picks a model: the API runs single-tenant with token auth,
  and we do NOT claim tenant isolation is production-ready.

## What we need from the owner
1. Pick A/B/C/D (recommendation: B, with C as a later hardening step).
2. Confirm shared DB vs read-replica for platform auth (affects `CICC_PLATFORM_DB_URL`).
3. Approve the migration plan (additive columns first, backfill, enforce).
