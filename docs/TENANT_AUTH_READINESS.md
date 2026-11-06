# TENANT & AUTHORIZATION READINESS — proposal (M42, 2026-11-06)

Status: **PROPOSAL / PREPARATION ONLY**. Tenant isolation enforcement, platform
auth, and any shared auth/schema change are **owner-reserved** (see
TENANT_ISOLATION_DECISION.md). Nothing here is claimed as enforced. Current safe
behavior is implemented and tested (below).

## Server-side authentication contract (current, verified)

- API reads: `Authorization: Bearer $CICC_OPS_READ_TOKEN`; writes additionally
  require `$CICC_OPS_WRITE_TOKEN` (write implies read). Missing/invalid →
  401; authenticated-but-not-allowed → 403.
- Browser: BFF injects the token server-side (`API_INTERNAL_URL` +
  `WEB_BFF_API_TOKEN`); browser JS holds no token; web storage holds no
  secrets; write path via BFF is create-only `POST /api/v1/coordination/tasks`
  (domain invoke/mount/deregister verified blocked for browsers, 403).
- Webhook: HMAC signature, fail-closed when secret unset, delivery-id dedup.
- No raw tokens are ever logged; audit actor is the literal
  `api-write-token`/`api-read-token`, never the credential.

## Principal-to-tenant resolution (proposed)

1. Platform auth (owner-pending) issues a principal; map principal → tenant
   server-side at the BFF/API boundary. Never trust a client-supplied
   `tenant_id` as identity.
2. Current gateway behavior (implemented, tested): an optional `tenant_id` in
   an invoke body is recorded as a **`claimed_tenant` event marked
   "unverified claim"** — metadata only, no enforcement, no leakage. Missing
   tenant is safe (no claim event, request proceeds).
3. Domain handlers receive the task object and may read the claim for
   labeling only.

## Domain-level authorization (proposed)

- Per-domain ACL: which principals/roles may invoke/mount/deregister each
  kind; enforced at the gateway (write-token + role claim), not in the browser.
- Tenant-scoped status/stats: `GET /domains*` would filter by resolved tenant;
  until then these endpoints are global ops views gated by the read token and
  expose **no per-tenant fields** (tested).

## Cross-tenant access-denial tests (planned, blocked on enforcement)

- principal of tenant A invoking/mounting/reading tenant B's domain data →
  403 + audit event; B never sees A's tasks (`?tenant=` filter server-side).
- Currently: NOT enforceable (no platform auth) — explicitly BLOCKED on owner;
  safe fallback verified: no cross-tenant data exists in status/stats output.

## Auditability (implemented, tested)

- Sensitive ops (domain mount/deregister/invoke, approvals, webhook deliveries)
  write audit events (`coordination.domains` source, actor label only).
- All task transitions are append-only events (`coord_task_events`) visible via
  `/tasks/{id}/trace`.

## M44 note (2026-11-06T09:50Z)

Gateway observability (M44, `GET /api/v1/coordination/domains/metrics`) and
diagnostics are verified by tests to exclude tenant ids, tokens, and payload
values; metric labels are bounded to server-registered domain `kind` only.
Claimed-vs-authenticated distinction is unchanged (claimed_tenant trace event
remains UNVERIFIED; no isolation claims). Remaining cross-tenant enforcement,
audit-actor, and DB-access (RLS) requirements stay owner-reserved — see
"What requires owner approval" below.

## M45 note (2026-11-06T10:35Z)

Beta-readiness work changed nothing about tenant semantics: claimed tenant
ids remain UNVERIFIED claims (trace event only), no tenant-isolation claims are
made, and the M45 MVP trial verifies that tenant ids never appear in metrics,
diagnostics, alerts, or audit-derived views. Auth gating regression-tested
(401 no/wrong token; read token cannot invoke/mount; browser domain invoke
403 at the BFF). Cross-tenant enforcement, audit-actor, and DB-access (RLS)
requirements remain owner-reserved below.

## What requires owner approval

- Enabling platform auth / tenant resolution (shared infra).
- Any RLS/tenant column in shared models (schema change).
- Changing the BFF auth model.
