# Security Prerequisites — Design & Inert Scaffolding (M32)

Status: **DESIGN ONLY — nothing activated**. Tenant isolation/RLS, platform
authentication, notifications, and production credentials remain owner-reserved
decisions (see `docs/TENANT_ISOLATION_DECISION.md`). This document prepares
safe implementation paths without weakening any current control.

## 1. Tenant isolation / PostgreSQL RLS
- Current state: single-tenant deployment assumption is explicit
  (`CICC_OPS_TRUSTED_SINGLE_TENANT=true` is required by BFF write paths);
  fail-closed elsewhere (see verified platform-auth contract on
  `origin/arena/da631853-cicc` apps/api — adapter inert).
- Design path (NOT implemented): per-tenant `tenant_id` column on all
  coordination tables; `SET LOCAL row_security` / RLS policies keyed on a
  session `app.tenant_id` set by the platform auth layer; migration behind an
  owner-approved flag; tests only against a verified platform contract.
- Inert scaffolding now: `docs/TENANT_ISOLATION_DECISION.md` records options;
  no RLS policies exist; no tenant columns added. **No speculative RLS.**

## 2. Platform authentication & authorization
- Boundary: API coordination endpoints use static ops tokens
  (`CICC_OPS_READ_TOKEN`/`CICC_OPS_WRITE_TOKEN`); BFF holds server-only tokens
  (`WEB_BFF_API_TOKEN`, `WEB_BFF_WRITE_TOKEN`) and injects them server-side.
- Design path: replace static tokens with platform-issued JWTs verified
  fail-closed at the API edge; per-endpoint scopes; BFF exchanges browser
  session for a short-lived downstream token. Requires the verified platform
  contract before any code activates.
- Current enforcement (VERIFIED by tests): read/write token gates, approver
  gate for approvals + amendment decisions, self-approval prohibition, BFF
  fixed-route write allowlist, header stripping, same-origin enforcement,
  body size caps, sanitized errors.

## 3. Replay protection
- Webhook: GitHub sends no signed timestamp — HMAC signature verification is
  detection/alerting only; duplicates are deduped by delivery id
  (DB-enforced, PG-tested). Detection ≠ rejection; documented.
- Task submission: idempotency_key dedup at DB level (unique constraint +
  guarded replay → `duplicate_idempotency_key` event). BFF generates
  `bff-<uuid>` server-side per request.
- Not claimed: cryptographic replay protection for arbitrary clients.

## 4. Notifications & production credentials
- Outbound notifications remain disabled pending owner authorization.
- No secrets in repo/logs; `.env.example` documents required env vars only;
  fixture tokens used in all sandbox evidence and labeled as such.

## 5. Test posture
- All security-relevant behavior is pinned by unit + PG concurrency tests
  (36 PG tests). Any future RLS/platform-auth change must add tests against
  the verified platform contract before activation.
