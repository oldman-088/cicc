# Security Review — Coordination + Ops subsystem (M8)

Scope: `apps/api/app/coordination/*`, `apps/api/app/{ratelimit,platform_auth,notifications,checks}.py`, webhook handling, token handling. Reviewed 2026-11-04 against the mandate's security list.

## Controls implemented (with tests)

| Area | Control | Evidence |
|---|---|---|
| Webhook auth | HMAC sha256 (`X-Hub-Signature-256`), constant-time compare, fail-closed 401 when `CICC_GH_WEBHOOK_SECRET` unset | test_webhook_bad_signature_rejected, test_webhook_fail_closed_without_secret |
| Replay protection | `X-GitHub-Delivery` primary key in `coord_github_events`; duplicates acknowledged, not reprocessed | test_webhook_replay_dedup |
| Event allowlist | Only allowlisted event types create tasks; others recorded only; 256 KiB cap (413); JSON-object validation | test_non_allowlisted_event_recorded_not_tasked |
| Secret redaction | Normalized payloads stripped of token/authorization/secret/password keys; GitHub token used only as request header to api.github.com, never logged/returned (test asserts absence from responses) | test_webhook_ingest…, test_github_sync_… |
| Auth gates | Read token on all reads; write token on writes; write⊇read; platform-auth adapter inert unless enabled, fail-closed, role allow-lists | test_write_token_also_satisfies_read, test_platform_auth_* |
| Rate limiting | Global sliding window (429) + per-principal write limiter keyed by sha256(bearer) | test_keyed_write_rate_limit |
| Body size | 16 KiB API cap (413) + 256 KiB webhook cap | existing + M7 tests |
| Audit integrity | Every coordination transition (incl. rejected ones) recorded in coord_task_events; approvals in coord_approvals; ops events in events | lifecycle/approval tests |
| Notifications | Disabled adapter only; no network code path; suppression events logged | test_notifications_never_send |
| Delivery honesty | DELIVERING only after publisher confirm on a real broker; human-assisted records say "published", task stays QUEUED | test_handoff_broker_failure_falls_back |
| DB changes | Additive-only migrations (inspector-based ADD COLUMN), no destructive ops; retention deletes only ops-owned tables | test_retention_purge_only_old_rows |

## Findings & dispositions

1. **Webhook has no read-token gate** (by design — GitHub sends none): mitigated by HMAC + allowlist + size cap + fail-closed. Accepted.
2. **Static env tokens are bearer secrets in dev mode**: documented as single-tenant/dev only; platform auth is the production path (adapter ready, inert until `CICC_OPS_USE_PLATFORM_AUTH=1` + `CICC_PLATFORM_DB_URL` verified). Tenant scoping NOT claimed complete — see TENANT_ISOLATION_PLAN.md (owner decision pending).
3. **GitHub API polling uses env GH_TOKEN if present**: header-only, rate-limit aware (stops <5 remaining), circuit breaker. Accepted.
4. **Coordination write endpoints trust the network when no write token set** (dev mode): same posture as ops API, documented in contracts; production must set tokens. Accepted with documentation.
5. **No CSRF surface**: API is bearer-token based, no cookies; web dashboard calls same-origin relative URLs only. Accepted.

## Open security work (backlog)
- Tenant-scoped ops data + per-tenant rate buckets (awaiting DB-model decision).
- Webhook secret rotation procedure.
- Ops audit adapter into platform `security_audit_events`.
- Optional: webhook timestamp freshness check (tolerance window) to further harden replay.
