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
| Coordination writes | All coordination POST endpoints now require write token AND per-principal sliding-window rate limit (sha256-keyed, 429), incl. programmatic `POST /tasks` (strict field validation: kind charset, priority range, path-safe task_id, payload size via 16 KiB cap) | test_coordination_writes_rate_limited, test_create_task_validation |
| Notifications | Disabled adapter only; no network code path; suppression events logged | test_notifications_never_send |
| Delivery honesty | DELIVERING only after publisher confirm on a real broker; human-assisted records say "published", task stays QUEUED | test_handoff_broker_failure_falls_back |
| DB changes | Additive-only migrations (inspector-based ADD COLUMN), no destructive ops; retention deletes only ops-owned tables | test_retention_purge_only_old_rows |

## Findings & dispositions

1. **Webhook has no read-token gate** (by design — GitHub sends none): mitigated by HMAC + allowlist + size cap + fail-closed. Accepted.
2. **Static env tokens are bearer secrets in dev mode**: documented as single-tenant/dev only; platform auth is the production path (adapter ready, inert until `CICC_OPS_USE_PLATFORM_AUTH=1` + `CICC_PLATFORM_DB_URL` verified). Tenant scoping NOT claimed complete — see TENANT_ISOLATION_PLAN.md (owner decision pending).
3. **GitHub API polling uses env GH_TOKEN if present**: header-only, rate-limit aware (stops <5 remaining), circuit breaker. Accepted.
4. **Coordination write endpoints trust the network when no write token set** (dev mode): same posture as ops API, documented in contracts; production must set tokens. Accepted with documentation.
5. **Webhook secret rotation** (M9): dual-secret verification — `CICC_GH_WEBHOOK_SECRET` (current) + `CICC_GH_WEBHOOK_SECRET_PREVIOUS` (grace); either signature accepted, wrong secrets still 401, unset both = fail closed. Rotation procedure: (1) set PREVIOUS=<old>, SECRET=<new> and restart; (2) update the secret in GitHub webhook settings; (3) verify deliveries pass; (4) remove PREVIOUS. Tests: test_rotation_old_secret_accepted_during_grace, test_rotation_wrong_secret_rejected.
6. **Retry backoff** (M9): `CICC_COORD_RETRY_BACKOFF_S` (default 30) exponential `base*2^(attempts-1)` capped 1h, stored as `next_retry_at`; sweep requeues only after backoff elapses. Prevents hot retry loops.
7. **No CSRF surface**: API is bearer-token based, no cookies; web dashboard calls same-origin relative URLs only. Accepted.

## M11 updates
- Deliver with unmet `depends_on` now returns **409** (was 200 with
  `delivered:false`) — clearer contract, audited `delivery_blocked_deps`.
- GitHub API calls: transient retry (5xx/429/timeout only), pagination cap,
  full-body reads, rate-limit guard (<5 remaining aborts), token header-only.
- Tenant isolation: decision document `docs/TENANT_ISOLATION_DECISION.md`
  (options A–D, recommendation B schema-per-tenant with additive tenant_id
  columns; **awaiting owner decision — not claimed production-ready**).

## M12-06 review (2026-11-05)
Re-checked: authn (read/write tokens, write⊇read, platform adapter inert+fail-closed),
authz (approver gate 403, per-endpoint gates), rate limits (global 429 + per-principal
write 429 on ALL coordination writes), audit (every transition incl. rejected),
secret redaction (webhook payloads, GH token header-only, `check_no_secrets.sh`),
body caps (16 KiB API / 256 KiB webhook), replay (delivery-id dedup + dual-secret
rotation). Cross-tenant access boundary: **single-tenant token mode only** — tenant
isolation is a documented decision pending owner approval
(`docs/TENANT_ISOLATION_DECISION.md`); NOT claimed production-ready. Outbound
notifications remain DISABLED (no network path in adapters).

### Unresolved security decisions (owner)
1. Tenant isolation model (A/B/C/D in the decision doc; recommendation B).
2. Shared DB vs read-replica for platform auth (`CICC_PLATFORM_DB_URL`).
3. Webhook delivery timestamp freshness (GitHub sends no signed timestamp — evaluate).
4. Ops audit adapter into platform `security_audit_events`.
5. Outbound notification channels (require explicit authorization).

## Open security work (backlog)
- Tenant-scoped ops data + per-tenant rate buckets (awaiting DB-model decision).
- Webhook secret rotation procedure.
- Ops audit adapter into platform `security_audit_events`.
- Optional: webhook timestamp freshness check (tolerance window) to further harden replay.
