# M45 — AMD-003 implementation plan (PRECISE, REVERSIBLE; approval still PENDING)

Status: AMD-003 remains **PENDING — owner-reserved**. Nothing in this plan has
been applied as a shared-contract change. The gateway implementation on
`arena/961971ed-cicc` (PR #4) runs under Agent 1 autonomous authority and is
fully reversible (single branch; revert = drop the M37–M45 commits). This
document identifies the exact approval required and the exact shared changes
it would authorize.

## Exact approval required (one owner decision on AMD-003)

Approve AMD-003 as written in `docs/AMD003_DOMAIN_LIFECYCLE.md`, i.e.:

1. The shared coordination API surface: `GET /api/v1/coordination/domains`,
   `GET /domains/{kind}/status`, `GET /domains/metrics` (M44, read-only),
   `POST /domains/{kind}/mount|deregister|invoke` (write-token gated), and the
   extended `GET /health` `components[]` `domains` entry — all **additive** to
   the existing contract descriptor (`apps/api/app/coordination/contract.py`).
2. Write-token gating of mount/deregister/invoke (security-sensitive: mounting
   executes code paths).
3. The `coord_domain_stats` table (additive, already created on PR #4) and the
   proposed M45 beta extension below.

## Current state on PR #4 (implemented, tested, reversible — NOT approved)

- Domain registry + gateway invoke with timeout/retries (same idempotency key),
  sanitized errors (type names removed in M45), payload caps (16 KiB middleware
  + 64 KiB router), circuit breaker (process-local fail-safe; transitions
  persisted as audit events in M45), alert wiring (`domain_status` rule with
  history via `/api/v1/ops/alerts/history`), mount history (`mount_count`
  process-local + `mounts_total` persisted audit count), M44 metrics
  (`labels=["kind"]`, no tenant/token/payload data), M45 `last_success_at`.
- Persistence without schema change: `coord_domain_stats` rows
  (invokes/successes/consecutive_failures/last_*), `events` audit rows
  (mount/deregister/invoke/circuit transitions/api start-stop), `alerts` rows.
  Startup (lifespan) restores persisted stats for ALL kinds so health/metrics
  are correct immediately after a restart.

## Proposed shared DB change for controlled beta (the only reserved schema item)

Additive columns on `coord_domain_stats` (or one JSON `extra` column) to make
the fine-grained M44 counters restart-persistent — currently they are
documented process-local (latency aggregates, timeouts, retries, stale/skew
counts, circuit opens/closes, mount_count, last_success_at). Proposed:

```sql
ALTER TABLE coord_domain_stats ADD COLUMN extra_json TEXT NULL;  -- preferred (no per-counter DDL)
-- backfill: extra_json = '{}' for existing rows; rollback: drop the column / ignore it
```

Read path: merge `extra_json` into `_STATS` on startup (same volatile-carry
merge as M45). Write path: `_persist_domain_stats` serializes the process-local
counters into `extra_json`. Bounded, sanitized content only (numbers + kind;
never tenant ids/tokens/payloads).

Reversible: additive nullable column; readers tolerate NULL; rollback = stop
writing it (no data loss) or `ALTER TABLE ... DROP COLUMN`.

Not a beta prerequisite: M45 keeps these counters process-local with the
limitation documented in `DOMAIN_STATUS_CONTRACT.md`; the persisted
invokes/successes/consecutive_failures + audit events + alerts already cover
operational recovery.

## Lifecycle / registration flow (as implemented on PR #4)

`POST /domains/{kind}/mount` (write token) → read-only module import
(`load_handler_from_module`, no file modification) → validate handler contract
→ register → audit event + persisted stats → status MOUNTED/AVAILABLE →
first successful invoke → EXECUTION_VERIFIED (task + trace + provenance
persisted) → failures → DEGRADED/FAILED + `domain_status` alert + circuit
breaker after threshold → recovery → EXECUTION_VERIFIED + alert resolved.
Deregister → NOT_MOUNTED (honest). Unknown kind → NOT_MOUNTED with zeroed
evidence (200, not an error).

## Executable verification (no shared changes needed)

- `apps/api/tests/test_m45_beta_readiness.py` (7/7): restart recovery,
  persisted circuit-transition audit, mounts_total persistence, auth/tenant
  boundaries, error isolation/sanitization, lifespan events.
- `scripts/m45_mvp_beta_trial.py --manage-api` **26/26 @ 2026-11-06T10:33:17Z**
  (SANDBOX/FIXTURE + SANDBOX/UNMERGED-BRANCH): 11 acceptance items incl. real
  PR-head TI (`f3d3a7f`) and VI (`f8e96c7`) modules invoked through the gateway
  and a SIGKILL restart-recovery pass.
- Full suites on PR #4 @ M45: API 282/282, PG 42/42, web 35/35, contract 31/31.

## What remains blocked on owner decisions (not code)

- AMD-003 approval (above) — unlocks treating the gateway surface as the
  shared contract and the `coord_domain_stats` extension.
- Real mounts of TI/VI in a merged application: PR #3 (`f3d3a7f`) and PR #1
  (`f8e96c7`, with PR #8 `3bc6527` merged into its branch 09:33Z) are NOT on
  main (`ca8f82c`) yet — mounts today are SANDBOX/UNMERGED-BRANCH only.
- Tenant enforcement (RLS/roles), platform auth, RabbitMQ live verification,
  outbound notifications — all owner-reserved; see TENANT_AUTH_READINESS.md.

## M46 readiness overlay (AMD-003 still PENDING)

M46 adds only independent operational behavior: breaker reset on handler remount
/ deregister, a process-local single half-open probe with cooldown re-arming on
probe failure, and an acknowledged-alert reactivation lifecycle. It makes no
`coord_domain_stats` DDL change, adds no shared endpoint/DTO field, and does not
require AMD-003 approval. The proposed `extra_json` persistence extension above
remains unapplied and is not a prerequisite for these tests.

`test_m46_ops_reliability.py` (9/9), `test_m46_acceptance_gate.py` (4/4), and
full API 295/295 + PG 42/42 verify these independent paths. M46 also keeps
process-local metric counters intact when a persisted row has the same invoke
count; the M44 live trial is rerunnable after remount on a non-empty DB. The
repeatable `scripts/m46_merged_app_acceptance.py` gate verifies exact PR
merge-result commit reachability from a queried main SHA before any merged-app
mount. At 2026-11-06T12:26:21Z, main was
`ca8f82c0500637e22851d7128cddf99081ef3c08`; PR #1 at
`78f869b82f5262ab4cacfb996847173274c259ef` and PR #3 at
`5fec62ef39ab66e6fe36ccc483b302eddb7c5a38` were open/unmerged, so the
MERGED-APPLICATION phase was **NOT RUN**. The separate M45 trial at 12:25Z used
those exact branch heads through the sandbox gateway only; it is not merged-app
or production evidence. AMD-003 remains owner-reserved; no shared changes applied.
