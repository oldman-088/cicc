# Internal MVP Trial Readiness Assessment (M32)

Scope: smallest safe end-to-end internal CICC trial with human-coordinated
workflow (RabbitMQ NOT a blocker; no broker claims).

## Satisfied prerequisites (evidence-backed)
- Coordination API operational: create/route/deliver(human-assisted)/ack/
  start/progress/complete/fail/cancel/retry/approve/reject/sweep — 225 API
  tests, 36 real-PG, guarded CAS transitions, lease recovery, dead-letter,
  append-only event audit; contract v1.0 self-describing + amendment
  governance (pending/accepted/rejected/withdrawn/superseded/stale, PG race
  tests, self-approval prohibited).
- BFF operational flow: read proxy + single approved write route
  (POST /api/v1/coordination/tasks) with server-injected tokens and
  idempotency key; VERIFIED live in shared sandbox env for both the reference
  dashboard (PR #4) and Backup Agent 4's component (PR #7 @ multiple heads,
  read-only re-verification by Agent 1).
- Health & trace visibility: `GET /coordination/health` (component statuses +
  actionable reasons + last_operations, explicitly on-demand), `GET
  /tasks/{id}/trace` (correlation, events, deliveries, approvals), dashboard
  health panel. Live VERIFIED via BFF.
- Contract compatibility & governance: wire-pin tests (contract descriptor ==
  implementation), amendments with compat validation, effective version.

## Blocked / not satisfied (owner decisions or missing infra)
- AMD-001 acceptance (owner); Agents 2/6 explicit ACCEPTs (TI adoption).
- Tenant isolation/RLS, platform auth, notifications, prod credentials —
  owner-reserved; design-only docs this milestone.
- Broker-backed delivery (no Docker/RabbitMQ in sandbox) — human-assisted
  path is honest and labeled; not claimed as broker delivery.
- Continuous monitoring — no scheduler runtime exists; on-demand only.

## Smallest safe trial
1. Run API + reference dashboard with fixture tokens in the sandbox (already
   VERIFIED live: contract 31/31, e2e 24/24).
2. Drive a scripted lifecycle via BFF (create → route → ack → start →
   progress → complete; failure/retry path; approval path) — covered by
   `scripts/e2e_check.py` (24/24).
3. Inspect health + trace endpoints for degraded reasons.
4. Record evidence with sandbox labels; no production claims.
