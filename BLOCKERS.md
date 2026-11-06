# BLOCKERS — consolidated (Agent 1 view, 2026-11-05)

Owner decisions required:
1. Tenant-isolation architecture (options + recommendation: docs/TENANT_ISOLATION_DECISION.md). Blocks: platform-auth enablement, any multi-tenant exposure, DoD "tenant isolation tested".
2. Platform auth enablement (CICC_OPS_USE_PLATFORM_AUTH=1 + CICC_PLATFORM_DB_URL; shared DB vs read-replica).
3. Outbound notification channels authorization (adapters disabled, no network path).
4. RabbitMQ as release requirement? (currently deprioritized per owner M13-05/M15-05).

Environment-blocked here:
- Real RabbitMQ broker verification (no Docker; egress allowlist) — run `VERIFY_RABBITMQ=1 bash scripts/validate_compose.sh` where Docker exists; attach evidence to PR #4.

External dependencies:
- Explicit contract v1.0 confirmations from Agents 2/3/4 (PR #4 comments, issue #5) — all PENDING as of 2026-11-05; silence not treated as acceptance (docs/CONTRACT_ADOPTION.md).
- Agent 4 visual QA sign-off (desktop/mobile, EN/AR RTL, states) — requested, pending.

## M47 refreshed blockers (2026-11-06 13:22 UTC; supersedes older head/ownership notes above)

- **Security / Beta P0:** no verified production principal/auth contract propagated into tenant-scoped API and domain operations; current Ops token gates are optional, not user identity. No enforced tenant boundary, actor-specific data pools/roles, RLS, or cross-tenant acceptance suite. Owner/security/DB decision and executable tests are required before sensitive or multi-tenant Beta.
- **Schema/release:** no versioned migration mechanism in this checkout; `create_all` is startup bootstrap. AMD-003 remains pending. No proposed shared schema SQL is applied.
- **Agent 2 TI:** PR #3 is OPEN/Draft at `7136538f74ab08b33607774c507785fc0c59cd03`, and the PR #3 tree now contains an Agent 2 TI handover plus Replacement Agent 3 VI work. Handover says its standalone relationship host is unmounted, principal/DB/audit callbacks are not supplied, actual-host tests are 0 executed / 8 skipped, and no security/schema/host approval is present. Agent 1's existing TI adapter is for a different legacy simulated dispatcher. Need explicit owner/source revision and approved host contract; do not mount unilaterally.
- **Replacement Agent 3 VI:** current branch/entry point is not proven compatible with Agent 1's legacy VI adapter. Need explicit owner-approved module/tree/API/payload/source-of-record plus real host acceptance; no PR branch modifications by Agent 1.
- **Agent 4 UI:** PR #2 is OPEN at `e745cc2b8ff995b040896212eab2995607c48963`; its own code calls the lifecycle/error/diagnostic decoder candidate, but the checked-out Agent 1 frontend does not call the domain routes. No Agent 4 approval; PR #2 description includes stale older heads and must be refreshed before integration.
- **Exact app/CI:** PR #4 had no checks at pre-publication HEAD `4a797f480377bc94fa8eec56ae692a8fc337db5d`; no Agent 1 CI run is claimed. M47 no-manifest preflight exited 2/BLOCKED before starting an API because PR #1/#3 are open and no owner-approved manifest/tenant driver exists. Do not label branch tests as merged-app or production evidence.
- **RabbitMQ / delivery:** no broker was verified in this environment. This is not a blocker for the human-assisted workflow; broker-confirmed delivery is a separate acceptance and revisit autonomous delivery when background coordination is required.
- **Notifications / product scope:** outbound notification adapters remain disabled pending owner authorization; 3D command theater, full source coverage and whole-product Beta remain outside this Agent 1 handover and must not be represented as delivered.

Latest other-branch heads for read-only tracking: PR #1 `a942baabc3260683ec1a2b8c9d953c04dceaae9a`, PR #2 `e745cc2b8ff995b040896212eab2995607c48963`, PR #3 `7136538f74ab08b33607774c507785fc0c59cd03`, PR #6 `02616bb5a34bc0dfa6beaee598948b09b7ba1127`; refresh before any integration decision. No owner response or approval is inferred from these heads or their CI runs.
