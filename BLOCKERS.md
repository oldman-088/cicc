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
