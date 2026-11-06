# AMD-003 — Domain lifecycle & evidence-based health (PROPOSED 2026-11-06, PENDING — owner-reserved)

Status: implemented under Agent 1 autonomous authority; **NOT treated as approved**.

## Requires OWNER approval (shared-contract / security-sensitive)
1. New HTTP endpoints on the shared coordination API: `GET /domains/{kind}/status`,
   `POST /domains/{kind}/mount`, `POST /domains/{kind}/deregister`, and the extended
   `GET /domains` / `GET /health` shapes (contract descriptor changed — additive only).
2. Write-token-gated mount/deregister (security-sensitive: mounting code paths).
3. `coord_domain_stats` table in the shared models (additive).

## Does NOT require owner approval (internal to Agent 1)
- In-memory registry/stats logic, retry/timeout implementation, state-chain bug fix,
  sanitized error handling, unit tests, docs.

Pending AMD-003 does not block unrelated implementation/testing (per directive §6).
