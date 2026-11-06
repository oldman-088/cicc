# P2-01 and intelligence assessment progress — 2026-11-06

## Implemented and security scope
- Preserved GUC-based RLS and pooling protections. Added an independent role-bound RLS alternative: per-tenant PostgreSQL `session_user` mapping, protected security-definer lookup, policies, role/context checks and separate forward/rollback SQL proposals. Eleven local PostgreSQL tests cover arbitrary GUC attempts, cross-tenant reads/writes/traversal/audit, role/mapping/DDL denial, pool reuse, rollback, concurrent calls, wrong/additional policies and audit rollback. **No shared migration or role was changed.**
- This alternative assumes unique authenticated tenant DB logins, secure role/mapping/function/schema ownership and pool routing. Tests demonstrate that a role with audit INSERT can forge audit records for its own tenant. Owners, BYPASSRLS, compromised credentials/memberships and shared server-side logins remain critical risks. It is a local proposal, not verified production tenant isolation; see `ROLE_BOUND_TENANT_SECURITY_PROPOSAL.md`.
- Added explicit caller-defined evidence collection-age classification, preserving timestamps and provenance without inventing freshness thresholds; future timestamps are flagged. Added confidence boundary/rounding tests. Scores still require analyst inputs, withhold on conflict/insufficiency, and are experimental—not calibrated or verified. See `INTELLIGENCE_ASSESSMENT_CONTRACT.md`.
- Maintained the five prepared Agent 1 actual-host acceptance cases and added a sixth pool-reuse case. All remain skipped until an approved isolated actual host and owner-supplied harness exist. Reviewed Agent 1 PR #4 at `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26`: its tenant claim is unverified and legacy adapter does not invoke this router. See `HOST_INTEGRATION_HANDOFF.md`.

## Executed and skipped tests (categories overlap)
- Standalone ASGI: **10 passed**; fixture identities, not actual host.
- Isolated PostgreSQL integration: **34 passed** (11 store + 12 GUC RLS + 11 role-bound RLS). Includes standalone ASGI calls, separate DB role logins and explicit audit-forgery demonstration.
- Offline assessment: **13 passed** (6 observation/temporal + 7 confidence tests).
- Actual Agent 1 host acceptance: **6 skipped, 0 run**; live provider ingestion: **0 run**.
- Full isolated run: `CICC_TEST_PG_EMBEDDED=1 /home/user/.venv-cicc-pg/bin/python -m pytest -q --disable-warnings` → **154 passed, 6 skipped**. Default run: `venv/bin/python -m pytest -q --disable-warnings` → **120 passed, 40 skipped**.

## Master Prompt alignment
- `/home/user/cicc/README.md`, *ULTIMATE MASTER PROMPT v1.0*, reviewed at commit `ca8f82c0500637e22851d7128cddf99081ef3c08`; working file hash matches commit. Agent 2 responsibilities: Domain B 10–24, D 34–43, F 51–59, G 60–69 and Sections 6, 7, 8 and 10.
- Completed in narrow scope: experimental relationship API, standalone PostgreSQL/audit store, local RLS proposals/tests and explicit-input assessment. Not whole-product completion.
- Partial: shared graph, provenance, tenant isolation design, confidence and collection-time analysis, conflict preservation, source parsing and security foundations. Tenant role model and assessment policy are not owner-approved or calibrated.
- Unimplemented/unverified: actual gateway→router host execution, trusted host principal/tenant and database pool binding, production authorization/RLS and tamper-resistant audit, approved migrations, temporal validity, automatic conflict resolution, live provider ingestion, AI and broad investigation/organizational capabilities.
- Deviations: separate migration proposals and explicit analyst-supplied values rather than shared schema changes or invented confidence/reliability. Role-bound model is an alternative to the untrusted GUC, not an approved platform design. No evidence supports a whole-product completion percentage.
- Blockers/owner decisions: Agent 1/owner gateway and host contract, principal identity, per-tenant credentials/pool design, database role and schema governance, trusted audit, timeout/retry semantics, AMD-003 and frontend read contract. No real host approval/harness received.
- Next: agree and test actual gateway/host with the prepared suite; review role-bound and controlled-entry-point alternatives with owners; secure in-tenant authorization and audit, expand temporal/conflict semantics, and verify authorized live sources separately.
