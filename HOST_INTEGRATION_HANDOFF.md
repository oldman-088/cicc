# Agent 1 / Agent 2 host integration handoff — proposed, not approved

## Actual interface reviewed
Read-only inspection of Agent 1 PR #4 head `752dc99ececef934fef2d699aae571502639bc1f`: `apps/api/app/coordination/domains.py` registers a `handle(payload, task) -> {result, provenance}` callable using `register_domain`; it invokes with retries and a per-attempt timeout using a worker thread. Its existing `domain_adapters/threat_intel_adapter.py` instantiates Agent 2's legacy `ThreatIntelligenceAPI`, not the P2-01 router. The adapter maps response-generation time to freshness and legacy confidence 1.0; neither establishes intelligence freshness or confidence. The host does not yet mount Agent 2's current router in the reviewed code. A gateway timeout cannot be assumed to cancel an already-running worker; idempotency is necessary but does not itself prevent late side effects.

## Changes and ownership to agree
| Change | Proposed owner | Status |
| --- | --- | --- |
| Establish approved tenant model, trusted principal-to-tenant and permissions binding, trusted correlation and idempotency propagation | Agent 1 / project owner | Pending; never trust client tenant fields |
| Decide whether gateway handler invokes a mounted ASGI router or a shared service directly; choose authorized path and `handle(payload, task)` mapping, response/errors, retries and timeouts | Agent 1 with Agent 2 | Pending; do not invent gateway→router semantics or assume HTTP mount |
| Mount `apps.threat_intelligence.relationship_api.router` at approved host prefix; provide verified `get_principal`, store and audit dependencies, safe error handlers | Agent 1, coordinated with Agent 2 | Pending; no shared host files changed |
| Approve/own migration sequencing, database roles, schema grants/search path, RLS policies and security model, audit retention and independent security event sink | Agent 1 / project owner / database owner | Pending; proposal in Agent 2 branch only |
| Adapt relationship service and migration proposals to approved contracts; unit, ASGI, SQL and security tests | Agent 2 | Independent implementation in PR #3 |
| BFF/frontend read/write contracts and UI | Agent 4 after Agent 1/owner approval | Pending; browser write boundary remains create-only POST `/api/v1/coordination/tasks` |

## Reproducible verification gates
1. Current independent test: `CICC_TEST_PG_EMBEDDED=1 /home/user/.venv-cicc-pg/bin/python -m pytest -q apps/threat_intelligence/tests/test_relationship_postgres.py apps/threat_intelligence/tests/test_relationship_rls.py --disable-warnings`. This verifies actual standalone ASGI → injected trusted fixture principal → isolated PostgreSQL → audit → response, **not the real gateway**.
2. Once Agent 1 publishes an approved test host and identity binding, add an end-to-end test in the agreed integration environment that mounts the actual domain, creates a gateway task with a test principal and stable idempotency key, invokes through the actual registered adapter, then verifies response provenance/label, the tenant-scoped persisted record and correlated committed audit event. Exercise missing authentication, forbidden operation, forged tenant input, other-tenant record/traversal/audit, failure/timeout/retry and audit rollback. Use explicit local fixtures and approved isolated schema only; do not assert host integration based on a simulated gateway.
3. Verify frontend access only through the approved BFF → gateway → domain path; no browser domain invocation or invented read route. Agent 4 must await the approved DTO and identity semantics.

The proposed `cicc.tenant_id` RLS GUC is mutable by the application DB role and cannot authenticate a tenant; review the threat model in `THREAT_RELATIONSHIP_API_CONTRACT.md`. This proposal is not a substitute for owner-approved DB identity and actual host integration testing.
