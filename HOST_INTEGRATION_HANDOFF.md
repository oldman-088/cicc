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

## Prepared executable host suite (not run)

`apps/threat_intelligence/tests/host_integration/test_agent1_gateway_contract.py` is an opt-in acceptance suite, not an implementation of the Agent 1 host or a claim of integration. It currently skips because no approved host/identity/test adapter is available. A jointly developed, owner-approved test harness module supplies the actual transport, isolated identity fixtures, database audit inspection and fault injection; no host URL or credential is hard-coded or printed. Only enable in an explicitly isolated, authorized environment:

```
CICC_TI_HOST_ISOLATED=1 CICC_TI_HOST_TEST_HARNESS=<approved_python_module> \
  python -m pytest -q apps/threat_intelligence/tests/host_integration/test_agent1_gateway_contract.py
```

Harness module interface for **test tooling only**: `build_harness()` returns an object with `assert_isolated_actual_host()`, `close()`, fixture identities `tenant_a`, `tenant_b`, `unauthenticated`, tenant identifiers `tenant_a_id` and `tenant_b_id`; `create(identity, payload, key)`, `get(identity, relationship_id)`, `traverse(identity, entity_type, entity_id)` return objects with `status`, `body`, `gateway_task_id`, `correlation_id`; `read_audit(identity, correlation_id)` returns a tenant-scoped audit row or `None`; `find_by_idempotency_key(identity,key)` uses isolated DB inspection; `fail_next_relationship_audit()` is a context manager that injects a failure only in the disposable test environment. The harness must demonstrate that calls traverse the **actual** gateway and mounted Agent 2 router; mock-only implementations must not be used to claim this test category. The provisional suite expects the standalone route's 201/200/401/404/409/422 and rollback semantics; reconcile them with approved gateway error mapping and identity policy before use. It tests successful task/correlation/record/audit, missing authentication, forged input, cross-tenant record/traversal/audit, replay/conflict and injected audit rollback.

Agent 1 PR #4 head `f96037b00f03018d6bca6c11cfd1bec407cdf7fa`, `docs/TENANT_AUTH_READINESS.md`: current token actors are shared read/write labels, request-body `tenant_id` is explicitly an **unverified claim**, and principal-to-tenant mapping remains an owner-reserved proposal. The adapter at that head still passes the payload's claim into the legacy dispatcher. It must not be promoted into an authenticated tenant context. Shared migrations, platform auth and BFF auth changes are owner-reserved; the actual host gateway-to-router path remains pending.

The host acceptance suite now also defines `verify_pool_reuse_isolation()` on the owner-supplied test harness. It must exercise actual host requests through reused pooled connections in an isolated deployment and return `reused_backend_observed`, `same_tenant_access_preserved`, `cross_tenant_access_denied`, and `transaction_rollback_isolated`; it must not fabricate these observations. This sixth acceptance test remains skipped until the approved real host/harness exists. With per-tenant DB logins, reuse must not imply using one authenticated server login for multiple tenants.

Agent 1 PR #4 head `6c2c2a1fa2904b0ee13263421674ed22fe8e9d26` still documents tenant claim as unverified and its legacy adapter remains separate from this router. `ROLE_BOUND_TENANT_SECURITY_PROPOSAL.md` provides an alternative per-tenant-login/RLS design and residual audit risk for owner review; it is not an agreed production connection model. Host owners must choose identity, credential/pool, policy, migration and audit designs before executing the acceptance suite.


Agent 2 now has a separately injectable controlled create/get/list/traversal store and `host_adapter.create_host_application` ASGI binding; see `TRUSTED_RELATIONSHIP_WRITES.md`. The real host must decide how verified actor/tenant identity maps to database login pools, authorize role grants and migration, and bind gateway task/trace to the database-generated correlation ID. All four operations emit atomic DB-derived audit events, including traversal not-found and bounded-limit outcomes. Existing Agent 1 gateway and host have not executed this implementation.


## Six recommended decisions for the actual beta host (owner review)
Agent 1 head `2ef50e77a429fed35b8cc3991301608e9537d313` still marks body tenant as unverified and uses the legacy simulated adapter, not the relationship router. No actual host integration has been demonstrated.

| Decision | Recommendation and consequence | Beta blocker? |
| --- | --- | --- |
| Verified principal and tenant | Host maps verified user/service credentials server-side to tenant and explicit `threat:read`/`threat:write`; never use body `tenant_id`. Shared platform auth is owner-reserved. | Yes |
| Database identity and pooling | Provision separate per-actor/tenant authenticated DB login pools; grant only allowed function EXECUTEs; never switch tenants through a mutable GUC or transaction pool using one server login. Higher credential/pool operational cost; perform actual host pool-reuse tests. | Yes |
| Gateway invocation | Mount the actual Agent 2 router under approved host auth or use an approved direct service handler; preserve task ID separately and link it server-side to DB-generated correlation. Specify retry/timeout and late-write/idempotency handling. Shared contract is owner-reserved. | Yes |
| Schema and roles | Owner reviews/applies ordered P2-01 SQL proposals and P2-02 KEV proposal, owner ownership, operation grants, rollback and retention; no startup auto-migration. Destructive KEV rollback requires backup. | Yes |
| Security audit and trace | Keep atomic DB success/not-found/limit audit; host independently logs auth/validation/denial/failure, correlates gateway task and DB ID, and exports append-only events to an independently protected sink. Privileged admins can modify DB history without external controls. | Yes |
| Frontend and scheduling | Agent 4 gets approved read-only DTOs only after host authentication and BFF read routes are approved; browser writes remain task-create only. Agent 1 owns scheduling the one-shot KEV worker, secret/role provisioning and alerting; no browser or untrusted request can invoke the collector. | Yes for advertised frontend/feed beta |

Agent 2-owned DTOs in `relationship_api.py`: list response `{items,total,offset,limit,has_more}`, traversal `{entity_id,entity_type,max_depth,visited_entities,items:[{depth,relationship}],total,offset,limit,has_more,experimental_label}`. Relationship records preserve evidence source, collection timestamps and provenance. `X-Correlation-ID` is DB-derived for successful and audited not-found/cap outcomes. Counts and records are tenant-scoped in local DB tests. This is a candidate contract, not an approved Agent 4 endpoint or a claim of actual host integration. Complete-source KEV persistence is global public-feed storage, not a tenant API; no frontend exposure is approved.


## M46 prepared host code and acceptance extension

`M46_HOST_ADAPTER.md` documents the runnable host-mount adapter, exact verified principal/pool/audit/trace callbacks, failure and rollback semantics, and consolidated owner decision package. Independent mounted-ASGI + disposable PostgreSQL tests execute the adapter, but Agent 1's real host remains unintegrated. The actual-host harness must additionally supply `gateway_trace_contains(identity, task_id, correlation_id)` by reading the real task trace and `list(identity, entity_type, entity_id, limit, offset)` by making the actual authenticated request; a seventh acceptance test covers tenant-scoped list and audit. All seven are currently skipped. The legacy task adapter still supplies only a claimed tenant, not trusted context.
