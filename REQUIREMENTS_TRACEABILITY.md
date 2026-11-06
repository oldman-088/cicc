# Requirements traceability — 2026-11-06

| README v1.0 requirement | Evidence | Status / limitations |
| --- | --- | --- |
| Section 6 graph, evidence, PostgreSQL, tenant scope | `relationship_api.py`, `relationship_storage.py`, controlled SQL and isolated DB tests | Partial: locally tested create/get/list/traversal; real host identity, deployment, multi-request snapshot and shared graph pending |
| Section 5.2 confidence, reliability, freshness and conflicts | `intelligence_assessment.py`, `confidence_assessment.py` | Explicit analyst-input experimental score and collection-age classification; not calibrated, no source-independence guarantee or automatic conflict resolution |
| Section 7 real intelligence integrations | `cisa_github_collector.py`, `cisa_kev_persistence.py` | Complete GitHub mirror collection, isolated durable snapshots, real-source network/persistence tests; host scheduling and operations pending |
| Section 8 AI intelligence | No verified integration | Not implemented |
| Section 10 security | `TRUSTED_RELATIONSHIP_WRITES.md`, PostgreSQL security tests | Restricted-role create/get/list/traversal audit tested locally; real actor identity, administrator-resistant audit, production isolation and host security unverified |
| Gateway/frontend coordination | `HOST_INTEGRATION_HANDOFF.md`, host acceptance scaffold | Actual host tests skipped; no approved host mount or frontend binding |

See `P2_01_VERIFICATION_REPORT.md` for current verification and limitations.
