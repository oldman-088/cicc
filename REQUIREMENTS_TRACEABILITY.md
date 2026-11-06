# Requirements traceability — 2026-11-06

| README v1.0 requirement | Evidence | Status / limitations |
| --- | --- | --- |
| Section 6 graph, evidence, PostgreSQL, tenant scope | `relationship_api.py`, `relationship_storage.py`, controlled SQL, `host_adapter.py` | Partial: locally tested create/get/list/traversal and independent mounted host; actual host identity and shared deployment pending |
| Section 5.2 confidence, reliability, freshness and conflicts | `intelligence_assessment.py`, `confidence_assessment.py`, `kev_correlation.py` | Explicit analyst-input experimental assessment and exact-source joins; not calibrated, no source-independence guarantee or automatic conflict resolution |
| Section 7 real intelligence integrations | `cisa_github_collector.py`, `cisa_kev_persistence.py`, `cisa_kev_snapshot.py`, `cisa_kev_health.py` | Complete GitHub mirror collection, isolated durable/reloadable snapshots and real-source tests; actual host scheduling/monitoring pending |
| Section 8 AI intelligence | No verified integration | Not implemented |
| Section 10 security | `TRUSTED_RELATIONSHIP_WRITES.md`, PostgreSQL tests, `host_adapter.py` | Restricted-role audited operations and mounted-host security events tested locally; actual actor identity, admin-resistant audit, production isolation and host security unverified |
| Gateway/frontend coordination | `M46_HOST_ADAPTER.md`, `HOST_INTEGRATION_HANDOFF.md`, `FRONTEND_READ_ONLY_TI_CONTRACT.md` | Candidate adapter and DTOs; seven actual-host tests skipped; no approved host mount, trace or frontend binding |

See `P2_01_VERIFICATION_REPORT.md` for current verification and limitations.
