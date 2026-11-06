# Requirements traceability — 2026-11-06

| README v1.0 requirement | Evidence | Status / limitations |
| --- | --- | --- |
| Section 6 graph, evidence, PostgreSQL, tenant scope | `relationship_analysis.py`, `relationship_api.py`, `relationship_storage.py` and isolated DB tests | Partial: full graph prototype plus controlled write-only audited adapter; approved host identity, secure audited reads and shared graph pending |
| Section 5.2 confidence, reliability, freshness and conflicts | `intelligence_assessment.py`, `confidence_assessment.py` | Explicit analyst-input experimental score and collection-age classification; not calibrated, no reliable source independence or conflict resolution |
| Section 7 real intelligence integrations | `cisa_github_collector.py` | One real read from CISA GitHub mirror and offline parsing tests; no persistent ingestion/scheduler or operational readiness |
| Section 8 AI intelligence | No verified integration | Not implemented |
| Section 10 security | `TRUSTED_RELATIONSHIP_WRITES.md`, PostgreSQL security tests | Restricted-role controlled create audit tested locally; real actor identity, audited reads, administrator-resistant audit, production isolation and host security unverified |
| Gateway/frontend coordination | `HOST_INTEGRATION_HANDOFF.md`, host acceptance scaffold | Actual host tests skipped; no approved host mount or frontend binding |

See `P2_01_VERIFICATION_REPORT.md` for current verification and limitations.
