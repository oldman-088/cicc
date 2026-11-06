# Requirements traceability — 2026-11-06

| README v1.0 requirement | Evidence | Status / limitations |
| --- | --- | --- |
| Section 6 graph relationships, evidence, PostgreSQL and tenant scope | `relationship_analysis.py`, `relationship_api.py`, `relationship_storage.py`, local PostgreSQL and RLS tests | Partial experimental implementation; per-tenant DB-login alternative locally tested but no approved host schema, role/pool model or principal binding |
| Section 5.2 confidence, reliability, freshness, corroboration and conflicts | `intelligence_assessment.py`, `confidence_assessment.py`, offline tests | Explicit-input experimental weighted score and collection-age classification; no calibrated reliability, actual event-time freshness, independence or conflict resolution |
| Section 7 real source integrations | `cisa_kev.py`, `vendor_advisories.py`, `osint_sources.py`, `source_adapters.py` | Offline parsing and simulations only; no live verification |
| Section 8 AI intelligence | No verified integration | Not implemented |
| Section 10 security | API, RLS and PostgreSQL tests; `ROLE_BOUND_TENANT_SECURITY_PROPOSAL.md` | Tenant-login role isolation locally tested under assumptions; own-tenant arbitrary SQL and audit forgery remain possible; host/production identity and security unverified |
| Gateway and frontend coordination | `HOST_INTEGRATION_HANDOFF.md`; opt-in actual-host test scaffold | Agent 1 adapter invokes legacy demo; 6 host tests skipped; no approved host mount, frontend integration or owner approval |

See `P2_01_VERIFICATION_REPORT.md`; historical claims elsewhere are not substitutes for current verification.
