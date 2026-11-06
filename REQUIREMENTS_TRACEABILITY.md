# Requirements traceability — 2026-11-06

| README v1.0 requirement | Evidence | Status / limitations |
| --- | --- | --- |
| Section 6 graph relationships, evidence, PostgreSQL and tenant scope | `relationship_analysis.py`, `relationship_api.py`, `relationship_storage.py`, local PostgreSQL and RLS tests | Partial experimental implementation; no approved host schema or principal binding; GUC-based RLS is not authentication |
| Section 5.2 confidence, reliability, freshness, corroboration and conflicts | `intelligence_assessment.py`, offline unit tests | Partial declaration/evidence summary and collection-time filtering only; no score, source reliability, independence, validity or conflict resolution |
| Section 7 real source integrations | `cisa_kev.py`, `vendor_advisories.py`, `osint_sources.py`, `source_adapters.py` | Offline parsing and simulations only; no live verification |
| Section 8 AI intelligence | No verified integration | Not implemented |
| Section 10 security | API, RLS and PostgreSQL tests | Application tenant predicates and transactional audit tested locally; actual authentication, DB-role trust model and production security not established |
| Gateway and frontend coordination | `HOST_INTEGRATION_HANDOFF.md`; PR #4 source review and handoff | Separate Agent 1 adapter invokes legacy demo; no current host mount, approved frontend integration or owner approval |

See `P2_01_VERIFICATION_REPORT.md`; historical claims elsewhere are not substitutes for current verification.
