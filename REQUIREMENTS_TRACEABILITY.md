# Requirements traceability — 2026-11-06

| README v1.0 requirement | Evidence | Status / limitations |
| --- | --- | --- |
| Section 6 graph relationships, provenance, tenant scope and PostgreSQL | `relationship_analysis.py`, `relationship_api.py`, `relationship_storage.py`, isolated PostgreSQL tests | Partial experimental implementation; database persistence, indices and tenant predicates tested locally; no approved shared schema or host identity binding |
| Section 7 real source integrations | `cisa_kev.py`, `vendor_advisories.py`, `osint_sources.py`, `source_adapters.py` | Offline parsing and simulations only; no live verification |
| Section 8 AI intelligence | No verified integration | Not implemented |
| Section 10 security | API and PostgreSQL integration tests | Fail-closed identity dependency, permissions, transactional audit and application tenant scoping tested locally; real authentication, PostgreSQL RLS and production security not established |
| Gateway and frontend coordination | `THREAT_RELATIONSHIP_API_CONTRACT.md`; PR #4 handoff | Separate Agent 1 adapter invokes legacy demo; no current host mount, frontend integration or owner approval |

See `P2_01_VERIFICATION_REPORT.md`; historical claims elsewhere are not substitutes for current verification.
