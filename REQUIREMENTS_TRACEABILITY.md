# Requirements traceability — 2026-11-06

| README v1.0 requirement | Evidence | Status / limitations |
| --- | --- | --- |
| Section 6 graph relationships, provenance and tenant scope | `relationship_analysis.py`, `relationship_api.py`, offline tests | Partial experimental, tenant-keyed in-memory prototype; no PostgreSQL persistence or verified host identity |
| Section 7 real source integrations | `cisa_kev.py`, `vendor_advisories.py`, `osint_sources.py`, `source_adapters.py` | Offline parsing and simulations only; no live verification |
| Section 8 AI intelligence | No verified integration | Not implemented |
| Section 10 security | `relationship_api.py`, `test_relationship_http.py` | Fail-closed injected identity, permission and audit-attempt hooks tested locally; production authentication, durable audit and tenant isolation not established |
| Gateway and frontend coordination | `THREAT_RELATIONSHIP_API_CONTRACT.md`; PR #4 handoff | Separate Agent 1 adapter invokes legacy demo; no current host mount, frontend integration or owner approval |

See `P2_01_VERIFICATION_REPORT.md`; historical claims elsewhere are not substitutes for a current verification run.
