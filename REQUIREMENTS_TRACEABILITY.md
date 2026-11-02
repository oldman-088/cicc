# Requirements traceability

The only implemented product slice is a synthetic read-only overview. All other requirements remain NOT_STARTED unless specified. No listed domain is considered a complete module. Queue IDs reference acceptance criteria and tests in MASTER_TASK_QUEUE.md. Future model/API/UI fields below are planned, not implemented.

| Requirement / modules | Backend / model / API | Frontend | Tests / documentation | Status |
|---|---|---|---|---|
| Command center, global overview, monitoring, landscape, SOC, map, alerts, timeline, missions (1–9) | demo fixture, GET /api/v1/overview; no persistent model | partial overview, placeholder globe | API tests; README, API_DOCUMENTATION | IN_PROGRESS (P0-02, P1-03, P2-03) |
| Threat intelligence, actors/groups, campaigns, IOC/IP/domain/URL/hash, malware/family, TTP/ATT&CK, advisories/reports (10–24) | none | no functional module | planned P1-01/03 | NOT_STARTED |
| Vulnerabilities, CVE/CVSS, exploits, KEV, patches, prioritization, exposure, asset correlation (25–33) | none | none | planned P1-02/03 | NOT_STARTED |
| Investigations, cases, evidence/timeline, relationships/link/attack paths, incident correlation, hunting, reports (34–43) | none | none | planned P1-04/P2-01 | NOT_STARTED |
| Events, alerts, logs, detection, anomaly, response, posture (44–50) | none | none | planned P1-03 | NOT_STARTED |
| OSINT, feeds, APIs, ingestion, normalization, enrichment, reliability, dedupe (51–59) | none | source names only, status explicitly unconfigured | planned P1-01/02; source registry | NOT_STARTED |
| Assets, attack surface, third parties, risk, compliance, governance, risk register, recommendations, reporting, admin (60–69) | none | none | planned P1-03/P3-01/02 | NOT_STARTED |
| Fusion, trust/confidence, provenance graph, pattern discovery, gap analysis | none | fixture confidence only, not calculated | planned P2-01 | NOT_STARTED |
| Requirements, third-party risk, SBOM, business impact, memory, simulation | none | none | planned P3-01 | NOT_STARTED |
| 3D theater, replay, spatial workspace | none | static illustrative globe only | planned P2-03 | NOT_STARTED |
| Zero trust, audit/compliance, AI governance, federation, benchmarks | none | no functional controls | planned P0-03/05, P3-02 | NOT_STARTED |
| Disaster recovery, backup and verified restoration | none | none | DISASTER_RECOVERY.md; P3-03 | NOT_STARTED |
| Unified graph entities/relationships, validity, tenant scope and provenance | draft SQLAlchemy tenant/entity/relationship schema and Alembic migration; no API | none | SQLite and disposable PostgreSQL 16.2 migration, schema parity and selected constraint tests; GitHub CI unverified; P0-04/P2-01 | IN_PROGRESS |
| Real data sources, connector health, freshness, provenance | status constants only; no connections | unconfigured status visible | API tests; INTELLIGENCE_SOURCE_REGISTRY.md | IN_PROGRESS (P1-02) |
| AI provider interface, safety, human review | none | none | P2-02 | NOT_STARTED |
| English/Arabic/Persian, RTL and accessibility | none | English only | P1-05 | NOT_STARTED |
| Auth, RBAC, isolation, secure uploads, security controls | none | demo only | SECURITY_STATUS.md, P0-03/05 | NOT_STARTED |
| Infrastructure, migrations, monitoring, CI/CD, deployment | unverified local Compose only | Dockerfile | DEPLOYMENT_GUIDE.md, P3-03 | IN_PROGRESS |

Experimental partial implementation: manual entity creation/list in `apps/api/app/protected_api.py`, SQLAlchemy `Entity` and migration 0006, endpoints `POST/GET /api/v1/secure/entities`; SQLite API/authorization/audit tests. Source and optional confidence stored, unverified by default. No frontend workflow, evidence history, live integration, updates, complete model or PostgreSQL verification; P1-01 remains IN_PROGRESS.

Experimental partial evidence references: `EvidenceReference` model, migration 0007, protected `GET/POST /api/v1/secure/entities/{id}/evidence`, SQLite API and migration tests. Analyst-entered metadata and optional asserted digest only; no files, hash verification, chain of custody, UI or comprehensive PostgreSQL verification. P1-04 remains NOT_STARTED as a full module.

Partial provenance history: model `ProvenanceEvent`, migration 0008 and tenant-scoped GET `/api/v1/secure/entities/{id}/provenance`. Manual entity creation and evidence reference addition produce event snapshots, linked to the exact tenant/entity/evidence. SQLite and PostgreSQL tests pass. Earlier records are not backfilled and the API warns history may be incomplete. No tamper-proof storage, transformation history, connector provenance or frontend. P2-01 remains IN_PROGRESS, not complete.

Experimental manual entity update: `PATCH /api/v1/secure/entities/{id}` with expected version, tenant-scoped writer authorization, audit and before/after provenance. SQLite tests and disposable PostgreSQL concurrent update test pass; no full record lifecycle, UI or production verification.

Experimental graph relationship assertions: `Relationship` model and migration 0010, protected `POST /api/v1/secure/relationships` and `GET /api/v1/secure/entities/{id}/relationships`; tenant/role checks, audit and provenance, SQLite and disposable PostgreSQL tests. Inputs are analyst assertions, not verified correlations. No graph UI, relationship edit/validity, automated fusion or comprehensive provenance; P2-01 IN_PROGRESS.

CISA KEV adapter: `apps/api/app/connectors/cisa_kev.py` and synthetic contract tests in `apps/api/tests/test_cisa_kev.py`. Fixed official URL, limited bytes, validation and bounded retries; no persistence, API, UI, synchronization health, actual feed verification or scheduler. P1-02 IN_PROGRESS; historical increment, see newer NVD entries below.

CISA KEV internal snapshot persistence: migration 0011, tenant-scoped catalog state/records linked to unified entities, `connectors/cisa_import.py`; SQLite and PostgreSQL tests cover deduplication, authorization, stale rejection, rollback, concurrency and source provenance. No live fetch orchestration, attempt/failure status, external API, UI or scheduler; only synthetic fixtures have been imported in tests. P1-02 IN_PROGRESS.

CISA sync attempt tracking: migration 0012, `connectors/cisa_sync.py` with tenant/admin checks, atomic success, explicit failure/abandonment and audited internal status. Synthetic fixture tests include failure, rollback and PostgreSQL concurrent starts. No API, scheduler, UI, live source verification or production readiness. P1-02 IN_PROGRESS.

Experimental CISA status/abandon APIs: `GET /api/v1/secure/sources/cisa-kev/status`, `POST /api/v1/secure/sources/cisa-kev/attempts/{id}/abandon`, admin/tenant authorization and audit, SQLite and PostgreSQL-backed tests. No API to start sync, no UI/scheduler or live verification. P1-02 remains IN_PROGRESS.

- Identity/session concurrency (partial): protected transactions recheck locked actor/session on PostgreSQL; forced lock-wait demotion/revocation tests pass. In-flight operations may finish before revocation, SQLite lacks equivalent locks, throughput and broader concurrency/security review remain open.

- P1-02 source operation (partial): an interactive administrator-session CLI can trigger one fixed-endpoint CISA sync. Synthetic fixture and PostgreSQL authorization tests pass; live source, provider terms, actual TTY, strict runtime deadline, scheduler and UI remain unverified/missing.

- P1-04 investigations (partial): experimental tenant-scoped case creation/list, versioned open/closed status and event history. SQLite/PostgreSQL tests cover permissions, tenant scope, transactional rollback, pagination, database constraints and conflicting writes. No evidence handling, assignments, reports, UI or tamper-resistant audit.

- P1-04 entity associations (partial): experimental tenant-bound, audited case/entity links with unverified status and pagination; audited unlink is supported for open cases; no evidence validation or complete investigation workflow.

- P1-04 evidence references (partial): experimental case links to same-tenant references belonging to already-linked entities, with link/unlink, pagination, composite FKs and transactional history/audit. References remain unverified; no file handling, integrity validation or chain of custody.

- P1-04 assignment (partial): admin-only case assignment to active same-tenant analyst/admin, optimistic version, case history and targeted audit. Disabled/demoted assignees are not automatically cleared; no notifications, UI or complete case workflow.

- P1-04 notes (partial): experimental append-only-through-API case notes with tenant and actor FKs, audit, history and pagination. Notes are unverified and not database-tamper-resistant; no editing, deletion, UI or retention.

- P1-05 localization (partial): synthetic demo heading, warning and illustrative nonfunctional navigation labels available in English/Arabic/Persian with scoped RTL and local storage preference. Other interface text and demo records remain English; translation review, full RTL and browser/assistive-technology tests are pending.

- P1-05 browser smoke: production build with mocked synthetic response tested locally in headless Chromium for Arabic/Persian direction, Arabic persistence, modal focus/Escape, one 390px viewport and API failure. Partial localization, other browsers, assistive technology and native-speaker review remain unverified.

- P1-04 partial: tenant-scoped open-case details update with optimistic version, case history and audit is tested on migrated SQLite/PostgreSQL, including selected PostgreSQL lock races; verified evidence, reports and UI remain missing.

- P3-03 partial: disposable synthetic PostgreSQL logical dump/restore drill checks selected records, schema parity and one tenant constraint. It does not validate production recovery, encryption, roles, off-site backup or RPO/RTO.

- P0-03 partial: experimental self session listing/revocation and session-target audit snapshot tested on migrated SQLite/PostgreSQL, including selected forced lock races. No production TLS, MFA, durable audit or secure operational UI is verified.

- P1-04 partial: tenant/entity-scoped evidence-reference detail and composite audit target tested; no file handling, integrity verification or chain of custody. Historical audit targets are not backfilled.

- P1-02 partial NVD: fixed-URL single-CVE adapter with synthetic fixtures only; internal tenant-scoped importer implemented with migration 0031, role checks, source-specific deduplication, provenance and audit; fixture-only SQLite/PostgreSQL tests including isolation and a concurrent import. Protected tenant-scoped observation read is tested; no exposed NVD sync API, scheduler, coordinated rate limiting, UI or live verification.

- P1-02 partial NVD manual sync coordinator: migration 0032, tenant/admin authorization and audit, one running attempt per tenant, distinct not-found/failure/abandonment, atomic import and synthetic SQLite/PostgreSQL tests. No live verification, public status/start API, CLI, scheduler, shared provider-wide rate limiting or UI.
