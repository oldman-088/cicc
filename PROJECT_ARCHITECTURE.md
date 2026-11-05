# Threat Intelligence Module Architecture Documentation

## Project Overview
- Repository: oldman-088/cicc
- Branch: arena/28e50255-cicc (Agent 6 - Full Threat Intelligence Backup Engineer)
- Primary owner branch: arena/93315d2c-cicc (Agent 2, PR #3 Draft - untouched)
- Status: Stage 2 — P3-01 Persistence + P3-02 API surface + P3-03 Collection workers + source reliability + contract registry (fixture-tested, none mounted)
- Total Tests: 849/849 passed (0 warnings)
- Base: main @ ca8f82c
- PR: #6 (OPEN, base main)
- Recovered from Agent 2 commits: 933b29f, 805cd2b, 1a46f70

## Module Map (as of Agent 6 Stage 2)
```
apps/threat_intelligence/
├── __init__.py               # v1.2.0, 128 exported symbols (Agent 6)
│
│  --- P1-00 core entity modules ---
├── threat_actors.py          # ThreatActorModel + ThreatActorService
├── malware.py                # MalwareModel + MalwareService
├── campaigns.py              # CampaignModel + CampaignService
├── ttps.py                   # TTPModel + TTPService
├── mitre_mapping.py          # MITREMappingModel + MITREMappingService
│
│  --- extended layers ---
├── relationships.py          # RelationshipModel + RelationshipService
├── enrichment.py             # IntelligenceSourceModel / IntelligenceEnrichmentModel + Service
├── collection.py             # CollectionTaskModel / NormalizationRecordModel + CollectionService
│
│  --- P1-01 .. P1-04 ingestion ---
├── mitre_ingestion.py        # P1-01 MITREIngestionService (+ STIX 2.1 ATT&CK bundle)
├── cisa_kev.py               # P1-02 CISAKEVIngestionService (+ catalog feed, get_by_cve)
├── vendor_advisories.py      # P1-03 VendorSecurityAdvisoryIngestionService (6 parsers)
├── osint_sources.py          # P1-04 OSINTIngestionService (STIX 2.1 / TAXII 2.1) - Agent 6
│
│  --- P3-01 .. P3-03 platform layers (Agent 6) ---
├── persistence.py            # P3-01 SQLite repository, append-only triggers, tenant isolation
├── api_surface.py            # P3-02 typed route registry + dispatcher (NOT mounted)
├── collection_workers.py     # P3-03 job lifecycle, retries, leases, circuit breaker (no worker runs)
├── source_reliability.py     # reliability / freshness / evidence-gated verification
├── observability.py          # P3-04 domain health, freshness, worker/conflict rollups (no daemon)
│
│  --- P0 domain capabilities (Agent 6, Stage 3) ---
├── reports.py                # Domain B item 24: Threat Intelligence Reports + append-only history
├── relationship_analysis.py  # P2-01 typed semantics, contradictions, cycle-safe traversal
├── conflict_resolution.py    # P2-04 source claims vs normalized conclusions, deterministic
├── live_source_readiness.py  # P2 opt-in live-source gate, schema validation, no network client
│
│  --- cross-agent coordination (Agent 6) ---
├── integration_contracts.py  # Agent 1 / Agent 3 / Agent 4 payload & DTO models (1.1.0-proposed)
├── contract_registry.py      # proposed-vs-accepted registry with pinned commit provenance
│
└── tests/                    # 24 test files, 849 tests
```

### Layer dependency direction (verified acyclic by `test_package_integrity.py`)
Derived by AST from the actual `import` statements, not from documentation:
```
observability ──> collection_workers
      │     └──> conflict_resolution ──> cisa_kev
      │     └──> relationship_analysis ──> relationships
      │     └──> source_reliability
      └────> cisa_kev

api_surface ──> integration_contracts ──> cisa_kev
     │                             └──> vendor_advisories
     └────────> persistence

live_source_readiness ──> integration_contracts, cisa_kev
reports               ──> cisa_kev

collection_workers, source_reliability, osint_sources, mitre_ingestion,
relationships, enrichment, collection, campaigns, malware, ttps,
threat_actors, mitre_mapping  ──> (leaf modules, no intra-package imports)
```
`observability` is the only module with five intra-package dependencies; it imports services but
is imported by none, so it sits at the top of the graph and no cycle is possible through it.
Cold package import measured at ~181 ms in a clean interpreter and asserted
`< 2000 ms`. All 23 submodules import standalone.

### P3-01 Persistence (Agent 6)
- `SQLiteThreatIntelRepository` on the standard library `sqlite3`. **No SQLAlchemy,
  no new third-party dependency.**
- Append-only enforcement is at the **database** layer: `BEFORE UPDATE` /
  `BEFORE DELETE` triggers on `ti_observations`, `ti_entity_history`,
  `ti_conflicts` and `ti_audit_log` raise `ABORT`. A raw `DELETE` therefore fails
  even for a caller holding the live connection.
- The repository **verifies its own triggers at construction** inside a
  rolled-back transaction. If a SQLite build ignored them, construction raises
  `AppendOnlyViolationError` rather than silently permitting history rewrite.
- `tenant_id` participates in every primary key and every `WHERE` clause.
- Every statement is parameterized; `_safe_identifier` rejects anything outside
  `^[A-Za-z_][A-Za-z0-9_]*$`.

### P3-02 API surface (Agent 6) — contract only
- `ROUTES` is a declarative `RouteSpec` tuple: method, path template, operation
  id, request model, required scope, tenant requirement, path params.
- `ThreatIntelApiSurface.dispatch` validates scope → tenant → parameters →
  handler, and maps domain errors to HTTP codes deterministically.
- FastAPI appears **only** inside a guarded import in `build_fastapi_router`;
  with FastAPI absent (the state of this repository) it raises
  `ApiSurfaceNotMountedError`.
- Nothing is mounted: no server is bound, no ASGI app is exported, and
  `mount_status()` reports `not_mounted_pending_owner_approval` until a host
  calls `mark_mounted(mounted_by=...)`.

### P3-03 Collection workers (Agent 6) — nothing runs in the background
- `CollectionWorker.run_pending(handler, now=...)` executes synchronously when
  invoked. No thread, process, asyncio loop or scheduler is created.
- Time is fully injected, which is what makes backoff and expiry testable
  without sleeping.

### Source reliability (Agent 6)
- Reliability = windowed success ratio × (1 − 0.5 × min(1, streak/5)).
- Zero outcomes ⇒ score `None`, tier `UNSCORED`; `confidence_adjustment` returns
  `applied: false` rather than silently trusting an unscored source.
- Freshness is measured from the last **successful** collection.
- Verification promotion is evidence-gated: `promote_verification` requires a
  specific `observation_ref` and an attributable `performed_by`, forbids rank
  skipping, and has no flag-only path to `live_verified`.

### Contract registry (Agent 6)
- `contract_registry.py` pins each cross-agent dependency to the exact commit it
  was read from, and records `proposed` / `accepted` / `superseded` / `rejected`.
- `load_bearing` cannot be set at construction; only
  `record_owner_acceptance(contract_id, accepted_by=…, acceptance_reference=…)`
  flips it, and placeholder actors or references are rejected.
- `assert_load_bearing` raises `ContractNotAcceptedError` while a contract is
  still a proposal, naming the owner, commit and document.

### Domain B item 24 — Threat Intelligence Reports (Agent 6, Stage 3)
- `ThreatIntelReportService` — typed reports with stable IDs, classification
  (`unclassified` / `internal` / `confidential` / `restricted`), lifecycle
  (`draft` → `in_review` → `published` / `retracted`), and kind.
- **Reports reference entities; they never re-represent them.** Every relationship endpoint must
  appear in `entity_refs`, so a report cannot invent an entity ID.
- `content_hash` covers the analytical content only (title, summary, body, kind, classification,
  references), so identity and bookkeeping fields are excluded and byte-identical analysis
  deduplicates while any analytical change produces a new hash.
- History is append-only: revision replaces the record and chains
  `previous_content_hash` → `content_hash`. Prior records are never mutated in place.
- Inference is never laundered: `ReportRelationshipRef.inferred` survives revision and
  publication, and `has_inferred_relationships()` reports it.

### Relationship analysis (Agent 6, Stage 3)
- An **analysis layer over `relationships.py`**, reusing `RelationshipModel` and
  `RELATIONSHIP_TYPES`. There is no second relationship schema.
- Semantics per type: direction, symmetry, inverse, `exclusive_with`, transitivity — derived from
  the existing type registry so a new type gets an entry automatically.
- `SourceClaim`-style separation: `RelationshipAssertion` is what a source claimed; the normalized
  `RelationshipModel` is the conclusion. Corroboration raises confidence without duplicating the
  normalized record, and an inferred assertion never launders a directly-sourced one.
- Exclusivity is declared as **unordered pairs** and expanded both ways, so detection does not
  depend on the order assertions arrive in.
- Contradictions preserve both sides. Resolution requires an attributable actor and a stated
  basis, and supersedes rather than edits the earlier record.
- Traversal is depth-, fan-out- and cycle-bounded; a cycle counts only when an edge not already
  walked is encountered.
- `PathResult.reliability_statement` refuses to describe an inferred path as confirmed, and the
  hop is represented by the **strongest-origin** assertion rather than an arbitrary one.

### Conflict resolution (Agent 6, Stage 3)
- `SourceClaim` (what a source said) is kept strictly separate from `ResolvedValue` (what the
  system concluded). Nothing collapses one into the other.
- Deterministic strategies: highest-confidence-then-newest, newest-then-highest-confidence,
  source-priority-then-confidence, majority-then-confidence, manual.
- Detection is **order-independent**; the evidential tie-break key excludes `claim_id` so a genuine
  tie is detectable and left `UNRESOLVED` rather than guessed.
- Repeated ingestion of the same value from the same source is **idempotent** — no second claim, no
  confidence inflation. A changed value appends a new claim and withdraws the old one from
  consideration without deleting it.
- Manual resolution requires an attributable actor and a stated basis, and supersedes the automated
  record so the earlier outcome stays auditable.

### Domain observability (Agent 6, Stage 3)
- `ThreatIntelObservabilityService` **composes** `SourceReliabilityService`, `CollectionWorker`,
  `ConflictResolutionService` and (optionally) `RelationshipAnalysisService`. It duplicates no state.
- Freshness is **recomputed** from `last_success_at` against the caller's clock; reading the frozen
  `data_age_seconds` would keep a days-old source looking fresh.
- Health precedence: open circuit → never succeeded → weak reliability tier → stale →
  never collected → unscored → healthy.
- Events and snapshots are bounded. `runtime_status` is `caller_invoked_no_daemon` and every
  snapshot repeats that no worker process or event loop is running.
- **Scope boundary:** this is domain observability only. `to_agent1_payload()` formats values for
  Agent 1's *proposed* heartbeat and marks `contract_status: proposed_not_accepted`; it does not
  redefine Agent 1's shared system-health contract.

### Live-source readiness (Agent 6, Stage 3)
- **No network client exists in this package** (enforced by static check). A transport is injected
  by the host.
- Live execution requires **both** an environment opt-in (`CICC_TI_ALLOW_LIVE_SOURCES`) **and** a
  caller-supplied `allow_live=True`. No test in the normal suite can satisfy both.
- Credentials never pass through this layer: policies carry a `credential_ref` *name*, and a value
  that looks like secret material is rejected at validation.
- Payloads are validated before persistence — schema, record keys, record-count bounds, size and
  content type — and a rejection returns a status rather than raising, so previously stored data is
  never corrupted by a bad response.
- A rate-limit floor is enforced between fetches, and a retrying policy is refused unless it
  declares one.

### P1-04 OSINT layer (Agent 6)
- `OSINTIngestionService` — single entry point; `tenant_id` scoped; `max_payload_bytes` cap (1 MiB default).
- Entity models: `OSINTThreatActorModel`, `OSINTIndicatorModel`, `OSINTCampaignModel`,
  `OSINTMalwareModel`, `OSINTInfrastructureModel`, `OSINTRelationshipModel`.
- Standards models: `STIX21CompatibilityReport`, `TAXII21CollectionModel`, `TAXII21ManifestEntryModel`,
  `TAXII21EnvelopeModel`, `TAXII21SyncStateModel`.
- Audit models: `OSINTObservationModel` (append-only provenance), `OSINTConflictRecordModel`
  (kept/discarded values + resolution policy).
- Confidence rule: base confidence from raw observations `+ 0.05 * (distinct_source_count - 1)`.
  A same-source re-fetch **cannot** inflate confidence — this was a confirmed defect, now regression-tested.
- Resilience: per-source failure tracking, circuit breaker with `reset_circuit_breaker`,
  `SecurityError` on oversize payload.

### Cross-agent integration contract layer (Agent 6)
- `ThreatIntelligenceIntegrationBridge` — single entry point across all three contract families.
- Agent 1: `Agent1RegistrationPayload`, `Agent1HeartbeatPayload`, `Agent1OpsWorkerHeartbeatPayload`,
  `Agent1TaskEnqueuePayload`.
- Agent 3 (M1-M6): `KEVVulnerabilityCorrelationDTO`, `VendorAdvisoryLinkDTO`,
  `AttackTechniqueMappingEntryDTO`, `CVETechniqueCorrelationDTO`, `TechniqueRollupDTO`,
  `ProvenanceSummaryDTO`.
- Agent 4: `ThreatIntelListEnvelope`, `ThreatIntelDetailEnvelope`, `ThreatIntelErrorEnvelope`,
  `FreshnessMetaDTO`, `PaginationMetaDTO`.
- Full mapping and contract-status rules: `docs/THREAT_INTELLIGENCE_INTEGRATION_CONTRACTS.md`.
- **Status: implemented and tested, NOT accepted, NOT mounted.** No HTTP routes, no ORM tables,
  no background workers are created by this package.

## Core Architecture (Phase 0 - COMPLETED)
### Independent Module Structure
```
apps/threat_intelligence/
├── threat_actors.py          # ThreatActorModel + ThreatActorService
├── malware.py                # MalwareModel + MalwareService
├── campaigns.py              # CampaignModel + CampaignService
├── ttps.py                   # TTPModel + TTPService
├── mitre_mapping.py          # MITREMappingModel + MITREMappingService
├── tests/
│   ├── test_threat_actors.py # 9 tests
│   ├── test_malware.py       # 9 tests
│   ├── test_campaigns.py     # 9 tests
│   ├── test_ttps.py          # 9 tests
│   └── test_mitre_mapping.py # 5 tests
```

## Extended Architecture (Extended Authorization - COMPLETED)
### Relationship Layer (NEW)
```
apps/threat_intelligence/relationships.py
├── RelationshipModel         # Relationship entity model
└── RelationshipService       # Relationship traversal and management
```
**Features:** 12 tests (apps/threat_intelligence/tests/test_relationships.py)

### Enrichment Layer (NEW)
```
apps/threat_intelligence/enrichment.py
├── IntelligenceSourceModel     # Source entity model
├── IntelligenceEnrichmentModel # Enrichment entity model
└── IntelligenceEnrichmentService # Source integration and enrichment
```
**Features:** 16 tests (apps/threat_intelligence/tests/test_enrichment.py)

### Collection/Normalization Layer (NEW)
```
apps/threat_intelligence/collection.py
├── CollectionTaskModel       # Collection task entity model
├── NormalizationRecordModel  # Normalization record entity model
└── CollectionService         # Execution simulation and normalization
```
**Features:** 15 tests (apps/threat_intelligence/tests/test_collection.py)

## Autonomous Engineering Architecture (IN PROGRESS)
### MITRE ATT&CK Structured Ingestion Pipeline (COMPLETED - P1-01)
```
apps/threat_intelligence/mitre_ingestion.py
├── MITREFrameworkModel         # Framework version and metadata
├── MITRETechniqueModel        # Techniques and sub-techniques
├── MITRETacticModel           # Tactics and categories
├── MITREGroupModel            # Threat groups and actors
├── MITRESoftwareModel         # Software and tools
├── MITRERelationshipModel     # Relationships between entities
└── MITREIngestionService      # Structured ingestion pipeline
```
**Features:** 24 tests (apps/threat_intelligence/tests/test_mitre_ingestion.py)

### CISA KEV Integration Connector (COMPLETED - P1-02)
```
apps/threat_intelligence/cisa_kev.py
├── CISAKEVSourceModel         # Source metadata and attribution
├── CISAKEVRecordModel        # Individual KEV record (CVE, vendor, product, etc.)
├── CISAKEVHistoryModel       # Historical change tracking
└── CISAKEVIngestionService   # Structured ingestion pipeline
```
**Features:** 20 tests (apps/threat_intelligence/tests/test_cisa_kev.py)

### Vendor Security Advisories Integration Framework (IN PROGRESS - P1-03)
```
apps/threat_intelligence/vendor_advisories.py
├── VendorSecurityAdvisorySourceModel   # Vendor source metadata and attribution
├── VendorSecurityAdvisoryRecordModel   # Individual advisory record (CVE, product, version, etc.)
├── VendorSecurityAdvisoryHistoryModel  # Historical change tracking
└── VendorSecurityAdvisoryIngestionService # Reusable connector interface (Microsoft, Cisco, Red Hat, Ubuntu)
```
**Features:**
- Reusable connector interface for vendor security advisories
- Vendor-specific parsing and normalization (framework foundation)
- Original advisory IDs and source references preservation
- Publication, modification, and ingestion timestamps preservation
- CVE references and affected product/version extraction
- Source provenance and confidence scoring (1.0 = verified vendor source)
- Duplicate detection and conflict resolution
- Historical observation preservation
- Malformed input and schema change safety
- Timeouts, bounded retries, rate limits, circuit breakers (simulation)
- Offline fixtures and deterministic tests (EXPERIMENTAL_DEMO_DATA_ONLY)
- Verified vs inferred distinction
- No live synchronization claims without evidence
- **Tests**: 20 tests (apps/threat_intelligence/tests/test_vendor_advisories.py)

## Integration Contracts (DEFINED & EXPANDED)
### Production Integration Preparation
1. **PostgreSQL/SQLAlchemy** - Database models and relationships for all entities including MITRE ingestion, CISA KEV integration, vendor advisories
2. **FastAPI Routers** - API endpoints for all modules, layers, and ingestion pipelines
3. **Authentication/Authorization** - Security boundaries and role-based access
4. **Tenant Isolation** - Multi-tenant data separation and enforcement
5. **Audit Logging** - Complete audit trail for all operations including ingestion events
6. **Investigation Workflows** - Workflow integration points and data export
7. **Intelligence Collection** - Collection pipeline integration and source connectors
8. **Vulnerability Intelligence** - CVE correlation interface (Agent 3 coordination)
9. **Command Theater** - Visualization data preparation and export
10. **System Health/Operations Dashboard** - Monitoring and health checks including ingestion pipeline health

### Coordination Interfaces (DEFINED)
- **Command Theater**: Clean interface contract (no modification to branch/files)
- **Vulnerability Intelligence (Agent 3)**: Clean interface contract (no modification to branch/files)
- **System Health/Operations Dashboard**: Clean interface contract (no modification to branch/files)
- **Agent 1 (Coordination)**: Clean interface contract (no modification to branch/files)
- **Agent 4 (Integration & Coordination)**: Clean interface contract (no modification to branch/files)

## Security & Data Integrity (VERIFIED & ENHANCED)
- **Strict Input Validation**: All models and services validate inputs (162/162 tests passed)
- **Safe Untrusted Content Handling**: Secure processing in enrichment, collection, MITRE ingestion, CISA KEV integration, vendor advisories
- **Malicious Feed Protection**: Built into source integration and MITRE/CISA KEV/Vendor ingestion architecture
- **Secret and Credential Protection**: No credentials exposed, protection mechanisms maintained
- **Tenant Isolation**: Enforced boundaries in all services and ingestion pipelines
- **Authorization Boundaries**: Strict authorization checks at service level
- **Auditability**: Complete audit trail preservation including MITRE, CISA KEV, and vendor ingestion events
- **Provenance Preservation**: Maintained across all entities, relationships, MITRE ingestion, CISA KEV integration, vendor advisories
- **Safe Logging**: Structured logging without sensitive data
- **Dependency Security**: Pydantic V2 ConfigDict (secure validation)
- **Resilient External Integrations**: Timeouts, retries, rate limits, circuit breakers designed in MITRE, CISA KEV, and vendor ingestion

## Testing Architecture (COMPLETED & EXPANDED)
- **Phase 0 Tests**: 41 tests (core modules)
- **Extended Authorization Tests**: 57 tests (extended layers)
- **Autonomous Engineering Tests**: 64 tests (MITRE ingestion: 24, CISA KEV: 20, Vendor Advisories: 20)
- **Total Tests**: 162 tests
- **Results**: 162/162 passed, 0 warnings
- **Coverage**: Unit, cross-module, integration contracts, normalization, provenance/attribution, deduplication/conflict, invalid/malicious input, failure recovery, source connectors, tenant isolation, authorization, performance, regression, security validation

## Documentation Maintenance (COMPLETED & EXPANDED)
- **PROJECT_STATE.json**: Updated with autonomous engineering status (162/162 tests)
- **MASTER_TASK_QUEUE.md**: Updated with autonomous backlog (P1-P2 completed, P1-03 foundation implemented, P1-04 next)
- **DEVELOPMENT_LOG.md**: Updated with autonomous progress (162/162 tests)
- **PROJECT_ARCHITECTURE.md**: Updated with MITRE ingestion, CISA KEV, and vendor advisories architecture
- **INTEGRATION_PREPARATION_REPORT.md**: Updated with integration contracts
- **BACKLOG.md**: Updated - Autonomous Engineering Backlog (P1-P3 priorities, MITRE, CISA KEV, Vendor Advisories implemented, next tasks identified)
- **SECURITY_REVIEW.md**: Updated - Security validation and enhancement plan

## Completion & Handoff Status (IN PROGRESS - AUTONOMOUS)
- **Functionality**: Completed across all modules, layers, MITRE ingestion, CISA KEV integration, vendor advisories framework
- **Architecture Summary**: Documented in PROJECT_ARCHITECTURE.md
- **Files Created/Modified**: 51 files total
- **Test Results**: 162/162 passed (evidence available)
- **Security/Integrity Review**: Passed (SECURITY_REVIEW.md)
- **Remaining Limitations**: None critical
- **Integration Contracts**: Defined in INTEGRATION_PREPARATION_REPORT.md
- **Commit SHAs**: f8f2868, d639eee, 933b29f, 805cd2b, f7d3939, 480fa3d
- **Branch Name**: arena/93315d2c-cicc
- **PR URL**: https://github.com/oldman-088/cicc/pull/3
- **Handoff Ready**: Yes (Autonomous Engineering Authorization active)

## Next Priorities (IDENTIFIED IN BACKLOG)
1. **P1-03**: Vendor Security Advisories Integration Framework (IN PROGRESS - Foundation implemented, parsers next)
2. **P1-04**: OSINT Intelligence Sources Integration
3. **P2-01**: Cross-Entity Relationship Analysis Engine
4. **P2-02**: Confidence Scoring and Reliability Framework
5. **P2-03**: Temporal Intelligence Analysis
6. **P2-04**: Conflicting Intelligence Resolution
7. **P3-01**: PostgreSQL/SQLAlchemy Integration Contracts
8. **P3-02**: FastAPI Integration Interfaces
9. **P3-03**: Background Collection Workflows
10. **P3-04**: Observability and Performance
11. **P4-01**: Vulnerability Intelligence Interface (Agent 3 coordination)
12. **P4-02**: Command Theater Interface
13. **P4-03**: System Health/Operations Dashboard Interface
14. **P4-04**: Investigation Integration
15. **P5-01**: Advanced Security Validation Enhancements
16. **P5-02**: Expanded Test Coverage
17. **P5-03**: Documentation Maintenance

# Architectural Boundaries (Agent 6 - explicit)
- **No network I/O.** No module in `apps/threat_intelligence/` opens a socket, makes an HTTP
  request, or resolves an external host. Every ingestion entry point accepts already-fetched
  payload data as a `dict`. Live fetching is the platform owner's concern.
- **No persistence.** No SQLAlchemy models, no Alembic migrations, no DDL. In-memory dicts only.
  The persistence contract is described in `INTEGRATION_PREPARATION_REPORT.md`, not implemented.
- **HTTP surface is contract-only.** `api_surface.py` exposes a route registry and a
  dispatcher, but binds no server and exports no ASGI app.
  `FreshnessMetaDTO.host_mount_status` defaults to
  `not_mounted_pending_owner_approval` so a frontend cannot mistake "not mounted" for "empty".
- **Persistence is local, not shared.** `persistence.py` opens a SQLite file (or `:memory:`)
  and nothing else. It is **not** offered as the host SQL adapter: Agent 3's storage-port
  contract states the subsystem defines the port and *the host implements the adapter* behind an
  approved migration.
- **No background execution.** `collection_workers.py` starts no thread, process or event loop.
  `run_pending` runs when a caller invokes it and returns.
- **No shared-file mutation.** `models.py`, `main.py`, and migrations were never touched.
- **Verification honesty.** `verification_mode` is `fixture_tested` on every service; promotion to
  `oracle_verified` / `live_verified` requires a real `VerificationEvidence` record with a specific
  `observation_ref` and an attributable `performed_by`. There is no flag-only path.
- **These boundaries are enforced by test, not by comment.** `test_package_integrity.py`
  (141 checks) asserts the acyclic import graph, the absence of any networking client, that no
  socket is opened at import, that no thread or process is started, that no secret-looking
  literal exists, and that every service defaults to `fixture_tested`.

# Completion Status
✅ Phase 0: COMPLETED (41/41 tests passed, commit f8f2868)
✅ Extended Authorization: COMPLETED (57 new tests, 98/98 total passed, commit d639eee)
✅ Completion & Handoff: COMPLETED (commit 933b29f, recovered by Agent 6)
✅ Autonomous Engineering Authorization: IN PROGRESS (P1-01/P1-02/P1-03 completed by Agent 2)
✅ P1-04 OSINT Intelligence Sources Integration: COMPLETED by Agent 6 (16 tests)
✅ Cross-Agent Integration Contracts: IMPLEMENTED by Agent 6 (18 tests), NOT accepted
✅ P3-01 Persistence: IMPLEMENTED by Agent 6 (29 tests), NOT mounted
✅ P3-02 API surface: IMPLEMENTED by Agent 6 (36 tests), NOT mounted
✅ P3-03 Collection workers: IMPLEMENTED by Agent 6 (40 tests), NO worker running
✅ Source reliability + evidence-gated verification: IMPLEMENTED by Agent 6 (47 tests)
✅ Contract registry: IMPLEMENTED by Agent 6 (36 tests), 5 proposed / 0 accepted
✅ Static integrity checks: ADDED by Agent 6 (141 tests)
✅ PR #3 <-> PR #6 reconciliation: DOCUMENTED (docs/PR3_PR6_RECONCILIATION.md)
✅ Documentation: MAINTAINED (7 root files + 2 docs/ files)
✅ Branch: ACTIVE (arena/28e50255-cicc), PR #6 OPEN
✅ Handoff to Agent 2: READY (see DEVELOPMENT_LOG.md)

# Last Updated
2026-11-05 - Stage 2: persistence, API surface, collection workers, source reliability, contract registry and static checks added by Agent 6
Agent: Arena.ai Agent Mode - Agent 6 (Full Threat Intelligence Backup Engineer)
Branch: arena/28e50255-cicc
PR: https://github.com/oldman-088/cicc/pull/6 (OPEN, base main)
Recovered from Agent 2 commits: 933b29f, 805cd2b, 1a46f70
Agent 2 PR: https://github.com/oldman-088/cicc/pull/3 (untouched)
Total Tests: 849/849 passed (0 warnings)
