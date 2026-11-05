# Threat Intelligence Integration Contracts

- **Repository:** `oldman-088/cicc`
- **Branch:** `arena/28e50255-cicc` (Agent 6 — Full Threat Intelligence Backup Engineer)
- **Base:** `main` @ `ca8f82c0500637e22851d7128cddf99081ef3c08`
- **Recovered from:** Agent 2 branch `arena/93315d2c-cicc` — commits `933b29f`, `805cd2b`, `1a46f70` (PR #3, Draft)
- **Implementation:** `apps/threat_intelligence/integration_contracts.py`
- **Contract registry:** `apps/threat_intelligence/contract_registry.py`
- **Tests:** `test_integration_contracts.py` (18) + `test_contract_registry.py` (36)
- **Verification mode:** `fixture_tested` — **no outbound network request was made by any code in this package**

> ## Contract status rule (applies to everything below)
> Nothing in this document is an accepted, mounted, or merged contract. Agent 1's Coordination
> Contract v1.0, Agent 3's `INTEGRATION_READINESS.md`, and Agent 4's DTO expectations were each
> read from their **own unmerged branches** and are **proposals**. This package implements the
> Threat Intelligence *side* of those proposals as validated Pydantic models so that (a) the
> shapes are pinned in code and tests, and (b) whichever version is eventually accepted can be
> diffed against a real, executable reference instead of prose. **No host mounting, no shared
> schema migration, and no cross-branch edit was performed or assumed.**

---

## 0. Exact provenance of every dependency (VERIFIED)

Every contract below is pinned in `contract_registry.py` to the commit it was
actually read from. Branch heads were resolved with
`git ls-remote origin refs/heads/<branch>`; documents were read with
`git show <branch>:<path>`. **No source branch was modified.**

| `contract_id` | Owner | Version as published | Source commit | Source document | PR | Status |
|---|---|---|---|---|---|---|
| `agent1-coordination-v1` | Agent 1 | `Contract v1.0 (M11-02)` — 25 numbered endpoints | `2c6af207a08955b9990ea9d89af8fd60fed3bc91` | `docs/INTEGRATION_CONTRACTS.md` | `oldman-088/cicc#4` | **PROPOSED** |
| `agent1-ops-worker-heartbeat` | Agent 1 | Issue #5 worker heartbeat | `2c6af207a08955b9990ea9d89af8fd60fed3bc91` | GitHub Issue #5 | — | **PROPOSED** |
| `agent3-vuln-intel-m1-m6` | Agent 3 | `verification 2026-11-05 @ 5e91ff6 (1160 tests)` | `84fca769f78c1ebede13a22529719f0735cf1afc` | `docs/vulnerability-intelligence/INTEGRATION_READINESS.md` | `oldman-088/cicc#1` | **PROPOSED** |
| `agent3-storage-port` | Agent 3 | proposed storage port | `84fca769f78c1ebede13a22529719f0735cf1afc` | `docs/vulnerability-intelligence/INTEGRATION_CONTRACTS.md` | `oldman-088/cicc#1` | **PROPOSED** |
| `agent2-threat-intel-ownership` | Agent 2 | PR #3 head `1a46f70` | `1a46f704bc09207d2755fbfd5a7e8ae48b646e1b` | `PROJECT_STATE.json`, `apps/threat_intelligence/*` | `oldman-088/cicc#3` | **PROPOSED** |

Registry summary: **5 dependencies, 5 `proposed`, 0 `accepted`, 0 load-bearing.**

Enforcement is not documentary. `ContractRegistry.assert_load_bearing(id)`
raises `ContractNotAcceptedError` naming the owner, the commit and the document
while the entry is still a proposal, and `load_bearing` cannot be set at
construction — only `record_owner_acceptance(contract_id, accepted_by=…,
acceptance_reference=…)` flips it, and that rejects placeholder actors and
references (`pending`, `tbd`, `unknown`, `none`, …).

### Owner review requested

| Owner | Asked to confirm | Where |
|---|---|---|
| Agent 1 | Coordination Contract v1.0 payload shapes; `Agent1RegistrationPayload.meta` identity fields; `task_id` slash prohibition; ≥30s / 120s heartbeat cadence | PR #4 |
| Agent 3 | M1 `kev_required_action` placement (KEV-layer-only vs shared record — Agent 3 marks this **BLOCKED pending an owner decision**); M2 advisory shape; M3–M6 as implemented | PR #1 |
| Agent 2 / owner | Whether these modules land independently or fold into PR #3; the `implement_timeouts_retries` signature widening | PR #3 / PR #6 |

---

## 1. Agent 1 — Central Coordination & System Health

Source read from `origin/arena/961971ed-cicc:docs/INTEGRATION_CONTRACTS.md` at
commit `2c6af20` (Coordination Contract v1.0, M11-02) and Issue #5 (ops worker
heartbeat).

| Contract surface | Implemented model | Enforcement |
|---|---|---|
| Agent registration | `Agent1RegistrationPayload` | `extra="forbid"`; canonical `agent="agent-2-threat-intel"` with `meta.acting_agent="agent-6-backup"` and `meta.primary_owner="agent-2"` so the backup never impersonates the primary owner |
| Agent heartbeat | `Agent1HeartbeatPayload` | `extra="forbid"`; `status` + `active_tasks >= 0` |
| Ops worker heartbeat (Issue #5) | `Agent1OpsWorkerHeartbeatPayload` | `interval_seconds` clamped to `10..60` (Issue #5 requires `>=30s`); `stall_threshold_seconds >= 60`, default `120` (= 4 missed beats) |
| Task enqueue | `Agent1TaskEnqueuePayload` | `kind` must match `^[a-z0-9_]+$`; `task_id` must be path-safe `[A-Za-z0-9_.:-]` (**slashes rejected**, so a task id can never escape its URL path segment); `priority` `1..10`; `ttl_s`/`timeout_s` `>= 1`; `repo`/`branch_ref` default to this repo and this branch |

Identity honesty: the registration payload registers **Agent 2's domain identity** while recording
in `meta` that the work was performed by Agent 6 as backup. Agent 2 remains the primary owner and
can adopt or reject the registration without an identity conflict.

---

## 2. Agent 3 — Vulnerability Intelligence (M1–M6)

Source read from `origin/arena/fa0df787-cicc:docs/vulnerability-intelligence/INTEGRATION_READINESS.md` §3.2.

### M1 — KEV `requiredAction`
Agent 3 proposed `kev_required_action: str | None` on the KEV layer.
**Resolution:** `KEVVulnerabilityCorrelationDTO.kev_required_action` carries the **verbatim** CISA
`requiredAction` string, sourced from `CISAKEVRecordModel.required_action`. `ingest_kev_catalog_feed`
maps the official CISA field name `requiredAction` → `required_action`, defaulting to
`"Apply updates per vendor instructions"` when absent. `kev_due_date` and `known_ransomware_use`
travel with it.

### M2 — Vendor advisory identifiers must not be CVE aliases
Agent 3 proposed `vendor_advisories: tuple[VendorAdvisory, ...]` **separate** from CVE `aliases`
(`DSA-*` / `USN-*` / `RHSA-*`).
**Resolution:** `KEVVulnerabilityCorrelationDTO.vendor_advisories: list[VendorAdvisoryLinkDTO]` is a
distinct, structured field. Each link carries `advisory_id`, `vendor_source_id`, affected
products/versions, `required_action`, `severity`, `date_published`, `provenance`, and the
experimental label. `VendorSecurityAdvisoryIngestionService.parse_vendor_advisory` supports
`msrc`, `cisco`, `redhat`, `ubuntu`, `debian` (`DSA-*`) and `ghsa` (`GHSA-*`), and
`get_advisories_for_cve(cve_id)` provides the join.

### M3 — `mapping_type` in ATT&CK rollups
CTID defines four mapping types: `exploitation_technique`, `primary_impact`, `secondary_impact`,
`mitigation`.
**Resolution:** `TechniqueRollupDTO.techniques` is filtered to **`exploitation_technique` only**, so
impact/mitigation mappings can never inflate an exposure count. `techniques_by_mapping_type` provides
the additive split across all four types for drill-down. `VALID_MAPPING_TYPES` pins the enum and
`AttackTechniqueMappingEntryDTO` rejects anything outside it.

### M4 — Sub-technique identity
A rollup key must be the **full canonical identifier including the sub-technique suffix**
(`T1059.001`), never silently truncated to `T1059`.
**Resolution:** `AttackTechniqueMappingEntryDTO.technique_id` validates against
`^T\d{4}(\.\d{3})?$` and case-normalizes to upper. `T1059.0011` and `TECH-1` are rejected.
`MITRETechniqueModel.canonical_id` enforces the same rule on the ingestion side.

### M5 — Provenance granularity
`sources` is the **deduplicated set** of source names; `provenance` is the **append-only
observation history**; therefore `len(provenance) >= len(sources)`.
**Resolution:** `ProvenanceSummaryDTO` exposes all three numbers explicitly —
`sources` (dedup, insertion-ordered), `observations_count` (`== len(observation_sources)`),
`corroboration_count` (`== len(sources)`). The invariant `observations_count >= len(sources)` is
asserted in tests. `OSINTIngestionService` maintains the same shape per entity.

### M6 — `consulted` tri-state
"Mapping not consulted" must never be confused with "0 techniques mapped".
**Resolution:** `VALID_CONSULTED_STATES = {consulted_mapped, consulted_unmapped, not_consulted}`.
`CVETechniqueCorrelationDTO.consulted` and `TechniqueRollupDTO.consulted` are validated against it.
The same tri-state discipline is applied to KEV: `KEVVulnerabilityCorrelationDTO.kev` is
`None` (not consulted) / `False` (consulted, absent) / `True` (consulted, present) — see
`ThreatIntelligenceIntegrationBridge.correlate_cve_kev_and_advisories(cve_id, kev_consulted=...)`.

---

## 3. Agent 4 — Frontend typed DTO envelopes

| Envelope | Purpose |
|---|---|
| `ThreatIntelListEnvelope` | `data[]` + `page` (`limit`, `total_count`, opaque `next_cursor`) + `freshness` + `tenant_id` |
| `ThreatIntelDetailEnvelope` | single `data` object + `provenance_summary` + `freshness` + `tenant_id` |
| `ThreatIntelErrorEnvelope` | `status` (validated `400..599`), `error_code`, `message`, optional `details` |
| `FreshnessMetaDTO` | `origin`, `verification_mode`, `host_mount_status`, `collected_at`, `last_successful_sync`, `is_stale` |

Two frontend-critical honesty fields:

- **`verification_mode`** defaults to `fixture_tested` and must be promoted to `oracle_verified` or
  `live_verified` only by a caller that actually contacted a live source. The UI can therefore never
  render fixture data as verified.
- **`host_mount_status`** defaults to `not_mounted_pending_owner_approval`. Threat Intelligence
  exposes **no HTTP routes of its own**; this field tells the frontend explicitly that the endpoints
  do not exist yet rather than letting a 404 be mistaken for an empty result set.

---

## 4. `ThreatIntelligenceIntegrationBridge`

Single entry point for all three contract families. Constructor:
`ThreatIntelligenceIntegrationBridge(kev_service=None, advisory_service=None, tenant_id=None)`.

| Method | Returns | Notes |
|---|---|---|
| `build_agent1_registration()` | `Agent1RegistrationPayload` | Agent 1 contract #1 |
| `build_agent1_ops_heartbeat(worker_id, details)` | `Agent1OpsWorkerHeartbeatPayload` | Issue #5 |
| `correlate_cve_kev_and_advisories(cve_id, kev_consulted=True)` | `KEVVulnerabilityCorrelationDTO` | M1 + M2 + M6 |
| `build_technique_rollup(correlations, mapping_loaded=True)` | `TechniqueRollupDTO` | M3 + M4 + M6 |
| `summarize_provenance(entity_id, observation_sources)` | `ProvenanceSummaryDTO` | M5 |

Degradation is explicit rather than silent: with no `kev_service` injected, or with
`kev_consulted=False`, `kev` is `None` — never `False`. With `mapping_loaded=False`, the rollup
reports `consulted="not_consulted"` and zeroed split counts.

---

## 5. What is explicitly *not* claimed

| Claim | Status |
|---|---|
| Live CISA KEV catalog fetched over HTTPS | **Not done.** `ingest_kev_catalog_feed` is fixture-tested against the official CISA JSON schema shape only |
| Live MITRE ATT&CK Enterprise bundle fetched | **Not done.** `ingest_stix_attack_bundle` is fixture-tested |
| Live MSRC / Cisco / Red Hat / Ubuntu / Debian / GHSA feeds fetched | **Not done.** All six parsers are fixture-tested |
| Live STIX 2.1 / TAXII 2.1 server contacted | **Not done.** `evaluate_stix_taxii_compatibility`, bundle and envelope ingestion are fixture-tested |
| URLhaus / MalwareBazaar live queries | **Not done.** `parse_urlhaus_entry` / `parse_malwarebazaar_entry` are fixture-tested parsers |
| Agent 1 contract accepted and mounted | **No.** Models only |
| Agent 3 M1–M6 resolutions accepted by Agent 3 | **No.** Models only |
| Agent 4 DTO envelopes wired into a running frontend | **No.** Models only |
| Any outbound network call by this package | **None.** No module in `apps/threat_intelligence/` performs network I/O |

---

## 6. Coordination requests

1. **Agent 1** — confirm or amend `Agent1RegistrationPayload.meta` and the `>=30s` / `120s` heartbeat
   cadence. The `task_id` slash prohibition is load-bearing; if the coordination service accepts
   slashes, that must be stated explicitly.
2. **Agent 3** — confirm the M1–M6 resolutions above, in particular (a) `vendor_advisories` staying
   out of CVE `aliases`, and (b) `techniques` being exploitation-only while
   `techniques_by_mapping_type` carries the full split.
3. **Agent 4** — confirm `FreshnessMetaDTO` field names and that `host_mount_status` is the
   preferred way to signal unmounted routes.
4. **Owner / Agent 2** — decide whether these contract modules land on `main` independently or are
   folded into PR #3. Agent 6 has not merged anything and has not touched `arena/93315d2c-cicc`.
