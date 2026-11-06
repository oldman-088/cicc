import { describe, expect, it } from "vitest";
import {
  parseDomainLifecycleListCandidate,
  parseDomainLifecycleStatusCandidate,
  parseDomainMetricsCandidate,
  parseDomainProvenanceCandidate,
  agent1DomainUnresolvedSurfaces,
} from "./agent1-domains";
import {
  parseThreatCollectionFreshnessCandidate,
  parseThreatObservationAssessmentCandidate,
  parseThreatRelationshipPageCandidate,
  parseThreatTraversalPageCandidate,
  agent2ThreatReadiness,
} from "./agent2-threat-intelligence";
import {
  parseVulnerabilityAssessmentReportCandidate,
  parseVulnerabilityErrorCandidate,
  parseVulnerabilityInteropExportCandidate,
  parseVulnerabilityListCandidate,
  parseVulnerabilityPackageInventoryItemCandidate,
  parseVulnerabilityRecordCandidate,
  parseVulnerabilitySbomIngestResultCandidate,
  agent3VulnerabilityReadiness,
  vulnerabilityContractDrift,
  vulnerabilitySbomUploadReadiness,
} from "./agent3-vulnerability-intelligence";

const domainEvidence = {
  status: "NOT_MOUNTED",
  version: null,
  source_ref: null,
  mounted_at: null,
  invokes: 0,
  successes: 0,
  consecutive_failures: 0,
  last_stale: null,
  stale_after_s: null,
  last_invoke_at: null,
  last_error: null,
  circuit: { open: false, opened_at: null, threshold: 5, cooldown_s: 30, opens: 0, closes: 0 },
  mount_count: 0,
  previous_version: null,
};

const relationshipRecord = {
  relationship_id: "00000000-0000-4000-8000-000000000001",
  source_entity: { entity_id: "actor-1", entity_type: "ThreatActor", name: "Example actor", experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY" },
  target_entity: { entity_id: "campaign-1", entity_type: "Campaign", name: null, experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY" },
  relationship_type: "ATTRIBUTED_TO",
  confidence: "HIGH",
  evidence: [{
    evidence_id: "00000000-0000-4000-8000-000000000002",
    source: "recorded-test-source",
    timestamp: "2026-11-06T09:00:00Z",
    description: "Test-only evidence description",
    confidence: "MEDIUM",
    provenance: "recorded fixture reference",
    experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY",
  }],
  provenance: "recorded fixture reference",
  temporal_context: null,
  confirmed: false,
  conflicting_intelligence: [{ field: "relationship_type", kept: "ATTRIBUTED_TO", discarded: ["RELATED_TO"] }],
  created_at: "2026-11-06T09:00:00Z",
  updated_at: "2026-11-06T09:00:00Z",
  experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY",
};

const vulnerabilityRecord = {
  cve: "CVE-2026-1002",
  entity_id: "fixture-entity-2",
  origin: "fixture",
  collected_at: "2026-11-04T09:00:00+00:00",
  severity: "high",
  cvss: { assessed: true, base_score: 7.5, severity: "high", source: "nvd", vector: "AV:N/AC:L", version: "3.1" },
  kev: null,
  epss: { score: null, percentile: null, model_date: null },
  sources: ["nvd", "osv"],
  summary: "Test-only fixture vulnerability",
  confidence: null,
  affected: [],
  references: [],
  freshness: null,
  freshness_view: { age_seconds: null, assessed_at: "2026-11-04T09:00:00+00:00", observed_at: null, reason: "No observation timestamp", state: "unknown" },
  policy: null,
  record_status: "undergoing_analysis",
  withdrawn: null,
  conflicts: [{ field: "severity", kept: "high", discarded: ["critical"], dissenters: ["osv"] }],
  ssvc: {},
};

describe("M45 read-only contract candidate decoders", () => {
  it("validates the documented M44 lifecycle and metrics candidates without enabling a route", () => {
    const lifecycle = parseDomainLifecycleListCandidate({
      domains: [{ kind: "threat_intel", version: null, source_ref: null, mounted_at: null, status: "NOT_MOUNTED" }],
      statuses: { threat_intel: domainEvidence },
      states: ["NOT_MOUNTED", "UNKNOWN"],
      note: "Documented contract candidate, not a host response",
    });
    expect(lifecycle.statuses.threat_intel.mount_count).toBe(0);
    expect(parseDomainLifecycleStatusCandidate({ kind: "threat_intel", status: "NOT_MOUNTED", evidence: domainEvidence }).evidence.circuit?.open).toBe(false);

    const metrics = parseDomainMetricsCandidate({
      domains: {
        threat_intel: {
          invokes: 4, successes: 3, failures: 1, success_rate: 0.75, timeouts: 1, retries: 2,
          stale_count: 0, skew_count: 0,
          latency: { count: 4, avg_s: 0.5, max_s: 1.2, last_s: 0.3 },
          circuit: { open: false, opened_at: null, threshold: 5, cooldown_s: 30, opens: 0, closes: 1 },
          mount_count: 1, status: "DEGRADED",
        },
      },
      labels: ["kind"],
      note: "kind-bounded labels only",
    });
    expect(metrics.domains.threat_intel.success_rate).toBe(0.75);
    expect(() => parseDomainMetricsCandidate({ domains: {}, labels: ["kind", "tenant_id"], note: "bad" })).toThrow(/bounded 'kind' label/);
    expect(agent1DomainUnresolvedSurfaces).toMatchObject({ diagnostics: "not-defined", perRouteErrorEnvelope: "unresolved", ownerApproval: "pending" });
  });

  it("preserves provenance, collection freshness, and circuit/mount fields as evidence, not durability claims", () => {
    const provenance = parseDomainProvenanceCandidate({
      source: "agent-reported-source", produced_at: "2026-11-06T09:00:00Z", confidence: 0.6,
      freshness_s: 30, stale: false, freshness: { stale: false, age_s: 5, clock_skew_s: 0, basis: "freshness_s" },
      domain_specific: { version_label: "1.2.0" },
    });
    expect(provenance.confidence).toBe(0.6);
    expect(provenance.domain_specific).toEqual({ version_label: "1.2.0" });
    expect(() => parseDomainProvenanceCandidate({ source: "x", produced_at: null, confidence: 2, freshness_s: null })).toThrow(/between 0 and 1/);
  });

  it("decodes the Agent 2 package relationship/page/traversal candidate and retains explicit conflicts", () => {
    const page = parseThreatRelationshipPageCandidate({ items: [relationshipRecord], total: 1, offset: 0, limit: 100, has_more: false });
    expect(page.items[0].evidence[0].source).toBe("recorded-test-source");
    expect(page.items[0].conflicting_intelligence).toEqual(relationshipRecord.conflicting_intelligence);
    expect(page.items[0].experimental_label).toBe("EXPERIMENTAL_DEMO_DATA_ONLY");
    expect(() => parseThreatRelationshipPageCandidate({ items: [], total: 0, offset: 0, limit: 0, has_more: false })).toThrow(/between 1 and 500/);

    const traversal = parseThreatTraversalPageCandidate({
      entity_id: "actor-1", entity_type: "ThreatActor", max_depth: 3, visited_entities: 2,
      items: [{ depth: 1, relationship: relationshipRecord }], total: 1, offset: 0, limit: 100,
      has_more: false, experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY",
    });
    expect(traversal.items[0].depth).toBe(1);
    expect(agent2ThreatReadiness).toMatchObject({ hostMount: "not-mounted", assessmentOverHttp: "not-exposed", liveProviderVerified: false });
  });

  it("decodes Agent 2's internal observation summary without creating a live/score claim", () => {
    const assessment = parseThreatObservationAssessmentCandidate({
      relationship_count: 1,
      declared_confidence_counts: { LOW: 0, MEDIUM: 0, HIGH: 1, CONFIRMED: 0, INFERRED: 0 },
      declared_confirmed_count: 0,
      confirmed_without_evidence: [],
      evidence_count: 1,
      distinct_source_count: 1,
      observations: [{
        relationship_id: relationshipRecord.relationship_id,
        evidence_id: "00000000-0000-4000-8000-000000000002",
        source: "recorded-test-source", timestamp: "2026-11-06T09:00:00Z", description: "Test-only evidence description",
        confidence: "MEDIUM", provenance: "recorded fixture reference", relationship_provenance: "recorded fixture reference",
        experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY", relationship_experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY",
      }],
      conflicts: [{
        relationship_id: relationshipRecord.relationship_id, relationship_provenance: "recorded fixture reference",
        experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY", conflict: { field: "relationship_type", values: ["ATTRIBUTED_TO", "RELATED_TO"] },
      }],
      explanation: "Counts describe supplied declarations and observations, not truth or a calculated score.",
    });
    expect(assessment.declared_confidence_counts.HIGH).toBe(1);
    expect(assessment.conflicts).toHaveLength(1);
    expect(assessment.explanation).toMatch(/not truth/);
    expect(() => parseThreatObservationAssessmentCandidate({
      relationship_count: 0, declared_confidence_counts: { HIGH: 0 }, declared_confirmed_count: 0,
      confirmed_without_evidence: [], evidence_count: 0, distinct_source_count: 0, observations: [], conflicts: [], explanation: "counts only",
    })).toThrow(/declared_confidence_counts\.LOW/);
  });

  it("keeps caller-horizon age classification distinct from provider freshness", () => {
    const freshness = parseThreatCollectionFreshnessCandidate({
      observation: {
        relationship_id: "rel-1", evidence_id: "evidence-1", source: "test source",
        timestamp: "2026-11-06T09:00:00Z", description: "test-only observation", confidence: "HIGH",
        provenance: "fixture", relationship_provenance: "fixture", experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY",
        relationship_experimental_label: "EXPERIMENTAL_DEMO_DATA_ONLY",
      },
      as_of: "2026-11-06T08:59:00Z", max_age_seconds: 3600, age_seconds: -60,
      status: "future_collection_time",
    });
    expect(freshness.status).toBe("future_collection_time");
    expect(freshness.age_seconds).toBe(-60);
    expect(() => parseThreatCollectionFreshnessCandidate({
      observation: { ...freshness.observation, timestamp: "2026-11-06T09:00:00" },
      as_of: "2026-11-06T09:01:00Z", max_age_seconds: 60, age_seconds: 60, status: "within_window",
    })).toThrow(/explicit timezone/);
  });

  it("preserves vulnerability nulls, fixture origin, and known contract drift", () => {
    const parsed = parseVulnerabilityRecordCandidate(vulnerabilityRecord);
    expect(parsed.origin).toBe("fixture");
    expect(parsed.kev).toBeNull();
    expect(parsed.epss).toMatchObject({ score: null, percentile: null });
    expect(parsed.epss).not.toHaveProperty("available");
    expect(parsed.record_status).toBe("undergoing_analysis");
    expect(parsed.conflicts?.[0].discarded).toEqual(["critical"]);
    expect(vulnerabilityContractDrift.recordStatus.openapi).not.toContain("undergoing_analysis");
    expect(vulnerabilitySbomUploadReadiness).toMatchObject({ hostUploadRoute: "not-defined", validationDto: "not-defined" });
    expect(agent3VulnerabilityReadiness.liveProviderVerified).toBe(false);
  });

  it("decodes package inventory items without inventing an upload contract", () => {
    expect(parseVulnerabilityPackageInventoryItemCandidate({
      ecosystem: "npm", name: "example", version: "1.2.3", purl: "pkg:npm/example@1.2.3",
      asset: "service-a", direct: false, environment: "production",
    })).toEqual({
      ecosystem: "npm", name: "example", version: "1.2.3", purl: "pkg:npm/example@1.2.3",
      asset: "service-a", direct: false, environment: "production",
    });
    expect(() => parseVulnerabilityPackageInventoryItemCandidate({ ecosystem: "npm", name: "example", version: "" }))
      .toThrow(/version/);
  });

  it("decodes the package-local SBOM parse report and keeps incomplete inventory explicit", () => {
    const result = parseVulnerabilitySbomIngestResultCandidate({
      format: "cyclonedx-json", spec_version: "1.6", document_name: "test-bom", components: 1, duplicates: 0,
      assets: ["service-a"], licenses: { "pkg-a": ["Apache-2.0"] }, relationships: [["app", "pkg-a"]],
      skipped: [{ component: "unknown-version", reason: "no version: cannot be range matched" }],
      complete: false, warnings: ["One component could not be assessed"],
      inventory: { dependencies: 1, ecosystems: ["npm"], assets: ["service-a"] },
    });
    expect(result.complete).toBe(false);
    expect(result.skipped[0].reason).toMatch(/no version/);
    expect(result.inventory.dependencies).toBe(1);
    expect(() => parseVulnerabilitySbomIngestResultCandidate({
      format: "cyclonedx-json", spec_version: null, document_name: null, components: 0, duplicates: 0,
      assets: [], licenses: {}, relationships: [["only-one-item"]], skipped: [], complete: false, warnings: [],
      inventory: { dependencies: 0, ecosystems: [], assets: [] },
    })).toThrow(/two-item relationship tuple/);
  });

  it("validates opaque cursor, typed errors, export coverage, and fixture assessment warnings", () => {
    const page = parseVulnerabilityListCandidate({
      data: [vulnerabilityRecord],
      page: { limit: 50, next_cursor: "opaque-cursor:test", has_more: true },
      filters: { severity: null, kev_only: false, order: "cve" },
    });
    expect(page.page.next_cursor).toBe("opaque-cursor:test");
    expect(parseVulnerabilityErrorCandidate({ error: { code: "not_found", message: "not found", field: null } }).error.code).toBe("not_found");

    const exported = parseVulnerabilityInteropExportCandidate({
      document: { bomFormat: "CycloneDX" },
      meta: { format: "vex", generated_at: "2026-11-06T09:00:00Z", record_count: 1, exposure_evaluated: false, unassessed: ["CVE-2026-1002"], empty: false },
    });
    expect(exported.meta.exposure_evaluated).toBe(false);
    expect(exported.meta.unassessed).toEqual(["CVE-2026-1002"]);

    const report = parseVulnerabilityAssessmentReportCandidate({
      origin: "fixture", live_verified: false, notice: "Test-only report",
      exposure: { affected: 0, unexplorable: ["CVE-2026-1002"], unverified: 1, clean: false, warnings: ["inventory incomplete"] },
    });
    expect(report.live_verified).toBe(false);
    expect(report.exposure?.warnings).toEqual(["inventory incomplete"]);
    expect(() => parseVulnerabilityListCandidate({ data: [], page: { limit: 50, next_cursor: 1, has_more: false }, filters: {} })).toThrow(/string/);
  });
});
