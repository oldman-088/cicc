import {
  contractArray,
  contractBoolean,
  contractEnum,
  contractJsonObject,
  contractJsonValue,
  contractNonEmptyString,
  contractNonNegativeInteger,
  contractNumber,
  contractNonNegativeNumber,
  contractNullableString,
  contractObject,
  contractString,
  contractTimestamp,
  type JsonObject,
  type JsonValue,
} from "./decoder";

export const AGENT2_EXPERIMENTAL_LABEL = "EXPERIMENTAL_DEMO_DATA_ONLY" as const;

export const THREAT_RELATIONSHIP_TYPES = [
  "ATTRIBUTED_TO", "USES", "TARGETS", "INDICATES", "ASSOCIATED_WITH",
  "EXPLOITS", "AFFECTS", "OBSERVED_IN", "DERIVED_FROM", "CORROBORATES",
  "CONTRADICTS", "CONTAINS", "DEPENDS_ON", "BELONGS_TO", "RELATED_TO",
] as const;
export const THREAT_CONFIDENCE_LEVELS = ["LOW", "MEDIUM", "HIGH", "CONFIRMED", "INFERRED"] as const;

export type ThreatRelationshipType = (typeof THREAT_RELATIONSHIP_TYPES)[number];
export type ThreatConfidenceLevel = (typeof THREAT_CONFIDENCE_LEVELS)[number];

export type ThreatEntityReferenceCandidate = {
  entity_id: string;
  entity_type: string;
  name: string | null;
  experimental_label: string;
};

export type ThreatEvidenceCandidate = {
  evidence_id: string;
  source: string;
  timestamp: string;
  description: string;
  confidence: ThreatConfidenceLevel;
  provenance: string;
  experimental_label: string;
};

export type ThreatRelationshipCandidate = {
  relationship_id: string;
  source_entity: ThreatEntityReferenceCandidate;
  target_entity: ThreatEntityReferenceCandidate;
  relationship_type: ThreatRelationshipType;
  confidence: ThreatConfidenceLevel;
  evidence: ThreatEvidenceCandidate[];
  provenance: string;
  temporal_context: JsonObject | null;
  confirmed: boolean;
  conflicting_intelligence: JsonValue[] | null;
  created_at: string;
  updated_at: string;
  experimental_label: string;
};

export type ThreatRelationshipPageCandidate = {
  items: ThreatRelationshipCandidate[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
};

export type ThreatTraversalItemCandidate = {
  depth: number;
  relationship: ThreatRelationshipCandidate;
};

export type ThreatTraversalPageCandidate = {
  entity_id: string;
  entity_type: string;
  max_depth: number;
  visited_entities: number;
  items: ThreatTraversalItemCandidate[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
  experimental_label: string;
};

export type ThreatEvidenceObservationCandidate = {
  relationship_id: string;
  evidence_id: string;
  source: string;
  timestamp: string;
  description: string;
  confidence: ThreatConfidenceLevel;
  provenance: string;
  relationship_provenance: string;
  experimental_label: string;
  relationship_experimental_label: string;
};

export type ThreatCollectionFreshnessCandidate = {
  observation: ThreatEvidenceObservationCandidate;
  as_of: string;
  max_age_seconds: number;
  age_seconds: number;
  status: "within_window" | "outside_window" | "future_collection_time";
};

/** Internal caller-scoped observation summary; no score or HTTP route is defined. */
export type ThreatObservationAssessmentCandidate = {
  relationship_count: number;
  declared_confidence_counts: Record<ThreatConfidenceLevel, number>;
  declared_confirmed_count: number;
  confirmed_without_evidence: string[];
  evidence_count: number;
  distinct_source_count: number;
  observations: ThreatEvidenceObservationCandidate[];
  conflicts: Array<{ relationship_id: string; relationship_provenance: string; experimental_label: string; conflict: JsonValue }>;
  explanation: string;
};

/** The analyst-input score remains an experimental internal helper, not an API DTO. */
export type ThreatAnalystEvidenceRatingCandidate = {
  evidence_id: string;
  strength: string;
  source_reliability: string;
  stance: "supports" | "opposes" | "unknown";
  assessor: string;
  rationale_ref: string;
};

export const agent2ThreatReadiness = {
  packageRoutes: "proposed-standalone-only",
  hostMount: "not-mounted",
  trustedPrincipalTenantBinding: "pending",
  hostErrorMapping: "pending",
  sourceFreshnessContract: "not-provided-by-relationship-api",
  assessmentOverHttp: "not-exposed",
  conflictResolution: "not-implemented",
  liveProviderVerified: false,
} as const;

function parseConfidence(value: unknown, path: string): ThreatConfidenceLevel {
  return contractEnum(value, THREAT_CONFIDENCE_LEVELS, path);
}

function parseRelationshipType(value: unknown, path: string): ThreatRelationshipType {
  return contractEnum(value, THREAT_RELATIONSHIP_TYPES, path);
}

function parseEntity(value: unknown, path: string): ThreatEntityReferenceCandidate {
  const input = contractObject(value, path);
  return {
    entity_id: contractNonEmptyString(input.entity_id, `${path}.entity_id`),
    entity_type: contractNonEmptyString(input.entity_type, `${path}.entity_type`),
    name: contractNullableString(input.name, `${path}.name`),
    experimental_label: contractString(input.experimental_label, `${path}.experimental_label`),
  };
}

function parseEvidence(value: unknown, path: string): ThreatEvidenceCandidate {
  const input = contractObject(value, path);
  return {
    evidence_id: contractNonEmptyString(input.evidence_id, `${path}.evidence_id`),
    source: contractNonEmptyString(input.source, `${path}.source`),
    timestamp: contractTimestamp(input.timestamp, `${path}.timestamp`),
    description: contractNonEmptyString(input.description, `${path}.description`),
    confidence: parseConfidence(input.confidence, `${path}.confidence`),
    provenance: contractNonEmptyString(input.provenance, `${path}.provenance`),
    experimental_label: contractString(input.experimental_label, `${path}.experimental_label`),
  };
}

export function parseThreatRelationshipCandidate(value: unknown, path = "relationship"): ThreatRelationshipCandidate {
  const input = contractObject(value, path);
  const temporalContext = input.temporal_context === null
    ? null
    : contractJsonObject(input.temporal_context, `${path}.temporal_context`);
  const conflicts = input.conflicting_intelligence === null
    ? null
    : contractArray(input.conflicting_intelligence, `${path}.conflicting_intelligence`, contractJsonValue);
  return {
    relationship_id: contractNonEmptyString(input.relationship_id, `${path}.relationship_id`),
    source_entity: parseEntity(input.source_entity, `${path}.source_entity`),
    target_entity: parseEntity(input.target_entity, `${path}.target_entity`),
    relationship_type: parseRelationshipType(input.relationship_type, `${path}.relationship_type`),
    confidence: parseConfidence(input.confidence, `${path}.confidence`),
    evidence: contractArray(input.evidence, `${path}.evidence`, parseEvidence),
    provenance: contractNonEmptyString(input.provenance, `${path}.provenance`),
    temporal_context: temporalContext,
    confirmed: contractBoolean(input.confirmed, `${path}.confirmed`),
    conflicting_intelligence: conflicts,
    created_at: contractTimestamp(input.created_at, `${path}.created_at`),
    updated_at: contractTimestamp(input.updated_at, `${path}.updated_at`),
    experimental_label: contractString(input.experimental_label, `${path}.experimental_label`),
  };
}

function parseBoundedPageNumbers(input: Record<string, unknown>, path: string) {
  const limit = contractNonNegativeInteger(input.limit, `${path}.limit`);
  const offset = contractNonNegativeInteger(input.offset, `${path}.offset`);
  if (limit < 1 || limit > 500) throw new Error(`Contract payload at ${path}.limit must be between 1 and 500`);
  if (offset > 100_000) throw new Error(`Contract payload at ${path}.offset exceeds 100000`);
  return { limit, offset };
}

export function parseThreatRelationshipPageCandidate(value: unknown): ThreatRelationshipPageCandidate {
  const input = contractObject(value, "relationship-page");
  const { limit, offset } = parseBoundedPageNumbers(input, "relationship-page");
  return {
    items: contractArray(input.items, "relationship-page.items", parseThreatRelationshipCandidate),
    total: contractNonNegativeInteger(input.total, "relationship-page.total"),
    offset,
    limit,
    has_more: contractBoolean(input.has_more, "relationship-page.has_more"),
  };
}

function parseTraversalItem(value: unknown, path: string): ThreatTraversalItemCandidate {
  const input = contractObject(value, path);
  return {
    depth: contractNonNegativeInteger(input.depth, `${path}.depth`),
    relationship: parseThreatRelationshipCandidate(input.relationship, `${path}.relationship`),
  };
}

export function parseThreatTraversalPageCandidate(value: unknown): ThreatTraversalPageCandidate {
  const input = contractObject(value, "relationship-traversal");
  const { limit, offset } = parseBoundedPageNumbers(input, "relationship-traversal");
  const maxDepth = contractNonNegativeInteger(input.max_depth, "relationship-traversal.max_depth");
  if (maxDepth > 8) throw new Error("Contract payload at relationship-traversal.max_depth exceeds 8");
  return {
    entity_id: contractNonEmptyString(input.entity_id, "relationship-traversal.entity_id"),
    entity_type: contractNonEmptyString(input.entity_type, "relationship-traversal.entity_type"),
    max_depth: maxDepth,
    visited_entities: contractNonNegativeInteger(input.visited_entities, "relationship-traversal.visited_entities"),
    items: contractArray(input.items, "relationship-traversal.items", parseTraversalItem),
    total: contractNonNegativeInteger(input.total, "relationship-traversal.total"),
    offset,
    limit,
    has_more: contractBoolean(input.has_more, "relationship-traversal.has_more"),
    experimental_label: contractString(input.experimental_label, "relationship-traversal.experimental_label"),
  };
}

function parseObservation(value: unknown, path: string): ThreatEvidenceObservationCandidate {
  const input = contractObject(value, path);
  return {
    relationship_id: contractNonEmptyString(input.relationship_id, `${path}.relationship_id`),
    evidence_id: contractNonEmptyString(input.evidence_id, `${path}.evidence_id`),
    source: contractNonEmptyString(input.source, `${path}.source`),
    timestamp: contractTimestamp(input.timestamp, `${path}.timestamp`),
    description: contractNonEmptyString(input.description, `${path}.description`),
    confidence: parseConfidence(input.confidence, `${path}.confidence`),
    provenance: contractNonEmptyString(input.provenance, `${path}.provenance`),
    relationship_provenance: contractNonEmptyString(input.relationship_provenance, `${path}.relationship_provenance`),
    experimental_label: contractString(input.experimental_label, `${path}.experimental_label`),
    relationship_experimental_label: contractString(input.relationship_experimental_label, `${path}.relationship_experimental_label`),
  };
}

/** Internal collection-age result; this is not source freshness or a host response. */
export function parseThreatCollectionFreshnessCandidate(value: unknown): ThreatCollectionFreshnessCandidate {
  const input = contractObject(value, "collection-freshness");
  return {
    observation: parseObservation(input.observation, "collection-freshness.observation"),
    as_of: contractTimestamp(input.as_of, "collection-freshness.as_of"),
    max_age_seconds: contractNonNegativeNumber(input.max_age_seconds, "collection-freshness.max_age_seconds"),
    age_seconds: contractNumberWithNegativeAllowed(input.age_seconds, "collection-freshness.age_seconds"),
    status: contractEnum(input.status, ["within_window", "outside_window", "future_collection_time"] as const, "collection-freshness.status"),
  };
}

function parseObservationConflict(value: unknown, path: string): ThreatObservationAssessmentCandidate["conflicts"][number] {
  const input = contractObject(value, path);
  return {
    relationship_id: contractNonEmptyString(input.relationship_id, `${path}.relationship_id`),
    relationship_provenance: contractNonEmptyString(input.relationship_provenance, `${path}.relationship_provenance`),
    experimental_label: contractString(input.experimental_label, `${path}.experimental_label`),
    conflict: contractJsonValue(input.conflict, `${path}.conflict`),
  };
}

/** Decode an internal package summary only; it is not exposed by the HTTP API. */
export function parseThreatObservationAssessmentCandidate(value: unknown): ThreatObservationAssessmentCandidate {
  const input = contractObject(value, "relationship-assessment");
  const countsInput = contractObject(input.declared_confidence_counts, "relationship-assessment.declared_confidence_counts");
  const declaredConfidenceCounts = Object.fromEntries(
    THREAT_CONFIDENCE_LEVELS.map((level) => [
      level,
      contractNonNegativeInteger(countsInput[level], `relationship-assessment.declared_confidence_counts.${level}`),
    ]),
  ) as Record<ThreatConfidenceLevel, number>;
  const unknownLevels = Object.keys(countsInput).filter((level) => !(THREAT_CONFIDENCE_LEVELS as readonly string[]).includes(level));
  if (unknownLevels.length > 0) {
    throw new Error(`Contract payload at relationship-assessment.declared_confidence_counts has unknown levels: ${unknownLevels.join(", ")}`);
  }
  return {
    relationship_count: contractNonNegativeInteger(input.relationship_count, "relationship-assessment.relationship_count"),
    declared_confidence_counts: declaredConfidenceCounts,
    declared_confirmed_count: contractNonNegativeInteger(input.declared_confirmed_count, "relationship-assessment.declared_confirmed_count"),
    confirmed_without_evidence: contractArray(input.confirmed_without_evidence, "relationship-assessment.confirmed_without_evidence", contractNonEmptyString),
    evidence_count: contractNonNegativeInteger(input.evidence_count, "relationship-assessment.evidence_count"),
    distinct_source_count: contractNonNegativeInteger(input.distinct_source_count, "relationship-assessment.distinct_source_count"),
    observations: contractArray(input.observations, "relationship-assessment.observations", parseObservation),
    conflicts: contractArray(input.conflicts, "relationship-assessment.conflicts", parseObservationConflict),
    explanation: contractString(input.explanation, "relationship-assessment.explanation"),
  };
}

/** Relationship package errors have no approved host/BFF envelope yet. */
export type ThreatHostErrorContractStatus = "unresolved";
export type ThreatHostErrorCandidate = {
  status: number;
  body: unknown;
  contract: ThreatHostErrorContractStatus;
};

function contractNumberWithNegativeAllowed(value: unknown, path: string): number {
  return contractNumber(value, path);
}
