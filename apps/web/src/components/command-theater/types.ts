export const SUPPORTED_LOCALES = ["en", "ar", "fa"] as const;

export type Locale = (typeof SUPPORTED_LOCALES)[number];

export type IntelligenceEntityType =
  | "threat-actor"
  | "campaign"
  | "domain"
  | "incident"
  | "asset";

export const INTELLIGENCE_ENTITY_TYPES: readonly IntelligenceEntityType[] = [
  "threat-actor",
  "campaign",
  "domain",
  "incident",
  "asset",
];

export type IntelligenceRelationshipType =
  | "associated-with"
  | "uses"
  | "observed-in"
  | "affects";

export const INTELLIGENCE_RELATIONSHIP_TYPES: readonly IntelligenceRelationshipType[] = [
  "associated-with",
  "uses",
  "observed-in",
  "affects",
];

export type ConfidenceBasis =
  | "illustrative"
  | "analyst-assessed"
  | "model-assessed"
  | "unavailable";

export type ConfidenceAssessment =
  | {
      value: number;
      basis: Exclude<ConfidenceBasis, "unavailable">;
      method?: string;
      assessedAt?: string;
    }
  | {
      value: null;
      basis: "unavailable";
    };

export type VerificationStatus =
  | "verified"
  | "unverified"
  | "inferred"
  | "illustrative"
  | "unknown";

export type EvidenceReference = {
  id: string;
  label: string;
  sourceName: string;
  status: "verified" | "unverified";
  observedAt?: string;
};

export type ProvenanceRecord = {
  sourceName: string;
  sourceRecordId?: string;
  collectedAt?: string;
  publishedAt?: string;
};

export type GraphPosition = { x: number; y: number; z: number };

/**
 * Presentation-layer graph records, not a backend response schema.
 * Backend adapters must map real records into these types and preserve the
 * source/evidence/verification semantics instead of inferring them in the UI.
 */
export type IntelligenceNode = {
  id: string;
  label: string;
  type: IntelligenceEntityType;
  /** Optional layout hint; a deterministic display layout is assigned if absent. */
  position?: GraphPosition;
  confidence: ConfidenceAssessment;
  verificationStatus: VerificationStatus;
  provenance: ProvenanceRecord | null;
  evidence: EvidenceReference[];
};

export type PositionedIntelligenceNode = IntelligenceNode & {
  position: GraphPosition;
};

export type IntelligenceRelationship = {
  id: string;
  sourceId: string;
  targetId: string;
  type: IntelligenceRelationshipType;
  confidence: ConfidenceAssessment;
  verificationStatus: VerificationStatus;
  provenance: ProvenanceRecord | null;
  evidence: EvidenceReference[];
};

export type GraphFilters = {
  search?: string;
  entityType?: IntelligenceEntityType;
  relationshipType?: IntelligenceRelationshipType;
};

/** Cursor and filters belong to the frontend adapter contract, not an API route. */
export type GraphPageRequest = {
  cursor: string | null;
  limit: number;
  filters: Readonly<GraphFilters>;
};

export type GraphPage = {
  nodes: IntelligenceNode[];
  relationships: IntelligenceRelationship[];
  nextCursor: string | null;
  totalNodes?: number;
  totalRelationships?: number;
};

export type GraphDataSourceKind = "demo" | "backend";

/**
 * Inject a provider owned by the host application. This interface deliberately
 * makes no assumptions about endpoints, authentication, or backend payloads.
 */
export interface CommandTheaterDataSource {
  readonly kind: GraphDataSourceKind;
  loadPage(request: GraphPageRequest, signal: AbortSignal): Promise<GraphPage>;
}

export function isLocale(value: string): value is Locale {
  return SUPPORTED_LOCALES.some((locale) => locale === value);
}
