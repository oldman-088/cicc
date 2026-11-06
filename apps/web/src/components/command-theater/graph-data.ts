import {
  INTELLIGENCE_ENTITY_TYPES,
  INTELLIGENCE_RELATIONSHIP_TYPES,
  type ConfidenceAssessment,
  type EvidenceReference,
  type GraphPage,
  type GraphPosition,
  type IntelligenceNode,
  type IntelligenceRelationship,
  type PositionedIntelligenceNode,
  type ProvenanceRecord,
  type VerificationStatus,
} from "./types";
import { layoutGraphNodes } from "./graph-layout";

const VERIFICATION_STATUSES: readonly VerificationStatus[] = [
  "verified",
  "unverified",
  "inferred",
  "illustrative",
  "unknown",
];

export class GraphDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GraphDataError";
  }
}

function invalid(message: string): never {
  throw new GraphDataError(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown, field: string, maxLength = 2_000): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > maxLength) {
    return invalid(`Invalid ${field} in graph data.`);
  }
  return value;
}

function readOptionalString(
  value: unknown,
  field: string,
  maxLength = 2_000,
): string | undefined {
  if (value === undefined) return undefined;
  return readString(value, field, maxLength);
}

function readTimestamp(value: unknown, field: string): string | undefined {
  const timestamp = readOptionalString(value, field, 128);
  if (timestamp !== undefined && !Number.isFinite(Date.parse(timestamp))) {
    return invalid(`Invalid ${field} in graph data.`);
  }
  return timestamp;
}

function parsePosition(value: unknown, field: string): GraphPosition | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) return invalid(`Invalid ${field} in graph data.`);

  const x = value.x;
  const y = value.y;
  const z = value.z;
  if (
    typeof x !== "number" ||
    typeof y !== "number" ||
    typeof z !== "number" ||
    !Number.isFinite(x) ||
    !Number.isFinite(y) ||
    !Number.isFinite(z) ||
    x < 0 || x > 100 || y < 0 || y > 100 || Math.abs(z) > 100
  ) {
    return invalid(`Invalid ${field} in graph data; layout coordinates must be finite and normalized.`);
  }

  return { x, y, z };
}

function parseConfidence(value: unknown, field: string): ConfidenceAssessment {
  if (!isRecord(value)) return invalid(`Invalid ${field} in graph data.`);
  const basis = value.basis;

  if (basis === "unavailable") {
    if (value.value !== null) return invalid(`Invalid ${field} in graph data.`);
    return { value: null, basis };
  }

  if (
    basis !== "illustrative" &&
    basis !== "analyst-assessed" &&
    basis !== "model-assessed"
  ) {
    return invalid(`Invalid ${field} basis in graph data.`);
  }

  const score = value.value;
  if (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 1) {
    return invalid(`Invalid ${field} score in graph data; expected a number from 0 to 1.`);
  }

  const method = readOptionalString(value.method, `${field} method`, 512);
  const assessedAt = readTimestamp(value.assessedAt, `${field} assessment timestamp`);
  return {
    value: score,
    basis,
    ...(method ? { method } : {}),
    ...(assessedAt ? { assessedAt } : {}),
  };
}

function parseVerificationStatus(value: unknown, field: string): VerificationStatus {
  if (typeof value !== "string" || !VERIFICATION_STATUSES.includes(value as VerificationStatus)) {
    return invalid(`Invalid ${field} in graph data.`);
  }
  return value as VerificationStatus;
}

function parseProvenance(value: unknown, field: string): ProvenanceRecord | null {
  if (value === null) return null;
  if (!isRecord(value)) return invalid(`Invalid ${field} in graph data.`);

  const sourceName = readString(value.sourceName, `${field} source`, 512);
  const sourceRecordId = readOptionalString(value.sourceRecordId, `${field} record ID`, 512);
  const collectedAt = readTimestamp(value.collectedAt, `${field} collection timestamp`);
  const publishedAt = readTimestamp(value.publishedAt, `${field} publication timestamp`);

  return {
    sourceName,
    ...(sourceRecordId ? { sourceRecordId } : {}),
    ...(collectedAt ? { collectedAt } : {}),
    ...(publishedAt ? { publishedAt } : {}),
  };
}

function parseEvidence(value: unknown, field: string): EvidenceReference[] {
  if (!Array.isArray(value) || value.length > 1_000) {
    return invalid(`Invalid ${field} list in graph data.`);
  }

  return value.map((item, index) => {
    const itemField = `${field}[${index}]`;
    if (!isRecord(item)) return invalid(`Invalid ${itemField} in graph data.`);
    if (item.status !== "verified" && item.status !== "unverified") {
      return invalid(`Invalid ${itemField} status in graph data.`);
    }

    const observedAt = readTimestamp(item.observedAt, `${itemField} observation timestamp`);
    return {
      id: readString(item.id, `${itemField} ID`, 512),
      label: readString(item.label, `${itemField} label`, 1_000),
      sourceName: readString(item.sourceName, `${itemField} source`, 512),
      status: item.status,
      ...(observedAt ? { observedAt } : {}),
    };
  });
}

function parseNode(value: unknown, index: number): IntelligenceNode {
  const field = `nodes[${index}]`;
  if (!isRecord(value)) return invalid(`Invalid ${field} in graph data.`);
  if (
    typeof value.type !== "string" ||
    !INTELLIGENCE_ENTITY_TYPES.includes(value.type as IntelligenceNode["type"])
  ) {
    return invalid(`Invalid ${field} type in graph data.`);
  }

  const position = parsePosition(value.position, `${field} position`);
  return {
    id: readString(value.id, `${field} ID`, 512),
    label: readString(value.label, `${field} label`),
    type: value.type as IntelligenceNode["type"],
    ...(position ? { position } : {}),
    confidence: parseConfidence(value.confidence, `${field} confidence`),
    verificationStatus: parseVerificationStatus(value.verificationStatus, `${field} verification status`),
    provenance: parseProvenance(value.provenance, `${field} provenance`),
    evidence: parseEvidence(value.evidence, `${field} evidence`),
  };
}

function parseRelationship(value: unknown, index: number): IntelligenceRelationship {
  const field = `relationships[${index}]`;
  if (!isRecord(value)) return invalid(`Invalid ${field} in graph data.`);
  if (
    typeof value.type !== "string" ||
    !INTELLIGENCE_RELATIONSHIP_TYPES.includes(value.type as IntelligenceRelationship["type"])
  ) {
    return invalid(`Invalid ${field} type in graph data.`);
  }

  return {
    id: readString(value.id, `${field} ID`, 512),
    sourceId: readString(value.sourceId, `${field} source ID`, 512),
    targetId: readString(value.targetId, `${field} target ID`, 512),
    type: value.type as IntelligenceRelationship["type"],
    confidence: parseConfidence(value.confidence, `${field} confidence`),
    verificationStatus: parseVerificationStatus(value.verificationStatus, `${field} verification status`),
    provenance: parseProvenance(value.provenance, `${field} provenance`),
    evidence: parseEvidence(value.evidence, `${field} evidence`),
  };
}

function parseTotal(value: unknown, field: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    return invalid(`Invalid ${field} in graph data.`);
  }
  return value as number;
}

/** Runtime validation at the adapter boundary; TypeScript types do not validate network data. */
export function validateGraphPage(value: unknown): GraphPage {
  if (!isRecord(value) || !Array.isArray(value.nodes) || !Array.isArray(value.relationships)) {
    return invalid("Invalid graph page returned by the data source.");
  }

  const nodes = value.nodes.map(parseNode);
  const relationships = value.relationships.map(parseRelationship);
  const nodeIds = new Set(nodes.map((node) => node.id));
  const relationshipIds = new Set(relationships.map((relationship) => relationship.id));
  if (nodeIds.size !== nodes.length || relationshipIds.size !== relationships.length) {
    return invalid("Graph page contains duplicate record IDs.");
  }

  if (
    value.nextCursor !== null &&
    (typeof value.nextCursor !== "string" || value.nextCursor.length === 0 || value.nextCursor.length > 4_096)
  ) {
    return invalid("Invalid graph page cursor.");
  }

  const totalNodes = parseTotal(value.totalNodes, "entity total");
  const totalRelationships = parseTotal(value.totalRelationships, "relationship total");
  if ((totalNodes !== undefined && totalNodes < nodes.length) ||
      (totalRelationships !== undefined && totalRelationships < relationships.length)) {
    return invalid("Graph page totals are smaller than the records returned.");
  }

  return {
    nodes,
    relationships,
    nextCursor: value.nextCursor as string | null,
    ...(totalNodes !== undefined ? { totalNodes } : {}),
    ...(totalRelationships !== undefined ? { totalRelationships } : {}),
  };
}

export type MergedGraphPage = {
  nodes: PositionedIntelligenceNode[];
  relationships: IntelligenceRelationship[];
};

/** Merge cursor pages while preserving ID identity and rejecting dangling edges. */
export function mergeGraphPage(
  currentNodes: PositionedIntelligenceNode[],
  currentRelationships: IntelligenceRelationship[],
  page: GraphPage,
): MergedGraphPage {
  const nodesById = new Map<string, IntelligenceNode>(currentNodes.map((node) => [node.id, node]));
  for (const node of page.nodes) {
    const previous = nodesById.get(node.id);
    nodesById.set(
      node.id,
      node.position || !previous?.position ? node : { ...node, position: previous.position },
    );
  }

  const relationshipsById = new Map<string, IntelligenceRelationship>(
    currentRelationships.map((relationship) => [relationship.id, relationship]),
  );
  for (const relationship of page.relationships) {
    relationshipsById.set(relationship.id, relationship);
  }

  const mergedNodes = [...nodesById.values()];
  const nodeIds = new Set(mergedNodes.map((node) => node.id));
  for (const relationship of relationshipsById.values()) {
    if (!nodeIds.has(relationship.sourceId) || !nodeIds.has(relationship.targetId)) {
      return invalid(`Relationship ${relationship.id} references an entity outside the loaded graph page.`);
    }
  }

  return {
    nodes: layoutGraphNodes(mergedNodes),
    relationships: [...relationshipsById.values()],
  };
}
