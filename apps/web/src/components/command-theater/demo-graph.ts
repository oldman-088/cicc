import type {
  IntelligenceRelationship,
  PositionedIntelligenceNode,
} from "./types";

/**
 * Synthetic UI-only records. These examples are not live intelligence and have
 * no verified evidence, source connectivity, or operational attribution.
 */
const DEMO_PROVENANCE = {
  sourceName: "Synthetic UI fixture",
};

const illustrativeConfidence = (value: number) => ({
  value,
  basis: "illustrative" as const,
});

export const DEMO_NODES: PositionedIntelligenceNode[] = [
  {
    id: "actor-demo",
    label: "Demo threat actor",
    type: "threat-actor",
    position: { x: 14, y: 48, z: 0.2 },
    confidence: illustrativeConfidence(0.58),
    verificationStatus: "illustrative",
    provenance: DEMO_PROVENANCE,
    evidence: [],
  },
  {
    id: "campaign-demo",
    label: "Demo campaign",
    type: "campaign",
    position: { x: 38, y: 22, z: -0.1 },
    confidence: illustrativeConfidence(0.63),
    verificationStatus: "illustrative",
    provenance: DEMO_PROVENANCE,
    evidence: [],
  },
  {
    id: "domain-demo",
    label: "example.net",
    type: "domain",
    position: { x: 67, y: 39, z: 0.3 },
    confidence: illustrativeConfidence(0.71),
    verificationStatus: "illustrative",
    provenance: {
      sourceName: "Reserved example domain; no external lookup was performed",
    },
    evidence: [],
  },
  {
    id: "incident-demo",
    label: "Demo incident 01",
    type: "incident",
    position: { x: 47, y: 76, z: -0.3 },
    confidence: illustrativeConfidence(0.52),
    verificationStatus: "illustrative",
    provenance: DEMO_PROVENANCE,
    evidence: [],
  },
  {
    id: "asset-demo",
    label: "Demo research workstation",
    type: "asset",
    position: { x: 84, y: 67, z: 0.1 },
    confidence: illustrativeConfidence(0.66),
    verificationStatus: "illustrative",
    provenance: DEMO_PROVENANCE,
    evidence: [],
  },
];

export const DEMO_RELATIONSHIPS: IntelligenceRelationship[] = [
  {
    id: "actor-campaign",
    sourceId: "actor-demo",
    targetId: "campaign-demo",
    type: "associated-with",
    confidence: illustrativeConfidence(0.55),
    verificationStatus: "illustrative",
    provenance: { sourceName: "Synthetic UI fixture; illustrative edge only" },
    evidence: [],
  },
  {
    id: "campaign-domain",
    sourceId: "campaign-demo",
    targetId: "domain-demo",
    type: "uses",
    confidence: illustrativeConfidence(0.61),
    verificationStatus: "illustrative",
    provenance: { sourceName: "Synthetic UI fixture; illustrative edge only" },
    evidence: [],
  },
  {
    id: "domain-incident",
    sourceId: "domain-demo",
    targetId: "incident-demo",
    type: "observed-in",
    confidence: illustrativeConfidence(0.49),
    verificationStatus: "illustrative",
    provenance: { sourceName: "Synthetic UI fixture; illustrative edge only" },
    evidence: [],
  },
  {
    id: "incident-asset",
    sourceId: "incident-demo",
    targetId: "asset-demo",
    type: "affects",
    confidence: illustrativeConfidence(0.67),
    verificationStatus: "illustrative",
    provenance: { sourceName: "Synthetic UI fixture; illustrative edge only" },
    evidence: [],
  },
  {
    id: "actor-domain",
    sourceId: "actor-demo",
    targetId: "domain-demo",
    type: "uses",
    confidence: illustrativeConfidence(0.42),
    verificationStatus: "illustrative",
    provenance: { sourceName: "Synthetic UI fixture; illustrative edge only" },
    evidence: [],
  },
];
