import type { IntelligenceNode, IntelligenceRelationship } from "./types";

/**
 * Synthetic UI-only graph. These examples are not live intelligence and carry
 * no verified evidence, source connectivity, or operational attribution.
 */
export const DEMO_NODES: IntelligenceNode[] = [
  {
    id: "actor-demo",
    label: "Demo threat actor",
    type: "threat-actor",
    position: { x: 14, y: 48, z: 0.2 },
    confidence: 0.58,
    provenance: "Synthetic UI fixture; not an intelligence record.",
  },
  {
    id: "campaign-demo",
    label: "Demo campaign",
    type: "campaign",
    position: { x: 38, y: 22, z: -0.1 },
    confidence: 0.63,
    provenance: "Synthetic UI fixture; not an intelligence record.",
  },
  {
    id: "domain-demo",
    label: "example.net",
    type: "domain",
    position: { x: 67, y: 39, z: 0.3 },
    confidence: 0.71,
    provenance: "Reserved example domain; no external lookup was performed.",
  },
  {
    id: "incident-demo",
    label: "Demo incident 01",
    type: "incident",
    position: { x: 47, y: 76, z: -0.3 },
    confidence: 0.52,
    provenance: "Synthetic UI fixture; not an intelligence record.",
  },
  {
    id: "asset-demo",
    label: "Demo research workstation",
    type: "asset",
    position: { x: 84, y: 67, z: 0.1 },
    confidence: 0.66,
    provenance: "Synthetic UI fixture; not an intelligence record.",
  },
];

export const DEMO_RELATIONSHIPS: IntelligenceRelationship[] = [
  {
    id: "actor-campaign",
    sourceId: "actor-demo",
    targetId: "campaign-demo",
    type: "associated-with",
    confidence: 0.55,
    provenance: "Illustrative edge only; no source or evidence attached.",
  },
  {
    id: "campaign-domain",
    sourceId: "campaign-demo",
    targetId: "domain-demo",
    type: "uses",
    confidence: 0.61,
    provenance: "Illustrative edge only; no source or evidence attached.",
  },
  {
    id: "domain-incident",
    sourceId: "domain-demo",
    targetId: "incident-demo",
    type: "observed-in",
    confidence: 0.49,
    provenance: "Illustrative edge only; no source or evidence attached.",
  },
  {
    id: "incident-asset",
    sourceId: "incident-demo",
    targetId: "asset-demo",
    type: "affects",
    confidence: 0.67,
    provenance: "Illustrative edge only; no source or evidence attached.",
  },
  {
    id: "actor-domain",
    sourceId: "actor-demo",
    targetId: "domain-demo",
    type: "uses",
    confidence: 0.42,
    provenance: "Illustrative edge only; no source or evidence attached.",
  },
];
