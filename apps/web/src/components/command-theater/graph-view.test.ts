import { describe, expect, it } from "vitest";
import {
  MAX_VISIBLE_GRAPH_NODES,
  MAX_VISIBLE_GRAPH_RELATIONSHIPS,
  selectGraphView,
} from "./graph-view";
import type { IntelligenceNode, IntelligenceRelationship } from "./types";

function buildLargeGraph(nodeCount: number, relationshipCount: number) {
  const nodes: IntelligenceNode[] = Array.from({ length: nodeCount }, (_, index) => ({
    id: `graph-node-${index}`,
    label: `Graph entity ${index}`,
    type: "domain",
    position: {
      x: (index % 100) + 0.25,
      y: Math.floor(index / 100) % 100,
      z: 0,
    },
    confidence: { value: null, basis: "unavailable" },
    verificationStatus: "unknown",
    provenance: null,
    evidence: [],
  }));
  const relationships: IntelligenceRelationship[] = Array.from(
    { length: relationshipCount },
    (_, index) => ({
      id: `graph-edge-${index}`,
      sourceId: `graph-node-${index % 300}`,
      targetId: `graph-node-${(index * 17 + 1) % 300}`,
      type: "associated-with",
      confidence: { value: null, basis: "unavailable" },
      verificationStatus: "unknown",
      provenance: null,
      evidence: [],
    }),
  );
  relationships.push({
    id: "selected-entity-edge",
    sourceId: `graph-node-${nodeCount - 1}`,
    targetId: "graph-node-0",
    type: "uses",
    confidence: { value: null, basis: "unavailable" },
    verificationStatus: "inferred",
    provenance: null,
    evidence: [],
  });

  return { nodes, relationships };
}

describe("bounded graph view selection", () => {
  it("keeps the selected entity and its edge visible in a large graph", () => {
    const { nodes, relationships } = buildLargeGraph(10_000, 50_000);
    const selectedNodeId = "graph-node-9999";
    const startedAt = performance.now();
    const view = selectGraphView(nodes, relationships, selectedNodeId);
    const elapsedMs = performance.now() - startedAt;
    const visibleNodeIds = new Set(view.nodes.map((node) => node.id));

    expect(elapsedMs).toBeLessThan(2_000);
    expect(view.nodes).toHaveLength(MAX_VISIBLE_GRAPH_NODES);
    expect(view.relationships).toHaveLength(MAX_VISIBLE_GRAPH_RELATIONSHIPS);
    expect(visibleNodeIds.has(selectedNodeId)).toBe(true);
    expect(view.relationships[0]?.id).toBe("selected-entity-edge");
    expect(view.relationships.every((relationship) =>
      visibleNodeIds.has(relationship.sourceId) && visibleNodeIds.has(relationship.targetId),
    )).toBe(true);
    expect(view.omittedNodes).toBe(nodes.length - MAX_VISIBLE_GRAPH_NODES);
    expect(view.omittedRelationships).toBe(relationships.length - MAX_VISIBLE_GRAPH_RELATIONSHIPS);
  });
});
