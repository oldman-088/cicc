import { describe, expect, it } from "vitest";
import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import { GraphDataError, mergeGraphPage, validateGraphPage } from "./graph-data";
import { layoutGraphNodes } from "./graph-layout";
import type { GraphPage, IntelligenceNode } from "./types";

function page(overrides: Partial<GraphPage> = {}): GraphPage {
  return {
    nodes: DEMO_NODES,
    relationships: DEMO_RELATIONSHIPS,
    nextCursor: null,
    totalNodes: DEMO_NODES.length,
    totalRelationships: DEMO_RELATIONSHIPS.length,
    ...overrides,
  };
}

describe("Command Theater graph data boundary", () => {
  it("validates a normalized page and preserves evidence/provenance metadata", () => {
    const validated = validateGraphPage(page());

    expect(validated.nodes[0]?.verificationStatus).toBe("illustrative");
    expect(validated.nodes[0]?.confidence).toEqual({ value: 0.58, basis: "illustrative" });
    expect(validated.nodes[0]?.provenance?.sourceName).toBe("Synthetic UI fixture");
    expect(validated.nodes[0]?.evidence).toEqual([]);
  });

  it("rejects out-of-range confidence, duplicate IDs, and invalid totals", () => {
    const invalidScore = page({
      nodes: [{
        ...DEMO_NODES[0]!,
        confidence: { value: 101, basis: "analyst-assessed" },
      }],
      relationships: [],
      totalNodes: 1,
      totalRelationships: 0,
    });
    expect(() => validateGraphPage(invalidScore)).toThrow(GraphDataError);

    expect(() => validateGraphPage(page({ nodes: [DEMO_NODES[0]!, DEMO_NODES[0]!] })))
      .toThrow(/duplicate record IDs/);
    expect(() => validateGraphPage(page({ totalNodes: 0 })))
      .toThrow(/totals are smaller/);
    expect(() => validateGraphPage(page({ nextCursor: "" })))
      .toThrow(/Invalid graph page cursor/);
  });

  it("rejects dangling relationships instead of omitting them from the visualization", () => {
    const dangling = {
      id: "dangling",
      sourceId: "actor-demo",
      targetId: "not-loaded",
      type: "uses" as const,
      confidence: { value: 0.5, basis: "illustrative" as const },
      verificationStatus: "illustrative" as const,
      provenance: null,
      evidence: [],
    };
    const validPage = validateGraphPage(page({ relationships: [dangling] }));

    expect(() => mergeGraphPage([], [], validPage)).toThrow(/references an entity outside the loaded graph page/);
  });

  it("assigns deterministic bounded layout coordinates to records without positions", () => {
    const template = DEMO_NODES[0]!;
    const unpositioned: IntelligenceNode[] = Array.from({ length: 10_000 }, (_, index) => ({
      ...template,
      id: `layout-node-${index}`,
      position: undefined,
    }));

    const startedAt = performance.now();
    const first = layoutGraphNodes(unpositioned);
    const elapsedMs = performance.now() - startedAt;
    const second = layoutGraphNodes(unpositioned.slice(0, 20));

    expect(first).toHaveLength(10_000);
    expect(first.every((node) =>
      Number.isFinite(node.position.x) &&
      Number.isFinite(node.position.y) &&
      Number.isFinite(node.position.z),
    )).toBe(true);
    expect(first[0]?.position).toEqual(second[0]?.position);
    expect(elapsedMs).toBeLessThan(2_000);
  });

  it("preserves a node's previous layout when a later cursor page updates its metadata", () => {
    const existing = layoutGraphNodes([DEMO_NODES[0]!]);
    const update: IntelligenceNode = {
      ...DEMO_NODES[0]!,
      label: "Updated source label",
      position: undefined,
    };
    const updatePage = validateGraphPage({
      nodes: [update],
      relationships: [],
      nextCursor: null,
      totalNodes: 1,
      totalRelationships: 0,
    });

    const merged = mergeGraphPage(existing, [], updatePage);
    expect(merged.nodes[0]?.position).toEqual(existing[0]?.position);
    expect(merged.nodes[0]?.label).toBe("Updated source label");
  });
});
