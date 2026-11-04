import { describe, expect, it } from "vitest";
import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import { createRelationshipLineGeometry } from "./graph-geometry";

describe("createRelationshipLineGeometry", () => {
  it("stores 10,000 edges in one vertex buffer within a bounded build time", () => {
    const template = DEMO_RELATIONSHIPS[0]!;
    const relationships = Array.from({ length: 10_000 }, (_, index) => ({
      ...template,
      id: `geometry-edge-${index}`,
    }));

    const startedAt = performance.now();
    const geometry = createRelationshipLineGeometry(DEMO_NODES, relationships);
    const elapsedMs = performance.now() - startedAt;

    expect(geometry.getAttribute("position").count).toBe(20_000);
    expect(geometry.groups).toHaveLength(0);
    expect(elapsedMs).toBeLessThan(2_000);
    geometry.dispose();
  });
});
