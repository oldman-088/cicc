import type { IntelligenceNode, PositionedIntelligenceNode } from "./types";

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

/**
 * Preserve adapter-supplied coordinates. For records without layout metadata,
 * spread nodes over a deterministic golden-angle spiral in linear time. The
 * low-amplitude depth variation is only a visual hint; no coordinate encodes
 * intelligence significance.
 */
export function layoutGraphNodes(nodes: IntelligenceNode[]): PositionedIntelligenceNode[] {
  const count = nodes.length;
  if (count === 0) return [];

  return nodes.map((node, index) => {
    if (node.position) return { ...node, position: node.position };

    const radius = count === 1 ? 0 : Math.sqrt(index / (count - 1));
    const angle = -Math.PI / 2 + index * GOLDEN_ANGLE;
    return {
      ...node,
      position: {
        x: 50 + Math.cos(angle) * 42 * radius,
        y: 50 + Math.sin(angle) * 38 * radius,
        z: Math.sin(index * GOLDEN_ANGLE) * 0.35,
      },
    };
  });
}
