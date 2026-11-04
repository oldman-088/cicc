import type { IntelligenceNode, PositionedIntelligenceNode } from "./types";

/**
 * Preserve adapter-supplied coordinates. For records without layout metadata,
 * place them on a stable circle in linear time; this is a predictable fallback,
 * not a claim that the layout encodes intelligence significance.
 */
export function layoutGraphNodes(nodes: IntelligenceNode[]): PositionedIntelligenceNode[] {
  const count = nodes.length;
  if (count === 0) return [];

  return nodes.map((node, index) => {
    if (node.position) return { ...node, position: node.position };

    const angle = -Math.PI / 2 + (2 * Math.PI * index) / count;
    return {
      ...node,
      position: {
        x: 50 + Math.cos(angle) * 42,
        y: 50 + Math.sin(angle) * 38,
        z: 0,
      },
    };
  });
}
