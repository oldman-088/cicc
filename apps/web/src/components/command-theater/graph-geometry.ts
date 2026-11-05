import { BufferGeometry, Float32BufferAttribute } from "three";
import type { IntelligenceRelationship, PositionedIntelligenceNode } from "./types";

type Vector3Tuple = [number, number, number];

export function toScenePosition(node: PositionedIntelligenceNode): Vector3Tuple {
  return [
    (node.position.x - 50) / 9,
    (48 - node.position.y) / 8,
    node.position.z * 1.5,
  ];
}

/**
 * Build one GPU-ready line-segment geometry for an entire relationship set.
 * This keeps WebGL draw calls constant instead of creating a Drei Line mesh
 * and material for every edge.
 */
export function createRelationshipLineGeometry(
  nodes: PositionedIntelligenceNode[],
  relationships: IntelligenceRelationship[],
): BufferGeometry {
  const positionById = new Map(nodes.map((node) => [node.id, toScenePosition(node)]));
  const positions = new Float32Array(relationships.length * 6);
  let vertexCount = 0;

  for (const relationship of relationships) {
    const source = positionById.get(relationship.sourceId);
    const target = positionById.get(relationship.targetId);
    if (!source || !target) continue;

    positions.set(source, vertexCount * 3);
    positions.set(target, (vertexCount + 1) * 3);
    vertexCount += 2;
  }

  const geometry = new BufferGeometry();
  geometry.setAttribute(
    "position",
    new Float32BufferAttribute(positions.subarray(0, vertexCount * 3), 3),
  );
  return geometry;
}
