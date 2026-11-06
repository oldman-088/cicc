import type {
  IntelligenceNode,
  IntelligenceRelationship,
  PositionedIntelligenceNode,
} from "./types";
import { layoutGraphNodes } from "./graph-layout";

export const MAX_VISIBLE_GRAPH_NODES = 250;
export const MAX_VISIBLE_GRAPH_RELATIONSHIPS = 250;

export type GraphViewSlice = {
  nodes: PositionedIntelligenceNode[];
  relationships: IntelligenceRelationship[];
  omittedNodes: number;
  omittedRelationships: number;
};

/**
 * Choose one bounded, selected-entity-prioritized slice for both renderers.
 * The list explorer still owns complete paginated access to the loaded records.
 */
export function selectGraphView(
  nodes: IntelligenceNode[],
  relationships: IntelligenceRelationship[],
  selectedNodeId: string,
): GraphViewSlice {
  const selectedNode = nodes.find((node) => node.id === selectedNodeId);
  const selectedRelationships = relationships.filter(
    (relationship) =>
      relationship.sourceId === selectedNodeId || relationship.targetId === selectedNodeId,
  );
  const priorityNodeIds = new Set<string>();
  if (selectedNode) priorityNodeIds.add(selectedNode.id);
  for (const relationship of selectedRelationships) {
    priorityNodeIds.add(relationship.sourceId);
    priorityNodeIds.add(relationship.targetId);
  }

  const priorityNodes = nodes.filter((node) => priorityNodeIds.has(node.id));
  const remainingNodes = nodes.filter((node) => !priorityNodeIds.has(node.id));
  const chosenNodes = [...priorityNodes, ...remainingNodes].slice(0, MAX_VISIBLE_GRAPH_NODES);
  const visibleNodeIds = new Set(chosenNodes.map((node) => node.id));

  const related = selectedRelationships.filter(
    (relationship) =>
      visibleNodeIds.has(relationship.sourceId) && visibleNodeIds.has(relationship.targetId),
  );
  const relatedIds = new Set(related.map((relationship) => relationship.id));
  const remainingRelationships = relationships.filter(
    (relationship) =>
      !relatedIds.has(relationship.id) &&
      visibleNodeIds.has(relationship.sourceId) &&
      visibleNodeIds.has(relationship.targetId),
  );
  const visibleRelationships = [...related, ...remainingRelationships].slice(
    0,
    MAX_VISIBLE_GRAPH_RELATIONSHIPS,
  );

  return {
    nodes: layoutGraphNodes(chosenNodes),
    relationships: visibleRelationships,
    omittedNodes: Math.max(0, nodes.length - chosenNodes.length),
    omittedRelationships: Math.max(0, relationships.length - visibleRelationships.length),
  };
}
