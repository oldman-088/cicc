import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import type { CommandTheaterDataSource, GraphPageRequest, IntelligenceNode } from "./types";

function matchesSearch(node: IntelligenceNode, query: string): boolean {
  return `${node.id} ${node.label} ${node.type} ${node.provenance?.sourceName ?? ""}`
    .toLowerCase()
    .includes(query);
}

export const DEMO_DATA_SOURCE: CommandTheaterDataSource = {
  kind: "demo",
  async loadPage(request: GraphPageRequest, signal: AbortSignal) {
    if (signal.aborted) throw new DOMException("The graph request was aborted.", "AbortError");

    const query = request.filters.search?.trim().toLowerCase() ?? "";
    const matchingNodes = DEMO_NODES.filter((node) => {
      const matchesType = !request.filters.entityType || node.type === request.filters.entityType;
      const matchesText = !query || matchesSearch(node, query);
      return matchesType && matchesText;
    });
    const matchingNodeIds = new Set(matchingNodes.map((node) => node.id));
    const relationships = DEMO_RELATIONSHIPS.filter((relationship) => {
      const matchesRelationshipType =
        !request.filters.relationshipType || relationship.type === request.filters.relationshipType;
      const matchesRelatedNode =
        (!request.filters.entityType && !query) ||
        matchingNodeIds.has(relationship.sourceId) ||
        matchingNodeIds.has(relationship.targetId);
      const matchesRelationshipText =
        !!query && `${relationship.id} ${relationship.type} ${relationship.provenance?.sourceName ?? ""}`
          .toLowerCase()
          .includes(query);
      return matchesRelationshipType && (matchesRelatedNode || matchesRelationshipText);
    });

    const includedNodeIds = new Set(matchingNodeIds);
    for (const relationship of relationships) {
      includedNodeIds.add(relationship.sourceId);
      includedNodeIds.add(relationship.targetId);
    }
    const nodes = DEMO_NODES.filter((node) => includedNodeIds.has(node.id));

    return {
      nodes,
      relationships,
      nextCursor: null,
      totalNodes: nodes.length,
      totalRelationships: relationships.length,
    };
  },
};
