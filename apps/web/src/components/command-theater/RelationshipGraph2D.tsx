import { useId, useMemo, useRef, type KeyboardEvent } from "react";
import type {
  IntelligenceNode,
  IntelligenceRelationship,
  Locale,
  PositionedIntelligenceNode,
} from "./types";
import { getMessages } from "./translations";
import { safeDisplayText } from "./display-text";
import { selectGraphView } from "./graph-view";
import styles from "./CommandTheater.module.css";

type RelationshipGraph2DProps = {
  nodes: PositionedIntelligenceNode[];
  relationships: IntelligenceRelationship[];
  selectedNodeId: string;
  locale: Locale;
  totalNodes?: number | null;
  totalRelationships?: number | null;
  onSelectNode?: (nodeId: string) => void;
};

const WIDTH = 1000;
const HEIGHT = 520;

const entityColors: Record<IntelligenceNode["type"], string> = {
  "threat-actor": "#c4a6ff",
  campaign: "#76a9ff",
  domain: "#59e1d2",
  incident: "#ffbc72",
  asset: "#9be3a7",
};

function mapPoint(node: PositionedIntelligenceNode) {
  return { x: node.position.x * 10, y: node.position.y * 5.1 };
}

function fillCountTemplate(template: string, shown: number, total: number, locale: Locale) {
  const numberFormat = new Intl.NumberFormat(locale);
  return template
    .replace("{shown}", numberFormat.format(shown))
    .replace("{total}", numberFormat.format(total));
}

export function RelationshipGraph2D({
  nodes,
  relationships,
  selectedNodeId,
  locale,
  totalNodes,
  totalRelationships,
  onSelectNode,
}: RelationshipGraph2DProps) {
  const messages = getMessages(locale);
  const id = useId().replaceAll(":", "");
  const view = useMemo(
    () => selectGraphView(nodes, relationships, selectedNodeId),
    [nodes, relationships, selectedNodeId],
  );
  const nodeById = useMemo(() => new Map(view.nodes.map((node) => [node.id, node])), [view.nodes]);
  const nodeRefs = useRef(new Map<string, SVGGElement>());
  const selectedNodeVisible = nodeById.has(selectedNodeId);
  const confidenceFormat = useMemo(
    () => new Intl.NumberFormat(locale, { style: "percent", maximumFractionDigits: 0 }),
    [locale],
  );
  const adjacency = useMemo(() => {
    const neighbors = new Map<string, string[]>();
    for (const relationship of view.relationships) {
      const sourceNeighbors = neighbors.get(relationship.sourceId) ?? [];
      sourceNeighbors.push(relationship.targetId);
      neighbors.set(relationship.sourceId, sourceNeighbors);
      const targetNeighbors = neighbors.get(relationship.targetId) ?? [];
      targetNeighbors.push(relationship.sourceId);
      neighbors.set(relationship.targetId, targetNeighbors);
    }
    return neighbors;
  }, [view.relationships]);
  const relationshipTotal = Math.max(totalRelationships ?? relationships.length, relationships.length);
  const nodeTotal = Math.max(totalNodes ?? nodes.length, nodes.length);
  const limitNotices = [
    relationshipTotal > view.relationships.length
      ? fillCountTemplate(messages.mapLimitNotice, view.relationships.length, relationshipTotal, locale)
      : null,
    nodeTotal > view.nodes.length
      ? fillCountTemplate(messages.mapNodeLimitNotice, view.nodes.length, nodeTotal, locale)
      : null,
  ].filter((notice): notice is string => notice !== null);
  const limitNotice = limitNotices.join(" ");

  function handleNodeKeyDown(event: KeyboardEvent<SVGGElement>, current: PositionedIntelligenceNode) {
    if (!onSelectNode) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelectNode(current.id);
      return;
    }

    const currentIndex = view.nodes.findIndex((node) => node.id === current.id);
    if (currentIndex < 0 || view.nodes.length === 0) return;
    const linkedIds = adjacency.get(current.id) ?? [];
    const rtl = locale !== "en";
    const forward = event.key === "ArrowDown" || event.key === (rtl ? "ArrowLeft" : "ArrowRight");
    const backward = event.key === "ArrowUp" || event.key === (rtl ? "ArrowRight" : "ArrowLeft");

    let nextId: string | undefined;
    if (forward) {
      nextId = linkedIds[0] ?? view.nodes[(currentIndex + 1) % view.nodes.length]?.id;
    } else if (backward) {
      nextId = linkedIds.at(-1) ?? view.nodes[(currentIndex - 1 + view.nodes.length) % view.nodes.length]?.id;
    } else if (event.key === "Home") {
      nextId = view.nodes[0]?.id;
    } else if (event.key === "End") {
      nextId = view.nodes.at(-1)?.id;
    } else {
      return;
    }

    if (!nextId || nextId === current.id) return;
    event.preventDefault();
    onSelectNode(nextId);
    nodeRefs.current.get(nextId)?.focus();
  }

  return (
    <div className={styles.mapFrame}>
      <svg
        className={styles.relationshipMap}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role={onSelectNode ? "group" : "img"}
        aria-labelledby={`${id}-title`}
        aria-describedby={`${id}-description`}
        preserveAspectRatio="xMidYMid meet"
        direction="ltr"
      >
        <title id={`${id}-title`}>{messages.mapLabel}</title>
        <desc id={`${id}-description`}>
          {limitNotice ? `${messages.mapDescription} ${limitNotice}` : messages.mapDescription}
        </desc>
        <defs>
          <marker
            id={`${id}-arrowhead`}
            markerWidth="9"
            markerHeight="9"
            refX="7"
            refY="4.5"
            orient="auto"
            markerUnits="strokeWidth"
          >
            <path d="M0,0 L9,4.5 L0,9 z" fill="#55b9d4" />
          </marker>
        </defs>

        <g className={styles.edgeLayer}>
          {view.relationships.map((relationship) => {
            const source = nodeById.get(relationship.sourceId);
            const target = nodeById.get(relationship.targetId);
            if (!source || !target) return null;

            const start = mapPoint(source);
            const end = mapPoint(target);
            const midpoint = { x: (start.x + end.x) / 2, y: (start.y + end.y) / 2 };
            const isSelected =
              selectedNodeId === source.id || selectedNodeId === target.id;

            return (
              <g key={relationship.id}>
                <line
                  className={isSelected ? styles.edgeSelected : styles.edge}
                  x1={start.x}
                  y1={start.y}
                  x2={end.x}
                  y2={end.y}
                  markerEnd={`url(#${id}-arrowhead)`}
                />
                <text
                  className={styles.edgeLabel}
                  x={midpoint.x}
                  y={midpoint.y - 8}
                  textAnchor="middle"
                >
                  {messages.relationshipTypes[relationship.type]}
                </text>
              </g>
            );
          })}
        </g>

        <g className={styles.nodeLayer}>
          {view.nodes.map((node, index) => {
            const point = mapPoint(node);
            const selected = node.id === selectedNodeId;
            const color = entityColors[node.type];
            const confidence = node.confidence.value === null
              ? messages.confidenceBasis.unavailable
              : `${confidenceFormat.format(node.confidence.value)} (${messages.confidenceBasis[node.confidence.basis]})`;

            return (
              <g
                key={node.id}
                className={onSelectNode ? styles.mapNode : undefined}
                ref={onSelectNode ? (element) => {
                  if (element) nodeRefs.current.set(node.id, element);
                  else nodeRefs.current.delete(node.id);
                } : undefined}
                role={onSelectNode ? "button" : undefined}
                tabIndex={onSelectNode ? (selected || (!selectedNodeVisible && index === 0) ? 0 : -1) : undefined}
                aria-label={onSelectNode
                  ? `${safeDisplayText(node.label)}, ${messages.entityTypes[node.type]}, ${messages.verificationStatuses[node.verificationStatus]}, ${messages.confidence}: ${confidence}`
                  : undefined}
                aria-pressed={onSelectNode ? selected : undefined}
                onClick={onSelectNode ? () => onSelectNode(node.id) : undefined}
                onKeyDown={onSelectNode ? (event) => handleNodeKeyDown(event, node) : undefined}
              >
                {selected && (
                  <circle
                    className={styles.nodeHalo}
                    cx={point.x}
                    cy={point.y}
                    r="38"
                  />
                )}
                <circle
                  className={styles.node}
                  cx={point.x}
                  cy={point.y}
                  r="25"
                  fill={color}
                />
                <circle
                  className={styles.nodeCore}
                  cx={point.x}
                  cy={point.y}
                  r="8"
                />
                <text
                  className={styles.nodeLabel}
                  x={point.x}
                  y={point.y + 48}
                  textAnchor="middle"
                  direction="ltr"
                  style={{ unicodeBidi: "plaintext" }}
                >
                  {safeDisplayText(node.label)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      {limitNotice && <p className={styles.mapHint} role="note">{limitNotice}</p>}
      <p className={styles.mapHint}>{messages.keyboardHelp}</p>
    </div>
  );
}
