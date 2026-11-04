"use client";

import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import type {
  ConfidenceAssessment,
  GraphDataSourceKind,
  IntelligenceNode,
  IntelligenceRelationship,
  Locale,
  VerificationStatus,
} from "./types";
import { getMessages } from "./translations";
import { safeDisplayText } from "./display-text";
import type { CommandTheaterGraphState } from "./use-command-theater-graph";
import styles from "./CommandTheater.module.css";

type RelationshipExplorerProps = {
  nodes: IntelligenceNode[];
  relationships: IntelligenceRelationship[];
  selectedNodeId: string;
  locale: Locale;
  sourceKind: GraphDataSourceKind;
  totalNodes: number | null;
  totalRelationships: number | null;
  hasMoreData: boolean;
  loadingMore: boolean;
  pageError: CommandTheaterGraphState["pageError"];
  onSelectNode: (nodeId: string) => void;
  onLoadMore: () => void;
  onRetryMore: () => void;
};

const ENTITY_PAGE_SIZE = 50;
const RELATIONSHIP_PAGE_SIZE = 50;

function formatConfidence(confidence: ConfidenceAssessment, locale: Locale) {
  if (confidence.value === null) return null;
  return new Intl.NumberFormat(locale, {
    style: "percent",
    maximumFractionDigits: 0,
  }).format(confidence.value);
}

function formatTimestamp(value: string | undefined, locale: Locale) {
  if (!value) return null;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function RelationshipExplorer({
  nodes,
  relationships,
  selectedNodeId,
  locale,
  sourceKind,
  totalNodes,
  totalRelationships,
  hasMoreData,
  loadingMore,
  pageError,
  onSelectNode,
  onLoadMore,
  onRetryMore,
}: RelationshipExplorerProps) {
  const messages = getMessages(locale);
  const instanceId = useId().replaceAll(":", "");
  const ids = {
    heading: `${instanceId}-graph-explorer-heading`,
    entities: `${instanceId}-entities-heading`,
    relationships: `${instanceId}-relationships-heading`,
    selected: `${instanceId}-selected-entity-heading`,
  };
  const buttonRefs = useRef(new Map<string, HTMLButtonElement>());
  const [visibleEntityCount, setVisibleEntityCount] = useState(ENTITY_PAGE_SIZE);
  const [visibleRelationshipCount, setVisibleRelationshipCount] =
    useState(RELATIONSHIP_PAGE_SIZE);
  const [pendingFocusId, setPendingFocusId] = useState<string | null>(null);
  const nodeById = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const selectedNode = nodeById.get(selectedNodeId) ?? nodes[0];
  const visibleNodes = useMemo(() => {
    const shownNodes = nodes.slice(0, visibleEntityCount);
    if (!selectedNode || shownNodes.some((node) => node.id === selectedNode.id)) {
      return shownNodes;
    }
    return [...shownNodes.slice(0, -1), selectedNode];
  }, [nodes, selectedNode, visibleEntityCount]);
  const entityTotal = Math.max(totalNodes ?? nodes.length, nodes.length);
  const numberFormat = new Intl.NumberFormat(locale);
  const entityCountStatus = totalNodes === null
    ? messages.entityLoadedStatus
        .replace("{shown}", numberFormat.format(visibleNodes.length))
        .replace("{loaded}", numberFormat.format(nodes.length))
    : messages.entityCountStatus
        .replace("{shown}", numberFormat.format(visibleNodes.length))
        .replace("{total}", numberFormat.format(entityTotal));
  const visibleRelationships = relationships.slice(0, visibleRelationshipCount);
  const countStatus = totalRelationships === null
    ? messages.relationshipLoadedStatus
        .replace("{shown}", numberFormat.format(visibleRelationships.length))
        .replace("{loaded}", numberFormat.format(relationships.length))
    : messages.relationshipCountStatus
        .replace("{shown}", numberFormat.format(visibleRelationships.length))
        .replace("{total}", numberFormat.format(Math.max(totalRelationships, visibleRelationships.length)));

  useEffect(() => {
    if (!pendingFocusId) return;
    const target = buttonRefs.current.get(pendingFocusId);
    if (target) {
      target.focus();
      setPendingFocusId(null);
    }
  }, [pendingFocusId, visibleNodes]);

  const adjacency = useMemo(() => {
    const neighbors = new Map<string, string[]>();
    for (const relationship of relationships) {
      const sourceNeighbors = neighbors.get(relationship.sourceId) ?? [];
      sourceNeighbors.push(relationship.targetId);
      neighbors.set(relationship.sourceId, sourceNeighbors);
      const targetNeighbors = neighbors.get(relationship.targetId) ?? [];
      targetNeighbors.push(relationship.sourceId);
      neighbors.set(relationship.targetId, targetNeighbors);
    }
    return neighbors;
  }, [relationships]);

  function moveFocus(event: KeyboardEvent<HTMLButtonElement>, current: IntelligenceNode) {
    const currentIndex = nodes.findIndex((node) => node.id === current.id);
    if (currentIndex < 0 || nodes.length === 0) return;

    const linkedIds = adjacency.get(current.id) ?? [];
    const rtl = locale !== "en";
    const forward =
      event.key === "ArrowDown" || event.key === (rtl ? "ArrowLeft" : "ArrowRight");
    const backward =
      event.key === "ArrowUp" || event.key === (rtl ? "ArrowRight" : "ArrowLeft");

    let nextId: string | undefined;
    if (forward) {
      nextId = linkedIds[0] ?? nodes[(currentIndex + 1) % nodes.length]?.id;
    } else if (backward) {
      nextId = linkedIds.at(-1) ?? nodes[(currentIndex - 1 + nodes.length) % nodes.length]?.id;
    } else if (event.key === "Home") {
      nextId = nodes[0]?.id;
    } else if (event.key === "End") {
      nextId = nodes.at(-1)?.id;
    } else {
      return;
    }

    if (!nextId || nextId === current.id) return;
    event.preventDefault();
    setPendingFocusId(nextId);
    onSelectNode(nextId);
    buttonRefs.current.get(nextId)?.focus();
  }

  function confidenceDescription(confidence: ConfidenceAssessment) {
    const score = formatConfidence(confidence, locale);
    const basis = messages.confidenceBasis[confidence.basis];
    return score ? `${score} (${basis})` : basis;
  }

  function verificationLabel(status: VerificationStatus) {
    return messages.verificationStatuses[status];
  }

  const hasMoreLoadedRelationships = visibleRelationships.length < relationships.length;
  const canLoadMore = hasMoreLoadedRelationships || hasMoreData;
  const relationshipTotal = Math.max(totalRelationships ?? relationships.length, relationships.length);

  return (
    <section className={styles.explorer} aria-labelledby={ids.heading}>
      <div className={styles.panelHeading}>
        <div>
          <p className={styles.sectionEyebrow}>{messages.eyebrow}</p>
          <h2 id={ids.heading}>{messages.explorerTitle}</h2>
        </div>
        <span className={sourceKind === "demo" ? styles.demoMiniBadge : styles.backendMiniBadge}>
          {sourceKind === "demo" ? messages.demoBadge : messages.backendBadge}
        </span>
      </div>

      <div className={styles.entitySection}>
        <h3 className={styles.subheading} id={ids.entities}>
          {messages.entitiesTitle} <span>{entityTotal}</span>
        </h3>
        <p className={styles.relationshipCount} role="status" aria-live="polite">
          {entityCountStatus}
        </p>
        <ul className={styles.entityList} aria-labelledby={ids.entities}>
          {visibleNodes.map((node) => {
            const selected = selectedNode?.id === node.id;
            const confidence = confidenceDescription(node.confidence);
            const entityType = messages.entityTypes[node.type];
            const status = verificationLabel(node.verificationStatus);

            return (
              <li key={node.id}>
                <button
                  ref={(element) => {
                    if (element) buttonRefs.current.set(node.id, element);
                    else buttonRefs.current.delete(node.id);
                  }}
                  type="button"
                  className={selected ? styles.entityButtonSelected : styles.entityButton}
                  aria-pressed={selected}
                  aria-label={`${safeDisplayText(node.label)}, ${entityType}, ${status}, ${messages.confidence} ${confidence}`}
                  tabIndex={selected ? 0 : -1}
                  onClick={() => onSelectNode(node.id)}
                  onKeyDown={(event) => moveFocus(event, node)}
                >
                  <span className={styles.entityGlyph} data-type={node.type} aria-hidden="true" />
                  <span className={styles.entityCopy}>
                    <bdi className={styles.entityName} dir="auto">{safeDisplayText(node.label)}</bdi>
                    <span className={styles.entityMeta}>
                      {entityType} · {status} · {messages.confidence} {confidence}
                    </span>
                  </span>
                  <span className={styles.entityChevron} aria-hidden="true">↗</span>
                </button>
              </li>
            );
          })}
        </ul>
        {visibleEntityCount < nodes.length && (
          <button
            className={styles.showMoreRelationships}
            type="button"
            onClick={() => setVisibleEntityCount((count) =>
              Math.min(count + ENTITY_PAGE_SIZE, nodes.length),
            )}
          >
            {messages.showMoreEntities}
          </button>
        )}
        <p className={styles.keyboardHelp}>{messages.keyboardHelp}</p>
      </div>

      <div className={styles.relationshipSection}>
        <h3 className={styles.subheading} id={ids.relationships}>
          {messages.relationshipsTitle} <span>{relationshipTotal}</span>
        </h3>
        <p className={styles.relationshipCount} role="status" aria-live="polite">
          {countStatus}
        </p>
        <ul className={styles.relationshipList} aria-labelledby={ids.relationships}>
          {visibleRelationships.map((relationship) => {
            const source = nodeById.get(relationship.sourceId);
            const target = nodeById.get(relationship.targetId);
            if (!source || !target) return null;

            return (
              <li className={styles.relationshipItem} key={relationship.id}>
                <p className={styles.relationshipStatement}>
                  <bdi dir="auto">{safeDisplayText(source.label)}</bdi>
                  <span className={styles.relationshipArrow} aria-hidden="true">→</span>
                  <span className={styles.relationshipType}>
                    {messages.relationshipTypes[relationship.type]}
                  </span>
                  <span className={styles.relationshipArrow} aria-hidden="true">→</span>
                  <bdi dir="auto">{safeDisplayText(target.label)}</bdi>
                </p>
                <p className={styles.relationshipMeta}>
                  {verificationLabel(relationship.verificationStatus)} · {messages.confidence}: {confidenceDescription(relationship.confidence)}
                </p>
                {relationship.evidence.length > 0 ? (
                  <ul className={styles.evidenceList} aria-label={messages.evidence}>
                    {relationship.evidence.map((evidence) => (
                      <li key={evidence.id}>
                        <bdi dir="auto">{safeDisplayText(evidence.label)}</bdi> · <bdi dir="auto">{safeDisplayText(evidence.sourceName)}</bdi> · {messages.evidenceStatuses[evidence.status]}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className={styles.relationshipMeta}>
                    {sourceKind === "demo" ? messages.demoNoEvidence : messages.noEvidence}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
        {canLoadMore && (
          <button
            className={styles.showMoreRelationships}
            type="button"
            disabled={loadingMore}
            onClick={() => {
              if (hasMoreLoadedRelationships) {
                setVisibleRelationshipCount((count) =>
                  Math.min(count + RELATIONSHIP_PAGE_SIZE, relationships.length),
                );
              } else {
                onLoadMore();
              }
            }}
          >
            {loadingMore
              ? messages.loadingMoreGraph
              : hasMoreLoadedRelationships
                ? messages.showMoreRelationships
                : messages.loadMoreGraph}
          </button>
        )}
        {pageError && (
          <div className={styles.dataError} role="alert">
            <p>{pageError === "invalid-data" ? messages.invalidGraphData : messages.graphLoadError}</p>
            <button className={styles.fallbackButton} type="button" onClick={onRetryMore}>
              {messages.retry}
            </button>
          </div>
        )}
      </div>

      {selectedNode && (
        <section className={styles.detailCard} aria-labelledby={ids.selected}>
          <p className={styles.sectionEyebrow}>{messages.recordMetadata}</p>
          <h3 id={ids.selected}>{messages.selectedEntity}</h3>
          <p className={styles.selectedName} aria-live="polite">
            <bdi dir="auto">{safeDisplayText(selectedNode.label)}</bdi>
          </p>
          <dl className={styles.detailsList}>
            <div>
              <dt>{messages.entityType}</dt>
              <dd>{messages.entityTypes[selectedNode.type]}</dd>
            </div>
            <div>
              <dt>{messages.verificationStatusLabel}</dt>
              <dd>{messages.verificationStatuses[selectedNode.verificationStatus]}</dd>
            </div>
            <div>
              <dt>{messages.confidence}</dt>
              <dd>{confidenceDescription(selectedNode.confidence)}</dd>
            </div>
            <div>
              <dt>{messages.provenance}</dt>
              <dd>
                {selectedNode.provenance ? (
                  <>
                    <bdi dir="auto">{safeDisplayText(selectedNode.provenance.sourceName)}</bdi>
                    {selectedNode.provenance.sourceRecordId && (
                      <span className={styles.metadataValue}>
                        {messages.sourceRecordId}: <bdi dir="ltr">{safeDisplayText(selectedNode.provenance.sourceRecordId)}</bdi>
                      </span>
                    )}
                    {selectedNode.provenance.collectedAt && (
                      <span className={styles.metadataValue}>
                        {messages.collectedAt}: {formatTimestamp(selectedNode.provenance.collectedAt, locale)}
                      </span>
                    )}
                    {selectedNode.provenance.publishedAt && (
                      <span className={styles.metadataValue}>
                        {messages.publishedAt}: {formatTimestamp(selectedNode.provenance.publishedAt, locale)}
                      </span>
                    )}
                  </>
                ) : messages.provenanceUnavailable}
              </dd>
            </div>
            <div>
              <dt>{messages.evidence}</dt>
              <dd>
                {selectedNode.evidence.length > 0 ? (
                  <ul className={styles.evidenceList}>
                    {selectedNode.evidence.map((evidence) => (
                      <li key={evidence.id}>
                        <bdi dir="auto">{safeDisplayText(evidence.label)}</bdi> · <bdi dir="auto">{safeDisplayText(evidence.sourceName)}</bdi> · {messages.evidenceStatuses[evidence.status]}
                        {evidence.observedAt && ` · ${formatTimestamp(evidence.observedAt, locale)}`}
                      </li>
                    ))}
                  </ul>
                ) : sourceKind === "demo" ? messages.demoNoEvidence : messages.noEvidence}
              </dd>
            </div>
          </dl>
        </section>
      )}
    </section>
  );
}
