"use client";

import { useRef, useState, type KeyboardEvent } from "react";
import type {
  IntelligenceNode,
  IntelligenceRelationship,
  Locale,
} from "./types";
import { getMessages } from "./translations";
import styles from "./CommandTheater.module.css";

type RelationshipExplorerProps = {
  nodes: IntelligenceNode[];
  relationships: IntelligenceRelationship[];
  selectedNodeId: string;
  locale: Locale;
  onSelectNode: (nodeId: string) => void;
};

const RELATIONSHIP_PAGE_SIZE = 50;

function formatPercent(value: number, locale: Locale) {
  return new Intl.NumberFormat(locale, {
    style: "percent",
    maximumFractionDigits: 0,
  }).format(value);
}

function formatCountStatus(template: string, shown: number, total: number, locale: Locale) {
  const numberFormat = new Intl.NumberFormat(locale);
  return template
    .replace("{shown}", numberFormat.format(shown))
    .replace("{total}", numberFormat.format(total));
}

export function RelationshipExplorer({
  nodes,
  relationships,
  selectedNodeId,
  locale,
  onSelectNode,
}: RelationshipExplorerProps) {
  const messages = getMessages(locale);
  const buttonRefs = useRef(new Map<string, HTMLButtonElement>());
  const [visibleRelationshipCount, setVisibleRelationshipCount] =
    useState(RELATIONSHIP_PAGE_SIZE);
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const selectedNode = nodeById.get(selectedNodeId) ?? nodes[0];
  const visibleRelationships = relationships.slice(0, visibleRelationshipCount);
  const countStatus = formatCountStatus(
    messages.relationshipCountStatus,
    visibleRelationships.length,
    relationships.length,
    locale,
  );

  function moveFocus(event: KeyboardEvent<HTMLButtonElement>, current: IntelligenceNode) {
    const currentIndex = nodes.findIndex((node) => node.id === current.id);
    if (currentIndex < 0 || nodes.length === 0) return;

    let nextId: string | undefined;
    const linkedIds = relationships
      .filter(
        (relationship) =>
          relationship.sourceId === current.id || relationship.targetId === current.id,
      )
      .map((relationship) =>
        relationship.sourceId === current.id
          ? relationship.targetId
          : relationship.sourceId,
      );
    const rtl = locale !== "en";
    const forward =
      event.key === "ArrowDown" || event.key === (rtl ? "ArrowLeft" : "ArrowRight");
    const backward =
      event.key === "ArrowUp" || event.key === (rtl ? "ArrowRight" : "ArrowLeft");

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
    onSelectNode(nextId);
    buttonRefs.current.get(nextId)?.focus();
  }

  return (
    <section className={styles.explorer} aria-labelledby="graph-explorer-heading">
      <div className={styles.panelHeading}>
        <div>
          <p className={styles.sectionEyebrow}>{messages.eyebrow}</p>
          <h2 id="graph-explorer-heading">{messages.explorerTitle}</h2>
        </div>
        <span className={styles.demoMiniBadge}>{messages.demoBadge}</span>
      </div>

      <div className={styles.entitySection}>
        <h3 className={styles.subheading} id="entities-heading">
          {messages.entitiesTitle} <span>{nodes.length}</span>
        </h3>
        <ul className={styles.entityList} aria-labelledby="entities-heading">
          {nodes.map((node) => {
            const selected = selectedNodeId === node.id;
            const entityType = messages.entityTypes[node.type];
            const confidence = formatPercent(node.confidence, locale);

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
                  aria-label={`${node.label}, ${entityType}, ${messages.confidence} ${confidence}, ${messages.illustrative}`}
                  onClick={() => onSelectNode(node.id)}
                  onKeyDown={(event) => moveFocus(event, node)}
                >
                  <span className={styles.entityGlyph} data-type={node.type} aria-hidden="true" />
                  <span className={styles.entityCopy}>
                    <bdi className={styles.entityName} dir="auto">{node.label}</bdi>
                    <span className={styles.entityMeta}>
                      {entityType} · {messages.confidence} {confidence} ({messages.illustrative})
                    </span>
                  </span>
                  <span className={styles.entityChevron} aria-hidden="true">↗</span>
                </button>
              </li>
            );
          })}
        </ul>
        <p className={styles.keyboardHelp}>{messages.keyboardHelp}</p>
      </div>

      <div className={styles.relationshipSection}>
        <h3 className={styles.subheading} id="relationships-heading">
          {messages.relationshipsTitle} <span>{relationships.length}</span>
        </h3>
        <p className={styles.relationshipCount} role="status" aria-live="polite">
          {countStatus}
        </p>
        <ul className={styles.relationshipList} aria-labelledby="relationships-heading">
          {visibleRelationships.map((relationship) => {
            const source = nodeById.get(relationship.sourceId);
            const target = nodeById.get(relationship.targetId);
            if (!source || !target) return null;

            return (
              <li className={styles.relationshipItem} key={relationship.id}>
                <p className={styles.relationshipStatement}>
                  <bdi dir="auto">{source.label}</bdi>
                  <span className={styles.relationshipType}>
                    {messages.relationshipTypes[relationship.type]}
                  </span>
                  <bdi dir="auto">{target.label}</bdi>
                </p>
                <p className={styles.relationshipMeta}>
                  {messages.confidence}: {formatPercent(relationship.confidence, locale)} ({messages.illustrative})
                </p>
                <p className={styles.relationshipMeta}>{messages.noEvidence}</p>
              </li>
            );
          })}
        </ul>
        {visibleRelationships.length < relationships.length && (
          <button
            className={styles.showMoreRelationships}
            type="button"
            onClick={() =>
              setVisibleRelationshipCount((count) =>
                Math.min(count + RELATIONSHIP_PAGE_SIZE, relationships.length),
              )
            }
          >
            {messages.showMoreRelationships}
          </button>
        )}
      </div>

      {selectedNode && (
        <section
          className={styles.detailCard}
          aria-labelledby="selected-entity-heading"
          aria-live="polite"
        >
          <p className={styles.sectionEyebrow}>{messages.sampleSource}</p>
          <h3 id="selected-entity-heading">{messages.selectedEntity}</h3>
          <p className={styles.selectedName}><bdi dir="auto">{selectedNode.label}</bdi></p>
          <dl className={styles.detailsList}>
            <div>
              <dt>{messages.entityType}</dt>
              <dd>{messages.entityTypes[selectedNode.type]}</dd>
            </div>
            <div>
              <dt>{messages.confidence}</dt>
              <dd>
                {formatPercent(selectedNode.confidence, locale)} ({messages.illustrative})
              </dd>
            </div>
            <div>
              <dt>{messages.evidence}</dt>
              <dd>{messages.noEvidence}</dd>
            </div>
            <div>
              <dt>{messages.provenance}</dt>
              <dd><bdi dir="auto">{selectedNode.provenance}</bdi></dd>
            </div>
          </dl>
        </section>
      )}
    </section>
  );
}
