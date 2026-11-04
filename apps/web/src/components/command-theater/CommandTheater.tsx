"use client";

import dynamic from "next/dynamic";
import {
  Component,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { RelationshipExplorer } from "./RelationshipExplorer";
import { RelationshipGraph2D } from "./RelationshipGraph2D";
import { getMessages } from "./translations";
import { detectWebGLAvailability } from "./webgl-support";
import { useCommandTheaterGraph } from "./use-command-theater-graph";
import { selectGraphView } from "./graph-view";
import {
  INTELLIGENCE_ENTITY_TYPES,
  INTELLIGENCE_RELATIONSHIP_TYPES,
  isLocale,
  type CommandTheaterDataSource,
  type GraphFilters,
  type IntelligenceEntityType,
  type IntelligenceRelationshipType,
  type Locale,
} from "./types";
import styles from "./CommandTheater.module.css";

const LazyTheater3DCanvas = dynamic(
  () => import("./Theater3DCanvas").then((module) => module.Theater3DCanvas),
  {
    ssr: false,
    loading: () => (
      <div className={styles.canvasFallback} role="status">
        3D…
      </div>
    ),
  },
);

type CommandTheaterProps = {
  /** Optional locale supplied by the host application. */
  locale?: Locale;
  /** Adapter owned by the host CICC application; no backend route is assumed. */
  dataSource?: CommandTheaterDataSource;
  /** Explicitly load isolated synthetic UI data; never used as a request fallback. */
  demoMode?: boolean;
};

type GraphicsSupport = "checking" | "available" | "unavailable";
type SceneChunkErrorBoundaryProps = {
  children: ReactNode;
  fallback: ReactNode;
  onError: () => void;
};

type FilterDraft = {
  search: string;
  entityType: string;
  relationshipType: string;
};

type SelectionHistory = {
  ids: string[];
  index: number;
};

const MAX_INVESTIGATION_HISTORY = 50;

function createEmptySelectionHistory(): SelectionHistory {
  return { ids: [], index: -1 };
}

class SceneChunkErrorBoundary extends Component<
  SceneChunkErrorBoundaryProps,
  { hasError: boolean }
> {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch() {
    this.props.onError();
  }

  render() {
    return this.state.hasError ? this.props.fallback : this.props.children;
  }
}

export function CommandTheater({
  locale: initialLocale,
  dataSource,
  demoMode = false,
}: CommandTheaterProps) {
  const [locale, setLocale] = useState<Locale>(initialLocale ?? "en");
  const [graphicsSupport, setGraphicsSupport] = useState<GraphicsSupport>("checking");
  const [graphicsFailureReason, setGraphicsFailureReason] = useState<"context-lost" | null>(null);
  const [view, setView] = useState<"2d" | "3d">("2d");
  const [selectedNodeId, setSelectedNodeId] = useState("");
  const selectionHistoryRef = useRef<SelectionHistory>(createEmptySelectionHistory());
  const [selectionHistory, setSelectionHistory] = useState(selectionHistoryRef.current);
  const sourceIdentityRef = useRef({ dataSource, demoMode });
  const twoDButtonRef = useRef<HTMLButtonElement>(null);
  const [filters, setFilters] = useState<GraphFilters>({});
  const [filterDraft, setFilterDraft] = useState<FilterDraft>({
    search: "",
    entityType: "",
    relationshipType: "",
  });
  const messages = getMessages(locale);
  const instanceId = useId().replaceAll(":", "");
  const ids = {
    title: `${instanceId}-command-theater-title`,
    stage: `${instanceId}-relationship-theater-heading`,
    graphicsStatus: `${instanceId}-graphics-support-status`,
    search: `${instanceId}-graph-search`,
    entityType: `${instanceId}-entity-type-filter`,
    relationshipType: `${instanceId}-relationship-type-filter`,
  };
  const graph = useCommandTheaterGraph({ dataSource, demoMode, filters });
  const graphState = graph.state;
  const filterResetKey = JSON.stringify([
    filters.search ?? "",
    filters.entityType ?? "",
    filters.relationshipType ?? "",
  ]);
  const graphView = useMemo(
    () => view === "3d"
      ? selectGraphView(graphState.nodes, graphState.relationships, selectedNodeId)
      : null,
    [view, graphState.nodes, graphState.relationships, selectedNodeId],
  );
  const updateSelectionHistory = useCallback((next: SelectionHistory) => {
    selectionHistoryRef.current = next;
    setSelectionHistory(next);
  }, []);
  const resetSelectionHistory = useCallback(() => {
    updateSelectionHistory(createEmptySelectionHistory());
  }, [updateSelectionHistory]);
  const navigateToNode = useCallback((nodeId: string) => {
    setSelectedNodeId(nodeId);
    const current = selectionHistoryRef.current;
    if (current.ids[current.index] === nodeId) return;

    const ids = [...current.ids.slice(0, current.index + 1), nodeId]
      .slice(-MAX_INVESTIGATION_HISTORY);
    updateSelectionHistory({ ids, index: ids.length - 1 });
  }, [updateSelectionHistory]);

  useEffect(() => {
    if (initialLocale) {
      setLocale(initialLocale);
      return;
    }

    const documentLocale = document.documentElement.lang.toLowerCase().split("-")[0];
    if (isLocale(documentLocale)) setLocale(documentLocale);
  }, [initialLocale]);

  useEffect(() => {
    setGraphicsFailureReason(null);
    setGraphicsSupport(detectWebGLAvailability() ? "available" : "unavailable");
  }, []);

  useEffect(() => {
    if (
      sourceIdentityRef.current.dataSource === dataSource &&
      sourceIdentityRef.current.demoMode === demoMode
    ) return;
    sourceIdentityRef.current = { dataSource, demoMode };
    resetSelectionHistory();
  }, [dataSource, demoMode, resetSelectionHistory]);

  useEffect(() => {
    if (graphState.status === "ready" && graphState.nodes.length > 0) {
      const nextSelected = graphState.nodes.some((node) => node.id === selectedNodeId)
        ? selectedNodeId
        : graphState.nodes[0]!.id;
      if (nextSelected !== selectedNodeId) setSelectedNodeId(nextSelected);
      if (selectionHistoryRef.current.ids.length === 0) {
        updateSelectionHistory({ ids: [nextSelected], index: 0 });
      }
    } else if (graphState.status !== "loading") {
      if (selectedNodeId) setSelectedNodeId("");
      if (selectionHistoryRef.current.ids.length > 0) resetSelectionHistory();
    }
  }, [
    graphState.nodes,
    graphState.status,
    selectedNodeId,
    resetSelectionHistory,
    updateSelectionHistory,
  ]);

  const handleGraphicsFallback = useCallback((reason?: "context-lost") => {
    setGraphicsFailureReason(reason ?? null);
    setGraphicsSupport("unavailable");
    setView("2d");
    twoDButtonRef.current?.focus();
  }, []);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const next: GraphFilters = {
      ...(filterDraft.search.trim() ? { search: filterDraft.search.trim() } : {}),
      ...(filterDraft.entityType
        ? { entityType: filterDraft.entityType as IntelligenceEntityType }
        : {}),
      ...(filterDraft.relationshipType
        ? { relationshipType: filterDraft.relationshipType as IntelligenceRelationshipType }
        : {}),
    };
    resetSelectionHistory();
    setView("2d");
    setFilters(next);
  }

  function clearFilters() {
    setFilterDraft({ search: "", entityType: "", relationshipType: "" });
    resetSelectionHistory();
    setView("2d");
    setFilters({});
  }

  function navigateSelectionHistory(direction: -1 | 1) {
    const current = selectionHistoryRef.current;
    const nextIndex = current.index + direction;
    const nextNodeId = current.ids[nextIndex];
    if (!nextNodeId) return;
    if (!graphState.nodes.some((node) => node.id === nextNodeId)) {
      resetSelectionHistory();
      return;
    }

    updateSelectionHistory({ ...current, index: nextIndex });
    setSelectedNodeId(nextNodeId);
  }

  const graphicsMessage =
    graphicsSupport === "checking"
      ? messages.graphicsChecking
      : graphicsSupport === "available"
        ? messages.graphicsReady
        : graphicsFailureReason === "context-lost"
          ? messages.graphicsContextLost
          : messages.graphicsUnavailable;
  const hasGraph = graphState.status === "ready" && graphState.nodes.length > 0;
  const hasActiveFilters = Object.keys(filters).length > 0;
  const connectedData = graphState.status === "ready" || graphState.status === "empty";
  const entityCountLabel = graphState.sourceKind === "demo"
    ? messages.sampleEntitiesCount
    : messages.entitiesCount;
  const relationshipCountLabel = graphState.sourceKind === "demo"
    ? messages.sampleRelationshipsCount
    : messages.relationshipsCount;
  const historyNumberFormat = new Intl.NumberFormat(locale);
  const historyPosition = messages.investigationPosition
    .replace("{current}", historyNumberFormat.format(Math.max(1, selectionHistory.index + 1)))
    .replace("{total}", historyNumberFormat.format(Math.max(1, selectionHistory.ids.length)));
  const canNavigateBack = selectionHistory.index > 0;
  const canNavigateForward =
    selectionHistory.index >= 0 && selectionHistory.index < selectionHistory.ids.length - 1;
  const sceneNodeTotal = Math.max(graphState.totalNodes ?? graphState.nodes.length, graphState.nodes.length);
  const sceneRelationshipTotal = Math.max(
    graphState.totalRelationships ?? graphState.relationships.length,
    graphState.relationships.length,
  );
  const sceneLimitNotice = graphView && (
    sceneNodeTotal > graphView.nodes.length ||
    sceneRelationshipTotal > graphView.relationships.length
  )
    ? messages.sceneLimitNotice
        .replace("{shownNodes}", new Intl.NumberFormat(locale).format(graphView.nodes.length))
        .replace("{totalNodes}", new Intl.NumberFormat(locale).format(sceneNodeTotal))
        .replace("{shownRelationships}", new Intl.NumberFormat(locale).format(graphView.relationships.length))
        .replace("{totalRelationships}", new Intl.NumberFormat(locale).format(sceneRelationshipTotal))
    : null;

  return (
    <section
      className={styles.shell}
      lang={locale}
      dir={locale === "en" ? "ltr" : "rtl"}
      aria-labelledby={ids.title}
      role="region"
    >
      <div className={styles.console}>
        <header className={styles.header}>
          <div className={styles.brandBlock}>
            <p className={styles.eyebrow}>{messages.eyebrow}</p>
            <h1 id={ids.title}>{messages.title}</h1>
            <p className={styles.subtitle}>{messages.subtitle}</p>
          </div>

          <label className={styles.localeControl}>
            <span>{messages.language}</span>
            <select
              value={locale}
              onChange={(event) => setLocale(event.target.value as Locale)}
            >
              <option value="en">English</option>
              <option value="ar">العربية</option>
              <option value="fa">فارسی</option>
            </select>
          </label>
        </header>

        {connectedData && (
          <div
            className={graphState.sourceKind === "demo" ? styles.demoBanner : styles.backendBanner}
            role="note"
          >
            <span className={graphState.sourceKind === "demo" ? styles.demoBadge : styles.backendBadge}>
              {graphState.sourceKind === "demo" ? messages.demoBadge : messages.backendBadge}
            </span>
            <span>
              {graphState.sourceKind === "demo" ? messages.demoDescription : messages.backendDescription}
            </span>
          </div>
        )}

        <form className={styles.filterBar} onSubmit={applyFilters}>
          <label className={styles.filterField} htmlFor={ids.search}>
            <span>{messages.filterSearch}</span>
            <input
              id={ids.search}
              type="search"
              dir="auto"
              value={filterDraft.search}
              onChange={(event) => setFilterDraft((draft) => ({ ...draft, search: event.target.value }))}
              disabled={graphState.status === "unconfigured"}
            />
          </label>
          <label className={styles.filterField} htmlFor={ids.entityType}>
            <span>{messages.filterEntityType}</span>
            <select
              id={ids.entityType}
              value={filterDraft.entityType}
              onChange={(event) => setFilterDraft((draft) => ({ ...draft, entityType: event.target.value }))}
              disabled={graphState.status === "unconfigured"}
            >
              <option value="">{messages.allEntityTypes}</option>
              {INTELLIGENCE_ENTITY_TYPES.map((type) => (
                <option key={type} value={type}>{messages.entityTypes[type]}</option>
              ))}
            </select>
          </label>
          <label className={styles.filterField} htmlFor={ids.relationshipType}>
            <span>{messages.filterRelationshipType}</span>
            <select
              id={ids.relationshipType}
              value={filterDraft.relationshipType}
              onChange={(event) => setFilterDraft((draft) => ({ ...draft, relationshipType: event.target.value }))}
              disabled={graphState.status === "unconfigured"}
            >
              <option value="">{messages.allRelationshipTypes}</option>
              {INTELLIGENCE_RELATIONSHIP_TYPES.map((type) => (
                <option key={type} value={type}>{messages.relationshipTypes[type]}</option>
              ))}
            </select>
          </label>
          <div className={styles.filterActions}>
            <button className={styles.filterButton} type="submit" disabled={graphState.status === "unconfigured"}>
              {messages.applyFilters}
            </button>
            <button
              className={styles.filterButtonSecondary}
              type="button"
              onClick={clearFilters}
              disabled={!hasActiveFilters && !filterDraft.search && !filterDraft.entityType && !filterDraft.relationshipType}
            >
              {messages.clearFilters}
            </button>
          </div>
        </form>

        {hasGraph && (
          <div className={styles.statsRow}>
            <div className={styles.statCard}>
              <span className={styles.statValue}>{graphState.nodes.length}</span>
              <span className={styles.statLabel}>{entityCountLabel}</span>
            </div>
            <div className={styles.statCard}>
              <span className={styles.statValue}>{graphState.relationships.length}</span>
              <span className={styles.statLabel}>{relationshipCountLabel}</span>
            </div>
          </div>
        )}

        <div className={styles.contentGrid}>
          <section className={styles.stage} aria-labelledby={ids.stage}>
            <div className={styles.stageHeader}>
              <h2 id={ids.stage}>{messages.stageTitle}</h2>
              <div className={styles.viewControls} role="group" aria-label={messages.viewMode}>
                <button
                  ref={twoDButtonRef}
                  type="button"
                  className={view === "2d" ? styles.viewButtonActive : styles.viewButton}
                  aria-pressed={view === "2d"}
                  disabled={!hasGraph}
                  onClick={() => setView("2d")}
                >
                  {messages.view2d}
                </button>
                <button
                  type="button"
                  className={view === "3d" ? styles.viewButtonActive : styles.viewButton}
                  aria-pressed={view === "3d"}
                  aria-describedby={ids.graphicsStatus}
                  disabled={graphicsSupport !== "available" || !hasGraph}
                  onClick={() => setView("3d")}
                >
                  {messages.view3d}
                </button>
              </div>
            </div>

            <p id={ids.graphicsStatus} className={styles.graphicsStatus} role="status" aria-live="polite">
              {graphicsMessage}
            </p>

            <div className={styles.visualization}>
              {graphState.status === "loading" && (
                <div className={styles.dataState} role="status" aria-live="polite">
                  {messages.loadingGraph}
                </div>
              )}
              {graphState.status === "unconfigured" && (
                <div className={styles.dataState} role="status">
                  {messages.unconfiguredData}
                </div>
              )}
              {graphState.status === "error" && (
                <div className={styles.dataError} role="alert">
                  <p>{graphState.error === "invalid-data" ? messages.invalidGraphData : messages.graphLoadError}</p>
                  <button className={styles.fallbackButton} type="button" onClick={graph.retry}>
                    {messages.retry}
                  </button>
                </div>
              )}
              {graphState.status === "empty" && (
                <div className={styles.dataState} role="status">
                  {messages.emptyGraph}
                </div>
              )}
              {graphState.status === "ready" && graphState.nodes.length === 0 && (
                <div className={styles.dataState} role="status" aria-live="polite">
                  <p>
                    {graphState.pageError
                      ? graphState.pageError === "invalid-data"
                        ? messages.invalidGraphData
                        : messages.graphLoadError
                      : messages.emptyGraphPage}
                  </p>
                  {graphState.nextCursor !== null && (
                    <button
                      className={styles.fallbackButton}
                      type="button"
                      disabled={graphState.loadingMore}
                      onClick={graph.loadMore}
                    >
                      {graphState.loadingMore
                        ? messages.loadingMoreGraph
                        : graphState.pageError
                          ? messages.retry
                          : messages.loadMoreGraph}
                    </button>
                  )}
                </div>
              )}
              {hasGraph && view === "2d" && (
                <RelationshipGraph2D
                  nodes={graphState.nodes}
                  relationships={graphState.relationships}
                  selectedNodeId={selectedNodeId}
                  locale={locale}
                  totalNodes={graphState.totalNodes}
                  totalRelationships={graphState.totalRelationships}
                  onSelectNode={navigateToNode}
                />
              )}
              {hasGraph && view === "3d" && graphView && (
                <>
                  {sceneLimitNotice && <p className={styles.mapHint} role="note">{sceneLimitNotice}</p>}
                  <div className={styles.canvas3dFrame}>
                    <SceneChunkErrorBoundary
                      onError={handleGraphicsFallback}
                      fallback={
                        <div className={styles.canvasFallback} role="alert">
                          <p>{messages.canvasFallback}</p>
                          <button
                            className={styles.fallbackButton}
                            type="button"
                            onClick={() => handleGraphicsFallback()}
                          >
                            {messages.switchTo2d}
                          </button>
                        </div>
                      }
                    >
                      <LazyTheater3DCanvas
                        graphView={graphView}
                        selectedNodeId={selectedNodeId}
                        locale={locale}
                        onSelectNode={navigateToNode}
                        onFallback={handleGraphicsFallback}
                      />
                    </SceneChunkErrorBoundary>
                  </div>
                </>
              )}
            </div>
          </section>

          {hasGraph && graphState.sourceKind && (
            <RelationshipExplorer
              key={filterResetKey}
              nodes={graphState.nodes}
              relationships={graphState.relationships}
              selectedNodeId={selectedNodeId}
              locale={locale}
              sourceKind={graphState.sourceKind}
              totalNodes={graphState.totalNodes}
              totalRelationships={graphState.totalRelationships}
              hasMoreData={graphState.nextCursor !== null}
              loadingMore={graphState.loadingMore}
              pageError={graphState.pageError}
              historyPosition={historyPosition}
              canNavigateBack={canNavigateBack}
              canNavigateForward={canNavigateForward}
              onNavigateBack={() => navigateSelectionHistory(-1)}
              onNavigateForward={() => navigateSelectionHistory(1)}
              onSelectNode={navigateToNode}
              onLoadMore={graph.loadMore}
              onRetryMore={graph.loadMore}
            />
          )}
        </div>
      </div>
    </section>
  );
}
