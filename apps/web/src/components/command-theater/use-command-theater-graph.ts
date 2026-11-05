import { useCallback, useEffect, useRef, useState } from "react";
import { GraphDataError, mergeGraphPage, validateGraphPage } from "./graph-data";
import type {
  CommandTheaterDataSource,
  GraphDataSourceKind,
  GraphFilters,
  IntelligenceRelationship,
  PositionedIntelligenceNode,
} from "./types";

export const GRAPH_PAGE_SIZE = 250;

type GraphErrorKind = "request" | "invalid-data";
type GraphLoadStatus = "loading" | "unconfigured" | "ready" | "empty" | "error";

export type CommandTheaterGraphState = {
  status: GraphLoadStatus;
  sourceKind: GraphDataSourceKind | null;
  nodes: PositionedIntelligenceNode[];
  relationships: IntelligenceRelationship[];
  nextCursor: string | null;
  totalNodes: number | null;
  totalRelationships: number | null;
  loadingMore: boolean;
  error: GraphErrorKind | null;
  pageError: GraphErrorKind | null;
};

function getErrorKind(error: unknown): GraphErrorKind {
  return error instanceof GraphDataError ? "invalid-data" : "request";
}

function toStateStatus(
  nodes: PositionedIntelligenceNode[],
  relationships: IntelligenceRelationship[],
  nextCursor: string | null,
): GraphLoadStatus {
  return nodes.length > 0 || relationships.length > 0 || nextCursor !== null ? "ready" : "empty";
}

function initialState(status: GraphLoadStatus): CommandTheaterGraphState {
  return {
    status,
    sourceKind: null,
    nodes: [],
    relationships: [],
    nextCursor: null,
    totalNodes: null,
    totalRelationships: null,
    loadingMore: false,
    error: null,
    pageError: null,
  };
}

type UseCommandTheaterGraphProps = {
  dataSource?: CommandTheaterDataSource;
  demoMode: boolean;
  filters: GraphFilters;
};

export function useCommandTheaterGraph({
  dataSource,
  demoMode,
  filters,
}: UseCommandTheaterGraphProps) {
  const [state, setState] = useState<CommandTheaterGraphState>(() =>
    initialState(dataSource || demoMode ? "loading" : "unconfigured"),
  );
  const stateRef = useRef(state);
  const sourceRef = useRef<CommandTheaterDataSource | null>(dataSource ?? null);
  const requestControllerRef = useRef<AbortController | null>(null);
  const pageControllerRef = useRef<AbortController | null>(null);
  const seenCursorsRef = useRef(new Set<string>());
  const [retryToken, setRetryToken] = useState(0);

  const commit = useCallback((next: CommandTheaterGraphState) => {
    stateRef.current = next;
    setState(next);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    requestControllerRef.current = controller;
    pageControllerRef.current?.abort();
    pageControllerRef.current = null;
    sourceRef.current = null;
    seenCursorsRef.current.clear();
    commit(initialState(dataSource || demoMode ? "loading" : "unconfigured"));

    async function loadFirstPage() {
      let source = dataSource;
      if (!source && demoMode) {
        const demoModule = await import("./demo-data-source");
        source = demoModule.DEMO_DATA_SOURCE;
      }

      if (controller.signal.aborted) return;
      if (!source) {
        commit(initialState("unconfigured"));
        return;
      }

      sourceRef.current = source;
      const page = validateGraphPage(
        await source.loadPage(
          { cursor: null, limit: GRAPH_PAGE_SIZE, filters },
          controller.signal,
        ),
      );
      if (controller.signal.aborted) return;

      const merged = mergeGraphPage([], [], page);
      if (page.nextCursor !== null) seenCursorsRef.current.add(page.nextCursor);
      commit({
        status: toStateStatus(merged.nodes, merged.relationships, page.nextCursor),
        sourceKind: source.kind,
        nodes: merged.nodes,
        relationships: merged.relationships,
        nextCursor: page.nextCursor,
        totalNodes: page.totalNodes === undefined
          ? null
          : Math.max(page.totalNodes, merged.nodes.length),
        totalRelationships: page.totalRelationships === undefined
          ? null
          : Math.max(page.totalRelationships, merged.relationships.length),
        loadingMore: false,
        error: null,
        pageError: null,
      });
    }

    void loadFirstPage().catch((error: unknown) => {
      if (controller.signal.aborted) return;
      const failedState = initialState("error");
      failedState.sourceKind = sourceRef.current?.kind ?? dataSource?.kind ?? null;
      failedState.error = getErrorKind(error);
      commit(failedState);
    });

    return () => {
      controller.abort();
      if (requestControllerRef.current === controller) requestControllerRef.current = null;
      pageControllerRef.current?.abort();
      pageControllerRef.current = null;
    };
  }, [commit, dataSource, demoMode, filters, retryToken]);

  const loadMore = useCallback(async () => {
    const current = stateRef.current;
    const source = sourceRef.current;
    if (
      !source ||
      current.status !== "ready" ||
      !current.nextCursor ||
      current.loadingMore
    ) {
      return;
    }

    const controller = new AbortController();
    pageControllerRef.current?.abort();
    pageControllerRef.current = controller;
    commit({ ...current, loadingMore: true, pageError: null });

    try {
      const page = validateGraphPage(
        await source.loadPage(
          { cursor: current.nextCursor, limit: GRAPH_PAGE_SIZE, filters },
          controller.signal,
        ),
      );
      if (controller.signal.aborted) return;

      const latest = stateRef.current;
      if (page.nextCursor !== null && seenCursorsRef.current.has(page.nextCursor)) {
        throw new GraphDataError("Graph page cursor repeated; pagination did not advance.");
      }
      const merged = mergeGraphPage(latest.nodes, latest.relationships, page);
      if (page.nextCursor !== null) seenCursorsRef.current.add(page.nextCursor);
      commit({
        ...latest,
        status: toStateStatus(merged.nodes, merged.relationships, page.nextCursor),
        nodes: merged.nodes,
        relationships: merged.relationships,
        nextCursor: page.nextCursor,
        totalNodes: page.totalNodes === undefined && latest.totalNodes === null
          ? null
          : Math.max(page.totalNodes ?? latest.totalNodes ?? 0, merged.nodes.length),
        totalRelationships: page.totalRelationships === undefined && latest.totalRelationships === null
          ? null
          : Math.max(page.totalRelationships ?? latest.totalRelationships ?? 0, merged.relationships.length),
        loadingMore: false,
        error: null,
        pageError: null,
      });
    } catch (error) {
      if (controller.signal.aborted) return;
      const latest = stateRef.current;
      commit({ ...latest, loadingMore: false, pageError: getErrorKind(error) });
    } finally {
      if (pageControllerRef.current === controller) pageControllerRef.current = null;
    }
  }, [commit, filters]);

  const retry = useCallback(() => setRetryToken((token) => token + 1), []);

  return {
    state,
    loadMore,
    retry,
  };
}
