"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  IntegrationApiError,
  readIntegrationResource,
  type IntegrationFailureKind,
} from "../../lib/integration-api";

export type ResourceState<T> = {
  status: "loading" | "ready" | "error";
  data?: T;
  error?: { kind: IntegrationFailureKind; retryAfterSeconds?: number };
  checkedAt?: string;
};

export function useIntegrationResource<T>(
  endpoint: string,
  decode: (value: unknown) => T,
) {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<ResourceState<T>>({ status: "loading" });
  const requestGeneration = useRef(0);

  useEffect(() => {
    const controller = new AbortController();
    const generation = ++requestGeneration.current;
    let active = true;
    setState((current) => ({
      status: "loading",
      data: current.data,
      checkedAt: current.checkedAt,
    }));

    const isCurrentRequest = () => (
      active
      && !controller.signal.aborted
      && requestGeneration.current === generation
    );

    void readIntegrationResource(endpoint, decode, controller.signal)
      .then((data) => {
        // Some fetch implementations and test doubles may resolve despite abort.
        // Only the newest mounted request may publish a result.
        if (!isCurrentRequest()) return;
        setState({ status: "ready", data, checkedAt: new Date().toISOString() });
      })
      .catch((cause: unknown) => {
        if (!isCurrentRequest()) return;
        const error = cause instanceof IntegrationApiError
          ? cause
          : new IntegrationApiError("unavailable");
        setState((current) => ({
          status: "error",
          data: current.data,
          checkedAt: current.checkedAt,
          error: { kind: error.kind, retryAfterSeconds: error.retryAfterSeconds },
        }));
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [decode, endpoint, revision]);

  const refresh = useCallback(() => {
    // Invalidate the current generation immediately, before the next effect runs.
    // This closes the small interval between the click and effect cleanup.
    requestGeneration.current += 1;
    // Mark the resource busy in the same event that schedules its next GET. This
    // keeps the workspace-wide busy state accurate across concurrent refreshes.
    setState((current) => ({
      status: "loading",
      data: current.data,
      checkedAt: current.checkedAt,
    }));
    setRevision((value) => value + 1);
  }, []);

  return { state, refresh };
}
