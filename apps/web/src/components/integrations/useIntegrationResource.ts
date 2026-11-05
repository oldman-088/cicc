"use client";

import { useCallback, useEffect, useState } from "react";
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

  useEffect(() => {
    const controller = new AbortController();
    setState((current) => ({
      status: "loading",
      data: current.data,
      checkedAt: current.checkedAt,
    }));

    void readIntegrationResource(endpoint, decode, controller.signal)
      .then((data) => {
        setState({ status: "ready", data, checkedAt: new Date().toISOString() });
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
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

    return () => controller.abort();
  }, [decode, endpoint, revision]);

  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  return { state, refresh };
}
