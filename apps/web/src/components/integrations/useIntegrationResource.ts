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
  /** Bounded automatic-retry status; never present for non-retryable failures. */
  retry?: { attempt: number; maxAttempts: number; nextRetryInSeconds: number };
  checkedAt?: string;
};

const RETRYABLE: ReadonlySet<IntegrationFailureKind> = new Set(["rate_limited", "unavailable"]);
export const MAX_AUTO_RETRIES = 2;

export function retryDelaySeconds(kind: IntegrationFailureKind, retryAfterSeconds: number | undefined, attempt: number): number {
  if (kind === "rate_limited" && retryAfterSeconds !== undefined) return Math.min(Math.max(retryAfterSeconds, 1), 60);
  return Math.min(2 ** attempt, 30); // 1s, 2s — bounded, no uncontrolled loops
}

export function useIntegrationResource<T>(
  endpoint: string,
  decode: (value: unknown) => T,
) {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<ResourceState<T>>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setState((current) => ({
      status: "loading",
      data: current.data,
      checkedAt: current.checkedAt,
    }));

    const attempt = (attemptIndex: number): void => {
      void readIntegrationResource(endpoint, decode, controller.signal)
        .then((data) => {
          if (controller.signal.aborted) return;
          setState({ status: "ready", data, checkedAt: new Date().toISOString() });
        })
        .catch((cause: unknown) => {
          if (controller.signal.aborted) return;
          const error = cause instanceof IntegrationApiError
            ? cause
            : new IntegrationApiError("unavailable");
          if (RETRYABLE.has(error.kind) && attemptIndex < MAX_AUTO_RETRIES) {
            const delay = retryDelaySeconds(error.kind, error.retryAfterSeconds, attemptIndex);
            setState((current) => ({
              status: "error",
              data: current.data,
              checkedAt: current.checkedAt,
              error: { kind: error.kind, retryAfterSeconds: error.retryAfterSeconds },
              retry: { attempt: attemptIndex + 1, maxAttempts: MAX_AUTO_RETRIES, nextRetryInSeconds: delay },
            }));
            timer = setTimeout(() => attempt(attemptIndex + 1), delay * 1000);
            return;
          }
          setState((current) => ({
            status: "error",
            data: current.data,
            checkedAt: current.checkedAt,
            error: { kind: error.kind, retryAfterSeconds: error.retryAfterSeconds },
          }));
        });
    };
    attempt(0);

    return () => { controller.abort(); if (timer) clearTimeout(timer); };
  }, [decode, endpoint, revision]);

  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  return { state, refresh };
}
