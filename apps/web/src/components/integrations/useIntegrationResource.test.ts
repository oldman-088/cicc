import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parseCoordinationMetrics } from "../../lib/integration-api";
import { retryDelaySeconds, useIntegrationResource } from "./useIntegrationResource";

const metrics = { tasks_total: 0, by_state: {}, by_kind: {}, active_by_agent: {}, avg_progress_active: 0, dead_lettered: 0, deliveries_total: 0, deliveries_by_outcome: {}, approvals_pending: 0, agents_registered: 0, agents_online: 0 };
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("useIntegrationResource bounded retry", () => {
  it("honors Retry-After for rate limits and recovers only after a real success response", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ error: { code: "rate_limited" } }, 429, { "Retry-After": "2" }))
      .mockResolvedValueOnce(json(metrics));
    vi.stubGlobal("fetch", fetchMock);
    const { result } = renderHook(() => useIntegrationResource("/api/integrations/coordination/metrics", parseCoordinationMetrics));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(result.current.state.status).toBe("error");
    expect(result.current.state.retry).toMatchObject({ attempt: 1, nextRetryInSeconds: 2 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.current.state.status).toBe("ready");
    expect(result.current.state.retry).toBeUndefined();
  });

  it("never auto-retries non-retryable failures such as unauthorized", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockResolvedValue(json({ error: { code: "unauthorized" } }, 401));
    vi.stubGlobal("fetch", fetchMock);
    const { result } = renderHook(() => useIntegrationResource("/api/integrations/coordination/metrics", parseCoordinationMetrics));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(result.current.state).toMatchObject({ status: "error", error: { kind: "unauthorized" } });
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("caps backoff and Retry-After delays", () => {
    expect(retryDelaySeconds("unavailable", undefined, 0)).toBe(1);
    expect(retryDelaySeconds("unavailable", undefined, 10)).toBe(30);
    expect(retryDelaySeconds("rate_limited", 600, 0)).toBe(60);
  });
});
