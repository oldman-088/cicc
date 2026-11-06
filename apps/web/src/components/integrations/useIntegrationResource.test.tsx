import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useEffect } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  useIntegrationResource,
  type ResourceState,
} from "./useIntegrationResource";

type Value = { value: string };
type DeferredRequest = {
  signal: AbortSignal | undefined;
  promise: Promise<Response>;
  resolve: (response: Response) => void;
  reject: (error: unknown) => void;
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function jsonResponse(value: unknown) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function parseValue(value: unknown): Value {
  if (typeof value !== "object" || value === null || !("value" in value) || typeof value.value !== "string") {
    throw new Error("Invalid value response");
  }
  return { value: value.value };
}

function ResourceProbe({
  onState,
}: {
  onState?: (state: ResourceState<Value>) => void;
}) {
  const { state, refresh } = useIntegrationResource("/api/integrations/test-resource", parseValue);
  useEffect(() => onState?.(state), [onState, state]);

  return (
    <section>
      <p role="status" aria-busy={state.status === "loading"}>{state.status}</p>
      {state.data && <output>{state.data.value}</output>}
      {state.error && <p role="alert">{state.error.kind}</p>}
      <button type="button" onClick={refresh}>Refresh test resource</button>
    </section>
  );
}

function installDeferredFetch() {
  const requests: DeferredRequest[] = [];
  const fetchMock = vi.fn((_input: RequestInfo | URL, options?: RequestInit) => {
    const request = deferred<Response>();
    requests.push({
      signal: options?.signal as AbortSignal | undefined,
      promise: request.promise,
      resolve: request.resolve,
      reject: request.reject,
    });
    // Deliberately ignore AbortSignal here: browsers/proxies and response-body
    // parsing can settle after cancellation, so the hook must still reject stale results.
    return request.promise;
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, requests };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useIntegrationResource request lifecycle", () => {
  it("ignores late results from superseded requests after repeated refreshes", async () => {
    const { fetchMock, requests } = installDeferredFetch();
    render(<ResourceProbe />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    const refreshButton = screen.getByRole("button", { name: "Refresh test resource" });
    fireEvent.click(refreshButton);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(requests[0].signal?.aborted).toBe(true);

    fireEvent.click(refreshButton);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    expect(requests[1].signal?.aborted).toBe(true);
    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");

    await act(async () => {
      requests[2].resolve(jsonResponse({ value: "newest response" }));
      await requests[2].promise;
    });
    expect(await screen.findByText("newest response")).toBeInTheDocument();

    await act(async () => {
      requests[0].resolve(jsonResponse({ value: "stale initial response" }));
      await requests[0].promise;
    });
    await act(async () => {
      requests[1].reject(new Error("late aborted request failure"));
      await requests[1].promise.catch(() => undefined);
    });

    expect(screen.getByText("newest response")).toBeInTheDocument();
    expect(screen.queryByText("stale initial response")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("ready")).toHaveAttribute("aria-busy", "false");
  });

  it("aborts pending work on unmount and ignores a response that settles afterward", async () => {
    const { fetchMock, requests } = installDeferredFetch();
    const onState = vi.fn();
    const { unmount } = render(<ResourceProbe onState={onState} />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const stateUpdatesAtUnmount = onState.mock.calls.length;

    unmount();
    expect(requests[0].signal?.aborted).toBe(true);

    await act(async () => {
      requests[0].resolve(jsonResponse({ value: "after unmount" }));
      await requests[0].promise;
    });
    expect(onState).toHaveBeenCalledTimes(stateUpdatesAtUnmount);
  });
});
