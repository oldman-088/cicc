import { fireEvent, render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CiccApplication } from "../application/CiccApplication";
import { SystemHealthWorkspace } from "./SystemHealthWorkspace";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// Synthetic in-memory contract fixture for tests only; production never falls back to it.
function overview(dataSource = "live-ops-database") {
  return {
    generated_at: "2026-11-05T10:00:00Z",
    overall_status: "degraded",
    services: [{
      key: "api",
      kind: "service",
      name: "Operations API",
      status: "degraded",
      detail: "Provider-reported response",
      last_check_at: "2026-11-05T09:59:00Z",
      check: null,
    }],
    modules: [],
    metrics: {
      entities: 10,
      vulnerabilities: 4,
      campaigns: 2,
      recent_updates_24h: 7,
      last_successful_sync: null,
    },
    activity: [{ id: 1, ts: null, level: "info", source: "ops", message: "Recorded provider activity" }],
    data_source: dataSource,
    cached: true,
    cache_age_s: 1.25,
  };
}

function stubProvider(dataSource = "live-ops-database") {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, _options?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/ops/overview")) return jsonResponse(overview(dataSource));
    if (url.endsWith("/ops/alerts")) return jsonResponse({ alerts: [] });
    if (url.endsWith("/ops/workers")) return jsonResponse({ stall_threshold_s: 300, workers: [] });
    if (url.endsWith("/coordination/health")) return jsonResponse({ overall: "healthy", components: [{ key: "agents", status: "healthy", detail: "1 active", reasons: [] }], reasons: [], at: "2026-11-05T10:00:00Z", last_operations: { last_webhook_received: null, last_github_sync_success: null, last_github_sync_attempt: null, last_task_event: "2026-11-05T09:00:00Z", checked_at: "2026-11-05T10:00:00Z", note: "on-demand check; NOT continuous monitoring (no scheduler running)" } });
    return jsonResponse({ error: { code: "not_found" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("System Health workspace", () => {
  it("renders API-reported health, cache, components, and metrics without claiming an empty alert list is all-clear", async () => {
    const fetchMock = stubProvider();
    render(<SystemHealthWorkspace />);

    expect(await screen.findByText("Operations API")).toBeInTheDocument();
    expect(screen.getAllByText("degraded")).toHaveLength(2);
    expect(screen.getByText("live-ops-database")).toBeInTheDocument();
    expect(screen.getByText("Cached response · Cache age: 1.25s")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
    expect(screen.getByText(/This is not, by itself, a guarantee/)).toBeInTheDocument();
    expect(screen.getByText("Recorded provider activity")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(await screen.findByText("Coordination health")).toBeInTheDocument();
    expect(screen.getByText(/not continuous monitoring/)).toBeInTheDocument();
    for (const [url, options] of fetchMock.mock.calls) {
      expect(String(url)).toMatch(/^\/api\/integrations\/(ops|coordination)\//);
      expect(options?.method).toBe("GET");
      expect(options?.headers).not.toHaveProperty("Authorization");
    }
  });

  it("preserves Arabic/Persian RTL while isolating provider labels in LTR", async () => {
    window.localStorage.clear();
    stubProvider();
    render(<CiccApplication><SystemHealthWorkspace /></CiccApplication>);
    const localeSelect = screen.getByRole("combobox", { name: "Interface language" });

    for (const [locale, title] of [
      ["ar", "سلامة النظام"],
      ["fa", "سلامت سامانه"],
    ]) {
      fireEvent.change(localeSelect, { target: { value: locale } });
      const heading = await screen.findByRole("heading", { name: title, level: 1 });
      expect(heading.closest("[lang][dir]")).toHaveAttribute("lang", locale);
      expect(heading.closest("[lang][dir]")).toHaveAttribute("dir", "rtl");
    }

    expect(screen.getByText("live-ops-database").closest("bdi")).toHaveAttribute("dir", "ltr");
  });

  it("withholds operational counters for an unrecognized data-source label", async () => {
    stubProvider("unknown-source");
    render(<SystemHealthWorkspace />);

    expect(await screen.findByText(/Metrics are hidden because the provider did not return/)).toBeInTheDocument();
    expect(screen.queryByText("10")).not.toBeInTheDocument();
    expect(screen.getByText("unknown-source")).toBeInTheDocument();
  });

  it("keeps provider configuration failures distinct from empty operational data", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(jsonResponse(
      { error: { code: "provider_not_configured" } },
      503,
    ))));
    render(<SystemHealthWorkspace />);

    expect(await screen.findAllByText("The server-side provider is not configured in this deployment.")).toHaveLength(4);
    expect(screen.queryByText("No active alert records")).not.toBeInTheDocument();
  });

  it("passes automated structural axe checks for populated panels (contrast excluded)", async () => {
    stubProvider();
    const { container } = render(<SystemHealthWorkspace />);
    expect(await screen.findByText("Operations API")).toBeInTheDocument();
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());

    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
