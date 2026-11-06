import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { AnchorHTMLAttributes } from "react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BetaReadinessPanel } from "./BetaReadinessPanel";

const readinessLocale = vi.hoisted(() => ({ value: "en" as "en" | "ar" | "fa" }));

vi.mock("next/link", () => ({
  default: ({ href, children, ...props }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} {...props}>{children}</a>,
}));

vi.mock("../application/CiccApplication", () => ({
  useCiccLocale: () => ({ locale: readinessLocale.value, setLocale: () => {} }),
}));

const opsOverview = {
  generated_at: "2026-11-06T09:30:00Z",
  overall_status: "degraded",
  services: [],
  modules: [],
  metrics: { entities: 0, vulnerabilities: 0, campaigns: 0, recent_updates_24h: 0, last_successful_sync: null },
  activity: [],
  data_source: "experimental-fixture",
  cached: true,
  cache_age_s: 42,
};

const coordinationHealth = {
  overall: "degraded",
  components: [{
    key: "broker",
    status: "not_configured",
    detail: "Provider says delivery is prepared, not broker-confirmed.",
    reasons: ["No broker configured"],
  }],
  reasons: ["broker: not configured"],
  last_operations: {
    last_webhook_received: null,
    last_github_sync_success: null,
    last_github_sync_attempt: null,
    last_task_event: null,
    checked_at: "2026-11-06T09:31:00Z",
    note: "on-demand check; NOT continuous monitoring",
  },
  at: "2026-11-06T09:31:00Z",
};

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function pathOf(input: RequestInfo | URL): string {
  return new URL(String(input), "http://cicc.test").pathname;
}

function installReadyFetch() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, _options?: RequestInit) => {
    const path = pathOf(input);
    if (path.endsWith("/ops/overview")) return response(opsOverview);
    if (path.endsWith("/coordination/health")) return response(coordinationHealth);
    return response({ error: { code: "not_found" } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  readinessLocale.value = "en";
});

describe("controlled beta readiness panel", () => {
  it("shows only provider-reported on-demand statuses and identifies unbound modules", async () => {
    const fetchMock = installReadyFetch();
    render(<BetaReadinessPanel />);

    expect(screen.getByRole("heading", { name: "Operational readiness", level: 2 })).toBeInTheDocument();
    expect(await screen.findByText("experimental-fixture")).toBeInTheDocument();
    expect(screen.getByText("42s", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("No broker configured")).toBeInTheDocument();
    expect(screen.getByText(/on-demand check; NOT continuous monitoring/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Other integration gates" })).toBeInTheDocument();
    expect(screen.getByText("Package API not mounted in CICC")).toBeInTheDocument();
    expect(screen.getByText("Proposed API and fixtures only")).toBeInTheDocument();
    expect(screen.getByText("Contract and authorization review pending")).toBeInTheDocument();

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(fetchMock.mock.calls.map(([input]) => pathOf(input)).sort()).toEqual([
      "/api/integrations/coordination/health",
      "/api/integrations/ops/overview",
    ]);
    expect(fetchMock.mock.calls.every(([, options]) => (options?.method ?? "GET") === "GET")).toBe(true);
    expect(fetchMock.mock.calls.every(([, options]) => !new Headers(options?.headers).has("Authorization"))).toBe(true);
  });

  it("keeps an authorization failure local and allows an operator to retry that resource", async () => {
    let operationsCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path.endsWith("/ops/overview")) {
        operationsCalls += 1;
        return operationsCalls === 1
          ? response({ error: { code: "unauthorized" } }, 401)
          : response(opsOverview);
      }
      if (path.endsWith("/coordination/health")) return response(coordinationHealth);
      return response({ error: { code: "not_found" } }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<BetaReadinessPanel />);

    const operationsRegion = await screen.findByRole("region", { name: "System operations" });
    expect(await within(operationsRegion).findByRole("alert")).toHaveTextContent(/rejected the server-side read credential/i);
    expect(screen.getByText(/Degraded \(provider-reported\)/)).toBeInTheDocument();

    fireEvent.click(within(operationsRegion).getByRole("button", { name: "Refresh" }));
    expect(await within(operationsRegion).findByText("experimental-fixture")).toBeInTheDocument();
    expect(within(operationsRegion).queryByRole("alert")).not.toBeInTheDocument();
    expect(operationsCalls).toBe(2);
  });

  it("keeps the last successful partial data visibly stale when a later read fails", async () => {
    let operationsCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path.endsWith("/ops/overview")) {
        operationsCalls += 1;
        return operationsCalls === 1
          ? response(opsOverview)
          : response({ error: { code: "unavailable" } }, 503);
      }
      if (path.endsWith("/coordination/health")) return response(coordinationHealth);
      return response({ error: { code: "not_found" } }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<BetaReadinessPanel />);

    const operationsRegion = await screen.findByRole("region", { name: "System operations" });
    expect(await within(operationsRegion).findByText("experimental-fixture")).toBeInTheDocument();
    fireEvent.click(within(operationsRegion).getByRole("button", { name: "Refresh" }));

    expect(await within(operationsRegion).findByRole("alert")).toHaveTextContent(/could not be reached/i);
    expect(within(operationsRegion).getByText("experimental-fixture")).toBeInTheDocument();
    expect(within(operationsRegion).getByText(/last successful response, not a current provider check/i)).toBeInTheDocument();
    expect(screen.getByText("No broker configured")).toBeInTheDocument();
  });

  it("keeps the combined refresh busy until both concurrent provider checks settle", async () => {
    let hold = false;
    const deferred: Array<{ path: string; resolve: (value: Response) => void }> = [];
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (!hold) {
        return Promise.resolve(path.endsWith("/ops/overview") ? response(opsOverview) : response(coordinationHealth));
      }
      return new Promise<Response>((resolve) => deferred.push({ path, resolve }));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<BetaReadinessPanel />);

    const refresh = await screen.findByRole("button", { name: "Refresh operational checks" });
    await waitFor(() => expect(refresh).toBeEnabled());
    hold = true;
    fireEvent.click(refresh);
    await waitFor(() => expect(deferred).toHaveLength(2));
    expect(refresh).toBeDisabled();
    expect(refresh).toHaveAttribute("aria-busy", "true");

    const opsPending = deferred.find((item) => item.path.endsWith("/ops/overview"));
    const coordinationPending = deferred.find((item) => item.path.endsWith("/coordination/health"));
    expect(opsPending).toBeDefined();
    expect(coordinationPending).toBeDefined();
    await act(async () => { opsPending?.resolve(response(opsOverview)); });
    expect(refresh).toBeDisabled();
    await act(async () => { coordinationPending?.resolve(response(coordinationHealth)); });
    await waitFor(() => expect(refresh).toBeEnabled());
    expect(refresh).toHaveAttribute("aria-busy", "false");
  });

  it.each([
    { locale: "ar" as const, title: "الجاهزية التشغيلية", refresh: "تحديث الفحوصات التشغيلية" },
    { locale: "fa" as const, title: "آمادگی عملیاتی", refresh: "تازه‌سازی بررسی‌های عملیاتی" },
  ])("localizes the beta check and sets RTL for $locale", async ({ locale, title, refresh }) => {
    readinessLocale.value = locale;
    installReadyFetch();
    const { container } = render(<BetaReadinessPanel />);
    expect(await screen.findByRole("heading", { name: title, level: 2 })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: refresh })).toBeInTheDocument();
    expect(container.firstElementChild).toHaveAttribute("dir", "rtl");
  });

  it("has an accessible structure after provider responses resolve", async () => {
    installReadyFetch();
    const { container } = render(<BetaReadinessPanel />);
    await screen.findByText("experimental-fixture");
    await screen.findByText("No broker configured");
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockImplementation(() => null as never);
    const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } })
      .finally(() => canvasContext.mockRestore());
    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
