import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CiccApplication } from "../application/CiccApplication";
import { CoordinationWorkspace } from "./CoordinationWorkspace";

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

type CoordinationReadCategory = "health" | "metrics" | "agents" | "tasks" | "events" | "write-capabilities";

function providerFailure(status: number) {
  const code = status === 401 ? "unauthorized"
    : status === 403 ? "forbidden"
      : status === 404 ? "not_found"
        : status === 429 ? "rate_limited"
          : status >= 500 ? "upstream_unavailable" : "invalid_request";
  return new Response(JSON.stringify({ error: { code } }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function stubProvider(options: {
  taskCreationEnabled?: boolean;
  tasks?: Array<Record<string, unknown>>;
  failReads?: Partial<Record<CoordinationReadCategory, number>>;
} = {}) {
  // Synthetic unit-test contract data only; this fixture is never used as a UI fallback.
  const responses: Record<string, unknown> = {
    health: {
      overall: "degraded",
      components: [{
        key: "broker",
        status: "not_configured",
        detail: "Human-assisted delivery only",
        reasons: ["No broker configured: deliveries are prepared, not broker-delivered"],
      }],
      reasons: ["broker: No broker configured"],
      last_operations: {
        last_webhook_received: null,
        last_github_sync_success: null,
        last_github_sync_attempt: null,
        last_task_event: "2026-11-06T09:00:00Z",
        checked_at: "2026-11-06T09:00:00Z",
        note: "on-demand check; NOT continuous monitoring (no scheduler running)",
      },
      at: "2026-11-06T09:00:00Z",
    },
    metrics: {
      tasks_total: 2,
      by_state: { RUNNING: 1, QUEUED: 1 },
      by_kind: { ci_failed: 2 },
      active_by_agent: { agent_a: 1 },
      avg_progress_active: 30,
      dead_lettered: 0,
      deliveries_total: 1,
      deliveries_by_outcome: { published: 1 },
      approvals_pending: 1,
      agents_registered: 1,
      agents_online: 1,
    },
    agents: { agents: [{
      agent: "agent_a",
      specialization: "Build checks",
      capabilities: ["triage"],
      status: "online",
      health: "ACTIVE",
      stale: false,
      last_heartbeat: "2026-11-05T09:55:00Z",
      active_tasks: 1,
      completed: 3,
      failed: 0,
    }] },
    events: { events: [{
      delivery_id: "delivery-1",
      event: "pull_request",
      received_at: "2026-11-05T09:45:00Z",
      action: "opened",
      repo: "oldman-088/cicc",
      sender: "sample-sender",
      task_id: "task-running",
    }] },
    trace: {
      task_id: "task-running",
      correlation: { idempotency_key: "bff-fixture-key-1", event_id: "source-event-1" },
      state: "RUNNING",
      agent: "agent_a",
      attempts: 1,
      dead_letter: false,
      events: [{ id: 1, at: "2026-11-05T09:30:00Z", kind: "created", detail: "Task accepted" }],
      deliveries: [{ id: 1, channel: "human_assisted", queue: "default", message_id: null, status: "prepared", attempt: 1, at: "2026-11-05T09:31:00Z" }],
      approvals: [],
    },
  };
  const taskRecords = options.tasks ?? [
    {
      task_id: "task-running",
      kind: "ci_failed",
      state: "RUNNING",
      priority: 5,
      agent: "agent_a",
      title: "Current build check",
      repo: "oldman-088/cicc",
      branch_ref: "feature/read-only",
      idempotency_key: "bff-fixture-key-1",
      created_at: "2026-11-05T09:00:00Z",
      updated_at: "2026-11-05T09:30:00Z",
      dead_letter: false,
      attempts: 2,
      progress: 40,
      result: "Provider-reported build result",
      routing_explanation: { via: "score", score: 91, candidates: 1, reasons: ["specialization match"] },
    },
    {
      task_id: "task-queued",
      kind: "pr_opened",
      state: "QUEUED",
      priority: 4,
      agent: null,
      title: "Queued review",
      repo: null,
      branch_ref: null,
      created_at: null,
      updated_at: null,
      dead_letter: false,
      attempts: 0,
      progress: 0,
      result: null,
      routing_explanation: null,
    },
  ];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, requestOptions?: RequestInit) => {
    const url = String(input);
    const method = requestOptions?.method ?? "GET";
    if (url.endsWith("/coordination/write-capabilities")) {
      const status = options.failReads?.["write-capabilities"];
      if (status) return providerFailure(status);
      return jsonResponse({
        task_creation_enabled: options.taskCreationEnabled ?? false,
      });
    }
    if (url.includes("/coordination/task-trace?")) return jsonResponse(responses.trace);
    if (method === "POST" && url.endsWith("/coordination/tasks")) {
      const inputBody = JSON.parse(String(requestOptions?.body ?? "{}")) as Record<string, unknown>;
      const createdTask = {
        task_id: "task-created",
        kind: inputBody.kind,
        state: "CREATED",
        priority: inputBody.priority,
        agent: null,
        title: inputBody.title,
        repo: null,
        branch_ref: null,
        created_at: "2026-11-06T10:00:00Z",
        updated_at: "2026-11-06T10:00:00Z",
        dead_letter: false,
        attempts: 0,
        progress: 0,
        result: null,
        routing_explanation: null,
      };
      taskRecords.unshift(createdTask);
      return new Response(JSON.stringify({ task_id: "task-created", kind: inputBody.kind, state: "CREATED", duplicate: false }), {
        status: 201,
        headers: { "Content-Type": "application/json", "X-CICC-Idempotency-Key": "bff-unit-test-key" },
      });
    }
    if (url.endsWith("/coordination/tasks")) {
      const status = options.failReads?.tasks;
      if (status) return providerFailure(status);
      return jsonResponse({ tasks: taskRecords });
    }
    const key = Object.keys(responses).find((candidate) => url.endsWith(`/coordination/${candidate}`));
    if (!key) return new Response("", { status: 404 });
    if (key !== "trace") {
      const status = options.failReads?.[key as CoordinationReadCategory];
      if (status) return providerFailure(status);
    }
    return jsonResponse(responses[key]);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const coordinationReadPaths = [
  "/api/integrations/coordination/agents",
  "/api/integrations/coordination/events",
  "/api/integrations/coordination/health",
  "/api/integrations/coordination/metrics",
  "/api/integrations/coordination/tasks",
  "/api/integrations/coordination/write-capabilities",
].sort();

function expectCoordinationReadCategories(
  fetchMock: ReturnType<typeof stubProvider>,
  calls = fetchMock.mock.calls,
) {
  const paths = calls.map(([input]) => new URL(String(input), "http://localhost").pathname);
  expect([...new Set(paths)].sort()).toEqual(coordinationReadPaths);
  expect(calls.every(([, options]) => (options?.method ?? "GET") === "GET")).toBe(true);
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("Agent Coordination workspace", () => {
  it("shows provider-backed records, filters only returned tasks, and keeps writes disabled by default", async () => {
    const fetchMock = stubProvider();
    render(<CoordinationWorkspace />);

    expect(await screen.findByRole("heading", { name: "Coordination service health", level: 2 })).toBeInTheDocument();
    expect(screen.getByText("No broker configured: deliveries are prepared, not broker-delivered")).toBeInTheDocument();
    expect(screen.getByText("Not configured")).toBeInTheDocument();
    expect(screen.getByLabelText("Health check time")).toHaveAttribute("datetime", "2026-11-06T09:00:00Z");
    expect(await screen.findByRole("heading", { name: "agent_a", level: 3 })).toBeInTheDocument();
    expect(screen.getByText("Agent health reported by provider")).toBeInTheDocument();
    expect(screen.getByText("Task counts by state")).toBeInTheDocument();
    expect(screen.getByText("Webhook events received")).toBeInTheDocument();
    expect(screen.getByText("Current build check")).toBeInTheDocument();
    expect(screen.getByText("Queued review")).toBeInTheDocument();
    expect(screen.getByText(/Trusted single-tenant scope/)).toBeInTheDocument();
    expect(screen.getByText(/Task creation is disabled for this deployment/)).toBeInTheDocument();

    fireEvent.change(screen.getByRole("combobox", { name: "Filter loaded tasks by state" }), {
      target: { value: "RUNNING" },
    });
    expect(screen.getByText("Current build check")).toBeInTheDocument();
    expect(screen.queryByText("Queued review")).not.toBeInTheDocument();

    fireEvent.change(screen.getByRole("searchbox", { name: "Search the returned task records" }), {
      target: { value: "not-a-task" },
    });
    expect(screen.getByText("No returned task records match the selected filters.")).toBeInTheDocument();

    expect(fetchMock).toHaveBeenCalledTimes(6);
    expectCoordinationReadCategories(fetchMock);
    for (const [url, options] of fetchMock.mock.calls) {
      expect(String(url)).toMatch(/^\/api\/integrations\/coordination\//);
      expect(options?.method).toBe("GET");
      expect(options?.headers).not.toHaveProperty("Authorization");
    }
  });

  it("refreshes all provider panels through read-only requests", async () => {
    const fetchMock = stubProvider();
    render(<CoordinationWorkspace />);

    const refreshButton = await screen.findByRole("button", { name: "Refresh all provider data" });
    await waitFor(() => expect(refreshButton).toBeEnabled());
    expect(fetchMock).toHaveBeenCalledTimes(6);

    fireEvent.click(refreshButton);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(12));
    await waitFor(() => expect(refreshButton).toBeEnabled());
    expectCoordinationReadCategories(fetchMock, fetchMock.mock.calls.slice(6));

    fireEvent.click(refreshButton);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(18));
    await waitFor(() => expect(refreshButton).toBeEnabled());
    expectCoordinationReadCategories(fetchMock, fetchMock.mock.calls.slice(12));

    for (const [url, options] of fetchMock.mock.calls) {
      expect(String(url)).toMatch(/^\/api\/integrations\/coordination\//);
      expect(options?.method).toBe("GET");
      expect(options?.headers).not.toHaveProperty("Authorization");
    }
  });

  it("presents API-reported routing decisions, progress, attempts, and results without inference", async () => {
    stubProvider();
    render(<CoordinationWorkspace />);

    fireEvent.click(await screen.findByText("Current build check"));
    expect(screen.getAllByRole("heading", { name: "Routing decision" }).length).toBeGreaterThan(0);
    expect(screen.getByText("specialization match")).toBeInTheDocument();
    expect(screen.getByText("Provider-reported build result")).toBeInTheDocument();
    expect(screen.getAllByLabelText("Reported progress")[0]).toHaveAttribute("value", "40");
    expect(screen.getAllByText("Attempts reported")[0].nextElementSibling).toHaveTextContent("2");
  });

  it("creates a task only when the server capability is enabled and refreshes source-backed views", async () => {
    const fetchMock = stubProvider({ taskCreationEnabled: true });
    render(<CoordinationWorkspace />);

    expect(await screen.findByRole("heading", { name: "Create a coordination task" })).toBeInTheDocument();
    expect(screen.queryByText(/Task creation is disabled for this deployment/)).not.toBeInTheDocument();
    fireEvent.change(await screen.findByLabelText("Task kind"), { target: { value: "manual_review" } });
    fireEvent.change(screen.getByLabelText("Task title"), { target: { value: "Review release candidate" } });
    const payloadField = screen.getByLabelText("Task payload (JSON object)");
    fireEvent.change(payloadField, { target: { value: "not-json" } });
    fireEvent.click(screen.getByRole("button", { name: "Create task" }));
    expect(await screen.findByText("Enter a valid JSON object for the task payload.")).toBeInTheDocument();
    expect(payloadField).toHaveAttribute("aria-invalid", "true");
    const describedBy = payloadField.getAttribute("aria-describedby")?.split(" ") ?? [];
    expect(describedBy).toHaveLength(2);
    expect(describedBy.every((id) => document.getElementById(id))).toBe(true);

    fireEvent.change(payloadField, { target: { value: JSON.stringify({ labels: ["integration"] }) } });
    fireEvent.click(screen.getByRole("button", { name: "Create task" }));

    expect(await screen.findByText("The provider accepted the task creation request.")).toBeInTheDocument();
    expect(payloadField).toHaveAttribute("aria-invalid", "false");
    expect(await screen.findByText("Review release candidate")).toBeInTheDocument();
    const createCall = fetchMock.mock.calls.find(([, options]) => options?.method === "POST");
    expect(createCall).toBeDefined();
    expect(createCall?.[1]?.headers).not.toHaveProperty("Authorization");
    expect(JSON.parse(String(createCall?.[1]?.body))).toMatchObject({
      kind: "manual_review",
      title: "Review release candidate",
      payload: { labels: ["integration"] },
    });
  });

  it("paginates and resets to the first page after a task search", async () => {
    const tasks = Array.from({ length: 12 }, (_, index) => ({
      task_id: `page-task-${index + 1}`,
      kind: "review",
      state: "COMPLETED",
      priority: 5,
      agent: "agent_a",
      title: `Paged task ${index + 1}`,
      repo: null,
      branch_ref: null,
      created_at: null,
      updated_at: null,
      dead_letter: false,
      attempts: 1,
      progress: 100,
      result: null,
      routing_explanation: null,
    }));
    stubProvider({ tasks });
    render(<CoordinationWorkspace />);

    expect(await screen.findByText("Paged task 1")).toBeInTheDocument();
    expect(screen.queryByText("Paged task 11")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(screen.getByText("Paged task 11")).toBeInTheDocument();
    expect(screen.queryByText("Paged task 1")).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search the returned task records" }), {
      target: { value: "page-task-2" },
    });
    expect(screen.getByText("Paged task 2")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
  });

  it("keeps provider-reported routing output read-only and exposes no route action", async () => {
    const tasks = [{
      task_id: "task-route-read-only",
      kind: "review",
      state: "CREATED",
      priority: 5,
      agent: null,
      title: "Awaiting provider routing",
      repo: null,
      branch_ref: null,
      created_at: null,
      updated_at: null,
      dead_letter: false,
      attempts: 0,
      progress: 0,
      result: null,
      routing_explanation: {
        via: "score",
        score: 88,
        candidates: 1,
        reasons: ["Provider-owned routing decision"],
      },
    }];
    const fetchMock = stubProvider({ tasks });
    render(<CoordinationWorkspace />);

    fireEvent.click(await screen.findByText("Awaiting provider routing"));
    expect(await screen.findByText("Provider-owned routing decision")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Route task" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url, options]) =>
      String(url).includes("/coordination/tasks/") && String(url).endsWith("/route") && options?.method === "POST",
    )).toBe(false);
  });

  it("loads task trace only on analyst request and distinguishes delivered/prepared records", async () => {
    const fetchMock = stubProvider();
    render(<CoordinationWorkspace />);

    const traceButtons = await screen.findAllByRole("button", { name: "View task trace" });
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("task-trace"))).toBe(false);
    fireEvent.click(traceButtons[0]!);

    expect(await screen.findByText("Task accepted")).toBeInTheDocument();
    expect(screen.getByText("human_assisted")).toBeInTheDocument();
    expect(screen.getByText("prepared")).toBeInTheDocument();
    expect(screen.getAllByText("bff-fixture-key-1")).toHaveLength(2);
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/coordination/task-trace?task_id=task-running"))).toBe(true);
  });

  it("shows permission denial for the health resource without masking other panels", async () => {
    const fetchMock = stubProvider();
    const original = fetchMock.getMockImplementation();
    if (!original) throw new Error("expected a mocked provider");
    fetchMock.mockImplementation((input, options) => {
      if (String(input).endsWith("/coordination/health")) {
        return Promise.resolve(new Response(JSON.stringify({ error: { code: "forbidden" } }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }));
      }
      return original(input, options);
    });

    render(<CoordinationWorkspace />);
    expect(await screen.findByText("The provider did not authorize this read request.")).toBeInTheDocument();
    expect(await screen.findByText("Tasks total")).toBeInTheDocument();
  });

  it.each([
    "health",
    "metrics",
    "agents",
    "tasks",
    "events",
    "write-capabilities",
  ] as const)("keeps a %s read failure local while the other Coordination resources render", async (failedCategory) => {
    const fetchMock = stubProvider({ failReads: { [failedCategory]: 503 } });
    render(<CoordinationWorkspace />);

    expect(await screen.findByText("The provider could not be reached or returned an upstream error.")).toBeInTheDocument();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledTimes(6);
    expectCoordinationReadCategories(fetchMock);

    const successfulContent: Record<CoordinationReadCategory, string> = {
      health: "No broker configured: deliveries are prepared, not broker-delivered",
      metrics: "Tasks total",
      agents: "Build checks",
      tasks: "Current build check",
      events: "delivery-1",
      "write-capabilities": "Task creation is disabled for this deployment.",
    };
    for (const category of Object.keys(successfulContent) as CoordinationReadCategory[]) {
      if (category === failedCategory) continue;
      expect(screen.getByText((content) => content.includes(successfulContent[category]))).toBeInTheDocument();
    }
  });

  it("shows an explicit empty state when the provider returns no health components", async () => {
    const fetchMock = stubProvider();
    const original = fetchMock.getMockImplementation();
    if (!original) throw new Error("expected a mocked provider");
    fetchMock.mockImplementation((input, options) => {
      if (String(input).endsWith("/coordination/health")) {
        return Promise.resolve(jsonResponse({
          overall: "unknown",
          components: [],
          reasons: [],
          last_operations: {
            last_webhook_received: null,
            last_github_sync_success: null,
            last_github_sync_attempt: null,
            last_task_event: null,
            checked_at: null,
            note: "on-demand check; NOT continuous monitoring (no scheduler running)",
          },
          at: null,
        }));
      }
      return original(input, options);
    });

    render(<CoordinationWorkspace />);
    expect(await screen.findByText("The provider returned no component health records.")).toBeInTheDocument();
  });

  it("preserves Arabic/Persian RTL while isolating agent identifiers in LTR", async () => {
    window.localStorage.clear();
    stubProvider();
    render(<CiccApplication><CoordinationWorkspace /></CiccApplication>);
    const localeSelect = screen.getByRole("combobox", { name: "Interface language" });

    for (const [locale, title] of [
      ["ar", "تنسيق الوكلاء"],
      ["fa", "هماهنگی عامل‌ها"],
    ]) {
      fireEvent.change(localeSelect, { target: { value: locale } });
      const heading = await screen.findByRole("heading", { name: title, level: 1 });
      expect(heading.closest("[lang][dir]")).toHaveAttribute("lang", locale);
      expect(heading.closest("[lang][dir]")).toHaveAttribute("dir", "rtl");
    }

    const agentHeading = screen.getByRole("heading", { name: "agent_a", level: 3 });
    expect(agentHeading.querySelector("bdi")).toHaveAttribute("dir", "ltr");
  });

  it("marks stale agents using the provider flag rather than inferring liveness", async () => {
    const fetchMock = stubProvider();
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/coordination/agents")) {
        return jsonResponse({ agents: [{
          agent: "stale-agent",
          specialization: null,
          capabilities: [],
          status: "busy",
          stale: true,
          last_seen: null,
          active_tasks: 0,
          completed_tasks: 0,
          failed_tasks: 0,
        }] });
      }
      return new Response("", { status: 404 });
    });

    render(<CoordinationWorkspace />);
    expect(await screen.findByText("Stale per provider")).toBeInTheDocument();
    expect(screen.getAllByText("busy")).toHaveLength(2);
  });

  it("passes automated structural axe checks for populated panels (contrast excluded)", async () => {
    stubProvider();
    const { container } = render(<CoordinationWorkspace />);
    expect(await screen.findByText("Current build check")).toBeInTheDocument();
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, "getContext")
      .mockImplementation(() => null as never);
    const results = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
    }).finally(() => canvasContext.mockRestore());

    expect(results.violations.map((violation) => violation.id)).toEqual([]);
  });
});
