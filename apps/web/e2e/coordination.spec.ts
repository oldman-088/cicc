import { expect, test, type Page, type Route } from "@playwright/test";

const metrics = {
  tasks_total: 1,
  by_state: { RUNNING: 1 },
  by_kind: { review: 1 },
  active_by_agent: { agent_one: 1 },
  avg_progress_active: 40,
  dead_lettered: 0,
  deliveries_total: 1,
  deliveries_by_outcome: { prepared: 1 },
  approvals_pending: 0,
  agents_registered: 1,
  agents_online: 1,
};

const task = {
  task_id: "api-task-42",
  kind: "review",
  state: "RUNNING",
  priority: 4,
  agent: "agent_one",
  title: "Review current release",
  repo: "oldman-088/cicc",
  branch_ref: "release/2026.11",
  created_at: "2026-11-06T09:00:00Z",
  updated_at: "2026-11-06T09:05:00Z",
  idempotency_key: "bff-e2e-key-42",
  dead_letter: false,
  attempts: 1,
  progress: 40,
  result: "Provider-reported release review result",
  routing_explanation: { via: "score", score: 92, candidates: 1, reasons: ["review capability matched"] },
};

const health = {
  overall: "degraded",
  components: [{
    key: "broker",
    status: "not_configured",
    detail: "Human-assisted delivery only",
    reasons: ["No broker configured: task delivery is not broker-confirmed"],
  }],
  reasons: ["broker: no broker configured"],
  last_operations: {
    last_webhook_received: null,
    last_github_sync_success: null,
    last_github_sync_attempt: null,
    last_task_event: "2026-11-06T09:05:00Z",
    checked_at: "2026-11-06T09:06:00Z",
    note: "on-demand check; NOT continuous monitoring (no scheduler running)",
  },
  at: "2026-11-06T09:06:00Z",
};

const taskTrace = {
  task_id: "api-task-42",
  correlation: { idempotency_key: "bff-e2e-key-42", event_id: "webhook-event-42" },
  state: "RUNNING",
  agent: "agent_one",
  attempts: 1,
  dead_letter: false,
  events: [{ id: 1, at: "2026-11-06T09:05:00Z", kind: "created", detail: "Task accepted by the API" }],
  deliveries: [{
    id: 1,
    channel: "human_assisted",
    queue: "default",
    message_id: null,
    status: "prepared",
    attempt: 1,
    at: "2026-11-06T09:05:00Z",
  }],
  approvals: [],
};

async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

type MockWorkspaceOptions = {
  healthStatus?: number;
  onTrace?: () => void;
  taskCreationEnabled?: boolean;
  taskRoutingEnabled?: boolean;
  tasks?: Array<Record<string, unknown>>;
};

async function mockWorkspace(page: Page, options: MockWorkspaceOptions = {}) {
  // All payloads below are deterministic Playwright route fixtures, not application fallback data.
  const healthStatus = options.healthStatus ?? 200;
  const taskRecords = options.tasks ?? [task];
  await page.route("**/api/integrations/coordination/write-capabilities", (route) =>
    fulfillJson(route, {
      task_creation_enabled: options.taskCreationEnabled ?? false,
      task_routing_enabled: options.taskRoutingEnabled ?? false,
    }));
  await page.route("**/api/integrations/coordination/health", (route) =>
    fulfillJson(route, healthStatus === 200 ? health : { error: { code: "forbidden" } }, healthStatus));
  await page.route("**/api/integrations/coordination/metrics", (route) => fulfillJson(route, metrics));
  await page.route("**/api/integrations/coordination/agents", (route) => fulfillJson(route, {
    agents: [{
      agent: "agent_one",
      specialization: "Release review",
      capabilities: ["review"],
      status: "available",
      health: "ACTIVE",
      stale: false,
      last_heartbeat: "2026-11-06T09:05:00Z",
      active_tasks: 1,
      completed: 4,
      failed: 0,
    }],
  }));
  await page.route("**/api/integrations/coordination/tasks", async (route) => {
    if (route.request().method() === "POST") {
      const input = route.request().postDataJSON() as Record<string, unknown>;
      const created = {
        task_id: "api-created-task-43",
        kind: input.kind,
        state: "CREATED",
        priority: input.priority,
        agent: null,
        title: input.title,
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
      taskRecords.unshift(created);
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        headers: { "x-cicc-idempotency-key": "bff-e2e-created-key" },
        body: JSON.stringify({ task_id: created.task_id, kind: created.kind, state: created.state, duplicate: false }),
      });
      return;
    }
    await fulfillJson(route, { tasks: taskRecords });
  });
  await page.route("**/api/integrations/coordination/tasks/*/route", async (route) => {
    const url = new URL(route.request().url());
    const taskId = decodeURIComponent(url.pathname.split("/").at(-2) ?? "");
    const found = taskRecords.find((record) => record.task_id === taskId);
    if (!found) return fulfillJson(route, { error: { code: "not_found" } }, 404);
    Object.assign(found, {
      state: "QUEUED",
      agent: "agent_one",
      routing_explanation: { via: "score", score: 90, candidates: 1, reasons: ["review capability matched"] },
    });
    return fulfillJson(route, {
      task_id: taskId,
      agent: "agent_one",
      state: "QUEUED",
      explanation: found.routing_explanation,
    });
  });
  await page.route("**/api/integrations/coordination/events", (route) => fulfillJson(route, { events: [] }));
  await page.route((url) => url.pathname.endsWith("/api/integrations/coordination/task-trace"), (route) => {
    options.onTrace?.();
    const url = new URL(route.request().url());
    if (url.searchParams.get("task_id") !== task.task_id) {
      return fulfillJson(route, { error: { code: "invalid_request" } }, 400);
    }
    return fulfillJson(route, taskTrace);
  });
}

test("renders API-reported health and lazily loads the selected task audit trace", async ({ page }) => {
  let traceRequests = 0;
  await mockWorkspace(page, { onTrace: () => { traceRequests += 1; } });

  await page.goto("/coordination");
  await expect(page.getByRole("heading", { name: "Coordination service health" })).toBeVisible();
  await expect(page.getByText("Degraded")).toBeVisible();
  await expect(page.getByText("No broker configured: task delivery is not broker-confirmed")).toBeVisible();
  await expect(page.getByText("on-demand check; NOT continuous monitoring (no scheduler running)")).toBeVisible();
  await expect(page.getByText("Review current release")).toBeVisible();
  expect(traceRequests).toBe(0);

  await page.getByText("Review current release").click();
  await expect(page.getByText("Provider-reported release review result")).toBeVisible();
  await expect(page.getByText("review capability matched")).toBeVisible();
  await page.getByRole("button", { name: "View task trace" }).click();
  await expect(page.getByText("Task accepted by the API")).toBeVisible();
  await expect(page.getByText("human_assisted")).toBeVisible();
  await expect(page.getByText("prepared")).toBeVisible();
  await expect(page.getByText("bff-e2e-key-42").last()).toBeVisible();
  expect(traceRequests).toBe(1);
});

test("surfaces permission denial locally without hiding independent coordination data", async ({ page }) => {
  await mockWorkspace(page, { healthStatus: 403 });
  await page.goto("/coordination");

  await expect(page.getByRole("alert").filter({ hasText: "The provider did not authorize this read request." })).toBeVisible();
  await expect(page.getByText("Tasks total")).toBeVisible();
  await expect(page.getByText("Review current release")).toBeVisible();
});

test("creates a task through the gated UI and presents the server response", async ({ page }) => {
  await mockWorkspace(page, { taskCreationEnabled: true });
  await page.goto("/coordination");

  await page.getByLabel("Task kind").fill("manual_review");
  await page.getByLabel("Task title").fill("Review release candidate");
  await page.getByLabel("Task payload (JSON object)").fill('{"labels":["integration"]}');
  await page.getByRole("button", { name: "Create task" }).click();

  await expect(page.getByText("The provider accepted the task creation request.")).toBeVisible();
  await expect(page.getByText("bff-e2e-created-key")).toBeVisible();
  await expect(page.getByText("Review release candidate")).toBeVisible();
});

test("routes a CREATED task only when the separate routing capability is enabled", async ({ page }) => {
  const routeTask = {
    ...task,
    task_id: "api-task-route-44",
    state: "CREATED",
    agent: null,
    title: "Task awaiting route",
    routing_explanation: null,
  };
  await mockWorkspace(page, { taskRoutingEnabled: true, tasks: [routeTask] });
  await page.goto("/coordination");

  await page.getByText("Task awaiting route").click();
  await page.getByRole("button", { name: "Route task" }).click();
  await expect(page.getByText("Routing response received.")).toBeVisible();
  await expect(page.getByText("agent_one").last()).toBeVisible();
});

test("paginates the loaded response and resets the page when searching", async ({ page }) => {
  const tasks = Array.from({ length: 12 }, (_, index) => ({
    ...task,
    task_id: `page-task-${index + 1}`,
    state: "COMPLETED",
    title: `Paged task ${index + 1}`,
    result: null,
    routing_explanation: null,
  }));
  await mockWorkspace(page, { tasks });
  await page.goto("/coordination");

  await expect(page.getByText("Paged task 1")).toBeVisible();
  await expect(page.getByText("Paged task 11")).toHaveCount(0);
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.getByText("Paged task 11")).toBeVisible();
  await expect(page.getByText("Paged task 1")).toHaveCount(0);
  await page.getByRole("searchbox", { name: "Search the returned task records" }).fill("page-task-2");
  await expect(page.getByText("Paged task 2")).toBeVisible();
  await expect(page.getByRole("button", { name: "Previous page" })).toBeDisabled();
});

test("switches the workspace to Arabic RTL without changing the source record IDs", async ({ page }) => {
  await mockWorkspace(page);
  await page.goto("/coordination");
  await page.getByRole("combobox", { name: "Interface language" }).selectOption("ar");

  await expect(page.getByRole("heading", { name: "تنسيق الوكلاء" })).toBeVisible();
  await expect(page.locator('[lang="ar"][dir="rtl"]').first()).toBeAttached();
  await page.getByText("Review current release").click();
  await expect(page.locator('bdi[dir="ltr"]').filter({ hasText: "api-task-42" }).first()).toBeVisible();
});
