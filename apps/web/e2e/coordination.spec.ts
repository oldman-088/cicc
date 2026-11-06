import { createRequire } from "node:module";
import { expect, test, type Page, type Route } from "@playwright/test";

const require = createRequire(import.meta.url);

type AxeViolation = {
  id: string;
  impact: string | null;
  help: string;
  nodes: Array<{ target: string[]; failureSummary?: string }>;
};

type AxeRunner = {
  run: (context: Document, options: { runOnly: { type: "tag"; values: string[] } }) => Promise<{ violations: AxeViolation[] }>;
};

async function expectNoWcagViolations(page: Page) {
  await page.addScriptTag({ path: require.resolve("axe-core/axe.min.js") });
  const violations = await page.evaluate(async () => {
    const axe = (window as Window & { axe?: AxeRunner }).axe;
    if (!axe) throw new Error("axe-core did not attach to the page");
    const results = await axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] },
    });
    return results.violations.map(({ id, impact, help, nodes }) => ({ id, impact, help, nodes }));
  });
  expect(violations).toEqual([]);
}

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

const emptyMetrics = {
  tasks_total: 0,
  by_state: {},
  by_kind: {},
  active_by_agent: {},
  avg_progress_active: 0,
  dead_lettered: 0,
  deliveries_total: 0,
  deliveries_by_outcome: {},
  approvals_pending: 0,
  agents_registered: 0,
  agents_online: 0,
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
  beforeMetricsResponse?: () => Promise<void>;
  onTrace?: () => void;
  taskCreationEnabled?: boolean;
  metrics?: typeof metrics;
  agents?: Array<Record<string, unknown>>;
  events?: Array<Record<string, unknown>>;
  tasks?: Array<Record<string, unknown>>;
};

async function mockWorkspace(page: Page, options: MockWorkspaceOptions = {}) {
  // All payloads below are deterministic Playwright route fixtures, not application fallback data.
  const healthStatus = options.healthStatus ?? 200;
  const healthError = healthStatus === 401 ? "unauthorized" : "forbidden";
  const taskRecords = options.tasks ?? [task];
  await page.route("**/api/integrations/coordination/write-capabilities", (route) =>
    fulfillJson(route, {
      task_creation_enabled: options.taskCreationEnabled ?? false,
    }));
  await page.route("**/api/integrations/coordination/health", (route) =>
    fulfillJson(route, healthStatus === 200 ? health : { error: { code: healthError } }, healthStatus));
  await page.route("**/api/integrations/coordination/metrics", async (route) => {
    await options.beforeMetricsResponse?.();
    await fulfillJson(route, options.metrics ?? metrics);
  });
  await page.route("**/api/integrations/coordination/agents", (route) => fulfillJson(route, {
    agents: options.agents ?? [{
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
  await page.route("**/api/integrations/coordination/events", (route) =>
    fulfillJson(route, { events: options.events ?? [] }));
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
  expect(traceRequests).toBeGreaterThan(0);
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

test("keeps provider routing explanations read-only and sends no route write", async ({ page }) => {
  let routeWrites = 0;
  const routeTask = {
    ...task,
    task_id: "api-task-route-read-only",
    state: "CREATED",
    agent: null,
    title: "Task awaiting provider routing",
    routing_explanation: {
      via: "score",
      score: 90,
      candidates: 1,
      reasons: ["Provider-owned routing explanation"],
    },
  };
  await mockWorkspace(page, { tasks: [routeTask] });
  await page.route("**/api/integrations/coordination/tasks/*/route", async (route) => {
    routeWrites += 1;
    await fulfillJson(route, { error: { code: "not_found" } }, 404);
  });
  await page.goto("/coordination");

  await page.getByText("Task awaiting provider routing").click();
  await expect(page.getByText("Provider-owned routing explanation")).toBeVisible();
  await expect(page.getByRole("button", { name: "Route task" })).toHaveCount(0);
  expect(routeWrites).toBe(0);
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

  await expect(page.getByText("Paged task 1", { exact: true })).toBeVisible();
  await expect(page.getByText("Paged task 11", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.getByText("Paged task 11", { exact: true })).toBeVisible();
  await expect(page.getByText("Paged task 1", { exact: true })).toHaveCount(0);
  await page.getByRole("searchbox", { name: "Search the returned task records" }).fill("page-task-2");
  await expect(page.getByText("Paged task 2", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Previous page" })).toBeDisabled();
});

const localeCases = [
  { locale: "en", direction: "ltr", heading: "Agent Coordination" },
  { locale: "ar", direction: "rtl", heading: "تنسيق الوكلاء" },
  { locale: "fa", direction: "rtl", heading: "هماهنگی عامل‌ها" },
] as const;

for (const localeCase of localeCases) {
  test(`switches to ${localeCase.locale} with correct direction and stable source IDs`, async ({ page }) => {
    await mockWorkspace(page);
    await page.goto("/coordination");
    await page.getByRole("combobox", { name: "Interface language" }).selectOption(localeCase.locale);

    await expect(page.getByRole("heading", { name: localeCase.heading })).toBeVisible();
    await expect(page.locator(`[lang="${localeCase.locale}"][dir="${localeCase.direction}"]`).first()).toBeAttached();
    await page.getByText("Review current release").click();
    await expect(page.locator('bdi[dir="ltr"]').filter({ hasText: "api-task-42" }).first()).toBeVisible();
  });
}

test("announces provider loading while a read request is pending", async ({ page }) => {
  let releaseMetrics!: () => void;
  let markMetricsStarted!: () => void;
  const metricsGate = new Promise<void>((resolve) => { releaseMetrics = resolve; });
  const metricsStarted = new Promise<void>((resolve) => { markMetricsStarted = resolve; });
  await mockWorkspace(page, {
    beforeMetricsResponse: async () => {
      markMetricsStarted();
      await metricsGate;
    },
  });

  await page.goto("/coordination");
  await metricsStarted;
  await expect(page.getByRole("status").filter({ hasText: "Requesting provider data…" }).first()).toBeVisible();
  releaseMetrics();
  await expect(page.getByText("Tasks total")).toBeVisible();
});

test("renders explicit empty provider responses for agents, tasks, and events", async ({ page }) => {
  await mockWorkspace(page, { metrics: emptyMetrics, agents: [], events: [], tasks: [] });
  await page.goto("/coordination");

  await expect(page.getByText("The provider returned no agent records.")).toBeVisible();
  await expect(page.getByText("The provider returned no task records.")).toBeVisible();
  await expect(page.getByText("The provider returned no webhook event records.")).toBeVisible();
});

test("distinguishes an unauthorized provider credential from other resource failures", async ({ page }) => {
  await mockWorkspace(page, { healthStatus: 401 });
  await page.goto("/coordination");

  await expect(page.getByRole("alert").filter({ hasText: "The provider rejected the server-side read credential." })).toBeVisible();
  await expect(page.getByText("Review current release")).toBeVisible();
});

const viewportCases = [
  { name: "desktop", width: 1440, height: 1000, collapsibleNavigation: false },
  { name: "tablet", width: 820, height: 1180, collapsibleNavigation: true },
  { name: "mobile", width: 390, height: 844, collapsibleNavigation: true },
] as const;

for (const viewport of viewportCases) {
  test(`fits the ${viewport.name} viewport and preserves keyboard-operable navigation`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await mockWorkspace(page);
    await page.goto("/coordination");
    await expect(page.getByRole("heading", { name: "Agent Coordination" })).toBeVisible();

    const width = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
    }));
    expect(Math.max(width.document, width.body)).toBeLessThanOrEqual(width.client);

    const openNavigation = page.getByRole("button", { name: "Open workspace navigation" });
    if (viewport.collapsibleNavigation) {
      await expect(openNavigation).toBeVisible();
      await expect(openNavigation).toHaveAttribute("aria-expanded", "false");
      await openNavigation.focus();
      await page.keyboard.press("Enter");
      const closeNavigation = page.getByRole("button", { name: "Close workspace navigation" });
      await expect(closeNavigation).toHaveAttribute("aria-expanded", "true");
      await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
      await closeNavigation.click();
      await expect(openNavigation).toHaveAttribute("aria-expanded", "false");
    } else {
      await expect(openNavigation).toBeHidden();
      await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
    }
  });
}

test("supports the skip link and keyboard shortcut for workspace search", async ({ page }) => {
  await mockWorkspace(page);
  await page.goto("/coordination");

  const skipLink = page.getByRole("link", { name: "Skip to main content" });
  await page.keyboard.press("Tab");
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#cicc-main-content$/);

  await page.keyboard.press("Control+k");
  const search = page.getByRole("searchbox", { name: "Find a workspace page" });
  await expect(search).toBeFocused();
  await expect(search).toHaveAttribute("aria-keyshortcuts", "Control+K Meta+K");
  await search.fill("Agent Coordination");
  await expect(page.getByRole("link", { name: "Agent Coordination" })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/coordination(?:#cicc-main-content)?$/);
});

test("passes axe-core WCAG A/AA checks on the Coordination workspace", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await mockWorkspace(page);
  await page.goto("/coordination");
  await expect(page.getByRole("heading", { name: "Agent Coordination" })).toBeVisible();
  await expectNoWcagViolations(page);
});

test("passes axe-core WCAG A/AA checks in the Arabic mobile layout", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockWorkspace(page);
  await page.goto("/coordination");
  await page.getByRole("combobox", { name: "Interface language" }).selectOption("ar");
  await expect(page.locator('[lang="ar"][dir="rtl"]').first()).toBeAttached();
  await expectNoWcagViolations(page);
});

test("keeps threat and vulnerability workspaces explicitly disconnected and accessible", async ({ page }) => {
  await page.goto("/threat-intelligence");
  await expect(page.getByRole("heading", { name: "Threat Intelligence" })).toBeVisible();
  await expect(page.getByText(/in-process dispatcher with explicitly experimental sample handlers/)).toBeVisible();
  await expect(page.getByText(/sandbox gateway invocation/)).toBeVisible();
  await expectNoWcagViolations(page);

  await page.goto("/vulnerability-intelligence");
  await expect(page.getByRole("heading", { name: "Vulnerability API proposal is not mounted" })).toBeVisible();
  await expect(page.getByText(/still proposed and no CICC host mount/)).toBeVisible();
  await expectNoWcagViolations(page);
});

const disconnectedModuleLocaleCases = [
  {
    locale: "ar",
    threatTitle: "استخبارات التهديدات",
    threatStatus: "بيانات التهديدات غير متصلة",
    vulnerabilityTitle: "استخبارات الثغرات",
    vulnerabilityStatus: "اقتراح API للثغرات غير مركّب",
  },
  {
    locale: "fa",
    threatTitle: "اطلاعات تهدید",
    threatStatus: "دادهٔ تهدید متصل نیست",
    vulnerabilityTitle: "اطلاعات آسیب‌پذیری",
    vulnerabilityStatus: "پیشنهاد API آسیب‌پذیری نصب نشده است",
  },
] as const;

for (const localeCase of disconnectedModuleLocaleCases) {
  test(`keeps disconnected intelligence workspaces accessible in ${localeCase.locale} RTL`, async ({ page }) => {
    await page.goto("/threat-intelligence");
    await page.getByRole("combobox", { name: "Interface language" }).selectOption(localeCase.locale);
    await expect(page.locator(`[lang="${localeCase.locale}"][dir="rtl"]`).first()).toBeAttached();
    await expect(page.getByRole("heading", { name: localeCase.threatTitle })).toBeVisible();
    await expect(page.getByRole("heading", { name: localeCase.threatStatus })).toBeVisible();
    await expectNoWcagViolations(page);

    await page.goto("/vulnerability-intelligence");
    await expect(page.locator(`[lang="${localeCase.locale}"][dir="rtl"]`).first()).toBeAttached();
    await expect(page.getByRole("heading", { name: localeCase.vulnerabilityTitle })).toBeVisible();
    await expect(page.getByRole("heading", { name: localeCase.vulnerabilityStatus })).toBeVisible();
    await expectNoWcagViolations(page);
  });
}
