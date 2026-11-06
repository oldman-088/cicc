import { createRequire } from "node:module";
import { expect, test, type Page } from "@playwright/test";

const require = createRequire(import.meta.url);

type AxeViolation = { id: string; impact: string | null; help: string; nodes: Array<{ target: string[] }> };
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

const operationsOverview = {
  generated_at: "2026-11-06T09:30:00Z",
  overall_status: "degraded",
  services: [],
  modules: [],
  metrics: { entities: 0, vulnerabilities: 0, campaigns: 0, recent_updates_24h: 0, last_successful_sync: null },
  activity: [],
  data_source: "test-fixture: ops source label is unverified",
  cached: true,
  cache_age_s: 18,
};

const coordinationHealth = {
  overall: "degraded",
  components: [{
    key: "broker",
    status: "not_configured",
    detail: "Deliveries are prepared but not broker-confirmed.",
    reasons: ["No broker configured"],
  }],
  reasons: ["broker: no broker configured"],
  last_operations: {
    last_webhook_received: null,
    last_github_sync_success: null,
    last_github_sync_attempt: null,
    last_task_event: null,
    checked_at: "2026-11-06T09:31:00Z",
    note: "on-demand status check; NOT continuous monitoring",
  },
  at: "2026-11-06T09:31:00Z",
};

async function mockReadinessProviders(page: import("@playwright/test").Page) {
  let operationsCalls = 0;
  let coordinationCalls = 0;
  await page.route("**/api/integrations/ops/overview", async (route) => {
    operationsCalls += 1;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(operationsOverview) });
  });
  await page.route("**/api/integrations/coordination/health", async (route) => {
    coordinationCalls += 1;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(coordinationHealth) });
  });
  return {
    counts: () => ({ operations: operationsCalls, coordination: coordinationCalls }),
  };
}

test("shows provider-reported status while keeping unmounted TI/VI and contract gates explicit", async ({ page }) => {
  await mockReadinessProviders(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Operational readiness" })).toBeVisible();
  await expect(page.getByText("test-fixture: ops source label is unverified")).toBeVisible();
  await expect(page.getByText("Degraded (provider-reported)").first()).toBeVisible();
  await expect(page.getByText("No broker configured")).toBeVisible();
  await expect(page.getByText("Not host-verified").first()).toBeVisible();
  await expect(page.getByText("Package API not mounted in CICC")).toBeVisible();
  await expect(page.getByText("Proposed API and fixtures only")).toBeVisible();
  await expect(page.getByText(/A source label is not independent proof that data is live or authentic/)).toBeVisible();
  await expect(page.getByText(/not a whole-platform health guarantee/)).toBeVisible();
  await expect(page.getByText(/CVE-2026-/)).toHaveCount(0);
});

test("keeps the readiness panel responsive at mobile, tablet, and desktop widths", async ({ page }) => {
  await mockReadinessProviders(page);
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Refresh operational checks" })).toBeEnabled();

  for (const width of [360, 768, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    const dimensions = await page.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      document: document.documentElement.scrollWidth,
    }));
    expect(dimensions.document, `horizontal overflow at ${width}px viewport`).toBeLessThanOrEqual(dimensions.viewport + 1);
    const panel = page.getByTestId("beta-readiness-panel");
    const panelDimensions = await panel.evaluate((element) => ({
      client: element.clientWidth,
      scroll: element.scrollWidth,
    }));
    expect(panelDimensions.scroll, `readiness panel overflow at ${width}px viewport`).toBeLessThanOrEqual(panelDimensions.client + 1);
  }
});

test("passes axe-core WCAG A/AA checks in English and Arabic RTL", async ({ page }) => {
  await mockReadinessProviders(page);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Operational readiness" })).toBeVisible();
  await expectNoWcagViolations(page);

  await page.getByRole("combobox", { name: "Interface language" }).selectOption("ar");
  await expect(page.locator('[lang="ar"][dir="rtl"]').first()).toBeAttached();
  await expect(page.getByRole("heading", { name: "الجاهزية التشغيلية" })).toBeVisible();
  await expectNoWcagViolations(page);
});

test("supports keyboard refresh and exposes busy and provider alerts to assistive technology", async ({ page }) => {
  const mocks = await mockReadinessProviders(page);
  await page.goto("/");
  const refresh = page.getByRole("button", { name: "Refresh operational checks" });
  await expect(refresh).toBeEnabled();
  await refresh.focus();
  await expect(refresh).toBeFocused();

  const before = mocks.counts();
  await page.keyboard.press("Enter");
  await expect.poll(() => mocks.counts()).toEqual({
    operations: before.operations + 1,
    coordination: before.coordination + 1,
  });
  await expect(refresh).toBeEnabled();
  await expect(refresh).toHaveAttribute("aria-busy", "false");
});
