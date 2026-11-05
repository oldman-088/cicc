import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/", { waitUntil: "networkidle" });
  await page.evaluate(() => window.localStorage.clear());
});

test("investigation journey: create, annotate, reload persists (browser-local)", async ({ page }) => {
  await page.goto("/investigations", { waitUntil: "networkidle" });
  await expect(page.getByText(/stored only in this browser/)).toBeVisible();
  await page.getByLabel("Title").fill("E2E beacon case");
  await page.getByLabel("Summary").fill("Created by Playwright journey");
  await page.getByRole("button", { name: "Create investigation" }).click();
  await expect(page.getByRole("heading", { name: "E2E beacon case", level: 3 })).toBeVisible();
  await page.getByLabel("Add a note").fill("first analyst note");
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText(/first analyst note/).first()).toBeVisible();
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { name: "E2E beacon case", level: 3 })).toBeVisible();
  await page.getByRole("searchbox", { name: /Search local investigations/ }).fill("no-such-case");
  await expect(page.getByText(/No local investigations match/)).toBeVisible();
});

test("notification journey: local reminder read/unread persists, service still unavailable", async ({ page }) => {
  await page.goto("/settings", { waitUntil: "networkidle" });
  await expect(page.getByText(/No notification service is connected/)).toBeVisible();
  await page.getByLabel("Reminder text").fill("Review coordination queue");
  await page.getByRole("button", { name: "Add local reminder" }).click();
  await expect(page.getByText("Review coordination queue")).toBeVisible();
  await page.getByRole("button", { name: "Mark read" }).click();
  await expect(page.getByText("read", { exact: true }).first()).toBeVisible();
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.getByText("Review coordination queue")).toBeVisible();
});

test("failure states: coordination and intelligence pages are honestly unavailable without a provider", async ({ page }) => {
  await page.goto("/coordination", { waitUntil: "networkidle" });
  await expect(page.getByText(/not configured|unavailable|could not|refused/i).first()).toBeVisible();
  await page.goto("/threat-intelligence", { waitUntil: "networkidle" });
  await expect(page.getByText(/not connected/).first()).toBeVisible();
  await expect(page.getByLabel(/Search indicators/)).toBeDisabled();
  await page.goto("/vulnerability-intelligence", { waitUntil: "networkidle" });
  await expect(page.getByText(/not connected/).first()).toBeVisible();
});

test("cross-workspace journey: shell navigation reaches investigations and settings", async ({ page }) => {
  await page.goto("/", { waitUntil: "networkidle" });
  const investigationsLink = page.getByRole("link", { name: "Investigations" }).first();
  if (!(await investigationsLink.isVisible())) {
    // Mobile layouts collapse navigation behind a toggle; open it like a user would.
    await page.getByRole("button", { name: /Open workspace navigation/ }).click();
  }
  await investigationsLink.click();
  await expect(page).toHaveURL(/\/investigations$/);
  await expect(page.getByRole("heading", { name: "Investigations", level: 1 })).toBeVisible();
  const settingsLink = page.getByRole("link", { name: "Settings" }).first();
  if (!(await settingsLink.isVisible())) {
    await page.getByRole("button", { name: /Open workspace navigation/ }).click();
  }
  await settingsLink.click();
  await expect(page).toHaveURL(/\/settings$/);
});

test("coordination health journey: health panel is honestly unavailable without a provider", async ({ page }) => {
  await page.goto("/coordination", { waitUntil: "networkidle" });
  await expect(page.getByText("Coordination health").first()).toBeVisible();
  await expect(page.getByText(/not continuous monitoring/)).toBeVisible();
});

test("malformed import journey: invalid file is rejected visibly and local state is unchanged", async ({ page }) => {
  await page.goto("/investigations", { waitUntil: "networkidle" });
  await page.getByLabel("Title").fill("Import guard case");
  await page.getByRole("button", { name: "Create investigation" }).click();
  await expect(page.getByRole("heading", { name: "Import guard case", level: 3 })).toBeVisible();
  await page.getByLabel(/Import JSON/).setInputFiles({
    name: "bad.json",
    mimeType: "application/json",
    buffer: Buffer.from("{not json"),
  });
  await expect(page.getByRole("alert").filter({ hasText: /Import failed/ }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Import guard case", level: 3 })).toBeVisible();
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { name: "Import guard case", level: 3 })).toBeVisible();
});

test("local search journey: home search finds browser-local investigations only", async ({ page }) => {
  await page.goto("/investigations", { waitUntil: "networkidle" });
  await page.getByLabel("Title").fill("Searchable beacon");
  await page.getByRole("button", { name: "Create investigation" }).click();
  await expect(page.getByRole("heading", { name: "Searchable beacon", level: 3 })).toBeVisible();
  await page.goto("/", { waitUntil: "networkidle" });
  await page.getByRole("searchbox", { name: /Search investigations and reminders stored in this browser/ }).fill("searchable");
  await expect(page.getByRole("link", { name: /Searchable beacon/ })).toBeVisible();
  await expect(page.getByText(/Server-side global search across providers is not available yet/)).toBeVisible();
});

test("arabic RTL journey: investigations workspace is fully RTL and usable", async ({ page }) => {
  await page.goto("/investigations", { waitUntil: "networkidle" });
  await page.getByRole("combobox", { name: "Interface language" }).selectOption("ar");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await page.getByLabel("العنوان").fill("قضية اختبار");
  await page.getByRole("button", { name: "إنشاء تحقيق" }).click();
  await expect(page.getByRole("heading", { name: "قضية اختبار", level: 3 })).toBeVisible();
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { name: "قضية اختبار", level: 3 })).toBeVisible();
});

test("investigation delete journey: local investigation and note can be removed", async ({ page }) => {
  await page.goto("/investigations", { waitUntil: "networkidle" });
  await page.getByLabel("Title").fill("Disposable case");
  await page.getByRole("button", { name: "Create investigation" }).click();
  await expect(page.getByRole("heading", { name: "Disposable case", level: 3 })).toBeVisible();
  await page.getByRole("button", { name: "Delete this local investigation" }).click();
  await expect(page.getByText(/No investigations yet/)).toBeVisible();
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.getByText(/No investigations yet/)).toBeVisible();
});

test("theme journey: optional light theme applies and persists", async ({ page }) => {
  await page.goto("/settings", { waitUntil: "networkidle" });
  await page.getByRole("combobox", { name: "Choose interface theme" }).selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-cicc-theme", "light");
  await page.reload({ waitUntil: "networkidle" });
  await expect(page.locator("html")).toHaveAttribute("data-cicc-theme", "light");
  await page.getByRole("combobox", { name: "Choose interface theme" }).selectOption("dark");
  await expect(page.locator("html")).not.toHaveAttribute("data-cicc-theme", "light");
});

test("offline journey: banner appears offline and local data still works", async ({ page, context }) => {
  await page.goto("/investigations", { waitUntil: "networkidle" });
  await context.setOffline(true);
  await expect(page.getByRole("alert").filter({ hasText: /You are offline/ })).toBeVisible();
  await page.getByLabel("Title").fill("Offline case");
  await page.getByRole("button", { name: "Create investigation" }).click();
  await expect(page.getByRole("heading", { name: "Offline case", level: 3 })).toBeVisible();
  await context.setOffline(false);
  await expect(page.getByRole("alert").filter({ hasText: /You are offline/ })).toHaveCount(0);
});

test("not-found journey: unknown route shows an honest 404 page", async ({ page }) => {
  await page.goto("/no-such-workspace", { waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  await expect(page.getByText(/does not exist/)).toBeVisible();
});
