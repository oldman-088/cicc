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
  await page.getByRole("link", { name: "Investigations" }).first().click();
  await expect(page).toHaveURL(/\/investigations$/);
  await expect(page.getByRole("heading", { name: "Investigations", level: 1 })).toBeVisible();
  await page.getByRole("link", { name: "Settings" }).first().click();
  await expect(page).toHaveURL(/\/settings$/);
});
