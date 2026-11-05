import { expect, test } from "@playwright/test";

const routes = ["/", "/command-theater", "/threat-intelligence", "/vulnerability-intelligence", "/system-health", "/coordination", "/settings"] as const;

for (const route of routes) {
  test(`route ${route} renders, has no horizontal overflow, and is screenshot-captured`, async ({ page }, testInfo) => {
    const response = await page.goto(route, { waitUntil: "networkidle" });
    expect(response?.status()).toBe(200);
    await expect(page.locator("main, [role=main]").first()).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    await page.screenshot({ path: testInfo.outputPath(`${route.replaceAll("/", "_") || "_root"}.png`), fullPage: true });
  });
}

test("locale switching sets RTL for Arabic/Persian and LTR for English", async ({ page }) => {
  await page.goto("/settings", { waitUntil: "networkidle" });
  const select = page.getByRole("combobox").first();
  await select.selectOption("ar");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await select.selectOption("fa");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await select.selectOption("en");
  await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
});

test("keyboard navigation reaches interactive controls with visible focus", async ({ page }) => {
  await page.goto("/", { waitUntil: "networkidle" });
  await page.keyboard.press("Tab");
  const focused = page.locator(":focus");
  await expect(focused).toBeVisible();
  const outline = await focused.evaluate((el) => getComputedStyle(el).outlineStyle);
  expect(outline).not.toBe("none");
});

test("command theater WebGL canvas mounts or falls back accessibly", async ({ page }) => {
  await page.goto("/command-theater", { waitUntil: "networkidle" });
  // Either a canvas renders or an accessible fallback is announced; both are valid,
  // a blank/broken region is not.
  await expect(page.locator("canvas, [role=img], [data-testid=graph-fallback]").first()).toBeVisible();
});
