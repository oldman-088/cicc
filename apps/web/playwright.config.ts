import { defineConfig, devices } from "@playwright/test";

// Browser visual QA suite. Requires a browser binary:
//   npx playwright install chromium
// In sandboxes where the Chromium download host is blocked this suite cannot
// run; that limitation must be reported, never replaced with fake screenshots.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  reporter: [["list"], ["html", { open: "never" }]],
  use: { baseURL: process.env.CICC_WEB_URL ?? "http://127.0.0.1:3000", trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "mobile", use: { ...devices["Pixel 7"], viewport: { width: 390, height: 844 } } },
  ],
  webServer: process.env.CICC_WEB_URL ? undefined : {
    command: "npm run start",
    url: "http://127.0.0.1:3000",
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
