import { defineConfig } from "@playwright/test";

const externalBaseUrl = process.env.PLAYWRIGHT_BASE_URL;
const baseURL = externalBaseUrl ?? "http://127.0.0.1:3000";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  reporter: "list",
  timeout: 30_000,
  expect: { timeout: 7_500 },
  use: {
    baseURL,
    browserName: "chromium",
    trace: "retain-on-failure",
  },
  webServer: externalBaseUrl ? undefined : {
    command: "npm run dev --workspace=@cicc/web -- --port 3000",
    url: `${baseURL}/coordination`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
