import { defineConfig } from "@playwright/test";

const widths = [320, 390, 768, 1024, 1440];

export default defineConfig({
  testDir: "./tests",
  outputDir: "./artifacts/playwright-output",
  timeout: 180_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  reporter: [["line"]],
  use: {
    baseURL: process.env.BASE || "https://127.0.0.1:8443",
    browserName: "chromium",
    ignoreHTTPSErrors: true,
    actionTimeout: 10_000,
    navigationTimeout: 10_000,
    screenshot: "off",
    trace: "off",
    video: "off",
  },
  projects: widths.map((width) => ({
    name: `chromium-${width}`,
    metadata: { viewportWidth: width },
    use: { viewport: { width, height: width <= 390 ? 844 : 900 } },
  })),
});
