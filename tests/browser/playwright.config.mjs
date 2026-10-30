import { defineConfig } from "@playwright/test";

const port = Number(process.env.FERRET_BROWSER_PORT ?? 4577);

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  // One test at a time: each one runs Argon2id with tens or hundreds of MiB.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  forbidOnly: !!process.env.CI,
  // The slow tests set their own, longer limits.
  timeout: 120_000,
  reporter: [["list"], ["json", { outputFile: "results/report.json" }]],
  outputDir: "results/artifacts",
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    headless: true,
  },
  webServer: {
    command: "node serve.mjs",
    url: `http://127.0.0.1:${port}/index.html`,
    reuseExistingServer: false,
    timeout: 20_000,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "firefox", use: { browserName: "firefox" } },
    { name: "webkit", use: { browserName: "webkit" } },
  ],
});
