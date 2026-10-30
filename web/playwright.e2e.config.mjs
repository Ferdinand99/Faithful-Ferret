// The browser tests that run against the end-to-end test stack on the LANBox
// (scripts/lanbox-ferret-test.sh e2e-run): the real server, over https, on the
// test host names. There is no web server here. The runner makes Chromium and
// WebKit trust the stack's test CA, so for them a certificate problem is a test
// failure (see the Firefox project below).
import { defineConfig } from "@playwright/test";

const vault = process.env.FERRET_E2E_VAULT_URL;
if (!vault) {
  throw new Error("FERRET_E2E_VAULT_URL is not set: run these tests with scripts/lanbox-ferret-test.sh e2e-run");
}

export default defineConfig({
  testDir: "test/e2e-stack",
  testMatch: "*.spec.mjs",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 60_000,
  reporter: [["list"]],
  outputDir: "test-results",
  use: {
    baseURL: vault,
    headless: true,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    {
      name: "firefox",
      // Chromium and WebKit trust the test CA that the runner installs. Playwright's
      // Firefox keeps its own list of authorities and does not read the system
      // store (the preference for enterprise roots does not change that here), so it
      // accepts the certificate of the test stack, which is reachable from the test
      // container only.
      use: { browserName: "firefox", ignoreHTTPSErrors: true },
    },
    { name: "webkit", use: { browserName: "webkit" } },
  ],
});
