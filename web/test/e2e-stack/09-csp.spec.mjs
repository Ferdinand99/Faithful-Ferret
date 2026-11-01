// Scenario 9: nothing in the whole run broke the page's content security policy
// or Trusted Types, and no page threw. (Every test also checks this for its own
// pages, so a failure names the scenario; this one adds the total.)
import { expect, findings, test } from "./support.mjs";

test("csp_has_zero_violations_during_the_whole_run", async () => {
  expect(findings.pages).toBeGreaterThan(5);
  expect(findings.violations).toEqual([]);
  expect(findings.pageErrors).toEqual([]);
  expect(findings.consoleErrors).toEqual([]);
});
