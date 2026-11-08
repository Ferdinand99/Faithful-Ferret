// Nothing in the whole run broke the page's content security policy
// or Trusted Types, and no page threw. This is the total of the run. A test that
// uses the default context also checks its own pages, so a failure names it.
import { expect, findings, test } from "./support.mjs";

test("csp_has_zero_violations_during_the_whole_run", async () => {
  expect(findings.pages).toBeGreaterThan(5);
  expect(findings.violations).toEqual([]);
  expect(findings.pageErrors).toEqual([]);
  expect(findings.consoleErrors).toEqual([]);
  // WebKit reports the inline style of its own select widget (see `watchScript` in support.mjs).
  // Each console line needs a report that was set apart in the page, and nothing else is let through.
  expect(findings.engineConsole.length).toBeLessThanOrEqual(findings.engineReports.length);
});
