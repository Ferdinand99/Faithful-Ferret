// Nothing in the whole run broke the page's content security policy
// or Trusted Types, and no page threw. This is the total of the run. A test that
// uses the default context also checks its own pages, so a failure names it.
import { expect, findings, test } from "./support.mjs";

test("csp_has_zero_violations_during_the_whole_run", async () => {
  expect(findings.pages).toBeGreaterThan(5);
  expect(findings.violations).toEqual([]);
  expect(findings.pageErrors).toEqual([]);
  expect(findings.consoleErrors).toEqual([]);
  // WebKit reports the inline style of its own select (see `watchScript` in support.mjs), and
  // the report is set apart for each select that was made. The exception expires with the
  // problem: when WebKit stops reporting, there are fewer reports than selects, and this fails.
  expect(findings.engineReports.length, "WebKit no longer reports its select; remove the exception").toBe(findings.selectsMade);
  // Each console line that WebKit logs with such a report needs a report that was set apart.
  expect(findings.engineConsole.length).toBeLessThanOrEqual(findings.engineReports.length);
});
