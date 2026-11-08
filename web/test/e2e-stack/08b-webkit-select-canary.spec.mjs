// A canary for the one exception of the policy check (see `watchScript` in support.mjs):
// WebKit reports a `style-src-attr` violation for the inner style of its own `<select>`.
// It runs in WebKit only. A select that is made and nothing else is set apart as exactly
// one report, and a select that has a `style` attribute of its own is still a violation.
// When WebKit stops reporting its select, the first half fails and the exception is to be
// removed; when the check lets more through than that select, the second half fails.
import { expect, findings, freshContext, test, vaultUrl } from "./support.mjs";

test("webkit_select_report_is_set_apart_and_any_other_inline_style_is_not", async ({ browser }, testInfo) => {
  test.skip(browser.browserType().name() !== "webkit", "WebKit only: the other engines report nothing for a select");
  const context = await freshContext(browser);
  const page = await context.newPage();
  await page.goto(`${vaultUrl}/vault/`);
  await page.waitForTimeout(1_000);
  const settle = () => page.waitForTimeout(750);
  const mark = {
    violations: findings.violations.length,
    reports: findings.engineReports.length,
    console: findings.engineConsole.length,
    consoleErrors: findings.consoleErrors.length,
    selects: findings.selectsMade,
  };

  try {
    // A bare select, shown: one set-apart report and no violation.
    await page.evaluate(() => document.body.appendChild(document.createElement("select")));
    await settle();
    expect(findings.selectsMade - mark.selects, "selects made").toBe(1);
    expect(findings.engineReports.length - mark.reports, "WebKit no longer reports its select; remove the exception").toBe(1);
    expect(findings.violations.slice(mark.violations), "a bare select is no violation").toEqual([]);

    // A select that is made and never shown (the edit screen does this): one set-apart report.
    await page.evaluate(() => void document.createElement("select"));
    await settle();
    expect(findings.engineReports.length - mark.reports, "a select that is not shown").toBe(2);
    expect(findings.violations.slice(mark.violations)).toEqual([]);

    // A select with a style attribute of its own: a violation, and nothing set apart for it.
    const reports = findings.engineReports.length;
    await page.evaluate(() => {
      const select = document.createElement("select");
      select.setAttribute("style", "color: red");
      document.body.appendChild(select);
    });
    await settle();
    expect(findings.engineReports.length, "a select with a style attribute is not set apart").toBe(reports);
    expect(findings.violations.length - mark.violations, "a select with a style attribute is a violation").toBeGreaterThan(0);

    // Another element with a style attribute: a violation too.
    const before = findings.violations.length;
    await page.evaluate(() => {
      const div = document.createElement("div");
      div.setAttribute("style", "color: red");
      document.body.appendChild(div);
    });
    await settle();
    expect(findings.violations.length - before, "a div with a style attribute is a violation").toBeGreaterThan(0);
  } finally {
    // These were made on purpose: show them in the report, then take them out of the run's total.
    for (const description of findings.engineReports.slice(mark.reports)) {
      testInfo.annotations.push({ type: "known-engine-issue", description });
    }
    findings.violations.length = mark.violations;
    findings.engineReports.length = mark.reports;
    findings.engineConsole.length = mark.console;
    findings.consoleErrors.length = mark.consoleErrors;
    findings.selectsMade = mark.selects;
  }
});
