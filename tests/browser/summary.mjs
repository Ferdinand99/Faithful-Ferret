// Prints the result of a Playwright run per browser: how many tests passed,
// failed and were skipped, the vector counts and the export time.
//
//   node summary.mjs            reads results/report.json and results/*.json
//
// With GITHUB_STEP_SUMMARY set, the same text is appended there as Markdown.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const results = join(dirname(fileURLToPath(import.meta.url)), "results");
const reportPath = join(results, "report.json");
if (!existsSync(reportPath)) {
  console.error("summary: no results/report.json");
  process.exit(1);
}

const report = JSON.parse(readFileSync(reportPath, "utf8"));
const byProject = new Map();
const failed = [];
function walk(suite) {
  for (const spec of suite.specs ?? []) {
    for (const t of spec.tests ?? []) {
      const p = byProject.get(t.projectName) ?? { passed: 0, failed: 0, skipped: 0, flaky: 0 };
      if (t.status === "expected") p.passed++;
      else if (t.status === "skipped") p.skipped++;
      else if (t.status === "flaky") p.flaky++;
      else {
        p.failed++;
        failed.push(`${t.projectName}: ${spec.title}`);
      }
      byProject.set(t.projectName, p);
    }
  }
  for (const s of suite.suites ?? []) walk(s);
}
for (const s of report.suites) walk(s);

const kept = (name) => {
  const file = join(results, name);
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
};

const lines = ["| Browser | Tests passed | Failed | Skipped | Internal vectors | Slow vectors | External vectors | Export 256 MiB (write / open) |", "|---|---|---|---|---|---|---|---|"];
for (const [name, p] of [...byProject].sort()) {
  const v = kept(`${name}-vectors.json`)?.totals;
  const slow = kept(`${name}-slow-vectors.json`);
  const e = kept(`${name}-export-256mib.json`);
  lines.push(
    `| ${name} | ${p.passed} | ${p.failed} | ${p.skipped} | ${v ? v.internalPassed : "-"} | ${slow ? slow.passed : "-"} | ${v ? v.externalPassed : "-"} | ${e ? `${e.writeMs} ms / ${e.openMs} ms` : "not run"} |`,
  );
}
const text = lines.join("\n");
console.log(text);
if (failed.length) console.log(`\nFailed:\n${failed.map((f) => `- ${f}`).join("\n")}`);
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Browser smoke tests\n\n${text}\n`);
}
process.exit(failed.length ? 1 : 0);
