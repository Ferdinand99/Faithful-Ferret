// Checks that every finding of ct_analyzer is triaged in ct/TRIAGE.md.
//
//   node ct/check-triage.mjs <dir with the analyzer's JSON reports> ct/TRIAGE.md
//
// The analyzer has no data flow analysis: it reports every dangerous
// instruction. A person reads the code and decides whether an operand can
// depend on a secret (plan section 10 point 3). The decisions are in
// TRIAGE.md, in a fenced block named `triage` with one row per class of
// finding:
//
//     id @ file @ function (regular expression) @ mnemonic (regular expression) @ severity
//
// and every id has a `### id` heading with the reasoning. A finding is
// triaged when a row matches its file, function, mnemonic and severity. The
// script fails on a finding without a row, on a row without a heading, and
// on a report that has fewer functions than the file has public functions
// (the second fenced block, `coverage`): that would be a vacuous pass, such
// as a function that rustc left out of the compiled file.
//
// This is the test `ct_analyzer_clean_or_triaged`.

import { readFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";
import { pathOf } from "./rustname.mjs";

const [dir, triagePath] = process.argv.slice(2);
if (!dir || !triagePath) {
  console.error("usage: check-triage.mjs <reports dir> <TRIAGE.md>");
  process.exit(2);
}

function block(text, name) {
  const m = text.match(new RegExp("```" + name + "\\n([\\s\\S]*?)```"));
  if (!m) throw new Error("TRIAGE.md has no ```" + name + " block");
  return m[1]
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => l.split(" @ ").map((c) => c.trim()));
}

const text = readFileSync(triagePath, "utf8").replace(/\r\n/g, "\n");
const rows = block(text, "triage").map(([id, file, fn, mnemonic, severity]) => ({
  id,
  file: new RegExp("^(?:" + file + ")$"),
  fn: new RegExp(fn),
  mnemonic: new RegExp("^(?:" + mnemonic + ")$"),
  severity: new RegExp("^(?:" + severity + ")$"),
  used: 0,
}));
const coverage = Object.fromEntries(block(text, "coverage").map(([file, min]) => [file, Number(min)]));

let failed = false;
const fail = (msg) => {
  console.error("FAIL: " + msg);
  failed = true;
};

for (const row of rows) {
  if (!new RegExp("\\n### " + row.id + "[ .]").test(text)) fail(`row ${row.id} has no "### ${row.id} ..." section`);
}

const reports = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
if (reports.length === 0) fail(`no reports in ${dir}`);
let findings = 0;
let triaged = 0;
const untriaged = new Map();
for (const name of reports) {
  const [file, arch, opt] = basename(name, ".json").split("__");
  const report = JSON.parse(readFileSync(`${dir}/${name}`, "utf8"));
  if (report.error || !Array.isArray(report.violations)) {
    fail(`${name}: no report (${report.error ?? "unreadable"})`);
    continue;
  }
  if (!(file in coverage)) fail(`${name}: file ${file} is not in the coverage block`);
  else if (report.total_functions < coverage[file]) {
    fail(`${name}: only ${report.total_functions} functions analyzed, expected at least ${coverage[file]}`);
  }
  for (const v of report.violations) {
    findings++;
    const fn = pathOf(v.function);
    const row = rows.find(
      (r) => r.file.test(file) && r.fn.test(fn) && r.mnemonic.test(v.mnemonic) && r.severity.test(v.severity),
    );
    if (row) {
      row.used++;
      triaged++;
    } else {
      const key = `${file} | ${fn} | ${v.mnemonic} | ${v.severity}`;
      untriaged.set(key, [...(untriaged.get(key) ?? []), `${arch}:${opt}`]);
    }
  }
  console.log(
    `${name.padEnd(28)} functions ${String(report.total_functions).padStart(3)}  errors ${report.error_count}  warnings ${report.warning_count}`,
  );
}
for (const [key, configs] of untriaged) fail(`untriaged: ${key}  (${configs.join(", ")})`);
for (const row of rows) if (row.used === 0) console.log(`note: row ${row.id} matched nothing`);
console.log(`${reports.length} reports, ${findings} findings, ${triaged} triaged, ${findings - triaged} untriaged`);
process.exitCode = failed ? 1 : 0;
