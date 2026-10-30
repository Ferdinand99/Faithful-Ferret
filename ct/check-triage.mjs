// Checks that every finding of ct_analyzer is triaged in ct/TRIAGE.md.
//
//   node ct/check-triage.mjs <dir with the analyzer's JSON reports> ct/TRIAGE.md
//
// The analyzer has no data flow analysis: it reports every dangerous
// instruction. A person reads the code and decides whether an operand can
// depend on a secret. The decisions are in
// TRIAGE.md, in a fenced block named `triage` with one row per class of
// finding:
//
//     id @ file @ function (regular expression) @ mnemonic (regular expression) @ severity
//
// and every id has a `### id` heading with the reasoning. A finding is
// triaged when a row matches its file, function, mnemonic and severity.
//
// A second fenced block, `counts`, pins what each report holds:
//
//     file @ arch @ opt @ functions=N T1=a T2=b ...
//
// the number of functions the analyzer looked at and the number of findings
// that each row covers. The check fails when any of them changes, up or down:
// a new branch in a function that is already triaged is a new finding even if
// the row covers it, and a report with fewer functions than the file has
// public functions is a clean report of nothing (a function that rustc left out
// of the compiled file). `--write-counts` prints the block for the current
// reports, to be pasted after the change has been looked at.
//
// This is the test `ct_analyzer_clean_or_triaged`.

import { readFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";
import { pathOf } from "./rustname.mjs";

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const writeCounts = process.argv.includes("--write-counts");
const [dir, triagePath] = args;
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
const pinned = new Map(
  block(text, "counts").filter((c) => c.length === 4).map(([file, arch, opt, rest]) => [`${file} ${arch} ${opt}`, rest.split(/\s+/).sort().join(" ")]),
);
const current = new Map();

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
  const perRow = {};
  for (const v of report.violations) {
    findings++;
    const fn = pathOf(v.function);
    const row = rows.find(
      (r) => r.file.test(file) && r.fn.test(fn) && r.mnemonic.test(v.mnemonic) && r.severity.test(v.severity),
    );
    if (row) {
      row.used++;
      triaged++;
      perRow[row.id] = (perRow[row.id] ?? 0) + 1;
    } else {
      const key = `${file} | ${fn} | ${v.mnemonic} | ${v.severity}`;
      untriaged.set(key, [...(untriaged.get(key) ?? []), `${arch}:${opt}`]);
    }
  }
  current.set(
    `${file} ${arch} ${opt}`,
    [`functions=${report.total_functions}`, ...Object.entries(perRow).map(([id, n]) => `${id}=${n}`)].sort().join(" "),
  );
  console.log(
    `${name.padEnd(28)} functions ${String(report.total_functions).padStart(3)}  errors ${report.error_count}  warnings ${report.warning_count}`,
  );
}
if (writeCounts) {
  let out = "";
  for (const [key, value] of current) {
    const [file, arch, opt] = key.split(" ");
    out += `${file} @ ${arch} @ ${opt} @ ${value}
`;
  }
  process.stdout.write(out, () => process.exit(0));
  await new Promise(() => {});
}
for (const [key, value] of current) {
  if (!pinned.has(key)) fail(`${key}: no pinned counts (now: ${value})`);
  else if (pinned.get(key) !== value) fail(`${key}: pinned ${pinned.get(key)}, now ${value}`);
}
for (const key of pinned.keys()) if (!current.has(key)) fail(`${key}: pinned but there is no report`);
for (const [key, configs] of untriaged) fail(`untriaged: ${key}  (${configs.join(", ")})`);
for (const row of rows) if (row.used === 0) console.log(`note: row ${row.id} matched nothing`);
console.log(`${reports.length} reports, ${findings} findings, ${triaged} triaged, ${findings - triaged} untriaged`);
process.exitCode = failed ? 1 : 0;
