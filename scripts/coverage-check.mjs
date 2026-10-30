#!/usr/bin/env node
// Checks the coverage of the core against the thresholds in scripts/coverage-thresholds.json.
//
//   node scripts/coverage-check.mjs <llvm-cov-export.json> [--markdown]
//
// The input is the JSON of `cargo llvm-cov --branch --json` (llvm-cov export
// format). The thresholds live in scripts/coverage-thresholds.json: lines and
// branches per module, and the lines of the whole core. Files under
// "exclude" (the test-support code) are not counted anywhere. Exit code 1 if
// a threshold is not met, or if a path listed for a module matches no file.
//
// Inline #[cfg(test)] modules (for example in codes.rs) are counted too:
// llvm-cov cannot leave them out without #[coverage(off)] attributes, which
// need a nightly feature gate in the library source. Leaving them out changes
// the figures by under half a point (codes.rs lines 98.75 -> 98.29, core total
// 97.30 -> 97.26, branches unchanged) and no threshold turns on it.
import { readFileSync } from 'node:fs';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const input = args.find((a) => !a.startsWith('--'));
const markdown = args.includes('--markdown');
if (!input) {
  console.error('usage: node scripts/coverage-check.mjs <llvm-cov-export.json> [--markdown]');
  process.exit(2);
}
const config = JSON.parse(readFileSync(join(here, 'coverage-thresholds.json'), 'utf8'));
const report = JSON.parse(readFileSync(resolve(input), 'utf8'));

// Paths in the report are absolute (/src/...) and, for the files that the core
// includes with include!, spelled with ".." (for example
// /src/crates/ferret-core/src/../../../ct/harness/crockford.rs). Resolve the
// ".." first, then make the path relative to the repo.
const rel = (f) =>
  posix
    .normalize(f.replace(/\\/g, '/'))
    .replace(/^.*?(crates\/ferret-core\/|crates\/ferret-server-auth\/|ct\/harness\/)/, '$1');

const files = new Map();
for (const datum of report.data) {
  for (const f of datum.files) files.set(rel(f.filename), f.summary);
}

const counted = [...files].filter(
  ([name]) =>
    config.roots.some((r) => name.startsWith(r)) && !config.exclude.some((e) => name.startsWith(e)),
);
if (counted.length === 0) {
  console.error('coverage-check: no files of the core in the report');
  process.exit(2);
}

function sum(selected) {
  const t = { lines: { count: 0, covered: 0 }, branches: { count: 0, covered: 0 } };
  for (const [, s] of selected) {
    for (const kind of ['lines', 'branches']) {
      t[kind].count += s[kind]?.count ?? 0;
      t[kind].covered += s[kind]?.covered ?? 0;
    }
  }
  return t;
}
const pct = (k) => (k.count === 0 ? 100 : (100 * k.covered) / k.count);

const rows = [];
let failed = false;
const verdict = (value, min) => {
  if (min === undefined) return '';
  const ok = value >= min;
  if (!ok) failed = true;
  return ok ? 'pass' : 'FAIL';
};

for (const [name, mod] of Object.entries(config.modules)) {
  const matches = (p) => (f) => (p.endsWith('/') ? f.startsWith(p) : f === p);
  // Every listed path must match a file: a path that silently matches nothing
  // would leave code out of the module and flatter its figure.
  for (const p of mod.paths) {
    if (!counted.some(([f]) => matches(p)(f))) {
      console.error(`coverage-check: module ${name}: the path ${p} matches no file of the report`);
      failed = true;
    }
  }
  const selected = counted.filter(([f]) => mod.paths.some((p) => matches(p)(f)));
  if (selected.length === 0) continue;
  const t = sum(selected);
  rows.push({
    name,
    files: selected.length,
    lines: pct(t.lines),
    lineMin: mod.lines,
    lineVerdict: verdict(pct(t.lines), mod.lines),
    branches: pct(t.branches),
    branchMin: mod.branches,
    branchVerdict: verdict(pct(t.branches), mod.branches),
    branchCount: t.branches.count,
  });
}
const all = sum(counted);
rows.push({
  name: 'core total',
  files: counted.length,
  lines: pct(all.lines),
  lineMin: config.total.lines,
  lineVerdict: verdict(pct(all.lines), config.total.lines),
  branches: pct(all.branches),
  branchMin: config.total.branches,
  branchVerdict: verdict(pct(all.branches), config.total.branches),
  branchCount: all.branches.count,
});

const f = (n) => n.toFixed(2);
if (markdown) {
  console.log('| module | files | lines | needs | branches | needs | |');
  console.log('|---|---|---|---|---|---|---|');
  for (const r of rows) {
    const need = (m) => (m === undefined ? '-' : `${m}`);
    const v = [r.lineVerdict, r.branchVerdict].filter(Boolean).join(', ') || '-';
    console.log(`| ${r.name} | ${r.files} | ${f(r.lines)} | ${need(r.lineMin)} | ${f(r.branches)} (${r.branchCount}) | ${need(r.branchMin)} | ${v} |`);
  }
} else {
  const w = Math.max(...rows.map((r) => r.name.length));
  console.log(`${'module'.padEnd(w)}  files   lines%  (min)   branches%  (min)  verdict`);
  for (const r of rows) {
    const v = [r.lineVerdict, r.branchVerdict].filter(Boolean).join(',') || '-';
    console.log(
      `${r.name.padEnd(w)}  ${String(r.files).padStart(5)}  ${f(r.lines).padStart(7)}  (${String(r.lineMin ?? '-').padStart(3)})  ${f(r.branches).padStart(9)}  (${String(r.branchMin ?? '-').padStart(3)})  ${v}`,
    );
  }
}
if (failed) {
  console.error('coverage-check: below the thresholds');
  process.exit(1);
}
