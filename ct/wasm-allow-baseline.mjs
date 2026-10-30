// Compares ct/wasm-allow.toml with the one on the base branch.
//
//   node ct/wasm-allow-baseline.mjs base.toml ct/wasm-allow.toml
//
// In a key-handling function (ct/wasm-key.mjs) a new entry, or a `max` higher
// than the base's, is accepted only if its reason starts with `APPROVED: `,
// which ct/wasm-allow-gen.mjs writes for `--approve 'function=reason'`. A hand
// edit that raises a `max` leaves the reason as it was and fails here. (A
// person can still write the word by hand; that is a visible change in the diff
// of the pull request, and the point is that it takes a decision.)

import { readFileSync } from "node:fs";
import { KEY, pathOfEntry } from "./wasm-key.mjs";

function parse(path) {
  const entries = new Map();
  let cur = null;
  for (const raw of readFileSync(path, "utf8").replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line === "[[allow]]") {
      cur = {};
      continue;
    }
    const m = line.match(/^(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\d+))$/);
    if (!m || !cur) throw new Error(`cannot read "${raw}" in ${path}`);
    cur[m[1]] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : Number(m[3]);
    if (cur.function !== undefined && cur.instruction !== undefined && cur.max !== undefined && cur.reason !== undefined) {
      entries.set(`${cur.function}\u0000${cur.instruction}`, cur);
    }
  }
  return entries;
}

const [basePath, newPath] = process.argv.slice(2);
const base = parse(basePath);
const now = parse(newPath);
let failed = false;
let guarded = 0;
for (const [key, e] of now) {
  const path = pathOfEntry(e.function);
  if (!KEY.test(path)) continue;
  guarded++;
  const old = base.get(key);
  const raised = !old || e.max > old.max;
  if (raised && !e.reason.startsWith("APPROVED: ")) {
    console.log(`FAIL: ${path} / ${e.instruction}: ${old ? `max ${old.max} -> ${e.max}` : `new entry (${e.max})`} in a key-handling function without an APPROVED reason`);
    failed = true;
  }
}
console.log(`${guarded} entries in key-handling functions checked against the base${failed ? "" : ": none raised or new without an approval"}`);
process.exitCode = failed ? 1 : 0;
