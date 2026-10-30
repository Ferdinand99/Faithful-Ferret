// Scans the WebAssembly build for instructions whose time can depend on their
// operands (plan section 10 point 4, U3).
//
//   node ct/wasm-scan.mjs <module.wat> ct/wasm-allow.toml
//
// <module.wat> is `wasm-tools print` of the release build of the binding with
// its function names kept (ct/run.sh wasm-scan). In every function it looks for
//
//   * integer division and remainder: i32|i64.div_s|div_u|rem_s|rem_u,
//   * floating point f32|f64.div and f32|f64.sqrt,
//   * br_table (a jump table),
//   * a memory load whose address is the sum of two computed values, the shape
//     of a table lookup or an indexed slice access (`... ; i32.add ; i32.load`).
//
// and puts each function in a class by its name: `ferret_core`, `binding`
// (ferret_core_wasm), or another crate (argon2, sha2, core, alloc, ...) or
// `unnamed`. The first two are ours: every hit there must be in
// ct/wasm-allow.toml, with the reason that its operands are public, or the scan
// fails. Hits in other crates are counted and listed but do not fail the scan:
// the plan accepts them as a known residual risk (section 10 point 6: argon2 and
// the RustCrypto code are not re-verified by us).
//
// Inlining moves code between names. A function of ours that rustc inlined into
// a function of another crate would be counted there, and the other way round;
// the scan reads the final module, so the sum is right, the split is as good as
// the names. The totals are in the report.
//
// This is the test `wasm_scan_only_allowlisted`.

import { readFileSync } from "node:fs";
import { normalize, pathOf } from "./rustname.mjs";

const [watPath, allowPath] = process.argv.slice(2);
if (!watPath || !allowPath) {
  console.error("usage: wasm-scan.mjs <module.wat> <wasm-allow.toml>");
  process.exit(2);
}

// ------------------------------------------------------------- allow list

/** The `[[allow]]` tables of a small TOML subset: string and integer values. */
function parseAllow(text) {
  const entries = [];
  let cur = null;
  for (const raw of text.replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    if (line === "[[allow]]") {
      cur = {};
      entries.push(cur);
      continue;
    }
    const m = line.match(/^(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\d+))$/);
    if (!m || !cur) throw new Error(`wasm-allow.toml: cannot read "${raw}"`);
    cur[m[1]] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : Number(m[3]);
  }
  for (const e of entries) {
    for (const k of ["function", "instruction", "reason"]) {
      if (typeof e[k] !== "string" || !e[k]) throw new Error(`wasm-allow.toml: entry without ${k}: ${JSON.stringify(e)}`);
    }
    e.fn = new RegExp(e.function);
    e.ins = new RegExp("^(?:" + e.instruction + ")$");
    e.used = 0;
  }
  return entries;
}

// ------------------------------------------------------------ the module

const DANGEROUS = /^(?:(?:i32|i64)\.(?:div_s|div_u|rem_s|rem_u)|(?:f32|f64)\.(?:div|sqrt)|br_table)\b/;
const LOAD = /^(?:i32|i64|f32|f64|v128)\.load\w*/;

function* functions(wat) {
  const lines = wat.split("\n");
  let name = null;
  let body = [];
  for (const line of lines) {
    const m = line.match(/^  \(func (\$\S+)?/);
    if (m) {
      name = m[1] ?? "$unnamed";
      body = [];
    } else if (name !== null && line === "  )") {
      yield { name, body };
      name = null;
    } else if (name !== null) {
      body.push(line.trim());
    }
  }
}

/**
 * The crate a function is defined in: the first identifier of its path. For
 * `<Type as Trait>::method` that is the crate of the type, and for a generic
 * of another crate instantiated with our types (`alloc::vec::Vec<Field>`) it
 * is that other crate, so it is not counted as ours.
 */

function classify(raw) {
  if (raw === "$unnamed" || /^\$(?:func)?\d+$/.test(raw)) return "unnamed";
  if (/_\$LT\$ferret_core_wasm/.test(raw)) return "binding";
  if (/_\$LT\$ferret_core/.test(raw)) return "ferret_core";
  const first = normalize(raw)
    .split("::")
    .find((part) => /^[a-z_][a-z0-9_]{2,}$/.test(part));
  if (first === "ferret_core_wasm") return "binding";
  return first ?? "unnamed";
}

/** The instruction mnemonic of a line of `wasm-tools print`, or null. */
function mnemonic(line) {
  const m = line.match(/^([a-z0-9_]+(?:\.[a-z0-9_.]+)?)\b/);
  return m ? m[1] : null;
}

function scan(body) {
  const hits = [];
  const ins = body.map(mnemonic);
  for (let i = 0; i < body.length; i++) {
    const op = ins[i];
    if (!op) continue;
    if (DANGEROUS.test(op)) hits.push(op);
    else if (LOAD.test(op) && ins[i - 1] === "i32.add" && ins[i - 2] !== "i32.const" && ins[i - 3] !== undefined) {
      hits.push(`${op.split(".")[0]}.load(indexed)`);
    }
  }
  return hits;
}

// ------------------------------------------------------------------ main

const allow = parseAllow(readFileSync(allowPath, "utf8"));
const wat = readFileSync(watPath, "utf8").replace(/\r\n/g, "\n");

const totals = new Map(); // class -> Map(instruction -> count)
const ours = []; // {name, norm, ins, count}
let functionCount = 0;
let named = 0;
for (const fn of functions(wat)) {
  functionCount++;
  const cls = classify(fn.name);
  if (cls !== "unnamed") named++;
  const hits = scan(fn.body);
  if (hits.length === 0) continue;
  const byIns = new Map();
  for (const h of hits) byIns.set(h, (byIns.get(h) ?? 0) + 1);
  const t = totals.get(cls) ?? new Map();
  for (const [h, c] of byIns) t.set(h, (t.get(h) ?? 0) + c);
  totals.set(cls, t);
  if (cls === "ferret_core" || cls === "binding") {
    for (const [h, c] of byIns) ours.push({ cls, name: fn.name, norm: pathOf(fn.name), ins: h, count: c });
  }
}

console.log(`wasm-scan: ${functionCount} functions, ${named} with a name`);
if (functionCount > 0 && named / functionCount < 0.5) {
  console.error("FAIL: most functions have no name; build the module with its names (ct/run.sh wasm-scan)");
  process.exit(1);
}

let failed = false;
console.log("\nfunctions of ours (ferret_core, ferret_core_wasm):");
for (const hit of ours) {
  const entry = allow.find((e) => e.fn.test(hit.norm) && e.ins.test(hit.ins));
  if (entry) {
    entry.used += hit.count;
    console.log(`  allowed  ${hit.ins.padEnd(22)} x${hit.count}  ${hit.norm}  [${entry.reason}]`);
    if (typeof entry.max === "number" && entry.used > entry.max) {
      console.log(`  FAIL     the entry for ${entry.function} allows ${entry.max}, found ${entry.used}`);
      failed = true;
    }
  } else {
    console.log(`  NOT ALLOWED  ${hit.ins.padEnd(18)} x${hit.count}  ${hit.norm}`);
    failed = true;
  }
}
if (ours.length === 0) console.log("  none");

console.log("\nother crates (counted, not gated; section 10 point 6):");
const others = [...totals].filter(([cls]) => cls !== "ferret_core" && cls !== "binding").sort(([a], [b]) => a.localeCompare(b));
for (const [cls, t] of others) {
  console.log(`  ${cls.padEnd(22)} ${[...t].map(([i, c]) => `${i} x${c}`).join(", ")}`);
}
if (others.length === 0) console.log("  none");

for (const e of allow) if (e.used === 0) console.log(`note: allow entry for ${e.function} / ${e.instruction} matched nothing`);
console.log(failed ? "\nwasm-scan: FAILED" : "\nwasm-scan: ok (every hit in our functions is allowed)");
process.exitCode = failed ? 1 : 0;
