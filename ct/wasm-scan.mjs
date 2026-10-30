// Scans the WebAssembly build for instructions whose time can depend on their
// operands (plan section 10 point 4, U3).
//
//   node ct/wasm-scan.mjs <module.wat> ct/wasm-allow.toml [--no-gate]
//                         [--json totals.json] [--compare before.json]
//
// <module.wat> is `wasm-tools print` of the binding at the optimisation level
// that is shipped (wasm-bindgen, then wasm-opt -Oz, names kept with -g:
// ct/run.sh wasm-scan). In every function it looks for
//
//   * integer division and remainder: i32|i64.div_s|div_u|rem_s|rem_u,
//   * floating point f32|f64.div and f32|f64.sqrt,
//   * br_table (a jump table), and
//   * a table lookup, in the three shapes that LLVM gives it, as a load
//     "(indexed)": the address is the sum of two computed values
//     (`... ; i32.add ; i32.load`), "(static-table)": the base of a table in
//     the data segment is in the offset immediate of the load and the index is
//     whatever was computed before it (`local.get i ; i32.const 31 ; i32.and ;
//     i32.load8_u offset=1048700`, or the index straight from a local), and
//     "(const-add)": the base of a table is added to the index as a constant
//     (`local.get i ; i32.const 1048700 ; i32.add ; i32.load8_u`). A static
//     address is one at or above the start of the data segment.
//
// and puts each function in a class by its name: `ferret_core`, `binding`
// (ferret_core_wasm), `unnamed` (a function without a name, which wasm-opt may
// have made), or another crate (argon2, sha2, core, alloc, ...). The first
// three are ours: every hit there must be matched by an entry of
// ct/wasm-allow.toml, which names the function, the instruction, the reason
// that its operands are public, and `max`, the most hits the entry covers. A
// hit without an entry, or more hits than `max`, fails the scan; so does an
// entry without `max`. Hits in other crates are counted and listed but do not
// fail the scan: the plan accepts them as a known residual risk (section 10
// point 6: argon2 and the RustCrypto code are not re-verified by us).
//
// ct/wasm-selftest.mjs feeds the scan fixtures that must be flagged.
//
// This is the test `wasm_scan_only_allowlisted`.

import { readFileSync, writeFileSync } from "node:fs";
import { cleanPath } from "./rustname.mjs";

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const value = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const positional = argv.filter((a, i) => !a.startsWith("--") && !["--json", "--compare"].includes(argv[i - 1]));
const [watPath, allowPath] = positional;
if (!watPath || !allowPath) {
  console.error("usage: wasm-scan.mjs <module.wat> <wasm-allow.toml> [--no-gate] [--json out] [--compare before.json]");
  process.exit(2);
}

// ------------------------------------------------------------- allow list

/** The `[[allow]]` tables of a small TOML subset: string and integer values. */
function parseAllow(text) {
  const entries = [];
  let cur = null;
  for (const raw of text.replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trim();
    if (line.startsWith("#")) continue;
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
    if (!Number.isInteger(e.max) || e.max < 1) {
      throw new Error(`wasm-allow.toml: entry without max: ${e.function} / ${e.instruction}`);
    }
    e.fn = new RegExp(e.function);
    e.ins = new RegExp("^(?:" + e.instruction + ")$");
    e.used = 0;
  }
  return entries;
}

// ------------------------------------------------------------ the module

const DANGEROUS = /^(?:(?:i32|i64)\.(?:div_s|div_u|rem_s|rem_u)|(?:f32|f64)\.(?:div|sqrt)|br_table)$/;
const LOAD = /^(?:i32|i64|f32|f64|v128)\.load\w*$/;

/** The address at which the data segments start: static tables are at or above it. */
function dataStart(wat) {
  let start = Infinity;
  for (const m of wat.matchAll(/\(data\s+(?:\$\S+\s+)?(?:\(;\d+;\)\s+)?\(i32\.const (\d+)\)/g)) {
    start = Math.min(start, Number(m[1]));
  }
  return Number.isFinite(start) ? start : 1048576;
}

function* functions(wat) {
  const lines = wat.split("\n");
  let name = null;
  let body = [];
  for (const line of lines) {
    // The name is `$name` or, after wasm-bindgen, `$"a demangled name with spaces"`.
    const m = line.match(/^  \(func (\$"(?:[^"\\]|\\.)*"|\$[^\s()]+)?/);
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
 * is that other crate, so it is not counted as ours. A name without a path is
 * a function that wasm-bindgen made for an export, which is the binding's.
 */
function classify(raw) {
  if (raw === "$unnamed" || /^\$(?:func)?\d+$/.test(raw)) return "unnamed";
  const path = cleanPath(raw);
  const first = path.match(/^[A-Za-z_][A-Za-z0-9_]*/)?.[0];
  if (/^[A-Za-z_][A-Za-z0-9_]*( [a-z ]*shim)?$/.test(path)) return "binding";
  if (first === "ferret_core_wasm") return "binding";
  return first ?? "unnamed";
}

/** The instruction mnemonic of a line of `wasm-tools print`, or null. */
function mnemonic(line) {
  const m = line.match(/^([a-z0-9_]+(?:\.[a-z0-9_.]+)?)\b/);
  return m ? m[1] : null;
}

/** The `offset=N` of a memory instruction (0 if none). */
function offsetOf(line) {
  const m = line.match(/\boffset=(\d+)/);
  return m ? Number(m[1]) : 0;
}

/** The constant of an `i32.const N` line, or null. */
function constOf(line) {
  const m = line.match(/^i32\.const (-?\d+)/);
  return m ? Number(m[1]) : null;
}

function scan(body, staticFrom) {
  const hits = [];
  const ins = body.map(mnemonic);
  for (let i = 0; i < body.length; i++) {
    const op = ins[i];
    if (!op) continue;
    if (DANGEROUS.test(op)) {
      hits.push(op);
      continue;
    }
    if (!LOAD.test(op)) continue;
    const kind = op.split(".")[0];
    const prev = ins[i - 1];
    const before = ins[i - 2];
    // The base of a table in the offset immediate; the address operand is not
    // a constant (a constant address is a fixed place, not a lookup).
    if (offsetOf(body[i]) >= staticFrom && prev !== "i32.const") {
      hits.push(`${kind}.load(static-table)`);
    } else if (prev === "i32.add" && before === "i32.const" && constOf(body[i - 2]) >= staticFrom) {
      // The base of a table added to the index as a constant.
      hits.push(`${kind}.load(const-add)`);
    } else if (prev === "i32.add" && before !== "i32.const" && ins[i - 3] !== undefined) {
      hits.push(`${kind}.load(indexed)`);
    }
  }
  return hits;
}

// ------------------------------------------------------------------ main

const wat = readFileSync(watPath, "utf8").replace(/\r\n/g, "\n");
const staticFrom = dataStart(wat);
const gate = !flag("--no-gate");
const allow = gate ? parseAllow(readFileSync(allowPath, "utf8")) : [];

const OURS = new Set(["ferret_core", "binding", "unnamed"]);
const totals = new Map(); // class -> Map(instruction -> count)
const ours = []; // {name, norm, ins, count}
let functionCount = 0;
let named = 0;
for (const fn of functions(wat)) {
  functionCount++;
  const cls = classify(fn.name);
  if (cls !== "unnamed") named++;
  const hits = scan(fn.body, staticFrom);
  if (hits.length === 0) continue;
  const byIns = new Map();
  for (const h of hits) byIns.set(h, (byIns.get(h) ?? 0) + 1);
  const t = totals.get(cls) ?? new Map();
  for (const [h, c] of byIns) t.set(h, (t.get(h) ?? 0) + c);
  totals.set(cls, t);
  if (OURS.has(cls)) {
    for (const [h, c] of byIns) ours.push({ cls, name: fn.name, norm: cleanPath(fn.name), ins: h, count: c });
  }
}

console.log(`wasm-scan: ${functionCount} functions, ${named} with a name; static data from address ${staticFrom}`);
if (functionCount > 0 && named / functionCount < 0.5) {
  console.error("FAIL: most functions have no name; build the module with its names (ct/run.sh wasm-scan)");
  process.exit(1);
}

/** The totals of our functions by kind of hit. */
function kinds() {
  const k = { "div/rem/sqrt": 0, br_table: 0, "table loads": 0 };
  for (const hit of ours) {
    if (hit.ins === "br_table") k.br_table += hit.count;
    else if (hit.ins.includes(".load(")) k["table loads"] += hit.count;
    else k["div/rem/sqrt"] += hit.count;
  }
  return k;
}
const mine = kinds();
console.log(`hits in our functions: ${Object.entries(mine).map(([k, v]) => `${k} ${v}`).join(", ")}`);
if (value("--json")) {
  const hits = ours.map(({ norm, ins, count }) => ({ norm, ins, count }));
  writeFileSync(value("--json"), JSON.stringify({ ...mine, hits }));
}
if (value("--compare")) {
  const before = JSON.parse(readFileSync(value("--compare"), "utf8"));
  console.log(
    "before wasm-opt -> shipped level: " +
      Object.keys(mine)
        .map((k) => `${k} ${before[k]} -> ${mine[k]}`)
        .join(", "),
  );
}

let failed = false;
console.log("\nfunctions of ours (ferret_core, ferret_core_wasm, unnamed):");
if (gate) {
  for (const hit of ours) {
    const entry = allow.find((e) => e.fn.test(hit.norm) && e.ins.test(hit.ins));
    if (entry) {
      entry.used += hit.count;
      console.log(`  allowed  ${hit.ins.padEnd(24)} x${hit.count}  ${hit.norm}`);
    } else {
      console.log(`  NOT ALLOWED  ${hit.ins.padEnd(20)} x${hit.count}  ${hit.norm}`);
      failed = true;
    }
  }
  for (const e of allow) {
    if (e.used > e.max) {
      console.log(`  FAIL     the entry for ${e.function} / ${e.instruction} allows ${e.max}, found ${e.used}`);
      failed = true;
    }
  }
}
if (ours.length === 0) console.log("  none");

console.log("\nother crates (counted, not gated; section 10 point 6):");
const others = [...totals].filter(([cls]) => !OURS.has(cls)).sort(([a], [b]) => a.localeCompare(b));
for (const [cls, t] of others) {
  console.log(`  ${cls.padEnd(22)} ${[...t].map(([i, c]) => `${i} x${c}`).join(", ")}`);
}
if (others.length === 0) console.log("  none");

if (gate) {
  for (const e of allow) if (e.used === 0) console.log(`note: allow entry for ${e.function} / ${e.instruction} matched nothing`);
  console.log(failed ? "\nwasm-scan: FAILED" : "\nwasm-scan: ok (every hit in our functions is allowed, within its max)");
}
process.exitCode = failed ? 1 : 0;
