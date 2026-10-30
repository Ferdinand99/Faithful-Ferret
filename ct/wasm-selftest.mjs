// The positive controls of ct/wasm-scan.mjs. The scan is only worth anything if
// it flags what it is meant to flag, so this feeds it the fixtures of
// ct/wasm-fixtures and checks that
//
//   * every function of flagged.wat is flagged, with the kind of hit that the
//     function was written to have (the shapes of a table lookup: the sum of
//     two computed values, the table base in the offset immediate behind a
//     mask, the same behind a plain local, the table base added as a constant,
//     a scaled index; and a division, a remainder, a jump table, a square root
//     and a float division),
//   * clean.wat (a struct field, a load from a constant address, an xor and a
//     mask) is not flagged,
//   * an allow list with the right `max` accepts flagged.wat, an entry whose
//     `max` is one too small fails, and an entry without `max` is refused.
//
//   node ct/wasm-selftest.mjs

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "wasm-selftest-"));
const scan = (wat, allowText) => {
  const allow = join(dir, "allow.toml");
  writeFileSync(allow, allowText);
  const r = spawnSync(process.execPath, ["ct/wasm-scan.mjs", wat, allow], { encoding: "utf8" });
  return { status: r.status, out: r.stdout + r.stderr };
};

let failed = false;
const check = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failed = true;
};
const escape = (text) => text.replace(/[.()|]/g, (c) => "\\" + c);

// function -> the kinds of hit it must have
const expected = {
  "fixture::indexed": ["i32.load(indexed)"],
  "fixture::masked_table": ["i32.load(static-table)"],
  "fixture::local_table": ["i32.load(static-table)"],
  "fixture::const_add": ["i32.load(const-add)"],
  "fixture::scaled": ["i32.load(static-table)"],
  "fixture::division": ["i32.div_u", "i32.rem_s"],
  "fixture::wide_rem": ["i64.rem_u"],
  "fixture::jumps": ["br_table"],
  "fixture::root": ["f64.sqrt", "f64.div"],
};

const flagged = scan("ct/wasm-fixtures/flagged.wat", "");
check(flagged.status === 1, "flagged.wat fails with an empty allow list");
for (const [fn, kinds] of Object.entries(expected)) {
  for (const kind of kinds) {
    const re = new RegExp(`NOT ALLOWED\\s+${escape(kind)}\\s+x\\d+\\s+ferret_core::${fn}$`, "m");
    check(re.test(flagged.out), `${fn} is flagged as ${kind}`);
  }
}

const clean = scan("ct/wasm-fixtures/clean.wat", "");
check(clean.status === 0 && !/NOT ALLOWED/.test(clean.out), "clean.wat is not flagged");

// A TOML allow list: one entry per function and kind.
const entry = (fn, kind, max) =>
  `[[allow]]\nfunction = "^ferret_core::${fn}$"\ninstruction = "${escape(kind).replace(/\\/g, "\\\\")}"\nmax = ${max}\nreason = "fixture"\n`;
const all = Object.entries(expected)
  .flatMap(([fn, kinds]) => kinds.map((kind) => entry(fn, kind, 1)))
  .join("\n");

const exact = scan("ct/wasm-fixtures/flagged.wat", all);
check(exact.status === 0 && /wasm-scan: ok/.test(exact.out), "an allow list with the right max accepts flagged.wat");

// One entry that covers three functions with three hits.
const group = (max) =>
  `[[allow]]\nfunction = "^ferret_core::fixture::(masked_table|local_table|scaled)$"\ninstruction = "i32\\\\.load\\\\(static-table\\\\)"\nmax = ${max}\nreason = "fixture"\n`;
const rest = Object.entries(expected)
  .filter(([fn]) => !/masked_table|local_table|scaled/.test(fn))
  .flatMap(([fn, kinds]) => kinds.map((kind) => entry(fn, kind, 1)))
  .join("\n");
const enough = scan("ct/wasm-fixtures/flagged.wat", group(3) + "\n" + rest);
check(enough.status === 0, "an entry that covers three hits with max = 3 accepts them");
const tooSmall = scan("ct/wasm-fixtures/flagged.wat", group(2) + "\n" + rest);
check(tooSmall.status === 1 && /allows 2, found 3/.test(tooSmall.out), "the same entry with max = 2 fails");

const noMax = scan("ct/wasm-fixtures/flagged.wat", `[[allow]]\nfunction = "x"\ninstruction = "y"\nreason = "z"\n`);
check(noMax.status !== 0 && /without max/.test(noMax.out), "an entry without max is refused");

rmSync(dir, { recursive: true, force: true });
process.exitCode = failed ? 1 : 0;
