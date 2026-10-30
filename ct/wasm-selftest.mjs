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
//     `max` is one too small or one too large fails, and an entry without `max` is refused.
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

// `max` is exact: slack would absorb a later hit of the same kind.
const slack = scan("ct/wasm-fixtures/flagged.wat", group(4) + "\n" + rest);
check(slack.status === 1 && /allows 4, found 3/.test(slack.out), "an entry whose max is one too large fails");

const noMax = scan("ct/wasm-fixtures/flagged.wat", `[[allow]]\nfunction = "x"\ninstruction = "y"\nreason = "z"\n`);
check(noMax.status !== 0 && /without max/.test(noMax.out), "an entry without max is refused");


// An allow entry in TOML for a function path and a kind of hit, with the
// regular expressions escaped the way the generator writes them.
const BS = String.fromCharCode(92);
const regexEscape = (text) => text.replace(/[.()|]/g, (c) => BS + c);
const tomlEscape = (text) => text.split(BS).join(BS + BS);
const entryOf = (norm, ins, max, reason) =>
  `[[allow]]\nfunction = "${tomlEscape("^" + regexEscape(norm) + "$")}"\ninstruction = "${tomlEscape(regexEscape(ins))}"\nmax = ${max}\nreason = "${reason}"\n`;
const UNWRAP = "ferret_core::wrap::unwrap_vk";
const PASSKEY = "ferret_core_wasm::vault::Vault>::passkey_create";
const PUSH_HEX = "ferret_core::sheet::push_hex";
const METHODS_HEX = "ferret_core::methods::hex";
const MEMORY_RECORD = "ferret_core::sync_memory::SyncMemory>::record";
const EXISTING = [
  entryOf(UNWRAP, "br_table", 1, "written by a person"),
  entryOf(PASSKEY, "i32.load(indexed)", 1, "written by a person"),
  entryOf(PUSH_HEX, "i32.load(static-table)", 2, "written by a person"),
  entryOf(METHODS_HEX, "i32.load(indexed)", 1, "written by a person"),
  entryOf(MEMORY_RECORD, "i64.load(indexed)", 1, "written by a person"),
].join("\n");

// The generator of the allow list does not bless a new hit in a function that
// handles key material.
const generate = (hits, extra = []) => {
  const existing = join(dir, "existing.toml");
  const hitsFile = join(dir, "hits.json");
  writeFileSync(existing, EXISTING);
  writeFileSync(hitsFile, JSON.stringify({ hits }));
  const r = spawnSync(process.execPath, ["ct/wasm-allow-gen.mjs", hitsFile, "--existing", existing, ...extra], { encoding: "utf8" });
  return { status: r.status, out: r.stdout, err: r.stderr };
};
const unwrap = (count) => ({ norm: UNWRAP, ins: "br_table", count });
const passkey = (count) => ({ norm: PASSKEY, ins: "i32.load(indexed)", count });
const pushHex = (count) => ({ norm: PUSH_HEX, ins: "i32.load(static-table)", count });
const methodsHex = (count) => ({ norm: METHODS_HEX, ins: "i32.load(indexed)", count });
const memoryRecord = (count) => ({ norm: MEMORY_RECORD, ins: "i64.load(indexed)", count });
const baseHits = [unwrap(1), passkey(1), pushHex(2), methodsHex(1), memoryRecord(1)];
const withChange = (change) => baseHits.map((h) => change.find((c) => c.norm === h.norm && c.ins === h.ins) ?? h);

const same = generate(baseHits);
check(same.status === 0 && /reason = "written by a person"/.test(same.out), "the generator keeps an existing entry and its reason");
const more = generate(withChange([unwrap(2)]));
check(more.status === 3 && /max 1 -> 2/.test(more.err), "the generator refuses a higher max in a key-handling function");
const fresh = generate([...baseHits, { norm: UNWRAP, ins: "i32.load(static-table)", count: 1 }]);
check(fresh.status === 3 && /new entry/.test(fresh.err), "the generator refuses a new kind of hit in a key-handling function");
const approved = generate(withChange([unwrap(2)]), ["--approve", `${UNWRAP}=I read the code of unwrap_vk and the second jump is the same match`]);
check(
  approved.status === 0 && /max = 2/.test(approved.out) && /APPROVED: I read the code of unwrap_vk/.test(approved.out),
  "--approve lets it through and writes the reason, marked APPROVED",
);
const raisedBinding = generate(withChange([passkey(3)]));
check(
  raisedBinding.status === 3 && /Vault>::passkey_create/.test(raisedBinding.err) && /max 1 -> 3/.test(raisedBinding.err),
  "the generator refuses a higher max in Vault>::passkey_create (a named function of the binding)",
);
const newBinding = generate([...baseHits, { norm: "ferret_core_wasm::vault::Vault>::unlock", ins: "i32.load(indexed)", count: 2 }]);
check(newBinding.status === 3, "the generator refuses a new entry in a named function of the binding");
const raisedSheet = generate(withChange([pushHex(5)]));
check(raisedSheet.status === 3, "the generator refuses a higher max in sheet");
// The unlock-method and rollback-memory modules are guarded as well.
const raisedMethods = generate(withChange([methodsHex(2)]));
check(
  raisedMethods.status === 3 && /methods::hex/.test(raisedMethods.err) && /max 1 -> 2/.test(raisedMethods.err),
  "the generator refuses a higher max in the unlock-method module",
);
const raisedMemory = generate(withChange([memoryRecord(4)]));
check(
  raisedMemory.status === 3 && /sync_memory/.test(raisedMemory.err) && /max 1 -> 4/.test(raisedMemory.err),
  "the generator refuses a higher max in the rollback-memory module",
);
const newMemory = generate([...baseHits, { norm: "ferret_core::sync_memory::SyncMemory>::from_bytes", ins: "i32.rem_u", count: 1 }]);
check(newMemory.status === 3 && /new entry/.test(newMemory.err), "the generator refuses a new entry in the rollback-memory module");
const newMethods = generate([...baseHits, { norm: "ferret_core::methods::manifest_add_method", ins: "br_table", count: 1 }]);
check(newMethods.status === 3 && /new entry/.test(newMethods.err), "the generator refuses a new entry in the unlock-method module");
const approvedMemory = generate(withChange([memoryRecord(2)]), ["--approve", `${MEMORY_RECORD}=I read the code of record and the second load walks the rows the same way`]);
check(approvedMemory.status === 0 && /APPROVED: I read the code of record/.test(approvedMemory.out), "--approve lets a raise in the rollback-memory module through");
const other = generate([...baseHits, { norm: "ferret_core::cbor::decode::item", ins: "br_table", count: 3 }]);
check(other.status === 0 && /decode::item/.test(other.out), "a new entry outside the key-handling modules is generated");

// The file against the base branch: a raised max or a new entry in a
// key-handling function has to carry an APPROVED reason.
const baseline = (newText) => {
  const base = join(dir, "base.toml");
  const now = join(dir, "now.toml");
  writeFileSync(base, EXISTING);
  writeFileSync(now, newText);
  const r = spawnSync(process.execPath, ["ct/wasm-allow-baseline.mjs", base, now], { encoding: "utf8" });
  return { status: r.status, out: r.stdout + r.stderr };
};
check(baseline(EXISTING).status === 0, "the baseline check passes on an unchanged file");
const handRaised = baseline(EXISTING.replace(`br_table"\nmax = 1`, `br_table"\nmax = 2`));
check(handRaised.status === 1 && /unwrap_vk.*max 1 -> 2/.test(handRaised.out), "a hand-raised max in a key-handling function fails against the base");
const approvedRaise = baseline(
  EXISTING.replace(`br_table"\nmax = 1\nreason = "written by a person"`, `br_table"\nmax = 2\nreason = "APPROVED: I read it"`),
);
check(approvedRaise.status === 0, "the same raise with an APPROVED reason passes");
const newKey = baseline(EXISTING + "\n" + entryOf("ferret_core::codes::decode_secret_key", "br_table", 1, "plausible"));
check(newKey.status === 1 && /new entry/.test(newKey.out), "a new entry in a key-handling function without APPROVED fails");
const handRaisedMemory = baseline(
  EXISTING.replace(
    entryOf(MEMORY_RECORD, "i64.load(indexed)", 1, "written by a person"),
    entryOf(MEMORY_RECORD, "i64.load(indexed)", 2, "written by a person"),
  ),
);
check(handRaisedMemory.status === 1 && /sync_memory.*max 1 -> 2/.test(handRaisedMemory.out), "a hand-raised max in the rollback-memory module fails against the base");
const newMethodsEntry = baseline(EXISTING + "\n" + entryOf("ferret_core::methods::manifest_add_method", "br_table", 1, "plausible"));
check(newMethodsEntry.status === 1 && /new entry/.test(newMethodsEntry.out), "a new entry in the unlock-method module without APPROVED fails");
const newOutside = baseline(EXISTING + "\n" + entryOf("ferret_core::cbor::decode::item", "br_table", 9, "plausible"));
check(newOutside.status === 0, "a new entry outside the key-handling modules passes");

rmSync(dir, { recursive: true, force: true });
process.exitCode = failed ? 1 : 0;
