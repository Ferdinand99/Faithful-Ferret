// Checks on the release packages (pkg-web and pkg-node, built without
// `test-support`): what they export, what returns bytes, how big they are.
// Run: node --test tests/node/
import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { root } from "./paths.mjs";

const pkg = (dir, file) => join(root, "bindings", "wasm", dir, file);
const dts = readFileSync(pkg("pkg-node", "ferret_core_wasm.d.ts"), "utf8");
const wasmBytes = readFileSync(pkg("pkg-web", "ferret_core_wasm_bg.wasm"));

/** `{ methods: ["Vault.open_item", ...], returns: Map(name -> type) }` from the .d.ts. */
function readDts(text) {
  const entries = new Map();
  let current = null;
  for (const line of text.split("\n")) {
    const klass = /^export class (\w+)/.exec(line);
    if (klass) {
      current = klass[1];
      continue;
    }
    if (line.startsWith("}")) current = null;
    const method = /^\s+(\w+)\((.*)\): (.+);$/.exec(line);
    const fn = /^export function (\w+)\((.*)\): (.+);$/.exec(line);
    if (current && method && method[1] !== "free") entries.set(`${current}.${method[1]}`, method[3]);
    else if (!current && fn) entries.set(fn[1], fn[3]);
  }
  return entries;
}

const exportsOf = readDts(dts);

test("the .d.ts is read", () => {
  assert.ok(exportsOf.size > 50, `${exportsOf.size} exports`);
  assert.ok(exportsOf.has("Vault.open_item"));
  assert.ok(exportsOf.has("UnlockJob.login_start"));
  assert.ok(exportsOf.has("argon2_export_key"));
});

test("wasm_exports_have_no_test_support", () => {
  for (const file of ["pkg-web", "pkg-node"]) {
    const module = new WebAssembly.Module(readFileSync(pkg(file, "ferret_core_wasm_bg.wasm")));
    const names = WebAssembly.Module.exports(module).map((e) => e.name);
    assert.ok(names.length > 60);
    const bad = names.filter((n) => /(^|_)test_|replay/.test(n));
    assert.deepEqual(bad, [], `${file} exports test-support functions`);
  }
  assert.ok(!/test_|replay|TestServer/.test(dts), "the .d.ts of the release names no test support");
});

test("reveal_allowlist_matches_exports", () => {
  const allowlist = readFileSync(join(root, "bindings", "wasm", "reveal-allowlist.txt"), "utf8")
    .split("\n")
    .map((l) => l.replace(/#.*/, "").trim())
    .filter(Boolean)
    .sort();
  const exported = [...exportsOf.keys()]
    .map((k) => k.split(".").pop())
    .filter((n) => n.startsWith("reveal_"))
    .sort();
  assert.deepEqual(exported, allowlist);
  assert.ok(allowlist.length >= 4);
  // And none of them is a function that needs no vault: they are methods.
  for (const name of allowlist) {
    assert.ok([...exportsOf.keys()].some((k) => k === `Vault.${name}`), name);
  }
});

// Every export that returns a `Uint8Array`, and why it is not a key. A new one
// fails this test until it is listed here with a reason.
const BYTES_ALLOWED = {
  "Vault.auth_public_key": "pk_a, a public key",
  "Vault.auth_sign": "a signature (64 bytes), public",
  "Vault.export_finish": "the encrypted export file: ciphertext, to be saved",
  "UnlockJob.login_start": "KE1, a message of the OPAQUE protocol, public",
  "UnlockJob.register_start": "the OPAQUE registration request, public",
  "UnlockJob.recover_sign": "a signature (64 bytes), public",
  argon2_export_key:
    "K_exp: wraps the content key of one export file; it crosses between the job worker and the vault worker once and is wiped; it is not a vault key",
};

test("no_export_returns_key_bytes", () => {
  const returning = [...exportsOf.entries()]
    .filter(([, type]) => /Uint8Array/.test(type))
    .map(([name]) => name)
    .sort();
  assert.deepEqual(returning, Object.keys(BYTES_ALLOWED).sort());
  for (const [name, why] of Object.entries(BYTES_ALLOWED)) assert.ok(why.length > 10, name);
  // The handoff of the old design is gone.
  for (const name of exportsOf.keys()) assert.ok(!/handoff/i.test(name), name);
  assert.ok(!/Handoff|adopt_handoff/.test(dts));
});

test("every_secret_taking_export_copies_into_a_wiped_buffer", () => {
  // The glue wipes the arguments it knows are secret; each secret argument of
  // the exports has to be in its table.
  const source = readFileSync(join(root, "bindings", "wasm", "js", "protocol.mjs"), "utf8");
  for (const method of [
    "login_start", "register_start", "pin_unlock", "unlock_prf", "wrap_pin", "wrap_prf",
    "export_finish", "import_open", "argon2_export_key", "check_master_password",
  ]) {
    assert.ok(new RegExp(`\\b${method}:`).test(source), method);
  }
});

test("wasm_memory_maximum_is_1_gib", () => {
  // The memory section of the module: limits with a maximum.
  let p = 8;
  const leb = () => {
    let r = 0;
    let shift = 0;
    let b;
    do {
      b = wasmBytes[p++];
      r += (b & 0x7f) * 2 ** shift;
      shift += 7;
    } while (b & 0x80);
    return r;
  };
  let limits = null;
  while (p < wasmBytes.length && !limits) {
    const id = wasmBytes[p++];
    const size = leb();
    const end = p + size;
    if (id === 5) {
      leb(); // one memory
      const flags = wasmBytes[p++];
      const min = leb();
      const max = flags & 1 ? leb() : null;
      limits = { min, max };
    }
    p = end;
  }
  assert.ok(limits, "the module defines its memory");
  assert.equal(limits.max * 65536, 1024 * 1024 * 1024);
});

test("wasm_size_budget", () => {
  const raw = statSync(pkg("pkg-web", "ferret_core_wasm_bg.wasm")).size;
  console.log(`# wasm size: ${raw} bytes (${(raw / 1024 / 1024).toFixed(2)} MiB) of 2 MiB`);
  assert.ok(raw <= 2 * 1024 * 1024, `${raw} bytes`);
  assert.equal(raw, statSync(pkg("pkg-node", "ferret_core_wasm_bg.wasm")).size);
});
