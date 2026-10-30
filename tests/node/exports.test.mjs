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
  "UnlockJob.reauth_grant":
    "the one-time token for a plaintext export: a bearer permission that a fresh sign-in makes, not a key; the vault keeps a copy and the export uses it up",
  ferret_aaguid: "the AAGUID of Ferret, public (it is in every passkey response)",
  prf_salt_new: "the PRF salt of a new passkey registration: 32 random bytes, public (stored with the wrap)",
  sync_memory_new: "an empty rollback memory: item ids and revision numbers, public",
  "Vault.verify_checkpoint": "the updated rollback memory: item ids and revision numbers, public",
  "Vault.accept_older_state": "the new rollback memory: item ids and revision numbers, public",
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
    "export_finish", "import_open", "argon2_export_key", "check_master_password", "reveal_plain_export",
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

test("u32_args_table_matches_the_rust_signatures", async () => {
  // wasm-bindgen types both u32 and f64 as `number` in the .d.ts, so the
  // table of the u32 parameters is compared with the Rust signatures: every
  // exported `pub fn` with a `u32` or `Option<u32>` parameter has its place
  // in `U32_ARGS`, and the table has nothing else.
  const { U32_ARGS } = await import("../../bindings/wasm/js/protocol.mjs");
  const { readdirSync } = await import("node:fs");
  const dir = join(root, "bindings", "wasm", "src");
  const found = {};
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".rs") && f !== "vector_ops.rs")) {
    const text = readFileSync(join(dir, file), "utf8");
    for (const m of text.matchAll(/^\s*pub fn (\w+)\(([^)]*)\)/gm)) {
      // The parameters, without `self`; commas inside <> do not split.
      const params = [];
      let depth = 0;
      let current = "";
      for (const ch of m[2]) {
        if (ch === "<") depth++;
        if (ch === ">") depth--;
        if (ch === "," && depth === 0) {
          params.push(current.trim());
          current = "";
        } else current += ch;
      }
      if (current.trim()) params.push(current.trim());
      const args = params.filter((p) => !/^&?(mut )?self\b/.test(p));
      args.forEach((p, index) => {
        const type = p.split(":").slice(1).join(":").trim();
        if (type === "u32" || type === "Option<u32>") {
          (found[m[1]] ??= []).push([index, type !== "u32"]);
        }
      });
    }
  }
  assert.deepEqual(found, U32_ARGS);
});

test("every_secret_argument_is_a_bytes_argument_and_every_key_is_listed", async () => {
  const { SECRET_ARGS, TEXT_ARGS, BYTES_ARGS } = await import("../../bindings/wasm/js/protocol.mjs");
  // Each secret position must be type-checked as a Uint8Array at the worker,
  // and each text position is a password: not all-zero checked, but typed.
  for (const [method, positions] of Object.entries(SECRET_ARGS)) {
    const checked = (BYTES_ARGS[method] ?? []).map(([i]) => i).sort();
    assert.deepEqual(checked, [...positions].sort(), method);
  }
  for (const [method, positions] of Object.entries(TEXT_ARGS)) {
    for (const i of positions) {
      const entry = (BYTES_ARGS[method] ?? []).find(([index]) => index === i);
      assert.ok(entry, `${method}[${i}] is text and is typed`);
      assert.equal(entry[2], false, `${method}[${i}]: a password is not rejected for being zero bytes`);
    }
  }
  // The keys that are refused when all zero: PRF output, K_exp, the device PIN
  // key, the export token.
  const zeroRefused = Object.entries(BYTES_ARGS)
    .flatMap(([method, list]) => list.filter(([, , zero]) => zero).map(([i]) => `${method}:${i}`))
    .sort();
  assert.deepEqual(zeroRefused, [
    "export_finish:0", "import_open:1", "pin_unlock:3", "reveal_plain_export:3", "unlock_prf:2",
    "wrap_pin:2", "wrap_prf:2",
  ]);
});

test("f64_args_table_matches_the_rust_signatures", async () => {
  // wasm-bindgen types f64 as `number`, like u32: the table of the f64
  // parameters is compared with the Rust signatures, so a new one cannot go
  // unchecked in JavaScript.
  const { F64_ARGS } = await import("../../bindings/wasm/js/protocol.mjs");
  const { readdirSync } = await import("node:fs");
  const dir = join(root, "bindings", "wasm", "src");
  const found = {};
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".rs") && f !== "vector_ops.rs")) {
    const text = readFileSync(join(dir, file), "utf8");
    for (const m of text.matchAll(/^\s*pub fn (\w+)\(([^)]*)\)/gm)) {
      const params = [];
      let depth = 0;
      let current = "";
      for (const ch of m[2]) {
        if (ch === "<") depth++;
        if (ch === ">") depth--;
        if (ch === "," && depth === 0) {
          params.push(current.trim());
          current = "";
        } else current += ch;
      }
      if (current.trim()) params.push(current.trim());
      params
        .filter((p) => !/^&?(mut )?self\b/.test(p))
        .forEach((p, index) => {
          if (p.split(":").slice(1).join(":").trim() === "f64") (found[m[1]] ??= []).push(index);
        });
    }
  }
  const table = Object.fromEntries(
    Object.entries(F64_ARGS).map(([method, list]) => [method, list.map(([i]) => i)]),
  );
  assert.deepEqual(found, table);
  for (const list of Object.values(F64_ARGS)) {
    for (const [, kind] of list) assert.ok(["u64", "seconds", "millis"].includes(kind));
  }
});

test("the_plain_export_and_the_passkey_wrap_take_their_new_arguments", () => {
  // The .d.ts of the release names the token and the AAGUID arguments.
  assert.match(dts, /reveal_plain_export\(rows: any, format: string, include_passkeys: boolean, token: Uint8Array\): string/);
  assert.match(dts, /wrap_prf\([^)]*aaguid: Uint8Array, stored_credential_ids: any\)/);
  assert.match(dts, /passkey_create_confirm\(pending: number\)/);
  assert.match(dts, /passkey_create_abort\(pending: number\)/);
  assert.match(dts, /reauth_grant\(vault: Vault, pw_wrap: any\): Uint8Array/);
  assert.match(dts, /export function ferret_aaguid\(\): Uint8Array/);
});
