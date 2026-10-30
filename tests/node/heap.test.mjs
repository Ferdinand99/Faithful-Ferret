// The heap of the slow step of an export or an import file (plan U15). The
// maximum of the linear memory is 1 GiB; the file is written with 256 MiB and
// read with up to 512 MiB. In production this runs in the short-lived job
// worker; here it runs in one instance, so the high-water mark printed after
// each step is the size that instance had grown to (memory only grows).
// Run: node --test tests/node/heap.test.mjs   (about half a minute)
import assert from "node:assert/strict";
import { test } from "node:test";
import { NOW, PASSWORD, enc, fill, newAccount, row, wasm } from "./helpers.mjs";

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

test("export_256mib_does_not_oom", () => {
  const { vault } = newAccount("heap-export");
  const id = fill(16, 0x41);
  const rows = [row(id, vault.encrypt_item(id, 1, { item_type: "note", name: "n", notes: "x".repeat(1000) }, undefined, NOW))];
  const before = wasm.test_memory_bytes();
  // The default: 256 MiB, 3 passes, 1 lane.
  const started = vault.export_begin(rows, NOW);
  assert.equal(started.kdf.m_kib, 262144);
  const key = wasm.argon2_export_key(enc.encode("export password for the heap"), started.salt, started.kdf, "write", enc.encode(PASSWORD));
  const file = vault.export_finish(key);
  const after = wasm.test_memory_bytes();
  console.log(`# export, 256 MiB: memory ${(before / MIB).toFixed(0)} -> ${(after / MIB).toFixed(0)} MiB`);
  assert.ok(after < GIB);
  // The file reads back with the same parameters.
  const header = wasm.import_header(file);
  const again = wasm.argon2_export_key(enc.encode("export password for the heap"), header.salt, header.kdf, "open", null);
  assert.equal(vault.import_open(file, again).count, 1);
});

test("import_ceiling_fits_the_heap", () => {
  // A file whose header asks for the ceiling, 512 MiB: only the slow step is
  // run here, which is where the memory goes. The vault worker never sees it.
  const before = wasm.test_memory_bytes();
  const key = wasm.argon2_export_key(
    enc.encode("export password for the heap"),
    fill(16, 9),
    { m_kib: 524288, t: 3, p: 1 },
    "open",
    null,
  );
  assert.equal(key.length, 32);
  const after = wasm.test_memory_bytes();
  console.log(`# import, 512 MiB ceiling: memory ${(before / MIB).toFixed(0)} -> ${(after / MIB).toFixed(0)} MiB of 1024`);
  assert.ok(after <= GIB);
  // Over the ceiling is refused before any memory is reserved.
  assert.throws(
    () => wasm.argon2_export_key(enc.encode("export password for the heap"), fill(16, 9), { m_kib: 524289, t: 3, p: 1 }, "open", null),
    (e) => e.code === "kdf_out_of_range",
  );
  assert.equal(wasm.test_memory_bytes(), after, "the refusal reserved nothing");
});
