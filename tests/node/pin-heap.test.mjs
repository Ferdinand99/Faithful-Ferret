// The memory of setting a PIN. The vault worker has done the sign-in's
// Argon2id (64 MiB) and holds a large open vault; WebAssembly memory never
// shrinks, so adding the PIN's 256 MiB there would leave it at about 320 MiB
// for good. The product sets the PIN with the Argon2id in a job worker
// instead: this file measures both, each in an instance of its own (the heap
// of one instance is the high-water mark of everything it has done).
// Run: node --test tests/node/pin-heap.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";
import { Worker } from "node:worker_threads";
import { join } from "node:path";
import { LOGIN_DRAFT, NOW, PIN_RULE, enc, fill, newAccount, root, wasm } from "./helpers.mjs";

const MIB = 1024 * 1024;
/** The ceiling this task keeps: the sign-in, a large vault and the PIN in one worker, with room. */
const CEILING = 512 * MIB;

test("pin_set_on_a_large_open_vault_stays_under_the_memory_ceiling", async () => {
  // The vault worker: a sign-in (64 MiB) and 400 open items, then the PIN in
  // the same worker (the single-call variant).
  const { vault } = newAccount("pin-heap");
  const handles = [];
  for (let i = 0; i < 400; i++) {
    const id = new Uint8Array(16);
    new DataView(id.buffer).setUint32(0, i + 1);
    id[15] = 0x41;
    const sealed = vault.encrypt_item(id, 1, { ...LOGIN_DRAFT, notes: "n".repeat(2000) }, undefined, NOW);
    handles.push(vault.open_item(id, 1, sealed.envelope, sealed.tag));
  }
  const afterVault = wasm.test_memory_bytes();
  vault.wrap_pin(enc.encode("123456"), fill(16, 0x75), PIN_RULE);
  const afterPin = wasm.test_memory_bytes();
  console.log(`# one worker: vault ${(afterVault / MIB).toFixed(0)} MiB, after the PIN ${(afterPin / MIB).toFixed(0)} MiB of ${CEILING / MIB}`);
  assert.ok(afterPin < CEILING, `${afterPin} bytes`);
  for (const h of handles) vault.close_item(h);
});

test("the_job_worker_half_keeps_the_vault_worker_small", async () => {
  // A fresh instance that only runs the PIN's Argon2id (the job worker) holds
  // the 256 MiB and nothing else; the vault worker that wraps with the 32 bytes
  // does not grow by it. The instance is a worker thread, so it is separate.
  const here = wasm.test_memory_bytes();
  const code = `
    const { parentPort, workerData } = require("node:worker_threads");
    const wasm = require(workerData.path);
    const out = wasm.argon2_pin_key(new TextEncoder().encode("123456"), workerData.rule);
    parentPort.postMessage({ key: out.key.length, memory: wasm.test_memory_bytes() });
  `;
  const path = join(root, "bindings", "wasm", "pkg-node-test", "ferret_core_wasm.js");
  const job = await new Promise((resolve, reject) => {
    const w = new Worker(code, { eval: true, workerData: { path, rule: PIN_RULE } });
    w.once("message", resolve);
    w.once("error", reject);
  });
  assert.equal(job.key, 32);
  console.log(`# job worker: ${(job.memory / MIB).toFixed(0)} MiB`);
  assert.ok(job.memory < CEILING);
  // The vault worker, wrapping with the key, does not touch that memory.
  const { vault } = newAccount("pin-heap-split");
  const before = wasm.test_memory_bytes();
  vault.wrap_pin_key(fill(32, 7), fill(16, 3), fill(16, 0x75));
  const after = wasm.test_memory_bytes();
  assert.ok(after - before < 8 * MIB, `${after - before} bytes`);
  assert.ok(here <= after);
});
