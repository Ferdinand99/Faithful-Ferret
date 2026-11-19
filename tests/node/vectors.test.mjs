// Every test vector through the WASM build (the one with `test-support`).
// The same runner is `node tests/node/run-vectors.mjs`.
// Run: node --test tests/node/
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  EXTERNAL_FILES,
  INTERNAL_FILES,
  NATIVE_ONLY_FILES,
  parseOps,
  runExternal,
  runVectorFile,
} from "../../bindings/wasm/js/vector-runner.mjs";
import { root, wasm } from "./helpers.mjs";

const vectors = join(root, "vectors");
const ops = parseOps(readFileSync(join(vectors, "OPS.md"), "utf8"));

test("OPS.md lists every op of every vector file", () => {
  assert.ok(ops.size >= 60, `${ops.size} ops`);
  for (const name of INTERNAL_FILES) {
    const file = JSON.parse(readFileSync(join(vectors, "internal", name), "utf8"));
    for (const c of file.cases) assert.ok(ops.has(c.op), `${c.id}: ${c.op}`);
  }
});

test("every vector file on disk has a runner entry; the server files are native-only", () => {
  const onDisk = readdirSync(join(vectors, "internal")).filter((n) => n.endsWith(".json")).sort();
  assert.deepEqual([...INTERNAL_FILES, ...NATIVE_ONLY_FILES].sort(), onDisk);
  for (const name of NATIVE_ONLY_FILES) {
    const file = JSON.parse(readFileSync(join(vectors, "internal", name), "utf8"));
    for (const c of file.cases) {
      assert.ok(c.tags.includes("native-only"), `${c.id} is run by a WASM runner`);
    }
  }
});

test("wasm_runs_all_internal_vectors_in_node", () => {
  let passed = 0;
  let skipped = 0;
  for (const name of INTERNAL_FILES) {
    const file = JSON.parse(readFileSync(join(vectors, "internal", name), "utf8"));
    const r = runVectorFile(wasm, file, ops);
    assert.deepEqual(r.failures, [], name);
    assert.equal(r.passed + r.skipped, file.cases.length, name);
    passed += r.passed;
    skipped += r.skipped;
  }
  console.log(`# internal vectors: ${passed} passed, ${skipped} native-only skipped`);
  assert.ok(passed > 800);
});

test("recovery_renew_vectors_match_in_rust_and_js", () => {
  // The same file runs through the core in crates/ferret-core/tests/account.rs.
  const file = JSON.parse(readFileSync(join(vectors, "internal", "recovery_renew.json"), "utf8"));
  assert.equal(file.group, "recovery_renew");
  const r = runVectorFile(wasm, file, ops);
  assert.deepEqual(r.failures, []);
  assert.equal(r.passed, file.cases.length);
  assert.equal(r.passed, 14);
  assert.ok(file.cases.every((c) => c.op === "account.renew_recovery"));
});

test("wasm_external_vectors_in_node", async () => {
  const read = async (name) => JSON.parse(readFileSync(join(vectors, "external", name), "utf8"));
  let passed = 0;
  for (const name of EXTERNAL_FILES) {
    const r = await runExternal(wasm, name, read);
    assert.deepEqual(r.failures, [], name);
    passed += r.passed;
  }
  console.log(`# external vectors: ${passed} passed`);
  assert.ok(passed > 1500);
});

test("a changed expectation fails the runner", () => {
  const file = JSON.parse(readFileSync(join(vectors, "internal", "tlv.json"), "utf8"));
  const bad = structuredClone(file);
  const valid = bad.cases.find((c) => c.status === "valid");
  valid.expect = { tlv: "00" };
  const r = runVectorFile(wasm, { ...bad, cases: [valid] }, ops);
  assert.equal(r.failures.length, 1);
  const unknown = runVectorFile(wasm, { cases: [{ ...valid, op: "not.an.op" }] }, ops);
  assert.equal(unknown.failures.length, 1);
});
