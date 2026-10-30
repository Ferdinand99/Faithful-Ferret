// Every test vector through the WASM build (the one with `test-support`).
// The same runner is `node tests/node/run-vectors.mjs`.
// Run: node --test tests/node/
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  EXTERNAL_FILES,
  INTERNAL_FILES,
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
