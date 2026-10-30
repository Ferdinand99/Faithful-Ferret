// Runs every test vector through the WASM build in Node.
//
//   node tests/node/run-vectors.mjs [--external-only | --internal-only]
//
// It needs `bindings/wasm/pkg-node-test`, the nodejs package built with the
// `test-support` feature (scripts/lanbox-wasm.sh --test). Exit code 0 only if
// every case of every file passed.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EXTERNAL_FILES,
  INTERNAL_FILES,
  parseOps,
  runExternal,
  runVectorFile,
} from "../../bindings/wasm/js/vector-runner.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const vectors = join(root, "vectors");
const require = createRequire(import.meta.url);
const wasm = require(join(root, "bindings", "wasm", "pkg-node-test", "ferret_core_wasm.js"));

const only = process.argv[2];
const ops = parseOps(readFileSync(join(vectors, "OPS.md"), "utf8"));
if (ops.size < 60) {
  console.error(`OPS.md: only ${ops.size} ops parsed`);
  process.exit(1);
}

let failed = 0;
let total = 0;

if (only !== "--external-only") {
  for (const name of INTERNAL_FILES) {
    const file = JSON.parse(readFileSync(join(vectors, "internal", name), "utf8"));
    const started = Date.now();
    const r = runVectorFile(wasm, file, ops);
    total += r.passed;
    failed += r.failures.length;
    console.log(
      `internal/${name}: ${r.passed} passed, ${r.skipped} skipped, ${r.failures.length} failed (${Date.now() - started} ms)`,
    );
    for (const f of r.failures) console.log(`  FAIL ${f.id}: ${f.reason}`);
  }
}

if (only !== "--internal-only") {
  const read = async (name) => JSON.parse(readFileSync(join(vectors, "external", name), "utf8"));
  for (const name of EXTERNAL_FILES) {
    const r = await runExternal(wasm, name, read);
    total += r.passed;
    failed += r.failures.length;
    console.log(`external/${name}: ${r.passed} passed, ${r.failures.length} failed`);
    for (const n of r.notes) console.log(`  note: ${n}`);
    for (const f of r.failures) console.log(`  FAIL ${f.id}: ${f.reason}`);
  }
}

console.log(`${total} cases passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
