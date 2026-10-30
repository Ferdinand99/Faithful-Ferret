// Runs the test vectors through the WASM build (the one with `test-support`)
// in a worker, so that a slow case never blocks the page.
//
// Request:  { mode, files? }
//   mode "fast"   every case that is not tagged `slow` or `native-only`, and
//                 every third-party file
//   mode "slow"   the cases tagged `slow` (the production Argon2id profile and
//                 the OPAQUE cases), once
//   mode "files"  all runnable cases of the internal files named in `files`
// Reply:    { done: true, files: [...] } or { error }
import init, * as wasm from "/test/pkg-web/ferret_core_wasm.js";
import {
  EXTERNAL_FILES,
  INTERNAL_FILES,
  parseOps,
  runExternal,
  runVectorFile,
} from "/test/js/vector-runner.mjs";

const getJson = async (path) => {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
};

async function run({ mode, files }) {
  await init();
  const ops = parseOps(await (await fetch("/vectors/OPS.md")).text());
  const out = [];
  const names = mode === "files" ? files : INTERNAL_FILES;
  for (const name of names) {
    const file = await getJson(`/vectors/internal/${name}`);
    const nativeOnly = file.cases.filter((c) => c.tags.includes("native-only")).length;
    const runnable = file.cases.filter((c) => !c.tags.includes("native-only"));
    const wanted = runnable.filter((c) => {
      const slow = c.tags.includes("slow");
      return mode === "slow" ? slow : mode === "fast" ? !slow : true;
    });
    const started = performance.now();
    const r = runVectorFile(wasm, { ...file, cases: wanted }, ops);
    out.push({
      kind: "internal",
      name,
      total: file.cases.length,
      nativeOnly,
      expected: wanted.length,
      passed: r.passed,
      skipped: r.skipped,
      failures: r.failures,
      ms: Math.round(performance.now() - started),
    });
  }
  if (mode === "fast") {
    for (const name of EXTERNAL_FILES) {
      const started = performance.now();
      const r = await runExternal(wasm, name, (n) => getJson(`/vectors/external/${n}`));
      out.push({
        kind: "external",
        name,
        passed: r.passed,
        failures: r.failures,
        notes: r.notes,
        ms: Math.round(performance.now() - started),
      });
    }
  }
  return out;
}

self.onmessage = async (event) => {
  try {
    self.postMessage({ done: true, files: await run(event.data) });
  } catch (e) {
    self.postMessage({ error: String(e?.stack ?? e) });
  }
};
