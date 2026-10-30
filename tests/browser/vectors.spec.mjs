// Every test vector through the WASM binding, in the browser.
//
// The cases run in a module worker (tests/browser/vectors.worker.mjs) on the
// web package built with `test-support`, with the same table-driven runner as
// the Node tests (bindings/wasm/js/vector-runner.mjs). The cases tagged
// `native-only` are not run by any WASM runner; every other case is.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import { EXTERNAL_FILES, INTERNAL_FILES, NATIVE_ONLY_FILES } from "../../bindings/wasm/js/vector-runner.mjs";
import { keep, openHarness, repo } from "./support.mjs";

const internalDir = join(repo, "vectors", "internal");
const read = (name) => JSON.parse(readFileSync(join(internalDir, name), "utf8"));

/** What the vector files hold, counted here in Node. */
function expected() {
  const files = {};
  for (const name of INTERNAL_FILES) {
    const cases = read(name).cases;
    const nativeOnly = cases.filter((c) => c.tags.includes("native-only")).length;
    const slow = cases.filter((c) => c.tags.includes("slow") && !c.tags.includes("native-only")).length;
    files[name] = { total: cases.length, nativeOnly, slow, fast: cases.length - nativeOnly - slow };
  }
  return files;
}

const readExternal = (name) => JSON.parse(readFileSync(join(repo, "vectors", "external", name), "utf8"));

/**
 * How many cases of a third-party file the runner counts as passed, from the
 * file itself. The runner counts every case of the RFC files, the cases of
 * Wycheproof that are `valid` or `invalid` (an `acceptable` one is counted
 * only for Ed25519 and ECDSA, where the runner pins how it must go), and
 * nothing for the OPRF file (no adapter).
 */
function externalCount(name) {
  const file = readExternal(name);
  if (name === "rfc9497-oprf-ristretto255.json") return 0;
  if (name === "rfc9807-opaque-ristretto255.json") return file.vectors.length;
  if (!name.startsWith("wycheproof/")) return file.cases.length;
  const tests = file.testGroups.flatMap((g) => g.tests);
  const withAcceptable = name.includes("ed25519") || name.includes("ecdsa");
  return tests.filter((t) => withAcceptable || t.result !== "acceptable").length;
}

const failures = (files) => files.flatMap((f) => f.failures.map((x) => ({ file: f.name, ...x })));

test("every vector file has a runner entry", () => {
  const onDisk = readdirSync(internalDir).filter((n) => n.endsWith(".json")).sort();
  expect([...INTERNAL_FILES, ...NATIVE_ONLY_FILES].sort()).toEqual(onDisk);
});

test("vectors pass", async ({ page, browserName }) => {
  test.setTimeout(180_000);
  await openHarness(page);
  const files = await page.evaluate(() => window.ferret.runVectors({ mode: "fast" }));
  expect(failures(files)).toEqual([]);

  const want = expected();
  const internal = files.filter((f) => f.kind === "internal");
  expect(internal.map((f) => f.name)).toEqual(INTERNAL_FILES);
  for (const f of internal) {
    expect(f.expected, f.name).toBe(want[f.name].fast);
    expect(f.passed, f.name).toBe(want[f.name].fast);
  }
  const external = files.filter((f) => f.kind === "external");
  expect(external.map((f) => f.name)).toEqual(EXTERNAL_FILES);
  for (const f of external) {
    expect(f.passed, f.name).toBe(externalCount(f.name));
    // Only the OPRF file has no adapter (see vector-runner.mjs).
    expect((f.notes ?? []).length, f.name).toBe(f.name === "rfc9497-oprf-ristretto255.json" ? 1 : 0);
  }

  const totals = {
    internalPassed: internal.reduce((n, f) => n + f.passed, 0),
    internalSlowDeferred: Object.values(want).reduce((n, f) => n + f.slow, 0),
    internalNativeOnly: Object.values(want).reduce((n, f) => n + f.nativeOnly, 0),
    externalPassed: external.reduce((n, f) => n + f.passed, 0),
    externalNotRun: external.filter((f) => f.notes?.length).map((f) => f.name),
  };
  console.log(`[${browserName}] vectors: ${JSON.stringify(totals)}`);
  keep(browserName, "vectors", { totals, files: files.map(({ failures: _f, ...rest }) => rest) });
  expect(totals.internalPassed).toBeGreaterThan(900);
  expect(totals.externalPassed).toBeGreaterThan(1500);
});

test("slow vectors run once per browser", async ({ page, browserName }) => {
  test.setTimeout(180_000);
  await openHarness(page);
  const started = Date.now();
  const files = await page.evaluate(() => window.ferret.runVectors({ mode: "slow" }));
  const ms = Date.now() - started;
  expect(failures(files)).toEqual([]);
  const want = expected();
  let passed = 0;
  for (const f of files) {
    expect(f.expected, f.name).toBe(want[f.name].slow);
    expect(f.passed, f.name).toBe(want[f.name].slow);
    passed += f.passed;
  }
  // The fast run and this one together are every case that is not native-only.
  expect(passed).toBeGreaterThan(20);
  console.log(`[${browserName}] slow vectors: ${passed} passed in ${ms} ms`);
  keep(browserName, "slow-vectors", { passed, ms, files: files.map(({ failures: _f, ...rest }) => rest) });
});

test("wasm_argon2_matches_native_in_each_browser", async ({ page, browserName }) => {
  test.setTimeout(180_000);
  await openHarness(page);
  const [file] = await page.evaluate(() => window.ferret.runVectors({ mode: "files", files: ["kdf.json"] }));
  expect(file.failures).toEqual([]);
  const cases = read("kdf.json").cases.filter((c) => c.op === "kdf.argon2id");
  const production = cases.filter((c) => c.input.m_kib === 65536);
  expect(production.length).toBeGreaterThan(0);
  // Every case of kdf.json (the bytes come from the Rust core) gives the same bytes in the browser.
  expect(file.passed).toBe(file.expected);
  expect(file.expected).toBe(file.total - file.nativeOnly);
  console.log(`[${browserName}] kdf.json: ${file.passed} cases, ${cases.length} Argon2id (${production.length} at 64 MiB), ${file.ms} ms`);
  keep(browserName, "argon2", { passed: file.passed, argon2Cases: cases.length, production: production.length, ms: file.ms });
});
