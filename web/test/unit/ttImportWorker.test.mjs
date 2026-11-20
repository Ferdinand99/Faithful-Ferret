// The place of the import worker: the Trusted Types policy lists exactly three workers, the build writes
// the worker's entry where the policy points, and the real import worker answers `unsupported` to everything
// that is not an import request.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { build } from "../../scripts/build.mjs";
import { DEFAULT_WORKERS, installTrustedTypes } from "../../src/tt.mjs";
import { answer } from "../../src/workers/import.worker.mjs";
import { makeRoot, web } from "./helpers.mjs";

const location = { href: "https://vault.test/app/", origin: "https://vault.test" };

test("trusted_types_policy_allows_exactly_three_workers", () => {
  assert.deepEqual(Object.keys(DEFAULT_WORKERS).sort(), ["import", "job", "vault"]);
  assert.deepEqual(
    { ...DEFAULT_WORKERS },
    { vault: "/js/vault.worker.mjs", job: "/js/job.worker.mjs", import: "/js/import.worker.mjs" },
  );
  assert.ok(Object.isFrozen(DEFAULT_WORKERS));

  let rules;
  const created = [];
  const tt = installTrustedTypes({
    location,
    trustedTypes: {
      createPolicy(name, r) {
        created.push(name);
        rules = r;
        return { createScriptURL: (x) => ({ trusted: r.createScriptURL(x) }) };
      },
    },
  });
  assert.equal(tt.available, true);
  assert.deepEqual(created, ["ferret"]);
  assert.deepEqual(tt.workerUrl("import"), { trusted: "/js/import.worker.mjs" });
  assert.deepEqual(tt.workerUrl("vault"), { trusted: "/js/vault.worker.mjs" });
  assert.deepEqual(tt.workerUrl("job"), { trusted: "/js/job.worker.mjs" });

  // The policy accepts three files and nothing else, not even the module the entry loads.
  const accepted = ["/js/vault.worker.mjs", "/js/job.worker.mjs", "/js/import.worker.mjs"];
  for (const path of accepted) assert.equal(rules.createScriptURL(path), path);
  for (const bad of [
    "/app/workers/import.worker.mjs",
    "/js/other.worker.mjs",
    "/js/import.worker.mjs?x=1",
    "/js/import.worker.mjs#x",
    "https://evil.test/js/import.worker.mjs",
    "//evil.test/js/import.worker.mjs",
    "/js/../js/import.worker.mjs",
    "/js/%69mport.worker.mjs",
    "blob:https://vault.test/abc",
    "data:text/javascript,1",
  ]) {
    assert.throws(() => rules.createScriptURL(bad), TypeError, bad);
  }
  for (const name of ["other", "__proto__", "constructor", "toString", "Import"]) assert.throws(() => tt.workerUrl(name), TypeError, name);

  // Without Trusted Types the same table gives the same plain strings.
  const plain = installTrustedTypes({ location });
  assert.equal(plain.available, false);
  for (const name of Object.keys(DEFAULT_WORKERS)) assert.equal(plain.workerUrl(name), DEFAULT_WORKERS[name]);
});

test("import_worker_entry_is_built_where_the_policy_points_and_loads_the_workers_module", async () => {
  const { root, out, tarPath } = makeRoot();
  const { manifest } = await build({ root, out, wasmTar: tarPath });
  // Every worker of the table is a file of dist (the two of the WASM package and the page's own).
  for (const path of Object.values(DEFAULT_WORKERS)) assert.ok(manifest[path.slice(1)], `${path} is in dist`);
  assert.ok(manifest["app/workers/import.worker.mjs"], "the worker's own module is in dist/app/workers");
  const entry = readFileSync(join(out, "js", "import.worker.mjs"), "utf8");
  assert.match(entry, /\nimport "\.\.\/app\/workers\/import\.worker\.mjs";\n$/);
  assert.equal(manifest["js/import.worker.mjs"].type, "text/javascript; charset=utf-8");
  // The entry resolves to the module from /js/.
  assert.equal(new URL("../app/workers/import.worker.mjs", "https://vault.test/js/import.worker.mjs").pathname, "/app/workers/import.worker.mjs");
  // The module is the source file, byte for byte.
  assert.equal(readFileSync(join(out, "app", "workers", "import.worker.mjs"), "utf8"), readFileSync(join(web, "src", "workers", "import.worker.mjs"), "utf8"));

  // A worker entry that would replace a file of the WASM package stops the build.
  const clash = makeRoot({ "src/workers/vault.worker.mjs": "export const x = 1;\n" });
  await assert.rejects(build({ root: clash.root, out: clash.out, wasmTar: clash.tarPath }), /js\/vault\.worker\.mjs: written twice/);

  // A file in src/workers that is not <name>.worker.mjs has no entry and stops the build.
  const odd = makeRoot({ "src/workers/helper.mjs": "export const x = 1;\n" });
  await assert.rejects(build({ root: odd.root, out: odd.out, wasmTar: odd.tarPath }), /expected <name>\.worker\.mjs/);
});

test("import_worker_answers_unsupported_to_what_is_not_an_import_request", () => {
  assert.deepEqual(answer({ id: 7, type: "import", file: "x" }), { id: 7, ok: false, error: "unsupported" });
  assert.deepEqual(answer({ id: "abc" }), { id: "abc", ok: false, error: "unsupported" });
  for (const message of [undefined, null, 5, "text", [], {}, { id: {} }, { id: null }, { id: Symbol.iterator }, new Uint8Array(4)]) {
    assert.deepEqual(answer(message), { id: null, ok: false, error: "unsupported" });
  }

  // Inside a worker the module answers every message it gets. The module is started in a process that
  // looks like a worker scope, so the test does not need a browser.
  const script = `
    class WorkerGlobalScope {}
    Object.setPrototypeOf(globalThis, WorkerGlobalScope.prototype);
    globalThis.WorkerGlobalScope = WorkerGlobalScope;
    const sent = [];
    globalThis.postMessage = (m) => sent.push(m);
    await import(process.argv[1]);
    if (typeof globalThis.onmessage !== "function") throw new Error("no onmessage");
    await globalThis.onmessage({ data: { id: 3, file: "x" } });
    await globalThis.onmessage({ data: null });
    console.log(JSON.stringify(sent));
  `;
  const url = new URL("../../src/workers/import.worker.mjs", import.meta.url).href;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", script, url], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), [
    { id: 3, ok: false, error: "unsupported" },
    { id: null, ok: false, error: "unsupported" },
  ]);

  // Outside a worker (this process) importing it started nothing.
  assert.equal(globalThis.onmessage, undefined);
});
