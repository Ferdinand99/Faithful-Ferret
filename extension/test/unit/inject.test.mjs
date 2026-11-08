// The injection of the fill script (src/background/inject.mjs): which target,
// which calls in which order, and that nothing is injected on a bad request.
// The manifest side: the permissions are there and no content script is declared.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { build } from "../../scripts/build.mjs";
import { injectFill } from "../../src/background/inject.mjs";
import { makeRoot } from "./buildHelpers.mjs";

/** A `scripting` that records its calls and answers with `results` for the function call. */
function fakeScripting(results = [{ frameId: 3, result: true }], loaded = [{ frameId: 3, result: null }]) {
  /** @type {any[]} */
  const calls = [];
  return {
    calls,
    executeScript: async (/** @type {any} */ injection) => {
      calls.push(injection);
      return "func" in injection ? results : loaded;
    },
  };
}

test("injects_the_entry_file_and_then_begins_the_request_in_one_frame", async () => {
  const scripting = fakeScripting();
  await injectFill({ scripting, tabId: 7, frameId: 3, requestId: "req-1" });
  assert.equal(scripting.calls.length, 2);
  assert.deepEqual(scripting.calls[0], { target: { tabId: 7, frameIds: [3] }, files: ["/content/fill.inject.js"] });
  assert.deepEqual(scripting.calls[1].target, { tabId: 7, frameIds: [3] });
  assert.deepEqual(scripting.calls[1].args, ["req-1"]);
  // The function is serialised by the browser: it names nothing outside itself and asks the engine to begin.
  const text = String(scripting.calls[1].func);
  assert.match(text, /__ferretFill/);
  const begins = [];
  const run = new Function("globalThis", `return (${text})("req-9");`);
  assert.equal(run({ __ferretFill: { begin: (/** @type {string} */ id) => { begins.push(id); return true; } } }), true);
  assert.deepEqual(begins, ["req-9"]);
  assert.equal(run({}), false, "no engine, no begin");
  assert.equal(run({ __ferretFill: { begin: () => false } }), false);
});

test("a_document_id_pins_both_calls_to_that_document", async () => {
  const scripting = fakeScripting();
  await injectFill({ scripting, tabId: 7, frameId: 3, documentId: "doc-abc", requestId: "req-1" });
  for (const call of scripting.calls) assert.deepEqual(call.target, { tabId: 7, documentIds: ["doc-abc"] });
});

test("a_bad_request_injects_nothing", async () => {
  const bad = [
    { tabId: -1, frameId: 0, requestId: "req-1" },
    { tabId: 1.5, frameId: 0, requestId: "req-1" },
    { tabId: 1, frameId: "0", requestId: "req-1" },
    { tabId: 1, frameId: 0, requestId: "" },
    { tabId: 1, frameId: 0, requestId: "has space" },
    { tabId: 1, frameId: 0, requestId: "x".repeat(65) },
    { tabId: 1, frameId: 0, requestId: 5 },
  ];
  for (const request of bad) {
    const scripting = fakeScripting();
    await assert.rejects(() => injectFill({ scripting, .../** @type {any} */ (request) }), TypeError, JSON.stringify(request));
    assert.deepEqual(scripting.calls, []);
  }
});

test("an_engine_that_did_not_begin_is_an_error", async () => {
  for (const results of [[{ frameId: 0, result: false }], [], [{ frameId: 0, result: true }, { frameId: 1, result: true }], [{ frameId: 0 }]]) {
    await assert.rejects(() => injectFill({ scripting: fakeScripting(results), tabId: 1, frameId: 0, requestId: "req-1" }), /did not begin/);
  }
  // A script that failed to load is reported in the result of the call, and is an error.
  await assert.rejects(
    () => injectFill({ scripting: fakeScripting(undefined, [{ frameId: 0, error: "Unable to load script" }]), tabId: 1, frameId: 0, requestId: "req-1" }),
    /did not load/,
  );
  // A failed injection call is not hidden.
  const failing = { executeScript: async () => { throw new Error("Missing host permission for the tab"); } };
  await assert.rejects(() => injectFill({ scripting: failing, tabId: 1, frameId: 0, requestId: "req-1" }), /Missing host permission/);
});

test("the_build_has_the_fill_permissions_the_scripts_and_no_content_script", async () => {
  for (const manifest of ["mv3", "mv2"]) {
    for (const variant of ["release", "test"]) {
      const env = makeRoot();
      try {
        const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest, variant });
        const json = JSON.parse(readFileSync(join(result.dir, "manifest.json"), "utf8"));
        assert.ok(json.permissions.includes("scripting"), `${manifest} ${variant}`);
        assert.ok(json.permissions.includes("activeTab"), `${manifest} ${variant}`);
        assert.equal("content_scripts" in json, false);
        assert.equal("web_accessible_resources" in json, false, "the page cannot load the engine, only the extension injects it");
        for (const path of ["content/fill.inject.js", "content/entry.mjs", "content/fill.mjs", "background/inject.mjs", "shared/protocol.mjs"]) {
          assert.ok(result.files.has(path), `${manifest} ${variant}: ${path}`);
        }
        // The only host permission is the optional one that was there before.
        assert.deepEqual(json.host_permissions ?? [], []);
      } finally {
        env.cleanup();
      }
    }
  }
});
