// The injection of the fill script (src/background/inject.mjs): which target,
// which calls in which order, and that nothing is injected on a bad request.
// The manifest side: the permissions are there and no content script is declared.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { build } from "../../scripts/build.mjs";
import { fieldPointsIn, frameChainShown, frameShownIn, injectFill } from "../../src/background/inject.mjs";
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

/**
 * A `scripting` for the frame checks. The frame's document answers `where` with `field`; each document above it
 * answers the question about a frame of it from `verdicts` (`"<documentId>:<frameId>"` → verdict), moving the points by
 * 100 each way when it says "shown", as its fill script would; every call is recorded.
 * @param {Record<string, unknown>} verdicts
 * @param {{ fail?: string[], field?: unknown }} [options] `fail`: documents into which nothing can be injected
 */
function frameScripting(verdicts, { fail = [], field = { points: [[10, 20]] } } = {}) {
  /** @type {any[]} */
  const calls = [];
  return {
    calls,
    executeScript: async (/** @type {any} */ injection) => {
      calls.push(injection);
      const doc = injection.target.documentIds?.[0] ?? `frame-${injection.target.frameIds?.[0]}`;
      if (fail.includes(doc)) throw new Error("Missing host permission for the tab or frames");
      if (!("func" in injection)) return [{ frameId: 0, result: null }];
      // The serialised function, run against the engine of that document.
      const run = new Function("globalThis", "args", `return (${String(injection.func)})(...args);`);
      const engine = {
        where: () => field,
        frameShown: (/** @type {number} */ id, /** @type {Array<[number, number]>} */ points) => {
          const verdict = verdicts[`${doc}:${id}`] ?? "gone";
          return verdict === "shown" ? { verdict, points: points.map(([x, y]) => [x + 100, y + 100]) } : { verdict };
        },
      };
      return [{ frameId: 0, result: run({ __ferretFill: engine }, injection.args) }];
    },
  };
}

const NESTED = { frameId: 9, documentId: "doc-9", ancestors: [{ frameId: 5, documentId: "doc-5" }, { frameId: 0, documentId: "doc-0" }] };
const ASK = { requestId: "req-1", kind: "password" };

test("the_frame_check_moves_the_fields_points_up_through_every_document_above_the_frame", async () => {
  // A frame inside a frame inside the top: the frame says where its field is; the parent checks those points and
  // moves them into its own coordinates; the top checks the moved points.
  const shown = frameScripting({ "doc-5:9": "shown", "doc-0:5": "shown" });
  assert.equal(await frameChainShown({ scripting: shown, tabId: 7, frame: NESTED, ...ASK }), null);
  assert.deepEqual(shown.calls.map((c) => [c.target, c.files ?? c.args]), [
    [{ tabId: 7, documentIds: ["doc-9"] }, ["req-1", "password"]],
    [{ tabId: 7, documentIds: ["doc-5"] }, ["/content/fill.inject.js"]],
    [{ tabId: 7, documentIds: ["doc-5"] }, [9, [[10, 20]]]],
    [{ tabId: 7, documentIds: ["doc-0"] }, ["/content/fill.inject.js"]],
    [{ tabId: 7, documentIds: ["doc-0"] }, [5, [[110, 120]]]],
  ]);
  // The functions are serialised by the browser: they name nothing outside themselves.
  for (const call of [shown.calls[0], shown.calls[2]]) {
    const text = String(call.func);
    assert.match(text, /__ferretFill/);
    assert.equal(new Function("globalThis", `return (${text})(9, []);`)({}), null, "no engine, no answer");
  }

  // The top has nothing above it: nothing is asked.
  const top = frameScripting({});
  assert.equal(await frameChainShown({ scripting: top, tabId: 7, frame: { frameId: 0, ancestors: [] }, ...ASK }), null);
  assert.deepEqual(top.calls, []);

  // Without document ids the frames are the targets.
  const byFrame = frameScripting({ "frame-0:3": "shown" });
  assert.equal(await frameChainShown({ scripting: byFrame, tabId: 7, frame: { frameId: 3, ancestors: [{ frameId: 0 }] }, ...ASK }), null);
  assert.deepEqual(byFrame.calls.map((c) => c.target), [{ tabId: 7, frameIds: [3] }, { tabId: 7, frameIds: [0] }, { tabId: 7, frameIds: [0] }]);
});

test("a_field_hidden_or_covered_in_any_document_above_its_frame_is_refused_with_frame_hidden", async () => {
  for (const verdict of ["hidden", "covered", "gone", "unchecked", "", "shown ", 1, null, true]) {
    // In the parent.
    const parent = frameScripting({ "doc-5:9": verdict, "doc-0:5": "shown" });
    assert.equal(await frameChainShown({ scripting: parent, tabId: 7, frame: NESTED, ...ASK }), "frame_hidden", `parent ${String(verdict)}`);
    // In the top, above a parent that shows it: the walk does not stop at the parent.
    const top = frameScripting({ "doc-5:9": "shown", "doc-0:5": verdict });
    assert.equal(await frameChainShown({ scripting: top, tabId: 7, frame: NESTED, ...ASK }), "frame_hidden", `top ${String(verdict)}`);
    assert.equal(top.calls.length, 5);
  }
  // The frame's own problem with its field is the answer, and nothing above it is asked.
  for (const problem of ["hidden", "covered", "gone", "wrong_kind"]) {
    const own = frameScripting({ "doc-5:9": "shown", "doc-0:5": "shown" }, { field: { problem } });
    assert.equal(await frameChainShown({ scripting: own, tabId: 7, frame: NESTED, ...ASK }), problem);
    assert.equal(own.calls.length, 1);
  }
  // A frame that gives no points, or points of another shape, is gone.
  for (const field of [null, {}, { points: [] }, { points: [[1, 2, 3]] }, { points: [[Number.NaN, 1]] }, { points: Array.from({ length: 9 }, () => [1, 1]) }, { problem: "nonsense" }]) {
    const odd = frameScripting({ "doc-5:9": "shown", "doc-0:5": "shown" }, { field });
    assert.equal(await frameChainShown({ scripting: odd, tabId: 7, frame: NESTED, ...ASK }), "gone", JSON.stringify(field));
  }
  // A parent that says "shown" but gives back other points (or none) is no answer.
  const lying = {
    executeScript: async (/** @type {any} */ i) => {
      if (!("func" in i)) return [{ frameId: 0 }];
      return String(i.func).includes("where") ? [{ frameId: 0, result: { points: [[1, 1], [2, 2]] } }] : [{ frameId: 0, result: { verdict: "shown", points: [[1, 1]] } }];
    },
  };
  assert.equal(await frameChainShown({ scripting: lying, tabId: 7, frame: { frameId: 3, ancestors: [{ frameId: 0 }] }, ...ASK }), "frame_hidden");
  // A document that cannot be asked (no host permission, gone, the script did not load) refuses.
  const blocked = frameScripting({ "doc-5:9": "shown", "doc-0:5": "shown" }, { fail: ["doc-0"] });
  assert.equal(await frameChainShown({ scripting: blocked, tabId: 7, frame: NESTED, ...ASK }), "frame_hidden");
  const notLoaded = { executeScript: async (/** @type {any} */ i) => ("files" in i ? [{ frameId: 0, error: "Unable to load script" }] : [{ frameId: 0, result: String(i.func).includes("where") ? { points: [[1, 1]] } : { verdict: "shown", points: [[1, 1]] } }]) };
  assert.equal(await frameChainShown({ scripting: notLoaded, tabId: 7, frame: { frameId: 3, ancestors: [{ frameId: 0 }] }, ...ASK }), "frame_hidden");
  const two = { executeScript: async () => [{ frameId: 0, result: { verdict: "shown", points: [[1, 1]] } }, { frameId: 1, result: null }] };
  assert.equal(await frameChainShown({ scripting: /** @type {any} */ (two), tabId: 7, frame: { frameId: 3, ancestors: [{ frameId: 0 }] }, ...ASK }), "gone");
  // A chain that does not reach the top, or is missing, refuses before asking anything.
  for (const frame of [{ frameId: 9, ancestors: [{ frameId: 5, documentId: "doc-5" }] }, { frameId: 9, ancestors: [] }, { frameId: 9 }, { frameId: -1, ancestors: [{ frameId: 0 }] }, null]) {
    const none = frameScripting({ "doc-5:9": "shown" });
    assert.equal(await frameChainShown({ scripting: none, tabId: 7, frame: /** @type {any} */ (frame), ...ASK }), "frame_hidden", JSON.stringify(frame));
    assert.deepEqual(none.calls, []);
  }
  // A bad question is never sent.
  const bad = frameScripting({});
  for (const request of [
    { tabId: -1, parent: { frameId: 0 }, childFrameId: 3, points: [[1, 1]] },
    { tabId: 7, parent: { frameId: 3 }, childFrameId: 3, points: [[1, 1]] },
    { tabId: 7, parent: null, childFrameId: 3, points: [[1, 1]] },
    { tabId: 7, parent: { frameId: 0 }, childFrameId: "3", points: [[1, 1]] },
    { tabId: 7, parent: { frameId: 0 }, childFrameId: 3, points: [] },
  ]) {
    assert.deepEqual(await frameShownIn({ scripting: bad, .../** @type {any} */ (request) }), { verdict: "unchecked" });
  }
  for (const request of [{ tabId: 7, frame: { frameId: 3 }, requestId: "bad id", kind: "password" }, { tabId: 7, frame: { frameId: 3 }, requestId: "r", kind: 5 }]) {
    assert.deepEqual(await fieldPointsIn({ scripting: bad, .../** @type {any} */ (request) }), { problem: "gone" });
  }
  assert.deepEqual(bad.calls, []);
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
