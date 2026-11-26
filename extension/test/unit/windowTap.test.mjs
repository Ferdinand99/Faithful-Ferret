// The test build's exact count of Ferret's chooser windows (background/test-only/windowTap.mjs), which the passkey matrix reads.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWindowTap } from "../../src/background/test-only/windowTap.mjs";

test("every_chooser_window_asked_for_is_counted_also_one_closed_at_once", async () => {
  const tap = createWindowTap();
  /** @type {Array<[string, unknown]>} */
  const calls = [];
  let next = 7;
  const windows = tap.tap({
    create: async (o) => {
      calls.push(["create", o]);
      return { id: next++ };
    },
    remove: async (id) => void calls.push(["remove", id]),
  });
  const run = (/** @type {any} */ args) => tap.ops.window_watch.run(null, args, /** @type {any} */ ({}));
  assert.deepEqual(await run({ cmd: "read" }), { ok: true, opened: 0, most: 0 });
  // The browser's own calls go through unchanged.
  assert.deepEqual(await windows.create({ type: "popup", url: "x" }), { id: 7 });
  await windows.remove(7);
  assert.deepEqual(await windows.create({ type: "popup", url: "y" }), { id: 8 });
  assert.deepEqual(calls, [["create", { type: "popup", url: "x" }], ["remove", 7], ["create", { type: "popup", url: "y" }]]);
  // Two were asked for, one after the other: at most one at once.
  assert.deepEqual(await run({ cmd: "read" }), { ok: true, opened: 2, most: 1 });
  // Two open at once (the second asked for before the first was removed).
  await windows.create({ type: "popup", url: "z" });
  assert.deepEqual(await run({ cmd: "read" }), { ok: true, opened: 3, most: 2 });
  // A reset forgets the windows open before it.
  assert.deepEqual(await run({ cmd: "reset" }), { ok: true });
  assert.deepEqual(await run({ cmd: "read" }), { ok: true, opened: 0, most: 0 });
  await assert.rejects(run({ cmd: "other" }), /invalid_input/);
  assert.equal(tap.ops.window_watch.vault, false);
});
