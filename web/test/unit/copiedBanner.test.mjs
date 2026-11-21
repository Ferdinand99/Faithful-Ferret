// An item restored over one the server had purged became a copy under a new id (the engine's `copied`): the screen of the old item
// moves to the copy, and the user is told once.
import assert from "node:assert/strict";
import { test } from "node:test";
import { shellView } from "../../src/views/shell.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { all, fakeEngine, fakeSession, find, t, textOf, withDom } from "./vaultHelpers.mjs";

const FROM = "11".repeat(16);
const TO = "cd".repeat(16);

function frame(hash) {
  const engine = fakeEngine();
  const moves = [];
  const root = shellView({
    t, engine, session: fakeSession(), content: document.createElement("div"), lock: async () => {}, touch: () => true,
    scope: createWipeScope(), onLocked: () => document.createElement("div"), router: { go: (p) => moves.push(p) },
    win: { location: { hash } },
  });
  return { engine, moves, root };
}

test("a_copy_under_a_new_id_moves_the_open_item_page_and_tells_the_user_once", async () => {
  await withDom(async () => {
    const { engine, moves, root } = frame(`#/items/${FROM}`);
    engine.emit("copied", { from: FROM, to: TO });
    assert.deepEqual(moves, [`/items/${TO}`]);
    assert.equal(all(root, "banner").length, 1);
    assert.ok(textOf(find(root, "banner")).includes("vault.banner.copied"));
    engine.emit("copied", { from: FROM, to: TO });
    assert.equal(all(root, "banner").length, 1, "the same notice is not shown twice");
  });
});

test("a_copy_does_not_move_a_page_that_is_not_about_the_item_but_still_tells_the_user", async () => {
  await withDom(async () => {
    const { engine, moves, root } = frame("#/items");
    engine.emit("copied", { from: FROM, to: TO });
    assert.deepEqual(moves, []);
    assert.equal(all(root, "banner").length, 1);
  });
  await withDom(async () => {
    // The edit page follows by itself and keeps what was typed: the frame does not rebuild it.
    const { engine, moves } = frame(`#/items/${FROM}/edit`);
    engine.emit("copied", { from: FROM, to: TO });
    assert.deepEqual(moves, []);
  });
});
