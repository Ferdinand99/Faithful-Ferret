// The top bar says which screen is open (aria-current) and follows the address.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { fakeEngine, find, t, withDom } from "./vaultHelpers.mjs";

function frame(win) {
  const engine = fakeEngine();
  const root = shellView({
    t, engine, session: { onLock() {} }, content: globalThis.document.createElement("div"),
    lock: async () => {}, touch: () => true, scope: createWipeScope(), onLocked: () => globalThis.document.createElement("div"), win,
  });
  return { root, items: find(root, "nav-items"), add: find(root, "nav-new") };
}

const current = (link) => link.getAttribute("aria-current");

test("the_link_of_the_open_screen_is_marked_and_the_mark_follows_the_address", async () => {
  await withDom(async () => {
    const listeners = [];
    const win = {
      location: { hash: "#/items" },
      addEventListener: (type, fn) => listeners.push([type, fn]),
      removeEventListener: (type, fn) => listeners.splice(listeners.findIndex(([a, b]) => a === type && b === fn), 1),
    };
    const { root, items, add } = frame(win);
    assert.deepEqual([current(items), current(add)], ["page", "false"]);

    const hashchange = () => listeners.filter(([type]) => type === "hashchange").forEach(([, fn]) => fn());
    win.location.hash = "#/items/new";
    hashchange();
    assert.deepEqual([current(items), current(add)], ["false", "page"]);
    // An item or its edit form belongs to the list.
    win.location.hash = "#/items/0123456789abcdef0123456789abcdef/edit";
    hashchange();
    assert.deepEqual([current(items), current(add)], ["page", "false"]);
    // Elsewhere neither is current.
    win.location.hash = "#/login";
    hashchange();
    assert.deepEqual([current(items), current(add)], ["false", "false"]);

    // A frame that was on the page and left it stops listening.
    root.isConnected = true;
    root.isConnected = false;
    hashchange();
    assert.equal(listeners.length, 0);
  });
});

test("a_page_without_an_address_still_builds_the_bar", async () => {
  await withDom(async () => {
    const { items, add } = frame(undefined);
    assert.deepEqual([current(items), current(add)], ["false", "false"]);
  });
});
