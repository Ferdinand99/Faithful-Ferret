// The side menu says which screen is open (aria-current) and follows the address.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { createUiPrefs } from "../../src/uiPrefs.mjs";
import exportRoute from "../../src/routes/export.route.mjs";
import favoritesRoute from "../../src/routes/favorites.route.mjs";
import listRoute from "../../src/routes/list.route.mjs";
import newRoute from "../../src/routes/new.route.mjs";
import trashRoute from "../../src/routes/trash.route.mjs";
import { fakeEngine, find, t, withDom } from "./vaultHelpers.mjs";

const ROUTES = [listRoute, newRoute, favoritesRoute, exportRoute, trashRoute];
const ROLES = ["nav-items", "nav-favorites", "nav-transfer", "nav-trash"];

function frame(win) {
  const engine = fakeEngine();
  const root = shellView({
    t, engine, session: { onLock() {} }, content: globalThis.document.createElement("div"),
    lock: async () => {}, touch: () => true, scope: createWipeScope(), onLocked: () => globalThis.document.createElement("div"), win,
    routes: ROUTES, prefs: createUiPrefs(null),
  });
  /** The roles of the entries that are marked as the current page. */
  const current = () => ROLES.filter((role) => find(root, role).getAttribute("aria-current") === "page");
  return { root, current };
}

/** The window of a page: an address, and the listeners the frame puts on it. */
function pageWindow(hash) {
  const listeners = [];
  const win = {
    location: { hash },
    addEventListener: (type, fn) => listeners.push([type, fn]),
    removeEventListener: (type, fn) => listeners.splice(listeners.findIndex(([a, b]) => a === type && b === fn), 1),
    go(next) {
      win.location.hash = next;
      listeners.filter(([type]) => type === "hashchange").forEach(([, fn]) => fn());
    },
    listeners,
  };
  return win;
}

test("the_entry_of_the_open_screen_is_marked_and_the_mark_follows_the_address", async () => {
  await withDom(async () => {
    const win = pageWindow("#/items");
    const { root, current } = frame(win);
    assert.deepEqual(current(), ["nav-items"]);

    win.go("#/items/new");
    assert.deepEqual(current(), ["nav-items"], "making an item has no entry of its own: it belongs to the list, whose Add button starts it");
    // An item or its edit form or its conflict belongs to the list.
    win.go("#/items/0123456789abcdef0123456789abcdef/edit");
    assert.deepEqual(current(), ["nav-items"]);
    win.go("#/items/0123456789abcdef0123456789abcdef/conflict");
    assert.deepEqual(current(), ["nav-items"]);
    win.go("#/favorites");
    assert.deepEqual(current(), ["nav-favorites"]);
    win.go("#/trash");
    assert.deepEqual(current(), ["nav-trash"]);
    // Import and export are one entry.
    win.go("#/export");
    assert.deepEqual(current(), ["nav-transfer"]);
    win.go("#/import");
    assert.deepEqual(current(), ["nav-transfer"]);
    // Elsewhere no entry is current.
    win.go("#/login");
    assert.deepEqual(current(), []);

    // A frame that was on the page and left it stops listening.
    root.isConnected = true;
    root.isConnected = false;
    win.go("#/items");
    assert.equal(win.listeners.length, 0);
  });
});

test("a_page_without_an_address_still_builds_the_menu", async () => {
  await withDom(async () => {
    const { current } = frame(undefined);
    assert.deepEqual(current(), []);
  });
});

test("the_menu_is_built_from_the_routes_and_a_page_with_no_routes_has_no_entries_of_its_own", async () => {
  await withDom(async () => {
    const bare = shellView({
      t, engine: fakeEngine(), session: { onLock() {} }, content: globalThis.document.createElement("div"),
      lock: async () => {}, touch: () => true, scope: createWipeScope(), onLocked: () => globalThis.document.createElement("div"),
      prefs: createUiPrefs(null),
    });
    assert.equal(find(bare, "nav-items"), null);
    // The planned pages are shown all the same, and they are not links.
    assert.ok(find(bare, "nav-generator"));
    assert.equal(find(bare, "nav-generator").getAttribute("href"), null);
  });
});

test("the_list_with_the_favourites_on_belongs_to_the_favourites_entry_whatever_else_is_chosen", async () => {
  await withDom(async () => {
    const win = pageWindow("#/items");
    const { current } = frame(win);
    win.go("#/items?fav=1");
    assert.deepEqual(current(), ["nav-favorites"]);
    win.go("#/items?type=login&fav=1&sort=changed");
    assert.deepEqual(current(), ["nav-favorites"]);
    win.go("#/items?type=login");
    assert.deepEqual(current(), ["nav-items"], "a filter that is not the favourites is the list of all items");
    win.go("#/items?sort=changed&dir=asc");
    assert.deepEqual(current(), ["nav-items"]);
  });
});

test("the_favourites_route_opens_the_list_with_the_chip_on_and_does_not_stay_in_the_history", async () => {
  await withDom(async () => {
    const replaced = [];
    const node = favoritesRoute.load({ replace: (path) => replaced.push(path) });
    assert.deepEqual(replaced, ["/items?fav=1"]);
    assert.ok(node);
  });
});
