// The item list as a screen: the chips and what they put in the address, the order, the table, the menu of a row, several
// rows at once through the sync engine's outbox, the empty states, the columns, folders that are not there yet, a long list
// and the lock. The fake DOM has no layout, so the focus and the window of a long list on a real page are in the browser
// tests (test/e2e/list.spec.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { createListPrefs, LIST_PREFS_KEY } from "../../src/listPrefs.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { listView } from "../../src/views/list.mjs";
import { WINDOW_FROM } from "../../src/views/listModel.mjs";
import { createFakeClient, Model, settle as settleEngine, syncDevice, until } from "./syncHelpers.mjs";
import { all, click, coded, fakeEngine, find, fire, settle, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

const base = {
  favorite: false, urls: [], username: "", rev: 1, pending: false, damaged: false, quarantined: false,
  missingOnServer: false, blocked: false, blockedReason: null, readOnly: false, type: "login", modified: 1_700_000_000_000,
};
const item = (n, extra = {}) => ({ ...base, id: String(n).padStart(32, "0"), name: `Item ${n}`, ...extra });

/** A stand-in for the address: what the list writes in it, and the way back and forward reach the list. */
function fakeNav(query = "") {
  const nav = {
    query,
    sets: [],
    watchers: new Set(),
    set(next) {
      nav.sets.push(next);
      nav.query = next;
    },
    watch(fn) {
      nav.watchers.add(fn);
      return () => void nav.watchers.delete(fn);
    },
    /** Back, forward or a link: only the query changes. */
    async go(next) {
      nav.query = next;
      for (const fn of [...nav.watchers]) fn(next);
      await settle();
    },
  };
  return nav;
}

/** Preferences over a plain object instead of localStorage. */
function memoryStorage() {
  const map = new Map();
  return { map, getItem: (key) => map.get(key) ?? null, setItem: (key, value) => void map.set(key, String(value)), removeItem: (key) => void map.delete(key) };
}

const names = (root) => all(root, "item-link").map((link) => textOf(link).replace(/\s+/g, " ").replace("★", "").trim());
const countText = (root) => textOf(find(root, "count")).replace(/\s+/g, " ").trim();
/** The entry of a chip menu or of the column menu with that value. */
const entryOf = (root, menuRole, value) => [...walk(find(root, menuRole))].find((n) => n.getAttribute?.("data-value") === value);
const checked = (node) => node.getAttribute("aria-checked");

const mixed = () => [
  item(1, { name: "Bank", type: "login", favorite: true, username: "ada", modified: 5000 }),
  item(2, { name: "Wifi", type: "note", modified: 3000 }),
  item(3, { name: "Visa", type: "card", favorite: true, modified: 9000 }),
  item(4, { name: "GitHub", type: "login", username: "ola", modified: 1000 }),
];

test("the_type_chip_filters_with_counts_and_puts_the_filter_in_the_address", async () => {
  await withDom(async () => {
    const nav = fakeNav();
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav, prefs: createListPrefs(memoryStorage()) });
    assert.deepEqual(names(root), ["Bank", "GitHub", "Visa", "Wifi"]);
    assert.equal(textOf(find(root, "type-chip")).includes("list.type"), true);
    assert.equal(find(root, "type-remove").hidden, true, "no filter, no cross");

    // The menu lists the types the vault has, in the order of the filter, each with how many items it has.
    const values = [...walk(find(root, "type-menu"))].filter((n) => n.getAttribute?.("data-value")).map((n) => n.getAttribute("data-value"));
    assert.deepEqual(values, ["login", "note", "card"]);
    assert.ok(textOf(entryOf(root, "type-menu", "login")).includes("2"));
    assert.equal(checked(entryOf(root, "type-menu", "login")), "false");

    await click(entryOf(root, "type-menu", "note"));
    assert.deepEqual(names(root), ["Wifi"]);
    assert.equal(checked(entryOf(root, "type-menu", "note")), "true");
    assert.deepEqual(nav.sets, ["type=note"]);
    assert.equal(find(root, "type-remove").hidden, false);
    assert.ok(textOf(find(root, "type-chip")).includes("list.chip_value"), "the chip says which type");
    assert.ok(countText(root).includes("vault.list.count"));

    // A second type adds to the first; the chip then says how many.
    await click(entryOf(root, "type-menu", "card"));
    assert.deepEqual(names(root), ["Visa", "Wifi"]);
    assert.deepEqual(nav.sets, ["type=note", "type=card,note"]);
    assert.ok(textOf(find(root, "type-chip")).includes("list.chip_count"));

    // The cross takes the filter off.
    await click(find(root, "type-remove"));
    assert.deepEqual(names(root), ["Bank", "GitHub", "Visa", "Wifi"]);
    assert.equal(nav.sets.at(-1), "");
  });
});

test("the_favourites_chip_toggles_and_the_title_follows", async () => {
  await withDom(async () => {
    const nav = fakeNav();
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav, prefs: createListPrefs(memoryStorage()) });
    const chip = find(root, "favorites-chip");
    assert.equal(chip.getAttribute("aria-pressed"), "false");
    assert.ok(textOf(find(root, "list-title")).includes("shell.nav.items"));
    await click(chip);
    assert.deepEqual(names(root), ["Bank", "Visa"]);
    assert.equal(chip.getAttribute("aria-pressed"), "true");
    assert.equal(find(root, "favorites-remove").hidden, false);
    assert.deepEqual(nav.sets, ["fav=1"]);
    assert.ok(textOf(find(root, "list-title")).includes("shell.nav.favorites"), "only the favourites: the page says so");
    // With a type as well, the page is a filtered list of all items.
    await click(entryOf(root, "type-menu", "card"));
    assert.deepEqual(names(root), ["Visa"]);
    assert.ok(textOf(find(root, "list-title")).includes("shell.nav.items"));
    assert.deepEqual(nav.sets, ["fav=1", "type=card&fav=1"]);
    await click(find(root, "favorites-remove"));
    assert.deepEqual(names(root), ["Visa"]);
    assert.equal(chip.getAttribute("aria-pressed"), "false");
  });
});

test("the_list_starts_from_the_address_and_follows_back_and_forward", async () => {
  await withDom(async () => {
    const nav = fakeNav("type=login&fav=1&sort=changed&dir=asc");
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav, prefs: createListPrefs(memoryStorage()) });
    assert.deepEqual(names(root), ["Bank"], "the filters of the address, the order of the address");
    assert.equal(find(root, "favorites-chip").getAttribute("aria-pressed"), "true");
    assert.equal(checked(entryOf(root, "type-menu", "login")), "true");
    assert.equal(find(root, "sort-changed").parentNode.getAttribute("aria-sort"), "ascending");
    assert.equal(find(root, "sort-name").parentNode.getAttribute("aria-sort"), "none");

    // Back: the address has no query.
    await nav.go("");
    assert.deepEqual(names(root), ["Bank", "GitHub", "Visa", "Wifi"]);
    assert.equal(find(root, "favorites-chip").getAttribute("aria-pressed"), "false");
    assert.equal(find(root, "type-remove").hidden, true);
    // Forward again, and a made-up query.
    await nav.go("type=card");
    assert.deepEqual(names(root), ["Visa"]);
    await nav.go("type=%3Cscript%3E&sort=password&fav=maybe");
    assert.deepEqual(names(root), ["Bank", "GitHub", "Visa", "Wifi"], "what is not understood is the default list");
    assert.deepEqual(nav.sets, [], "the list does not write the address that it only reads");
    // The list that is no longer on the page stops following the address.
    root.isConnected = false;
    await nav.go("type=note");
    assert.equal(nav.watchers.size, 0);
  });
});

test("the_search_text_is_never_put_in_the_address", async () => {
  await withDom(async () => {
    const nav = fakeNav();
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav, prefs: createListPrefs(memoryStorage()) });
    const search = find(root, "search");
    search.value = "bank";
    await fire(search, "input");
    assert.deepEqual(names(root), ["Bank"]);
    await click(find(root, "favorites-chip"));
    assert.deepEqual(nav.sets, ["fav=1"], "the filter is in the address, the text typed is not");
    assert.ok(!nav.sets.some((q) => q.includes("bank")));
    assert.equal(find(root, "search-clear").hidden, false);
    await click(find(root, "search-clear"));
    assert.equal(search.value, "");
    assert.deepEqual(names(root), ["Bank", "Visa"]);
    assert.equal(find(root, "search-clear").hidden, true);
  });
});

test("the_columns_order_the_list_and_say_so_to_a_screen_reader", async () => {
  await withDom(async () => {
    const nav = fakeNav();
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav, prefs: createListPrefs(memoryStorage()) });
    const sort = (key) => find(root, `sort-${key}`).parentNode.getAttribute("aria-sort");
    assert.deepEqual([sort("name"), sort("changed")], ["ascending", "none"], "names from A to start");
    await click(find(root, "sort-name"));
    assert.deepEqual(names(root), ["Wifi", "Visa", "GitHub", "Bank"]);
    assert.equal(sort("name"), "descending");
    assert.deepEqual(nav.sets, ["dir=desc"]);
    await click(find(root, "sort-changed"));
    assert.deepEqual(names(root), ["Visa", "Bank", "Wifi", "GitHub"], "the newest change first");
    assert.deepEqual([sort("name"), sort("changed")], ["none", "descending"]);
    assert.equal(nav.sets.at(-1), "sort=changed");
    await click(find(root, "sort-changed"));
    assert.deepEqual(names(root), ["GitHub", "Wifi", "Bank", "Visa"]);
    assert.equal(nav.sets.at(-1), "sort=changed&dir=asc");
    await click(find(root, "sort-name"));
    assert.deepEqual(names(root), ["Bank", "GitHub", "Visa", "Wifi"]);
    assert.equal(nav.sets.at(-1), "", "back to the default order");
  });
});

test("select_all_marks_every_shown_row_and_a_row_that_leaves_the_list_is_let_go", async () => {
  await withDom(async () => {
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    const selectAll = find(root, "select-all");
    assert.equal(find(root, "bulk").hidden, true);
    selectAll.checked = true;
    await fire(selectAll, "change");
    assert.equal(find(root, "bulk").hidden, false);
    assert.ok(textOf(find(root, "bulk-count")).includes("list.bulk_many"));
    assert.ok(all(root, "select").every((box) => box.checked === true));
    assert.ok(all(root, "item").every((row) => row.getAttribute("data-selected") === "true"));
    assert.equal(selectAll.indeterminate, false);

    // One row off: neither all nor none.
    const first = all(root, "select")[0];
    first.checked = false;
    await fire(first, "change");
    assert.equal(selectAll.indeterminate, true);
    assert.equal(selectAll.checked, false);
    assert.ok(textOf(find(root, "bulk-count")).includes("3"));

    // A filter that hides rows lets go of them: a bar for several rows never acts on rows that are not shown.
    await click(entryOf(root, "type-menu", "card"));
    assert.deepEqual(names(root), ["Visa"]);
    assert.ok(textOf(find(root, "bulk-count")).includes("list.bulk_one"));
    await click(find(root, "bulk-clear"));
    assert.equal(find(root, "bulk").hidden, true);
    assert.ok(all(root, "select").every((box) => box.checked === false));
  });
});

test("bulk_actions_write_each_item_once_and_say_what_was_done", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [...mixed(), item(5, { name: "Locked", readOnly: true }), item(6, { name: "Stuck", blocked: true })] });
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    const selectAll = find(root, "select-all");
    selectAll.checked = true;
    await fire(selectAll, "change");

    // Favourite: those that are not favourites yet get the one field; a read-only or blocked item is skipped, and said so.
    assert.equal(find(root, "bulk-favorite").getAttribute("data-mode"), "favorite");
    await click(find(root, "bulk-favorite"));
    await settle();
    const updates = engine.calls.filter(([kind]) => kind === "update");
    assert.deepEqual(updates.map(([, id]) => Number(id)).sort(), [2, 4], "only the items that are not favourites and may be changed");
    assert.ok(updates.every(([, , draft]) => JSON.stringify(draft) === JSON.stringify({ favorite: true })), "one field, nothing else");
    assert.deepEqual(engine.expectedRevs, [1, 1], "from the revision the list showed");
    const said = textOf(find(root, "message"));
    assert.ok(said.includes("list.done_favorite"));
    assert.ok(said.includes("list.done_skipped"));
    assert.equal(find(root, "bulk").hidden, true, "the rows that were settled are let go");
  });
});

test("bulk_trash_asks_first_and_cancel_changes_nothing", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: mixed() });
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    const selectAll = find(root, "select-all");
    selectAll.checked = true;
    await fire(selectAll, "change");
    await click(find(root, "bulk-trash"));
    await settle();
    assert.ok(textOf(find(root, "dialog")).includes("list.trash_title_many"));
    assert.ok(textOf(find(root, "dialog")).includes("4"), "it says how many");
    await click(find(root, "dialog-cancel"));
    await settle();
    assert.deepEqual(engine.calls.filter(([kind]) => kind === "remove"), []);
    assert.equal(find(root, "dialog"), null);
    assert.equal(find(root, "bulk").hidden, false, "the selection is still there");

    await click(find(root, "bulk-trash"));
    await settle();
    await click(find(root, "dialog-confirm"));
    await settle();
    assert.deepEqual(engine.calls.filter(([kind]) => kind === "remove").map(([, id]) => Number(id)).sort(), [1, 2, 3, 4]);
    assert.ok(textOf(find(root, "message")).includes("list.done_trash"));
  });
});

test("a_write_that_fails_is_said_in_words_and_its_row_stays_marked", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: mixed() });
    engine.failWith = coded("item_changed");
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    all(root, "select")[0].checked = true;
    await fire(all(root, "select")[0], "change");
    await click(find(root, "bulk-favorite"));
    await settle();
    assert.ok(textOf(find(root, "message")).includes("vault.error.item_changed"), "the code gives a fixed text, never the error's own message");
    assert.equal(find(root, "bulk").hidden, false, "the row that failed is still selected, to try again");
    assert.equal(find(root, "bulk-favorite").disabled, false, "and the buttons work again");
  });
});

test("the_menu_of_a_row_has_view_favourite_edit_and_delete_and_only_view_when_it_cannot_be_changed", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [item(1, { name: "Bank" }), item(2, { name: "Locked", readOnly: true }), item(3, { name: "Star", favorite: true })] });
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    const rows = all(root, "item");
    const buttonOf = (row) => [...walk(row)].find((n) => n.getAttribute?.("data-role") === "row-menu");
    const menuOf = (row) => [...walk(row)].find((n) => n.getAttribute?.("data-role") === "row-menu-list");
    const rolesIn = (row) => [...walk(menuOf(row))].filter((n) => n.getAttribute?.("role") === "menuitem").map((n) => n.getAttribute("data-role"));

    const button = buttonOf(rows[0]);
    assert.equal(button.getAttribute("aria-haspopup"), "menu");
    assert.equal(button.getAttribute("aria-expanded"), "false");
    assert.ok(button.getAttribute("aria-label").includes("list.options"), "an accessible name with the item's name");
    assert.ok(button.getAttribute("aria-label").includes("Bank"));
    assert.equal(menuOf(rows[0]), undefined, "the menu is made when it is first asked for");
    await click(button);
    assert.equal(button.getAttribute("aria-expanded"), "true");
    assert.equal(menuOf(rows[0]).hidden, false);
    assert.deepEqual(rolesIn(rows[0]), ["row-view", "row-favorite", "row-edit", "row-delete"], "no Move to folder until the folder task gives the way");
    assert.equal(menuOf(rows[0]).getAttribute("role"), "menu");
    const links = [...walk(menuOf(rows[0]))].filter((n) => n.tagName === "a").map((n) => n.getAttribute("href"));
    assert.deepEqual(links, [`#/items/${item(1).id}`, `#/items/${item(1).id}/edit`]);

    // Escape closes it.
    await fire(menuOf(rows[0]), "keydown", { key: "Escape" });
    assert.equal(button.getAttribute("aria-expanded"), "false");
    assert.equal(menuOf(rows[0]).hidden, true);

    // A read-only item: View only.
    await click(buttonOf(rows[1]));
    assert.deepEqual(rolesIn(rows[1]), ["row-view"]);

    // A favourite says so in its entry.
    await click(buttonOf(rows[2]));
    const fav = [...walk(menuOf(rows[2]))].find((n) => n.getAttribute?.("data-role") === "row-favorite");
    assert.ok(textOf(fav).includes("list.menu_unfavorite"));
    await click(fav);
    await settle();
    assert.deepEqual(engine.calls.filter(([kind]) => kind === "update").map(([, id, draft]) => [Number(id), draft]), [[3, { favorite: false }]]);
    assert.ok(textOf(find(root, "message")).includes("list.done_unfavorite"));
  });
});

test("a_row_menu_opens_one_at_a_time_and_a_press_outside_closes_it", async () => {
  await withDom(async () => {
    const saved = globalThis.document.addEventListener;
    const presses = [];
    globalThis.document.addEventListener = (type, fn) => presses.push([type, fn]);
    try {
      const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
      const buttons = all(root, "row-menu");
      await click(buttons[0]);
      await click(buttons[1]);
      assert.deepEqual(buttons.map((b) => b.getAttribute("aria-expanded")), ["false", "true", "false", "false"], "a second menu closes the first");
      await click(find(root, "customise"));
      assert.equal(buttons[1].getAttribute("aria-expanded"), "false");
      assert.equal(find(root, "customise").getAttribute("aria-expanded"), "true");
      const press = presses.find(([type]) => type === "pointerdown")[1];
      press({ target: find(root, "search") });
      assert.equal(find(root, "customise").getAttribute("aria-expanded"), "false", "a press on the page closes the open menu");
    } finally {
      globalThis.document.addEventListener = saved;
    }
  });
});

test("move_to_folder_is_in_the_menu_only_when_the_folder_task_gives_the_way", async () => {
  await withDom(async () => {
    const moved = [];
    const root = listView({ engine: fakeEngine({ items: [item(1)] }), router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()), moveToFolder: (items) => moved.push(items.map((i) => i.id)) });
    const row = all(root, "item")[0];
    await click([...walk(row)].find((n) => n.getAttribute?.("data-role") === "row-menu"));
    const move = [...walk(row)].find((n) => n.getAttribute?.("data-role") === "row-move");
    assert.ok(move);
    await click(move);
    assert.deepEqual(moved, [[item(1).id]]);
  });
});

test("folders_are_hidden_until_an_item_has_one_and_then_filter_and_show_in_a_column", async () => {
  await withDom(async () => {
    // No folder anywhere: no chip, no column, and a folder in the address is not applied.
    const nav = fakeNav("folder=Home");
    const plain = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav, prefs: createListPrefs(memoryStorage()) });
    assert.equal(find(plain, "chip-folders").hidden, true);
    assert.equal(find(plain, "table").getAttribute("data-folders"), "off");
    assert.equal(entryOf(plain, "customise-menu", "folders"), undefined);
    assert.equal(names(plain).length, 4, "a folder filter that cannot exist filters nothing");

    const items = [item(1, { name: "A", folders: ["Home", "Money"] }), item(2, { name: "B", folders: ["Home"] }), item(3, { name: "C" })];
    const engine = fakeEngine({ items });
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    assert.equal(find(root, "chip-folders").hidden, false);
    assert.equal(find(root, "table").getAttribute("data-folders"), "on");
    const first = all(root, "folders")[0];
    assert.ok(textOf(first).includes("Home"));
    assert.ok(textOf(first).includes("+1"), "the second folder is a count");
    assert.deepEqual([...walk(find(root, "folders-menu"))].filter((n) => n.getAttribute?.("data-value")).map((n) => [n.getAttribute("data-value"), textOf(n).trim().split(" ").pop()]), [["Home", "2"], ["Money", "1"]]);
    await click(entryOf(root, "folders-menu", "Money"));
    assert.deepEqual(names(root), ["A"]);
  });
});

test("the_columns_menu_hides_a_column_and_the_choice_is_kept_on_the_device", async () => {
  await withDom(async () => {
    const storage = memoryStorage();
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(storage) });
    const table = find(root, "table");
    assert.equal(table.getAttribute("data-changed"), "on");
    assert.equal(checked(entryOf(root, "customise-menu", "changed")), "true");
    await click(entryOf(root, "customise-menu", "changed"));
    assert.equal(table.getAttribute("data-changed"), "off");
    assert.equal(checked(entryOf(root, "customise-menu", "changed")), "false");
    assert.equal(storage.map.get(LIST_PREFS_KEY), JSON.stringify({ hidden: ["changed"] }));
    // A new list on this device starts the same way.
    const again = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(storage) });
    assert.equal(find(again, "table").getAttribute("data-changed"), "off");
    await click(entryOf(again, "customise-menu", "changed"));
    assert.equal(storage.map.has(LIST_PREFS_KEY), false, "nothing is kept when nothing is hidden");
  });
});

test("the_preferences_hold_only_column_names_and_read_anything_else_as_none", () => {
  const storage = memoryStorage();
  const prefs = createListPrefs(storage);
  prefs.setShown("name", false);
  prefs.setShown("<script>", false);
  assert.equal(storage.map.size, 0, "a column that cannot be hidden is not written");
  for (const junk of ["not json", "[]", "null", "{\"hidden\":\"changed\"}", "{\"hidden\":[\"folders\",\"x\"]}".padEnd(5000, " ")]) {
    storage.map.set(LIST_PREFS_KEY, junk);
    assert.equal(createListPrefs(storage).shows("changed"), true, junk.slice(0, 30));
    assert.equal(createListPrefs(storage).shows("folders"), true, junk.slice(0, 30));
  }
  storage.map.set(LIST_PREFS_KEY, "{\"hidden\":[\"folders\",\"x\"]}");
  const read = createListPrefs(storage);
  assert.deepEqual([read.shows("folders"), read.shows("changed")], [false, true]);
  // Storage that is blocked only means the choice is not remembered.
  const blocked = createListPrefs({ getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); }, removeItem() { throw new Error("blocked"); } });
  assert.equal(blocked.shows("changed"), true);
  blocked.setShown("changed", false);
  assert.equal(blocked.shows("changed"), false, "the page follows the choice, though it cannot be kept");
  assert.equal(createListPrefs(null).shows("changed"), true);
});

test("the_empty_states_say_what_is_wrong_and_how_to_leave_it", async () => {
  await withDom(async () => {
    // An empty vault: a way to the first item, nothing to search.
    const moves = [];
    const bare = listView({ engine: fakeEngine({ items: [] }), router: { go: (p) => moves.push(p) }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    assert.equal(find(bare, "list-empty").hidden, false);
    assert.ok(textOf(find(bare, "empty-text")).includes("vault.list.empty"));
    assert.equal(find(bare, "table").hidden, true);
    assert.equal(find(bare, "chip-type").hidden, true);
    await click(find(bare, "empty-add"));
    assert.deepEqual(moves, ["/items/new"]);

    // No match for the search.
    const root = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    const search = find(root, "search");
    search.value = "zzzz";
    await fire(search, "input");
    assert.ok(textOf(find(root, "empty-text")).includes("vault.list.no_match"));
    assert.equal(find(root, "empty-clear-filters"), null);
    await click(find(root, "empty-clear-search"));
    assert.equal(names(root).length, 4);
    assert.equal(find(root, "list-empty").hidden, true);

    // The filters leave nothing: a button takes them off.
    await click(find(root, "favorites-chip"));
    await click(entryOf(root, "type-menu", "note"));
    assert.deepEqual(names(root), []);
    assert.ok(textOf(find(root, "empty-text")).includes("list.empty_filters"));
    assert.equal(find(root, "empty-clear-search"), null);
    await click(find(root, "empty-clear-filters"));
    assert.equal(names(root).length, 4);
    assert.equal(find(root, "favorites-chip").getAttribute("aria-pressed"), "false");

    // Only the favourites and none: the page says there are none yet.
    const noFavorites = listView({ engine: fakeEngine({ items: [item(1)] }), router: { go() {} }, t, nav: fakeNav("fav=1"), prefs: createListPrefs(memoryStorage()) });
    assert.ok(textOf(find(noFavorites, "empty-text")).includes("shell.favorites.empty"));

    // Both.
    const both = listView({ engine: fakeEngine({ items: mixed() }), router: { go() {} }, t, nav: fakeNav("type=note"), prefs: createListPrefs(memoryStorage()) });
    const text = find(both, "search");
    text.value = "bank";
    await fire(text, "input");
    assert.ok(textOf(find(both, "empty-text")).includes("list.empty_both"));
    assert.ok(find(both, "empty-clear-search") && find(both, "empty-clear-filters"));
  });
});

test("the_list_follows_the_engine_and_keeps_the_filters_and_the_selection_that_still_apply", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: mixed() });
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav("type=login"), prefs: createListPrefs(memoryStorage()) });
    assert.deepEqual(names(root), ["Bank", "GitHub"]);
    all(root, "select")[0].checked = true;
    await fire(all(root, "select")[0], "change");
    // A new item on another device, and the engine says so (twice in one turn is one reading).
    engine.items = [...engine.items, item(9, { name: "Another", type: "login" })];
    engine.emit("changed", { ids: [item(9).id] });
    engine.emit("changed", { ids: [item(9).id] });
    await settle();
    assert.deepEqual(names(root), ["Another", "Bank", "GitHub"]);
    assert.ok(textOf(find(root, "bulk-count")).includes("list.bulk_one"), "the selection stays");
    // The selected item is deleted elsewhere.
    engine.items = engine.items.filter((i) => i.name !== "Bank");
    engine.emit("changed", {});
    await settle();
    assert.equal(find(root, "bulk").hidden, true, "a row that is gone is not selected");
  });
});

test("a_list_of_ten_thousand_draws_only_a_window_and_selects_them_all", async () => {
  await withDom(async () => {
    const big = Array.from({ length: 10_000 }, (_, i) => item(i + 1, { name: `Entry ${String(i).padStart(5, "0")}`, type: i % 3 === 0 ? "note" : "login", favorite: i % 50 === 0 }));
    const engine = fakeEngine({ items: big });
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    assert.ok(all(root, "item").length < 100, `a window of rows, not ${all(root, "item").length}`);
    assert.ok(all(root, "item").length > 0);
    assert.ok(countText(root).includes("list.count_all"));
    assert.ok(countText(root).includes("10000"));
    assert.equal(find(root, "table").getAttribute("aria-rowcount"), "10001");
    assert.ok(WINDOW_FROM < 10_000);
    const search = find(root, "search");
    search.value = "entry 00042";
    await fire(search, "input");
    assert.deepEqual(names(root), ["Entry 00042"]);
    search.value = "";
    await fire(search, "input");
    const selectAll = find(root, "select-all");
    selectAll.checked = true;
    await fire(selectAll, "change");
    assert.ok(textOf(find(root, "bulk-count")).includes("10000"), "every item of the list, not only the rows that are drawn");
    // Ten thousand writes are not made by a click: the dialog asks first.
    await click(find(root, "bulk-trash"));
    await settle();
    assert.ok(textOf(find(root, "dialog")).includes("10000"));
  });
});

test("the_lock_wipes_the_list_and_nothing_is_drawn_after_it", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: mixed() });
    const scope = createWipeScope();
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()), scope });
    assert.ok(textOf(root).includes("Bank"));
    scope.run();
    assert.equal(root.childNodes.length, 0, "the screen is emptied");
    assert.ok(!textOf(root).includes("Bank"));
    engine.items = [item(7, { name: "Late" })];
    engine.emit("changed", {});
    await settle();
    assert.equal(root.childNodes.length, 0, "an event after the lock draws nothing");
  });
});

test("the_conflict_note_leads_to_the_first_item_in_conflict", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [item(1), item(2, { conflict: true, name: "Clash" })] });
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    assert.equal(find(root, "first-conflict").getAttribute("href"), `#/items/${item(2).id}/conflict`);
    assert.ok(textOf(find(root, "conflict-note")).includes("conflict.list_count"));
    assert.ok(find(root, "trash-link"), "the way to the trash stays");
  });
});

test("several_rows_go_through_the_engines_outbox_and_the_server_sees_one_write_per_item", async () => {
  const model = new Model();
  const client = createFakeClient();
  const ids = ["11", "22", "33"].map((b) => b.repeat(16));
  ids.forEach((id, i) => model.set(id, { rev: 1, ...client.wireRow(id, 1, { item_type: "login", name: `Real ${i}`, fields: [{ id: "username", label: "User", kind: "text", value: `user${i}` }] }) }));
  const device = await syncDevice({ model, client });
  const { engine } = device;
  await engine.start();
  await withDom(async () => {
    try {
    const root = listView({ engine, router: { go() {} }, t, nav: fakeNav(), prefs: createListPrefs(memoryStorage()) });
    assert.deepEqual(names(root), ["Real 0", "Real 1", "Real 2"]);
    const selectAll = find(root, "select-all");
    selectAll.checked = true;
    await fire(selectAll, "change");

    // Favourites: one edit of each item (revision 2), the one field.
    const before = model.writes.length;
    await click(find(root, "bulk-favorite"));
    await until(() => engine.list().every((i) => i.favorite === true && !i.pending), "every item is a favourite and sent");
    await until(() => ids.every((id) => model.items.get(id).rev === 2), "the server has the three edits");
    assert.deepEqual(engine.list().map((i) => i.rev), [2, 2, 2]);
    assert.equal(model.writes.length - before, 3, "one write for each item");
    assert.deepEqual(ids.map((id) => model.items.get(id).rev), [2, 2, 2]);
    assert.deepEqual(names(root), ["Real 0", "Real 1", "Real 2"], "the user name and the rest are as they were");
    assert.ok(all(root, "item").every((row) => textOf(row).includes("★")));
    assert.ok(textOf(find(root, "message")).includes("list.done_favorite"));
    await settleEngine();

    // The same click again takes them off: every selected item is a favourite, so the button says so.
    selectAll.checked = true;
    await fire(selectAll, "change");
    assert.equal(find(root, "bulk-favorite").getAttribute("data-mode"), "unfavorite");
    await click(find(root, "bulk-favorite"));
    await until(() => engine.list().every((i) => i.favorite === false && !i.pending), "no favourites and sent");
    await until(() => !find(root, "message") || textOf(find(root, "message")).includes("list.done_unfavorite"), "the list says what was done");

    // Trash: a tombstone for each item, after the dialog.
    selectAll.checked = true;
    await fire(selectAll, "change");
    await click(find(root, "bulk-trash"));
    await settleEngine();
    await click(find(root, "dialog-confirm"));
    await until(() => engine.list().length === 0, "the items are gone");
    await until(() => ids.every((id) => model.items.get(id).deleted === true), "the server has the tombstones");
    assert.ok(all(root, "item").length === 0);
    assert.ok(textOf(find(root, "empty-text")).includes("vault.list.empty"));
    } finally {
      engine.stop();
    }
  });
});
