// What the side menu holds: the entries come from the routes, the counts, the
// pinned folders, the entry the page belongs to, and what the device remembers.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { countItems, currentEntry, initialsOf, pinnedTree, sidebarModel } from "../../src/views/sidebarModel.mjs";
import { createUiPrefs, MAX_PINNED, UI_PREFS_KEY } from "../../src/uiPrefs.mjs";
import { web } from "./helpers.mjs";

const ROUTES = [
  { path: "/items", title: "t.items", sidebar: { section: "main", order: 10, icon: "items", role: "nav-items", count: "all" }, load() {} },
  { path: "/favorites", title: "t.fav", sidebar: { section: "main", order: 20, icon: "star", role: "nav-favorites", count: "favorites" }, load() {} },
  { path: "/items/new", title: "t.new", sidebar: { section: "primary", order: 1, icon: "plus", role: "nav-new" }, load() {} },
  { path: "/trash", title: "t.trash", sidebar: { section: "manage", order: 20, icon: "trash", role: "nav-trash", title: "t.trash_label" }, load() {} },
  { path: "/export", title: "t.export", sidebar: { section: "tools", order: 30, icon: "transfer", role: "nav-transfer", activeFor: ["/import"] }, load() {} },
  { path: "/account", title: "t.account", load() {} },
  { path: "/password", title: "t.password", menu: "account", menuOrder: 10, load() {} },
];

const ids = (sections) => sections.map((section) => [section.id, section.entries.map((entry) => entry.id)]);

test("the_entries_come_from_the_routes_in_sections_and_in_order", () => {
  const sections = sidebarModel({ routes: ROUTES, counts: { all: 248, favorites: 12 } });
  assert.deepEqual(ids(sections), [
    ["primary", ["/items/new"]],
    ["main", ["/items", "/favorites"]],
    ["tools", ["generator", "health", "/export"]],
    ["manage", ["folders", "/trash"]],
  ]);
  const by = Object.fromEntries(sections.flatMap((s) => s.entries).map((e) => [e.id, e]));
  assert.equal(by["/items"].count, 248);
  assert.equal(by["/favorites"].count, 12);
  assert.equal(by["/items/new"].count, null);
  assert.equal(by["/items"].href, "#/items");
  assert.equal(by["/trash"].label, "t.trash_label", "the menu's own title, else the route's");
  assert.equal(by["/favorites"].label, "t.fav");
  assert.deepEqual(sections.map((s) => s.heading), [null, null, "shell.section.tools", "shell.section.manage"]);
});

test("a_route_that_does_not_ask_to_be_listed_is_not_listed", () => {
  const all = sidebarModel({ routes: ROUTES }).flatMap((s) => s.entries.map((e) => e.id));
  for (const unlisted of ["/account", "/password"]) assert.ok(!all.includes(unlisted), unlisted);
  // No routes at all: only the pages that are planned.
  assert.deepEqual(ids(sidebarModel({ routes: [] })), [["tools", ["generator", "health"]], ["manage", ["folders"]]]);
});

test("a_route_with_a_bad_menu_entry_is_left_out_and_never_breaks_the_menu", () => {
  const bad = [
    { path: "/a", title: "k", sidebar: { section: "nowhere", icon: "items", role: "nav-a" } },
    { path: "/b", title: "k", sidebar: { section: "main", icon: "not-an-icon", role: "nav-b" } },
    { path: "/c", title: "k", sidebar: { section: "main", icon: "items", role: "Nav C" } },
    { path: "/d/:id", title: "k", sidebar: { section: "main", icon: "items", role: "nav-d" } },
    { path: "/e", sidebar: { section: "main", icon: "items", role: "nav-e" } },
    { path: "/f", title: "k", sidebar: { section: "main", icon: "items", role: "nav-f", count: "everything" } },
    { path: "/g", title: "k", sidebar: { section: "main", icon: "items", role: "nav-g", activeFor: ["no slash"] } },
    { path: "/h", title: "k", sidebar: null },
    null,
    { path: "/ok", title: "k", sidebar: { section: "main", icon: "items", role: "nav-ok" } },
  ];
  assert.deepEqual(sidebarModel({ routes: bad }).find((s) => s.id === "main").entries.map((e) => e.id), ["/ok"]);
});

test("the_planned_pages_are_entries_that_are_not_links", () => {
  const soon = sidebarModel({ routes: [] }).flatMap((s) => s.entries);
  assert.deepEqual(soon.map((e) => [e.id, e.kind, e.href]), [["generator", "soon", null], ["health", "soon", null], ["folders", "soon", null]]);
});

test("the_counts_leave_out_the_unlock_manifest_and_count_the_favourites", () => {
  const items = [{ id: "a", favorite: true }, { id: "b" }, { id: "c", favorite: true }, { id: "m", favorite: true }];
  assert.deepEqual(countItems(items, "m"), { all: 3, favorites: 2 });
  assert.deepEqual(countItems([]), { all: 0, favorites: 0 });
});

const FOLDERS = [
  { id: "home", name: "Home", parentId: null },
  { id: "net", name: "Network", parentId: "home" },
  { id: "srv", name: "Servers", parentId: "home" },
  { id: "rack", name: "Rack", parentId: "srv" },
  { id: "fin", name: "Finance", parentId: null },
  { id: "dev", name: "Dev", parentId: null },
];

test("a_pinned_folder_is_listed_with_the_folders_below_it_and_nothing_else", () => {
  assert.deepEqual(pinnedTree(FOLDERS, ["Home"]).map((f) => [f.id, f.depth]), [["home", 0], ["net", 1], ["srv", 1], ["rack", 2]]);
  assert.deepEqual(pinnedTree(FOLDERS, ["Finance", "Home"]).map((f) => f.id), ["fin", "home", "net", "srv", "rack"], "in the order they were pinned");
  // A pin is a name: every folder with that name is pinned, and a folder made again under the name is pinned again.
  const twins = [...FOLDERS, { id: "home2", name: "Home", parentId: null }];
  assert.deepEqual(pinnedTree(twins, ["Home"]).filter((f) => f.pinned).map((f) => f.id), ["home", "home2"]);
  assert.deepEqual(pinnedTree(FOLDERS, []), []);
  // A pin that points at a folder that is gone shows nothing.
  assert.deepEqual(pinnedTree(FOLDERS, ["Gone"]), []);
  // A folder pinned below another pinned one stands once, below it.
  assert.deepEqual(pinnedTree(FOLDERS, ["Servers", "Home"]).map((f) => [f.id, f.depth]), [["home", 0], ["net", 1], ["srv", 1], ["rack", 2]]);
  // Folders that are each other's parent do not loop.
  const loop = [{ id: "x", name: "X", parentId: "y" }, { id: "y", name: "Y", parentId: "x" }];
  assert.deepEqual(pinnedTree(loop, ["X"]).map((f) => f.id), ["x", "y"]);
});

test("the_pinned_section_shows_only_when_a_folder_is_pinned_and_each_row_says_whether_it_can_be_unpinned", () => {
  const none = sidebarModel({ routes: ROUTES, folders: FOLDERS, pinned: [] });
  assert.ok(!none.some((s) => s.id === "pinned"), "no heading over nothing");
  const some = sidebarModel({ routes: ROUTES, folders: FOLDERS, pinned: ["Servers"] });
  const pinned = some.find((s) => s.id === "pinned");
  assert.equal(pinned.heading, "shell.section.pinned");
  assert.deepEqual(pinned.entries.map((e) => [e.label, e.depth, e.folder]), [["Servers", 0, "Servers"], ["Rack", 1, null]]);
  assert.equal(pinned.entries[0].href, "#/folders/srv");
  // The section stands between the items and the tools.
  assert.deepEqual(some.map((s) => s.id), ["primary", "main", "pinned", "tools", "manage"]);
});

test("the_entry_the_page_belongs_to_is_the_closest_one_and_only_one", () => {
  const sections = sidebarModel({ routes: ROUTES });
  const at = (path) => currentEntry(sections, path);
  assert.equal(at("/items"), "/items");
  assert.equal(at("/items/new"), "/items/new");
  assert.equal(at("/items/abc"), "/items");
  assert.equal(at("/items/abc/edit"), "/items");
  assert.equal(at("/export"), "/export");
  assert.equal(at("/import"), "/export");
  assert.equal(at("/trash"), "/trash");
  assert.equal(at("/account"), null);
  assert.equal(at("/itemsx"), null, "a longer word is not below the path");
  assert.equal(at("/generator"), null, "a planned page is never current");
});

test("every_route_of_the_build_that_asks_for_a_place_in_the_menu_gets_one", async () => {
  const dir = join(web, "src", "routes");
  const routes = [];
  for (const file of readdirSync(dir).filter((name) => name.endsWith(".route.mjs")).sort()) routes.push((await import(`../../src/routes/${file}`)).default);
  const asking = routes.filter((route) => route.sidebar);
  assert.ok(asking.length >= 5);
  const entries = sidebarModel({ routes }).flatMap((s) => s.entries).filter((e) => e.kind === "link");
  assert.deepEqual(entries.map((e) => e.id).sort(), asking.map((r) => r.path).sort());
  // No two entries share a role or a path.
  assert.equal(new Set(entries.map((e) => e.role)).size, entries.length);
  // Every entry has a text in both languages.
  for (const lang of ["en", "nb"]) {
    const catalog = {};
    for (const name of readdirSync(join(web, "src", "locales", lang))) Object.assign(catalog, JSON.parse(readFileSync(join(web, "src", "locales", lang, name), "utf8")));
    for (const entry of entries) assert.ok(entry.label in catalog, `${lang}: ${entry.label}`);
  }
  // The menu is for the vault: the pages of the sign-in and the account page are not in it.
  for (const route of routes.filter((r) => ["/login", "/setup", "/unlock", "/account"].includes(r.path))) assert.equal(route.sidebar, undefined, route.path);
});

test("the_round_mark_has_two_letters_from_the_user_part_of_the_address", () => {
  assert.equal(initialsOf("ada.lovelace@example.com"), "AL");
  assert.equal(initialsOf("ada@example.com"), "AD");
  assert.equal(initialsOf("ola_nordmann+test@example.com"), "ON");
  assert.equal(initialsOf("æøå@example.com"), "ÆØ");
  assert.equal(initialsOf("x@example.com"), "X");
  assert.equal(initialsOf(""), "?");
  assert.equal(initialsOf(null), "?");
  assert.equal(initialsOf("@example.com"), "?");
});

// ---------------------------------------------------------------- what the device remembers

/** A storage that is a map. */
function memory() {
  const map = new Map();
  return { map, getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, String(v)), removeItem: (k) => void map.delete(k) };
}

test("the_folded_state_is_remembered_per_device_and_the_pins_are_kept_in_memory", () => {
  const storage = memory();
  const prefs = createUiPrefs(storage, []);
  assert.equal(prefs.collapsed(), false);
  assert.deepEqual(prefs.pinned(), []);
  prefs.setCollapsed(true);
  assert.equal(createUiPrefs(storage, []).collapsed(), true, "another page of the device reads the same");
  assert.equal(prefs.pin("srv"), true);
  assert.equal(prefs.pin("home"), true);
  assert.equal(prefs.pin("srv"), true, "pinning twice is one pin");
  assert.deepEqual(prefs.pinned(), ["srv", "home"]);
  assert.equal(prefs.isPinned("home"), true);
  prefs.unpin("srv");
  assert.deepEqual(prefs.pinned(), ["home"]);
  assert.equal(prefs.collapsed(), true, "unpinning leaves the folded state alone");
  prefs.clearPins();
  assert.deepEqual(prefs.pinned(), [], "a lock forgets the pins");
  prefs.setCollapsed(false);
  assert.equal(storage.map.has(UI_PREFS_KEY), false, "nothing is kept when everything is the default");
});

test("pins_live_in_memory_only_and_no_folder_name_is_ever_written_to_the_device", () => {
  const writes = [];
  const storage = { ...memory(), setItem: (k, v) => void writes.push([k, v]) };
  const pins = [];
  const prefs = createUiPrefs(storage, pins);
  prefs.setCollapsed(true);
  for (const name of ["Bank", "Sundry secret folder", "Økonomi"]) prefs.pin(name);
  prefs.unpin("Bank");
  assert.deepEqual(pins, ["Sundry secret folder", "Økonomi"], "held in the memory that was given");
  // The only thing written is the folded flag.
  assert.deepEqual(writes, [[UI_PREFS_KEY, '{"collapsed":true}']]);
  for (const [, value] of writes) for (const name of ["Bank", "Sundry", "Økonomi"]) assert.ok(!value.includes(name), name);
  // Nothing else of the device is touched: there is no IndexedDB, no session storage and no cookie in the preferences.
  const source = readFileSync(join(web, "src", "uiPrefs.mjs"), "utf8");
  assert.ok(!/indexedDB|sessionStorage|document.cookie/.test(source));
  // The pins of a page are shared by its frames and are cleared as one.
  const first = createUiPrefs(null);
  first.pin("Shared");
  assert.deepEqual(createUiPrefs(null).pinned(), ["Shared"]);
  first.clearPins();
  assert.deepEqual(createUiPrefs(null).pinned(), []);
});

test("a_value_written_by_an_older_build_with_folder_names_is_rewritten_without_them", () => {
  const storage = memory();
  storage.setItem(UI_PREFS_KEY, JSON.stringify({ collapsed: true, pinned: ["Bank", "Home"] }));
  const prefs = createUiPrefs(storage, []);
  assert.equal(prefs.collapsed(), true);
  assert.deepEqual(prefs.pinned(), []);
  assert.equal(storage.map.get(UI_PREFS_KEY), '{"collapsed":true}');
  const other = memory();
  other.setItem(UI_PREFS_KEY, JSON.stringify({ pinned: ["Bank"] }));
  createUiPrefs(other, []);
  assert.equal(other.map.has(UI_PREFS_KEY), false);
});

test("a_pin_that_is_not_a_one_line_name_or_is_one_too_many_is_refused", () => {
  const prefs = createUiPrefs(memory(), []);
  for (const bad of ["", "two\nlines", "x".repeat(129), "tab\there", 5, null, undefined]) assert.equal(prefs.pin(bad), false, String(bad));
  assert.equal(prefs.pin("Økonomi og skatt <2026>"), true, "a name is any one line of text");
  prefs.unpin("Økonomi og skatt <2026>");
  assert.deepEqual(prefs.pinned(), []);
  for (let i = 0; i < MAX_PINNED; i += 1) assert.equal(prefs.pin(`f${i}`), true);
  assert.equal(prefs.pin("one-more"), false);
  assert.equal(prefs.pinned().length, MAX_PINNED);
});

test("a_stored_value_of_the_wrong_shape_reads_as_the_default", () => {
  for (const text of ["not json", "[]", "null", "5", '{"collapsed":"yes"}', "x".repeat(9000)]) {
    const storage = memory();
    storage.setItem(UI_PREFS_KEY, text);
    const prefs = createUiPrefs(storage, []);
    assert.equal(prefs.collapsed(), false, text.slice(0, 20));
    assert.deepEqual(prefs.pinned(), []);
  }
});

test("a_blocked_store_only_means_the_choice_is_not_remembered", () => {
  const blocked = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); }, removeItem() { throw new Error("blocked"); } };
  const prefs = createUiPrefs(blocked, []);
  assert.equal(prefs.collapsed(), false);
  prefs.setCollapsed(true);
  assert.equal(prefs.pin("a"), true);
  assert.deepEqual(prefs.pinned(), ["a"], "a pin does not need the store");
  const none = createUiPrefs(null, []);
  none.setCollapsed(true);
  assert.equal(none.collapsed(), false);
});

test("the_menu_texts_exist_in_both_languages_with_the_same_placeholders", () => {
  const read = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "shell.json"), "utf8"));
  const en = read("en");
  const nb = read("nb");
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  const holders = (text) => [...text.matchAll(/\{([a-z]+)\}/g)].map((m) => m[1]).sort().join();
  for (const [key, value] of Object.entries(en)) {
    assert.ok(key.startsWith("shell."), key);
    assert.ok(value.length > 0 && nb[key].length > 0, key);
    assert.equal(holders(value), holders(nb[key]), key);
  }
  // Every label the model can name has a text.
  const labels = sidebarModel({ routes: [], folders: FOLDERS, pinned: ["Home"] }).flatMap((s) => [s.heading, ...s.entries.map((e) => (e.kind === "folder" ? null : e.label))]).filter((x) => x !== null);
  for (const key of labels) assert.ok(key in en, key);
});
