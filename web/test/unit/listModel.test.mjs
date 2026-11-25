// What the item list decides, without a page: the filters, the order, the search, the address of the list, the window of a
// long list and how a moment reads.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  OVERSCAN, WINDOW_FROM, applyFilters, countByFolder, countByType, createMatcher, defaultDir, defaultState, formatListQuery, hasFilters, inDirection,
  initialOf, menuPathOf, normalState, parseListQuery, relativeTime, sameState, sortItems, typesPresent, windowRange,
} from "../../src/views/listModel.mjs";
import { parseLocation } from "../../src/router.mjs";

const item = (id, extra = {}) => ({ id: String(id).padStart(32, "0"), name: `Item ${id}`, type: "login", favorite: false, urls: [], username: "", modified: 1000, ...extra });

test("filters_by_type_favourite_and_folder_and_keeps_the_order", () => {
  const items = [
    item(1, { type: "login", favorite: true, folders: ["Home"] }),
    item(2, { type: "note", folders: ["Home", "Money"] }),
    item(3, { type: "card", favorite: true }),
    item(4, { type: "login", folders: ["Money"] }),
  ];
  const ids = (list) => list.map((i) => Number(i.id));
  const state = (extra) => ({ ...defaultState(), ...extra });
  assert.deepEqual(ids(applyFilters(items, state({}))), [1, 2, 3, 4], "no filter, every item");
  assert.deepEqual(ids(applyFilters(items, state({ types: ["login"] }))), [1, 4]);
  assert.deepEqual(ids(applyFilters(items, state({ types: ["login", "card"] }))), [1, 3, 4], "any of the chosen types");
  assert.deepEqual(ids(applyFilters(items, state({ favorite: true }))), [1, 3]);
  assert.deepEqual(ids(applyFilters(items, state({ favorite: true, types: ["card"] }))), [3], "the filters together");
  assert.deepEqual(ids(applyFilters(items, state({ folders: ["Money"] }))), [2, 4]);
  assert.deepEqual(ids(applyFilters(items, state({ folders: ["Home", "Money"] }))), [1, 2, 4], "an item with any of the folders");
  assert.deepEqual(ids(applyFilters(items, state({ types: ["nothing"] }))), []);
  // A dropdown asks what each of its values would give: its own filter is left out.
  assert.deepEqual(ids(applyFilters(items, state({ types: ["note"], favorite: true }), "types")), [1, 3]);
  assert.deepEqual(ids(applyFilters(items, state({ folders: ["Home"], types: ["login"] }), "folders")), [1, 4]);
  assert.ok(applyFilters(items, state({})) !== items, "a copy, never the list that was given");
});

test("counts_per_type_and_per_folder_and_the_types_the_vault_has", () => {
  const items = [item(1, { folders: ["A"] }), item(2, { type: "note", folders: ["A", "B"] }), item(3, { type: "weird" })];
  assert.deepEqual([...countByType(items)], [["login", 1], ["note", 1], ["weird", 1]]);
  assert.deepEqual([...countByFolder(items)], [["A", 2], ["B", 1]]);
  assert.deepEqual(typesPresent(items), ["login", "note", "weird"], "the known types in their order, then the others");
  assert.deepEqual(typesPresent([item(1)], ["card"]), ["login", "card"], "a chosen type with no item stays so its chip can be taken off");
  assert.deepEqual(typesPresent([]), []);
});

test("sorts_by_name_without_case_and_by_last_changed_and_never_wobbles", () => {
  const items = [
    item(1, { name: "banana", modified: 30 }), item(2, { name: "Apple", modified: 10 }), item(3, { name: "cherry", modified: 20 }),
    item(4, { name: "apple", modified: 20 }), item(5, { name: "Item 10", modified: 5 }), item(6, { name: "Item 9", modified: 5 }),
  ];
  const names = (list) => list.map((i) => i.name);
  assert.deepEqual(names(sortItems(items, "name", "asc")), ["Apple", "apple", "banana", "cherry", "Item 9", "Item 10"], "case ignored, numbers by value, ties by id");
  assert.deepEqual(names(sortItems(items, "name", "desc")), ["Item 10", "Item 9", "cherry", "banana", "apple", "Apple"]);
  assert.deepEqual(names(sortItems(items, "changed", "desc")).slice(0, 3), ["banana", "apple", "cherry"], "newest first, a tie by name");
  assert.deepEqual(names(sortItems(items, "changed", "asc")).slice(0, 2), ["Item 9", "Item 10"], "oldest first, a tie by name");
  assert.equal(defaultDir("name"), "asc");
  assert.equal(defaultDir("changed"), "desc");
  assert.deepEqual(inDirection([1, 2, 3], "desc"), [3, 2, 1]);
  assert.deepEqual(inDirection([1, 2, 3], "asc"), [1, 2, 3]);
  const before = items.map((i) => i.id).join();
  sortItems(items, "name", "asc");
  assert.equal(items.map((i) => i.id).join(), before, "the list that was given is not changed");
  // No name sorts (an item that cannot be read) and a missing date are fine.
  assert.equal(sortItems([item(1, { name: "" }), item(2, { modified: undefined })], "changed", "desc").length, 2);
});

test("search_needs_every_word_in_the_name_the_address_or_the_user_name", () => {
  const items = [
    item(1, { name: "Bank of Norway", urls: ["https://bank.example"], username: "ada" }),
    item(2, { name: "Mail", urls: ["https://MAIL.example/login"], username: "Grace.Hopper" }),
    item(3, { name: "ÅPNE kontoen" }),
  ];
  const matcher = createMatcher();
  const names = (q) => matcher.filter(items, q).map((i) => i.name);
  assert.deepEqual(names(""), ["Bank of Norway", "Mail", "ÅPNE kontoen"]);
  assert.deepEqual(names("   "), ["Bank of Norway", "Mail", "ÅPNE kontoen"], "a blank search shows everything");
  assert.deepEqual(names("BANK"), ["Bank of Norway"]);
  assert.deepEqual(names("mail.EXAMPLE"), ["Mail"]);
  assert.deepEqual(names("grace hopper"), ["Mail"]);
  assert.deepEqual(names("ada norway"), ["Bank of Norway"], "words from two fields");
  assert.deepEqual(names("åpne"), ["ÅPNE kontoen"]);
  assert.deepEqual(names("zzz"), []);
  // The folded text is kept per item until the item changes.
  items[0] = { ...items[0], name: "Savings" };
  assert.deepEqual(names("norway"), [], "the cache follows an edit of the name");
  assert.deepEqual(names("bank"), ["Savings"], "the address is still in the text");
  assert.deepEqual(names("savings"), ["Savings"]);
  items[1] = { ...items[1], urls: ["https://other.example"] };
  assert.deepEqual(names("mail.example"), [], "and of the addresses");
});

test("the_address_has_the_filters_and_the_order_and_never_the_search_text", () => {
  const roundTrip = (state, options) => parseListQuery(formatListQuery(state, options), options);
  assert.equal(formatListQuery(defaultState()), "", "the default list has no query");
  assert.deepEqual(parseListQuery(""), defaultState());
  const state = { types: ["note", "login"], favorite: true, passkey: false, folders: [], sort: "changed", dir: "asc" };
  assert.equal(formatListQuery(state), "type=login,note&fav=1&sort=changed&dir=asc", "one spelling: types sorted, only what is not the default");
  assert.deepEqual(roundTrip(state), normalState(state));
  assert.deepEqual(roundTrip({ ...defaultState(), sort: "changed", dir: "desc" }), { ...defaultState(), sort: "changed", dir: "desc" });
  assert.equal(formatListQuery({ ...defaultState(), sort: "changed", dir: "desc" }), "sort=changed", "the first direction of a column is not spelled");
  assert.equal(formatListQuery({ ...defaultState(), dir: "desc" }), "dir=desc");
  assert.deepEqual(parseListQuery("dir=desc"), { ...defaultState(), dir: "desc" });
  // A folder name is an encrypted label of the vault: it is never written in the address, which stays in the history of the browser.
  const withFolders = { ...defaultState(), folders: ["Home, sweet", "Ä/x"], types: ["note"] };
  assert.equal(formatListQuery(withFolders), "type=note", "the folder filter is not written");
  assert.ok(!formatListQuery(withFolders).includes("folder"));
  assert.deepEqual(parseListQuery("folder=Home&type=note").folders, [], "and not read");
  assert.equal(sameState({ ...defaultState(), folders: ["A"] }, defaultState()), false, "but it is part of the state");
  assert.equal(sameState({ ...defaultState(), folders: ["B", "A"] }, { ...defaultState(), folders: ["A", "B"] }), true);
  // No field of the state can carry the search text or an item name.
  for (const key of Object.keys(defaultState())) assert.ok(["types", "favorite", "passkey", "folders", "sort", "dir"].includes(key));
});

test("the_matcher_forgets_what_it_folded_when_asked", () => {
  const matcher = createMatcher();
  const items = [item(1, { name: "Secret bank" }), item(2, { name: "Other" })];
  matcher.filter(items, "bank");
  matcher.warm(items, 0, 10);
  assert.equal(matcher.size(), 2);
  matcher.clear();
  assert.equal(matcher.size(), 0, "nothing of a name stays after a lock");
});

test("an_address_that_is_made_up_reads_as_the_default_list", () => {
  const bad = [
    "type=<script>", "type=LOGIN", "type=", "fav=yes", "fav=2", "sort=name&dir=sideways", "sort=password", "type=a,b,c,d,e,f,g,h,i,j,k,l",
    "=1", "&&&", "type=login=note", "folder=%E0%A4%A", "__proto__=1", "type[]=login",
  ];
  for (const query of bad) {
    const state = parseListQuery(query);
    assert.ok(["asc", "desc"].includes(state.dir), query);
    assert.ok(state.types.length <= 8, query);
    for (const type of state.types) assert.match(type, /^[a-z][a-z0-9_-]{0,23}$/, query);
    assert.ok(["name", "changed"].includes(state.sort), query);
    assert.equal(typeof state.favorite, "boolean");
  }
  assert.deepEqual(parseListQuery("type=LOGIN&fav=yes&sort=password"), defaultState());
  assert.deepEqual(parseListQuery("type=login&type=note").types, ["login"], "the first of a repeated key");
  assert.deepEqual(parseListQuery("type=login,login,note").types, ["login", "note"]);
  assert.equal(parseListQuery("folder=%E0%A4%A").folders.length, 0, "a folder in the address is never read");
  assert.equal(sameState(parseListQuery("type=note,login"), parseListQuery("type=login,note")), true);
  assert.equal(hasFilters(defaultState()), false);
  assert.equal(hasFilters({ ...defaultState(), favorite: true }), true);
});

test("the_router_reads_the_query_of_the_address_and_nothing_else", () => {
  assert.deepEqual(parseLocation("#/items?type=login&fav=1"), { path: "/items", query: "type=login&fav=1" });
  assert.deepEqual(parseLocation("#/items"), { path: "/items", query: "" });
  assert.deepEqual(parseLocation("#/items?"), { path: "/items", query: "" });
  assert.deepEqual(parseLocation("#/items?folder=Home%2C%20x"), { path: "/items", query: "folder=Home%2C%20x" });
  for (const bad of ["#/items?a b", "#/items?<x>", "#/items?a;b", "#//items?x=1", "#/ite ms?x=1", `#/items?${"a".repeat(300)}`, null, 5]) {
    assert.equal(parseLocation(/** @type {any} */ (bad)), null, String(bad));
  }
  // What the list writes always passes.
  const query = formatListQuery({ ...defaultState(), types: ["login", "note"], favorite: true, folders: ["Ä b,c"], sort: "changed", dir: "asc" });
  assert.notEqual(parseLocation(`#/items?${query}`), null);
});

test("a_long_list_is_drawn_as_a_window_with_a_few_rows_around_the_screen", () => {
  const rowHeight = 56;
  const at = (top, extra = {}) => windowRange({ count: 10_000, rowHeight, top, viewport: 800, ...extra });
  assert.deepEqual(at(0), { start: 0, end: Math.ceil(800 / rowHeight) + OVERSCAN });
  // The page is scrolled 5600 px: the first row is 5600 above the screen.
  const scrolled = at(5600);
  assert.equal(scrolled.start, 100 - OVERSCAN);
  assert.equal(scrolled.end, Math.ceil(6400 / rowHeight) + OVERSCAN);
  assert.ok(scrolled.end - scrolled.start < 40, "a few dozen rows, not ten thousand");
  // The list is below the top of the screen: nothing is above it.
  assert.deepEqual(at(-300), { start: 0, end: Math.ceil(500 / rowHeight) + OVERSCAN });
  // Far past the end, the window is empty but valid.
  const past = at(rowHeight * 10_000 + 5000);
  assert.deepEqual(past, { start: 10_000, end: 10_000 });
  assert.deepEqual(windowRange({ count: 0, rowHeight, top: 0, viewport: 800 }), { start: 0, end: 0 });
  assert.deepEqual(windowRange({ count: 10, rowHeight: 0, top: 0, viewport: 800 }), { start: 0, end: 0 });
  // The window always lies inside the list.
  for (let top = -2000; top < 600_000; top += 7919) {
    const { start, end } = at(top);
    assert.ok(0 <= start && start <= end && end <= 10_000, String(top));
  }
  assert.ok(WINDOW_FROM > 50 && WINDOW_FROM < 1000);
});

test("a_moment_reads_the_way_a_person_says_it", () => {
  const now = Date.UTC(2026, 10, 22, 12, 0, 0);
  const ago = (ms) => relativeTime(now - ms, now, "en");
  assert.equal(ago(5_000), "now");
  assert.equal(ago(5 * 60_000), "5 minutes ago");
  assert.equal(ago(3 * 3_600_000), "3 hours ago");
  assert.equal(ago(86_400_000), "yesterday");
  assert.equal(ago(3 * 86_400_000), "3 days ago");
  assert.equal(ago(60 * 86_400_000), "2 months ago");
  assert.equal(ago(800 * 86_400_000), "2 years ago");
  assert.equal(relativeTime(now - 86_400_000, now, "nb"), "i går");
  assert.equal(relativeTime(0, now, "en"), null);
  assert.equal(relativeTime(NaN, now, "en"), null);
  assert.equal(relativeTime(/** @type {any} */ ("x"), now, "en"), null);
});

test("the_tile_has_the_first_letter_and_the_side_menu_entry_follows_the_filters", () => {
  assert.equal(initialOf("bank"), "B");
  assert.equal(initialOf("  åpne"), "Å");
  assert.equal(initialOf("😀 smile"), "😀", "a whole character, not half of a surrogate pair");
  assert.equal(initialOf(""), "?");
  assert.equal(menuPathOf("/items", ""), "/items");
  assert.equal(menuPathOf("/items", "fav=1"), "/favorites");
  assert.equal(menuPathOf("/items", "type=login&fav=1"), "/favorites");
  assert.equal(menuPathOf("/items", "type=login"), "/items");
  assert.equal(menuPathOf("/trash", "fav=1"), "/trash");
});
