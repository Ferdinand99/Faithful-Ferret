// The empty states of the shell's pages: one shape (an icon, one line, the one action worth taking), the same for the list,
// the favourites, a search with no hit, the trash and the devices. Each says why it is empty and offers a way on.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { devicesView } from "../../src/views/devices.mjs";
import { emptyBlock, emptyState } from "../../src/views/emptyState.mjs";
import { listView } from "../../src/views/list.mjs";
import { trashView } from "../../src/views/trash.mjs";
import { fakeConflictEngine } from "./conflictHelpers.mjs";
import { all, click, fakeEngine, find, fire, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

test("an_empty_state_is_an_icon_a_line_and_its_actions", async () => {
  await withDom(async () => {
    const taken = [];
    const root = emptyState({
      role: "x-empty", icon: "trash", text: "Nothing here.",
      actions: [
        { label: "Go on", role: "go", href: "#/items", primary: true },
        { label: "Try", role: "try", onClick: () => taken.push("try") },
      ],
    });
    assert.equal(root.getAttribute("data-role"), "x-empty");
    const icon = root.childNodes[0];
    assert.equal(icon.getAttribute("data-icon"), "trash");
    assert.equal(icon.getAttribute("aria-hidden"), "true", "the picture is decoration; the line says it");
    assert.equal(textOf(find(root, "empty-text")).trim(), "Nothing here.");
    const go = find(root, "go");
    assert.equal(go.tagName, "a", "a way to another page is a link");
    assert.equal(go.getAttribute("href"), "#/items");
    assert.match(go.getAttribute("class"), /btn-primary/);
    const tryIt = find(root, "try");
    assert.equal(tryIt.tagName, "button");
    assert.equal(tryIt.getAttribute("type"), "button");
    assert.match(tryIt.getAttribute("class"), /btn-secondary/);
    await click(tryIt);
    assert.deepEqual(taken, ["try"]);
  });
});

test("an_empty_block_can_be_filled_again_with_another_line_icon_and_actions", async () => {
  await withDom(async () => {
    const block = emptyBlock({ role: "b", icon: "items" });
    block.fill("First.", [{ label: "A", role: "a" }]);
    assert.equal(all(block.root, "a").length, 1);
    block.fill("Second.", [], "search");
    assert.equal(textOf(find(block.root, "empty-text")).trim(), "Second.");
    assert.equal(block.root.childNodes[0].getAttribute("data-icon"), "search");
    assert.equal(all(block.root, "a").length, 0, "the old action is gone");
  });
});

test("the_text_of_an_empty_state_is_text_and_never_markup", async () => {
  await withDom(async () => {
    const root = emptyState({ role: "x", icon: "items", text: "<img src=x onerror=alert(1)>", actions: [{ label: "<b>go</b>", role: "go" }] });
    assert.equal(textOf(find(root, "empty-text")).trim(), "<img src=x onerror=alert(1)>");
    assert.equal(textOf(find(root, "go")).trim(), "<b>go</b>");
  });
});

/** A list over an engine with these items. */
function list(items, nav) {
  const engine = fakeEngine({ items });
  const moves = [];
  const root = listView({ engine, router: { go: (path) => moves.push(path) }, t, nav: nav ?? { query: "", set() {}, watch: () => () => {} }, locale: "en" });
  return { root, moves, engine };
}

const ITEM = { id: "11".repeat(16), name: "Bank", type: "login", favorite: false, urls: [], username: "ada", rev: 1 };

test("an_empty_vault_says_so_and_offers_to_make_the_first_item", async () => {
  await withDom(async () => {
    const { root, moves } = list([]);
    const empty = find(root, "list-empty");
    assert.equal(empty.hidden, false);
    assert.ok(textOf(find(empty, "empty-text")).includes("vault.list.empty"));
    assert.equal(empty.childNodes[0].getAttribute("data-icon"), "items");
    assert.deepEqual(all(empty, "empty-add").map((b) => textOf(b).trim()), ["list.add"], "the one action");
    assert.equal(all(empty, "empty-clear-search").length + all(empty, "empty-clear-filters").length, 0);
    await click(find(empty, "empty-add"));
    assert.deepEqual(moves, ["/items/new"]);
  });
});

test("the_favourites_with_none_say_how_to_make_one", async () => {
  await withDom(async () => {
    const { root } = list([ITEM], { query: "fav=1", set() {}, watch: () => () => {} });
    const empty = find(root, "list-empty");
    assert.equal(empty.hidden, false);
    assert.ok(textOf(find(empty, "empty-text")).includes("shell.favorites.empty"));
    assert.equal(empty.childNodes[0].getAttribute("data-icon"), "star");
    assert.ok(find(empty, "empty-clear-filters"), "the way out is to clear the filter");
  });
});

test("a_search_with_no_hit_says_so_and_offers_to_clear_it", async () => {
  await withDom(async () => {
    const { root } = list([ITEM]);
    const search = find(root, "search");
    search.value = "zzz";
    await fire(search, "input");
    await settle();
    const empty = find(root, "list-empty");
    assert.equal(empty.hidden, false);
    assert.ok(textOf(find(empty, "empty-text")).includes("vault.list.no_match"));
    assert.equal(empty.childNodes[0].getAttribute("data-icon"), "search");
    assert.deepEqual(all(empty, "empty-clear-search").length, 1);
    await click(find(empty, "empty-clear-search"));
    await settle();
    assert.equal(find(root, "list-empty").hidden, true, "clearing the search brings the list back");
  });
});

test("an_empty_trash_says_so_and_leads_back_to_the_items", async () => {
  await withDom(async () => {
    const engine = fakeConflictEngine({ trash: [] });
    const root = await trashView({ engine, t, locale: "en", scope: createWipeScope() });
    const empty = find(root, "trash-empty-state");
    assert.ok(empty, "the empty state is there");
    assert.ok(textOf(empty).includes("conflict.trash.empty"));
    const way = find(empty, "empty-items");
    assert.equal(way.tagName, "a");
    assert.equal(way.getAttribute("href"), "#/items");
    // With something in the trash there is a count and no empty state.
    const full = await trashView({ engine: fakeConflictEngine({ trash: [{ id: "11".repeat(16), name: "Bank", deletedAt: 1_700_000_000_000 }] }), t, locale: "en", scope: createWipeScope() });
    assert.equal(find(full, "trash-empty-state"), null);
    assert.ok(textOf(find(full, "trash-empty")).includes("conflict.trash.count"));
  });
});

test("a_list_of_no_devices_says_so_and_offers_to_check_again", async () => {
  await withDom(async () => {
    let loads = 0;
    const view = devicesView({
      t, locale: "en",
      load: async () => {
        loads += 1;
        return { devices: [] };
      },
      revoke: async () => {}, revokeAll: async () => ({ revoked: 0 }), forgetOld: async () => ({ revoked: 0 }), reauth: async () => "ok",
    });
    await settle();
    const empty = find(view, "devices-empty-state");
    assert.ok(empty);
    assert.ok(textOf(empty).includes("devices.empty"));
    assert.equal(loads, 1);
    await click(find(empty, "devices-refresh"));
    await settle();
    assert.equal(loads, 2, "the action asks the server again");
  });
});
