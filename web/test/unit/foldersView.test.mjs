// The folder screens: the Folders page (open, pin, rename, delete), the bar of a folder's page, "Move to folder", the
// list of one folder, and the pinned folders in the side menu, which come from the items. Over a fake engine that records
// every write: a rename or a delete writes each item in the folder once, with its whole new list and nothing else.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createListPrefs } from "../../src/listPrefs.mjs";
import { createUiPrefs } from "../../src/uiPrefs.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { moveDialog } from "../../src/views/folderActions.mjs";
import { clearFolderLinks, folderHref, keyOfToken } from "../../src/views/folderLinks.mjs";
import { folderBar, foldersPage } from "../../src/views/foldersPage.mjs";
import { listView } from "../../src/views/list.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { el } from "../../src/dom.mjs";
import { all, click, coded, fakeEngine, fire, find, settle, submit, t, textOf, withDom } from "./vaultHelpers.mjs";

const base = {
  favorite: false, urls: [], username: "", pending: false, damaged: false, quarantined: false,
  missingOnServer: false, blocked: false, blockedReason: null, readOnly: false, type: "login", modified: 1_700_000_000_000,
};
const item = (n, folders, extra = {}) => ({ ...base, id: String(n).padStart(32, "0"), name: `Item ${n}`, rev: n, folders, ...extra });

/** A fake engine whose updates change its items, as the real one does (and say so). */
function liveEngine(items) {
  const engine = fakeEngine({ items });
  const update = engine.update;
  engine.update = async (id, draft, rev) => {
    await update(id, draft, rev);
    const at = engine.items.findIndex((entry) => entry.id === id);
    if (at >= 0 && Array.isArray(draft.folders)) engine.items[at] = { ...engine.items[at], folders: [...draft.folders], rev: rev + 1 };
    engine.emit("changed", { ids: [id] });
  };
  return engine;
}

const memoryStorage = () => {
  const map = new Map();
  return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, String(v)), removeItem: (k) => void map.delete(k) };
};

const rowNames = (root) => all(root, "folder-open").map((link) => textOf(link).trim());
const updates = (engine) => engine.calls.filter((call) => call[0] === "update").map(([, id, draft]) => [id, draft]);
const prefsFor = () => createUiPrefs(null, [], { save: null });

test("the_folders_page_lists_every_folder_once_with_its_count_and_a_link_that_holds_no_name", async () => {
  await withDom(async () => {
    clearFolderLinks();
    const engine = liveEngine([item(1, ["Work", "Bank"]), item(2, ["work"]), item(3, [])]);
    const root = foldersPage({ engine, t, prefs: prefsFor(), folderLink: folderHref });
    assert.deepEqual(rowNames(root), ["Bank", "Work"]);
    assert.deepEqual(all(root, "folder-count").map((c) => textOf(c).trim()), ['folders.count_one {"count":1}', 'folders.count_many {"count":2}']);
    for (const link of all(root, "folder-open")) {
      const href = link.getAttribute("href");
      assert.match(href, /^#\/folders\/[0-9a-f]{16}$/);
      assert.ok(keyOfToken(href.split("/")[2]) !== null);
    }
    // Empty vault of folders: the way to the items.
    const none = foldersPage({ engine: liveEngine([item(1, [])]), t, prefs: prefsFor(), folderLink: folderHref });
    assert.ok(find(none, "folders-empty"));
    assert.equal(find(none, "folders-empty-items").getAttribute("href"), "#/items");
  });
});

test("renaming_a_folder_writes_each_item_in_it_once_with_its_whole_new_list", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work", "Bank"]), item(2, ["work"]), item(3, ["Home"])]);
    const prefs = prefsFor();
    prefs.pin("Work");
    const root = foldersPage({ engine, t, prefs, folderLink: folderHref });
    await click(all(root, "folder-rename").find((b) => b.getAttribute("data-key") === "work"));
    const input = find(root, "folder-new-name");
    assert.equal(input.value, "Work");
    input.value = " Jobb ";
    await submit(find(root, "folder-rename-form"));
    await settle();
    assert.deepEqual(updates(engine), [[item(1).id, { folders: ["Jobb", "Bank"] }], [item(2).id, { folders: ["Jobb"] }]]);
    assert.deepEqual(engine.expectedRevs, [1, 2], "each write is made against the item's newest revision");
    assert.ok(textOf(find(root, "message")).includes("folders.done_rename"));
    assert.deepEqual(rowNames(root), ["Bank", "Home", "Jobb"]);
    assert.deepEqual(prefs.pinned(), ["Jobb"], "the pin follows the folder");
  });
});

test("a_rename_onto_another_folder_asks_first_and_a_bad_name_is_refused_with_its_reason", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work"]), item(2, ["Home"])]);
    const root = foldersPage({ engine, t, prefs: prefsFor(), folderLink: folderHref });
    await click(all(root, "folder-rename").find((b) => b.getAttribute("data-key") === "work"));
    find(root, "folder-new-name").value = "x".repeat(65);
    await submit(find(root, "folder-rename-form"));
    assert.equal(textOf(find(root, "folder-error")).trim(), "folders.error.folder_too_long");
    find(root, "folder-new-name").value = "HOME";
    const done = submit(find(root, "folder-rename-form"));
    await settle();
    assert.ok(find(root, "dialog"), "putting two folders together is asked first");
    await click(find(root, "dialog-confirm"));
    await done;
    await settle();
    assert.deepEqual(updates(engine), [[item(1).id, { folders: ["Home"] }]]);
    assert.deepEqual(rowNames(root), ["Home"]);
  });
});

test("deleting_a_folder_asks_and_takes_the_label_off_its_items_which_stay", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work", "Bank"]), item(2, ["Work"]), item(3, ["Bank"])]);
    const prefs = prefsFor();
    prefs.pin("Work");
    const root = foldersPage({ engine, t, prefs, folderLink: folderHref });
    const asked = click(all(root, "folder-delete").find((b) => b.getAttribute("data-key") === "work"));
    await settle();
    assert.ok(textOf(find(root, "dialog")).includes("folders.delete_body_many"));
    await click(find(root, "dialog-confirm"));
    await asked;
    await settle();
    assert.deepEqual(updates(engine), [[item(1).id, { folders: ["Bank"] }], [item(2).id, { folders: [] }]]);
    assert.equal(engine.calls.some((call) => call[0] === "remove"), false, "no item is deleted");
    assert.deepEqual(rowNames(root), ["Bank"]);
    assert.deepEqual(prefs.pinned(), [], "the pin of a deleted folder goes");
  });
});

test("a_run_that_fails_on_some_items_says_how_many_and_the_first_reason_and_keeps_the_pin", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work"]), item(2, ["Work"], { readOnly: true }), item(3, ["Work"])]);
    const update = engine.update;
    engine.update = async (id, draft, rev) => {
      if (id === item(3).id) throw coded("item_changed");
      return update(id, draft, rev);
    };
    const prefs = prefsFor();
    prefs.pin("Work");
    const root = foldersPage({ engine, t, prefs, folderLink: folderHref });
    await click(all(root, "folder-rename")[0]);
    find(root, "folder-new-name").value = "Jobb";
    await submit(find(root, "folder-rename-form"));
    await settle();
    const text = textOf(find(root, "message"));
    for (const part of ["folders.done_rename", "folders.done_skipped", "folders.done_failed", "vault.error.item_changed"]) assert.ok(text.includes(part), part);
    assert.deepEqual(prefs.pinned(), ["Work"], "the old folder still has items, so the pin stays with it");
  });
});

test("pinning_from_the_folders_page_and_from_a_folders_bar", async () => {
  await withDom(async () => {
    const prefs = prefsFor();
    const root = foldersPage({ engine: liveEngine([item(1, ["Work"])]), t, prefs, folderLink: folderHref });
    const pin = find(root, "folder-pin");
    assert.equal(pin.getAttribute("aria-pressed"), "false");
    await click(pin);
    assert.deepEqual(prefs.pinned(), ["Work"]);
    assert.equal(find(root, "folder-pin").getAttribute("aria-pressed"), "true");
    const bar = folderBar({ t, name: "Work", prefs });
    assert.equal(find(bar, "folder-pin").getAttribute("aria-pressed"), "true");
    await click(find(bar, "folder-pin"));
    assert.deepEqual(prefs.pinned(), []);
    assert.equal(find(bar, "folders-link").getAttribute("href"), "#/folders");
  });
});

test("a_lock_wipes_the_folders_page", async () => {
  await withDom(async () => {
    const scope = createWipeScope();
    const root = foldersPage({ engine: liveEngine([item(1, ["Secret project"])]), t, prefs: prefsFor(), folderLink: folderHref, scope });
    assert.ok(textOf(root).includes("Secret project"));
    scope.run();
    assert.equal(textOf(root).includes("Secret project"), false);
  });
});

test("move_to_folder_sets_the_folders_of_one_item_or_adds_to_several", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work"]), item(2, ["Home"]), item(3, [])]);
    const host = el("div", null);
    const one = moveDialog({ t, host, engine, ids: [item(1).id] });
    assert.ok(textOf(host).includes("folders.move.title_one"));
    assert.deepEqual(all(host, "folder-picked-chip").map((c) => textOf(c).trim()), ["Work"]);
    await click(all(host, "folder-offer").find((b) => b.getAttribute("data-folder") === "Home"));
    await click(find(host, "dialog-confirm"));
    assert.ok((await one).includes("folders.done_move"));
    assert.deepEqual(updates(engine), [[item(1).id, { folders: ["Work", "Home"] }]]);
    assert.equal(find(host, "folder-dialog"), null, "the dialog is gone");

    // Several: the chosen folders are added; an item that has them already is not written.
    const many = moveDialog({ t, host, engine, ids: [item(1).id, item(2).id, item(3).id] });
    find(host, "folder-input").value = "home";
    await click(find(host, "folder-add"));
    await click(find(host, "dialog-confirm"));
    await many;
    assert.deepEqual(updates(engine).slice(1), [[item(3).id, { folders: ["Home"] }]]);

    // Cancel writes nothing; neither does a save with no change.
    const before = updates(engine).length;
    const cancelled = moveDialog({ t, host, engine, ids: [item(2).id] });
    await click(find(host, "dialog-cancel"));
    assert.equal(await cancelled, "");
    const same = moveDialog({ t, host, engine, ids: [item(2).id] });
    await click(find(host, "dialog-confirm"));
    assert.ok((await same).includes("folders.done_none"));
    assert.equal(updates(engine).length, before);
  });
});

test("the_list_of_one_folder_has_its_name_as_heading_and_its_items_whatever_the_case", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work"]), item(2, ["work"]), item(3, ["Home"])]);
    const root = listView({ engine, router: { go() {} }, t, prefs: createListPrefs(memoryStorage()), folder: "WORK", folderLink: folderHref });
    assert.equal(textOf(find(root, "list-title")).trim(), "Work", "the heading is the folder's name as the vault shows it");
    assert.deepEqual(all(root, "item-link").map((link) => textOf(link).trim()), ["Item 1", "Item 2"]);
    // The folder column: the first label is a link to the folder's page, the rest a count.
    const cell = find(root, "folder-link");
    assert.match(cell.getAttribute("href"), /^#\/folders\/[0-9a-f]{16}$/);
  });
});

test("the_list_groups_a_folder_written_in_two_cases_as_one_in_its_filter", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work", "Bank"]), item(2, ["work"]), item(3, [])]);
    const root = listView({ engine, router: { go() {} }, t, prefs: createListPrefs(memoryStorage()) });
    await click(find(root, "folders-chip"));
    const options = all(root, "folders-menu").flatMap((menu) => [...menu.childNodes]).map((node) => node.getAttribute("data-value"));
    assert.deepEqual(options, ["Bank", "Work"]);
    const work = all(root, "folders-menu")[0].childNodes.find((node) => node.getAttribute("data-value") === "Work");
    assert.ok(textOf(work).includes("2"));
  });
});

test("the_row_menu_and_the_item_menu_open_move_to_folder_in_the_screens_own_place", async () => {
  await withDom(async () => {
    const engine = liveEngine([item(1, ["Work"])]);
    const calls = [];
    const root = listView({ engine, router: { go() {} }, t, prefs: createListPrefs(memoryStorage()), moveToFolder: (items, where) => calls.push([items.map((i) => i.id), where]) });
    await click(find(root, "row-menu"));
    await click(find(root, "row-move"));
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0][0], [item(1).id]);
    assert.equal(calls[0][1].host, find(root, "dialog-host"));
    calls[0][1].say("done");
    assert.ok(textOf(find(root, "message")).includes("done"));
  });
});

test("the_side_menu_shows_the_pinned_folders_the_items_have_and_follows_a_rename", async () => {
  await withDom(async () => {
    clearFolderLinks();
    const engine = liveEngine([item(1, ["Work"]), item(2, ["Bank"])]);
    const prefs = prefsFor();
    prefs.pin("WORK");
    prefs.pin("Gone");
    const scope = createWipeScope();
    const root = shellView({
      t, engine, session: { onLock() {} }, content: el("p", null, "x"), lock: async () => {}, touch: () => true, scope, onLocked: () => el("div"),
      routes: [], prefs, win: {},
    });
    const pinned = () => all(root, "nav-folder").map((link) => textOf(link).trim());
    assert.deepEqual(pinned(), ["Work"], "a pin of a folder with no items is hidden, not dropped");
    assert.deepEqual(prefs.pinned(), ["WORK", "Gone"]);
    assert.match(all(root, "nav-folder")[0].getAttribute("href"), /^#\/folders\/[0-9a-f]{16}$/);
    // Another device renamed it: the items change, the pin is of the old name, so the entry goes.
    await engine.update(item(1).id, { folders: ["Jobb"] }, 1);
    assert.deepEqual(pinned(), []);
    // Pinning from another screen shows at once.
    prefs.pin("Bank");
    assert.deepEqual(pinned(), ["Bank"]);
    // A lock forgets the pins and the tokens.
    scope.run();
    prefs.clearPins();
    assert.deepEqual(prefs.pinned(), []);
  });
});
