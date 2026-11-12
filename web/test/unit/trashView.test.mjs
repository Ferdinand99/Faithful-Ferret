// The local trash view: names and dates from the engine's memory, restore, and
// "remove for good" only after a yes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createWipeScope, formatMoment } from "../../src/views/common.mjs";
import { trashView } from "../../src/views/trash.mjs";
import { fakeConflictEngine } from "./conflictHelpers.mjs";
import { all, click, coded, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const id = (n) => n.toString(16).padStart(2, "0").repeat(16);
const DAY = 86_400_000;
const NOW = 1_700_000_000_000;
const ENTRIES = [
  { id: id(1), name: "Old router", deletedAt: NOW - 3 * DAY },
  { id: id(2), name: "Bank", deletedAt: NOW - DAY },
  { id: id(3), name: "", deletedAt: NOW - 2 * DAY },
];

async function open({ trash = ENTRIES, touch, scope = createWipeScope() } = {}) {
  const engine = fakeConflictEngine({ trash });
  const root = await trashView({ engine, t, locale: "en", touch, scope });
  return { engine, root, scope };
}

const names = (root) => all(root, "trash-name").map((n) => textOf(n).trim());

test("trash_lists_names_from_memory_only_and_restores", async () => {
  await withDom(async () => {
    // The engine hands over names and dates; a stray field (the sealed copy) never reaches the page.
    const withSealed = ENTRIES.map((e) => ({ ...e, envelope: "SEALED-BYTES", tag: "SEALED-TAG", plaintext: "SECRET-BODY" }));
    const { root, engine } = await open({ trash: withSealed });
    assert.deepEqual(engine.calls, [["trash"]], "the one call is the list; nothing else is read");
    assert.deepEqual(names(root), ["Bank", "vault.item.unnamed", "Old router"], "newest deletion first, a missing name as unnamed");
    assert.ok(textOf(root).includes(formatMoment(NOW - DAY, "en")));
    for (const hidden of ["SEALED-BYTES", "SEALED-TAG", "SECRET-BODY"]) assert.ok(!textOf(root).includes(hidden));

    const bank = all(root, "trash-item").find((n) => n.getAttribute("data-id") === id(2));
    await click(find(bank, "restore"));
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "restoreFromTrash"), [["restoreFromTrash", id(2)]]);
    assert.deepEqual(names(root), ["vault.item.unnamed", "Old router"], "the restored item leaves the trash");
    assert.ok(textOf(find(root, "message")).includes("conflict.trash.restored"));
    assert.ok(textOf(find(root, "message")).includes("Bank"));

    // The page does not read the store and holds no ciphertext: it only knows the engine.
    const source = readFileSync(new URL("../../src/views/trash.mjs", import.meta.url), "utf8");
    assert.ok(!/store\/|trash\.get|trash\.all|envelope|indexedDB/.test(source.replace(/\/\/.*$/gm, "")));
  });
});

test("an_empty_trash_says_so", async () => {
  await withDom(async () => {
    const { root } = await open({ trash: [] });
    assert.ok(textOf(find(root, "trash-empty")).includes("conflict.trash.empty"));
    assert.equal(all(root, "trash-item").length, 0);
    assert.equal(find(root, "back").getAttribute("href"), "#/items");
  });
});

test("remove_from_trash_asks_first", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    const row = () => all(root, "trash-item").find((n) => n.getAttribute("data-id") === id(1));
    const first = click(find(row(), "remove"));
    await settle();
    const dialog = find(root, "dialog");
    assert.ok(dialog, "a question is on the page");
    assert.ok(textOf(dialog).includes("conflict.trash.remove_title"));
    assert.ok(textOf(dialog).includes("Old router"));
    assert.deepEqual(engine.calls.filter((c) => c[0] === "removeFromTrash"), [], "nothing is removed before the yes");

    await click(find(root, "dialog-cancel"));
    await first;
    assert.equal(find(root, "dialog"), null);
    assert.deepEqual(engine.calls.filter((c) => c[0] === "removeFromTrash"), []);
    assert.equal(names(root).length, 3);

    const second = click(find(row(), "remove"));
    await settle();
    await click(find(root, "dialog-confirm"));
    await second;
    await settle();
    assert.deepEqual(engine.calls.filter((c) => c[0] === "removeFromTrash"), [["removeFromTrash", id(1)]]);
    assert.ok(!names(root).includes("Old router"));
    assert.ok(textOf(find(root, "message")).includes("conflict.trash.removed"));
  });
});

test("a_failed_restore_says_so_and_keeps_the_entry", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    engine.failWith = coded("quota_exceeded");
    const first = all(root, "trash-item")[0];
    await click(find(first, "restore"));
    await settle();
    assert.ok(textOf(find(root, "message")).includes("sync.error.quota_exceeded"));
    assert.equal(names(root).length, 3);
    // A failure the page has no text for shows the general one, never the message.
    engine.failWith = Object.assign(new Error("secret-detail"), { code: "weird" });
    await click(find(all(root, "trash-item")[0], "restore"));
    assert.ok(textOf(find(root, "message")).includes("vault.error.unknown"));
    assert.ok(!textOf(root).includes("secret-detail"));
  });
});

test("a_list_that_cannot_be_read_says_so", async () => {
  await withDom(async () => {
    const engine = fakeConflictEngine();
    engine.failTrash = coded("storage");
    const root = await trashView({ engine, t });
    assert.ok(textOf(find(root, "message")).includes("sync.error.storage"));
    assert.equal(all(root, "trash-item").length, 0);
  });
});

test("one_action_runs_at_a_time", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    const button = find(all(root, "trash-item")[0], "restore");
    await Promise.all([click(button), click(button)]);
    await settle();
    assert.equal(engine.calls.filter((c) => c[0] === "restoreFromTrash").length, 1);
  });
});

test("the_trash_leaves_the_page_when_the_vault_locks_and_ignores_actions_after_the_lock_time", async () => {
  await withDom(async () => {
    const { root, scope } = await open();
    assert.ok(names(root).length > 0);
    scope.run();
    assert.equal(root.childNodes.length, 0);
    assert.ok(!textOf(root).includes("Bank"));

    const idle = await open({ touch: () => false });
    await click(find(all(idle.root, "trash-item")[0], "restore"));
    await click(find(all(idle.root, "trash-item")[0], "remove"));
    assert.deepEqual(idle.engine.calls.filter((c) => c[0] !== "trash"), []);
    assert.equal(find(idle.root, "dialog"), null);
  });
});

test("the_trash_reads_again_when_the_engine_says_something_changed", async () => {
  await withDom(async () => {
    const { root, engine, scope } = await open();
    assert.equal(names(root).length, 3);
    // Another device deleted one more item, and the engine says so.
    engine.trashed.push({ id: id(4), name: "Laptop", deletedAt: NOW });
    engine.emit("changed", { ids: [id(4)] });
    await settle();
    assert.equal(names(root).length, 4);
    assert.equal(names(root)[0], "Laptop");
    // An item restored somewhere else leaves the list.
    engine.trashed = engine.trashed.filter((e) => e.id !== id(2));
    engine.emit("changed", { ids: [id(2)] });
    await settle();
    assert.ok(!names(root).includes("Bank"));
    // After the lock it reads nothing: the names stay where they are.
    scope.run();
    const reads = engine.calls.length;
    engine.emit("changed", { ids: [] });
    await settle();
    assert.equal(engine.calls.length, reads);
    assert.equal(root.childNodes.length, 0);
  });
});

test("a_failure_after_the_lock_writes_to_no_node", async () => {
  await withDom(async () => {
    const { root, engine, scope } = await open();
    const message = find(root, "message");
    let fail;
    engine.restoreFromTrash = () => new Promise((_, reject) => {
      fail = reject;
    });
    const pending = click(find(all(root, "trash-item")[0], "restore"));
    await settle(3);
    scope.run();
    fail(coded("storage"));
    await pending;
    await settle();
    assert.equal(textOf(message).trim(), "");
  });
});
