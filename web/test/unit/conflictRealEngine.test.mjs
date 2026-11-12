// The conflict view and the trash view driven by the REAL sync engine (over the fake server, the fake core and the real stores of
// the engine tests), not by a stand-in: what the screens are given by `conflict`, `resolve` and the trash, and what the engine
// writes when a choice is made. Reveals go through the fake core's open handles, as the worker's reveal calls do.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { conflictView } from "../../src/views/conflict.mjs";
import { trashView } from "../../src/views/trash.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import { EN, textFor, translator, withFocus } from "./syncWarningsHelpers.mjs";
import { createFakeClient, currentRev, Model, settle as settleEngine, syncDevice, until } from "./syncHelpers.mjs";
import { all, click, find, settle, textOf } from "./vaultHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);
const ID_D = "44".repeat(16);

const USER = (value) => ({ id: "username", label: "User", kind: "text", value });
const PASS = (value) => ({ id: "password", label: "Password", kind: "password", value });
const body = (name, fields = [USER("alice"), PASS("first")]) => ({ item_type: "login", name, fields });
const setRow = (model, client, id, rev, content, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, content), ...extra });
const setTomb = (model, client, id, rev, extra = {}) => model.set(id, { rev, deleted: true, tomb: client.wireTomb(id, rev), ...extra });
const itemOf = (d, id) => d.engine.list().find((entry) => entry.id === id);
const conflictsOf = (d) => d.engine.list().filter((entry) => entry.conflict).map((entry) => entry.id);

/** Runs a test body with a fake document whose elements start with the properties a real one has, and a focus. */
const withDom = (run) => {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  return withFocus(run).finally(() => {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  });
};

/** The worker's reveal calls, over the handles the fake core has open. */
const revealClient = (d) => ({
  vault: {
    async reveal_item_field(handle, index) {
      const open = d.client.vault.handles.get(handle);
      if (!open) throw Object.assign(new Error("invalid_handle"), { code: "invalid_handle" });
      return open.body.fields[index].value;
    },
    async reveal_item_notes(handle) {
      const open = d.client.vault.handles.get(handle);
      if (!open) throw Object.assign(new Error("invalid_handle"), { code: "invalid_handle" });
      return open.body.notes ?? "";
    },
  },
});

/** The view over the real engine. */
async function openView(d, id, { t = translator() } = {}) {
  const scope = createWipeScope();
  const moves = [];
  const root = await conflictView({ engine: d.engine, client: revealClient(d), id, t, router: { go: (path) => moves.push(path) }, locale: "en", scope });
  return { root, scope, moves };
}

/** Presses a choice and answers the question that comes first with yes. */
async function choose(root, role) {
  const pending = click(find(root, role));
  await settle();
  assert.ok(find(root, "dialog"), "a question comes first");
  await click(find(root, "dialog-confirm"));
  await pending;
  await settle();
}

/** One device with A at revision 1; another device then writes revision 2 (or deletes A), and this device changes A: a conflict. */
async function conflictWorld({ deletedThere = false } = {}) {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("Original"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  if (deletedThere) setTomb(model, client, ID_A, 2);
  else setRow(model, client, ID_A, 2, body("Server name", [USER("bob"), PASS("server-pass")]));
  await d.engine.update(ID_A, { name: "Local name", fields: [USER("alice"), PASS("local-pass")] }, currentRev(d.engine, ID_A));
  await until(() => d.events.error.some((e) => e.code === "conflict"), "the conflict");
  await until(() => (deletedThere ? itemOf(d, ID_A)?.conflict === true && d.client.vault.calls.some((c) => c[0] === "verify_tombstone" && c[2] === 2) : itemOf(d, ID_A)?.rev === 2), "the server's version");
  await settleEngine(10);
  return d;
}

/** A device whose server was restored from a backup, as the restore tests have it: it has stopped with `server_restored`. */
async function restoredWorld() {
  const model = new Model();
  const client = createFakeClient();
  const row = (id, rev, name) => setRow(model, client, id, rev, body(name), {});
  row(ID_A, 3, "A");
  row(ID_B, 3, "B");
  setTomb(model, client, ID_C, 4);
  row(ID_D, 1, "D");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.items.clear();
  setRow(model, client, ID_A, 2, body("A old"), { seq: 1 });
  setTomb(model, client, ID_B, 2, { seq: 2 });
  setRow(model, client, ID_C, 3, body("C old"), { seq: 3 });
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  return d;
}

test("keep_mine_with_the_real_engine_shows_both_versions_and_writes_mine_on_top", async () => {
  await withDom(async () => {
    const d = await conflictWorld();
    const { root, scope, moves } = await openView(d, ID_A);
    // Both versions, from the engine's data: names, devices, and the rows that differ first.
    const [local, server] = all(root, "side");
    assert.equal(textOf(find(local, "name")).trim(), "Local name");
    assert.equal(textOf(find(server, "name")).trim(), "Server name");
    assert.equal(find(root, "conflict-field", "username").getAttribute("data-same"), "differs");
    assert.equal(find(root, "conflict-field", "password").getAttribute("data-same"), "hidden");
    assert.equal(textOf(find(root, "value", "local.username")).trim(), "alice");
    assert.equal(textOf(find(root, "value", "server.username")).trim(), "bob");
    assert.equal(textOf(find(root, "keep-mine")).trim(), EN["conflict.choice.keep_mine"]);
    // One secret at a time, read through the handles the engine opened for each version.
    await click(find(root, "reveal", "local.password"));
    assert.ok(textOf(root).includes("local-pass"));
    await click(find(root, "reveal", "server.password"));
    assert.ok(textOf(root).includes("server-pass"));
    assert.ok(!textOf(root).includes("local-pass"));
    assert.equal(d.client.vault.handles.size, 2, "the engine holds one handle for each version while the view is shown");

    await choose(root, "keep-mine");
    assert.ok(!textOf(root).includes("server-pass"));
    assert.deepEqual(moves, [`/items/${ID_A}`]);
    await until(() => d.model.items.get(ID_A).rev === 3, "mine is on the server on top of revision 2");
    const sent = JSON.parse(d.model.writes.at(-1).body);
    assert.equal(sent.base_rev, 2);
    assert.equal(sent.resurrect, undefined);
    await until(() => itemOf(d, ID_A) && !itemOf(d, ID_A).conflict && itemOf(d, ID_A).name === "Local name", "the item is no longer in conflict");
    scope.run();
    await settleEngine(5);
    assert.equal(d.client.vault.handles.size, 0, "the view's handles are closed");
    d.engine.stop();
  });
});

test("a_stale_view_gets_not_found_from_the_engine_and_says_the_item_is_not_in_conflict_any_more", async () => {
  await withDom(async () => {
    const d = await conflictWorld();
    const first = await openView(d, ID_A);
    const second = await openView(d, ID_A);
    await choose(first.root, "keep-theirs");
    assert.deepEqual(first.moves, [`/items/${ID_A}`]);
    // The second view hears of the change and reads the item again: it says there is nothing to choose.
    await until(() => find(second.root, "no-conflict") !== null, "the second view has read the item again");
    assert.ok(textOf(find(second.root, "no-conflict")).includes(EN["conflict.not_in_conflict"]));
    assert.equal(all(second.root, "keep-mine").length, 0);
    assert.deepEqual(second.moves, [], "nothing was chosen");
    // And the engine itself refuses a choice for a conflict that is not there (a tab that never heard of the change).
    const written = d.model.writes.length;
    await assert.rejects(() => d.engine.resolve(ID_A, "mine"), { code: "not_found" });
    assert.equal(d.model.writes.length, written, "nothing was written");
    first.scope.run();
    second.scope.run();
    d.engine.stop();
  });
});

test("keep_theirs_over_a_deleted_row_goes_to_the_trash_and_the_trash_view_brings_it_back", async () => {
  await withDom(async () => {
    const d = await conflictWorld({ deletedThere: true });
    const { root, scope, moves } = await openView(d, ID_A);
    // The server's side is a deletion: its own words, and nothing to show on that side.
    assert.ok(textOf(all(root, "side")[1]).includes(EN["conflict.deleted_server"]));
    assert.equal(textOf(find(root, "keep-mine")).trim(), EN["conflict.choice.restore"]);
    assert.equal(textOf(find(root, "keep-theirs")).trim(), EN["conflict.choice.accept_deletion"]);
    assert.equal(all(root, "reveal", "server.password").length, 0);
    await click(find(root, "reveal", "local.password"));
    assert.ok(textOf(root).includes("local-pass"));

    await choose(root, "keep-theirs");
    assert.deepEqual(moves, ["/items"], "the item is gone: back to the list");
    assert.equal(itemOf(d, ID_A), undefined);

    // The version the user dropped is the newest copy: it is in the trash, named, and can be restored.
    const trashScope = createWipeScope();
    const page = await trashView({ engine: d.engine, t: translator(), locale: "en", scope: trashScope });
    assert.deepEqual(all(page, "trash-name").map((n) => textOf(n).trim()), ["Local name"]);
    await click(find(find(page, "trash-item"), "restore"));
    await until(() => d.model.items.get(ID_A).deleted === false, "restored on the server");
    const sent = JSON.parse(d.model.writes.at(-1).body);
    assert.deepEqual([sent.base_rev, sent.resurrect], [2, true]);
    assert.ok(textOf(find(page, "message")).includes(textFor(EN, "conflict.trash.restored", { name: "Local name" })));
    assert.equal(all(page, "trash-item").length, 0, "it has left the trash");
    assert.ok(textOf(find(page, "trash-empty")).includes(EN["conflict.trash.empty"]));
    await until(() => itemOf(d, ID_A)?.name === "Local name", "the item is back in the list");
    trashScope.run();
    scope.run();
    d.engine.stop();
  });
});

test("many_conflicts_after_accepting_an_older_state_are_stepped_through_with_next_conflict", async () => {
  await withDom(async () => {
    const d = await restoredWorld();
    assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 1, conflicts: 3, manifestOlder: false });
    const ids = conflictsOf(d);
    assert.deepEqual([...ids].sort(), [ID_A, ID_B, ID_C]);

    // Each conflict opens with the real data; the link goes to the next one in the list and round again to the first.
    const visited = [];
    let id = ids[0];
    for (let step = 0; step < 3; step += 1) {
      const { root, scope } = await openView(d, id);
      assert.equal(find(root, "no-conflict"), null, `${id} opens`);
      assert.ok(all(root, "side").length === 2);
      assert.ok(textOf(find(root, "more-conflicts")).includes(textFor(EN, "conflict.others", { count: 2 })));
      const href = find(find(root, "more-conflicts"), "next-conflict").getAttribute("href");
      visited.push(id);
      scope.run();
      id = /^#\/items\/([0-9a-f]{32})\/conflict$/.exec(href)[1];
    }
    assert.deepEqual(visited, ids, "in list order");
    assert.equal(id, ids[0], "and round to the first again");
    await settleEngine(5);
    assert.equal(d.client.vault.handles.size, 0, "every view closed its handles");

    // The item the restored server deleted offers the deletion; the one this device had deleted offers its own deletion or the
    // server's version; the one that is live on both sides offers the plain choices.
    const deleted = await openView(d, ID_B);
    assert.equal(textOf(find(deleted.root, "keep-theirs")).trim(), EN["conflict.choice.accept_deletion"]);
    const live = await openView(d, ID_C);
    assert.equal(textOf(find(live.root, "keep-mine")).trim(), EN["conflict.choice.delete_mine"]);
    assert.equal(textOf(find(live.root, "keep-theirs")).trim(), EN["conflict.choice.keep_server_version"]);
    const both = await openView(d, ID_A);
    assert.equal(textOf(find(both.root, "keep-theirs")).trim(), EN["conflict.choice.keep_theirs"]);
    both.scope.run();
    // Deciding one shortens the list for the others.
    await choose(live.root, "keep-theirs");
    assert.deepEqual(live.moves, [`/items/${ID_C}`]);
    assert.deepEqual([...conflictsOf(d)].sort(), [ID_A, ID_B]);
    const again = await openView(d, ID_A);
    assert.ok(textOf(find(again.root, "more-conflicts")).includes(textFor(EN, "conflict.others", { count: 1 })));
    assert.equal(find(find(again.root, "more-conflicts"), "next-conflict").getAttribute("href"), `#/items/${ID_B}/conflict`);
    for (const view of [deleted, live, again]) view.scope.run();
    await settleEngine(10);
    assert.equal(d.client.vault.handles.size, 0);
    d.engine.stop();
  });
});
