// The sync engine and conflicts: what a refused write becomes, what the user is shown, and what each choice writes.
// Keep mine writes the sealed local version on top of the server's revision (over a deleted row as a resurrection), keep
// theirs drops the draft, and nothing is ever merged.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { compareFields } from "../../src/sync/conflict.mjs";
import { ACCOUNT, scope, SERVER } from "./idbHelpers.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { createFakeClient, currentRev, Model, settle, syncDevice, until } from "./syncHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);
const ID_D = "44".repeat(16);

const USER = (value) => ({ id: "username", label: "User", kind: "text", value });
const PASS = (value) => ({ id: "password", label: "Password", kind: "password", value });
const body = (name, fields = [USER("alice"), PASS("first")]) => ({ item_type: "login", name, fields });

const setRow = (model, client, id, rev, content, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, content), ...extra });
const setTomb = (model, client, id, rev, extra = {}) => model.set(id, { rev, deleted: true, tomb: client.wireTomb(id, rev), ...extra });
const queued = (d) => outbox.all(d.store.database.store, scope());
const settingKey = () => `sync.flags.${scope().accountId}.${scope().vaultId}.${scope().vkEpoch}`;
const savedFlags = (d) => d.store.getSetting(d.store.database.store, settingKey());
const itemOf = (d, id = ID_A) => d.engine.list().find((entry) => entry.id === id);
const requests = (d) => d.api.puts.map((put) => ({ id: put.id, ...JSON.parse(put.text) }));
/** The same browser again after the page was closed: the storage and the locks stay, everything else is new. */
const reload = (d) => syncDevice({ model: d.model, client: d.client, db: d.store.database, locks: d.locks });
/** The view of a sealed row, by opening it with the core. */
async function viewOf(d, id, rev, blob, tag) {
  const handle = await d.client.vault.open_item(hex16.decode(id), rev, typeof blob === "string" ? b64u.decode(blob) : blob, typeof tag === "string" ? b64u.decode(tag) : tag);
  try {
    return await d.client.vault.item_view(handle);
  } finally {
    await d.client.vault.close_item(handle);
  }
}
const serverView = (d, id = ID_A) => {
  const row = d.model.items.get(id);
  return viewOf(d, id, row.rev, row.blob, row.tag);
};

/**
 * One device with A at revision 1. Another device then writes revision 2 (`theirs`, or a tombstone), and this device changes A
 * from revision 1 (`mine`, or deletes it): the server refuses it as a conflict.
 */
async function conflictWorld({ theirs = body("Server name", [USER("bob"), PASS("first")]), mine = { name: "Local name" }, deleteHere = false, deletedThere = false } = {}) {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("Original"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal(itemOf(d).name, "Original");
  if (deletedThere) setTomb(model, client, ID_A, 2);
  else setRow(model, client, ID_A, 2, theirs);
  if (deleteHere) await d.engine.remove(ID_A);
  else await d.engine.update(ID_A, mine, currentRev(d.engine, ID_A));
  await until(() => d.events.error.some((e) => e.code === "conflict"), "the conflict");
  // The server's version arrives through the feed (a live row is shown; a tombstone is verified and leaves the item as the draft).
  await until(() => (deletedThere ? itemOf(d)?.conflict === true && d.client.vault.calls.some((c) => c[0] === "verify_tombstone" && c[2] === 2) : itemOf(d)?.rev === 2), "the server's version");
  await settle(10);
  return d;
}

test("409_marks_a_conflict_keeps_the_sealed_local_version_and_shows_the_server_version", async () => {
  const d = await conflictWorld();
  const item = itemOf(d);
  assert.deepEqual([item.conflict, item.blocked, item.blockedReason], [true, true, "conflict"]);
  assert.deepEqual([item.name, item.rev], ["Server name", 2], "the screen shows the server's version");
  const event = d.events.error.find((e) => e.code === "conflict");
  assert.deepEqual([event.id, event.currentRev, event.deleted], [ID_A, 2, false]);

  // The local version is the sealed draft in the outbox, built on revision 1 and openable at revision 2.
  const [draft] = await queued(d);
  assert.equal(draft.baseRev, 1);
  assert.equal((await viewOf(d, ID_A, 2, draft.body.blob, draft.body.tag)).name, "Local name");
  // The mark is saved: what the server showed, and that it is a conflict.
  const saved = await savedFlags(d);
  assert.deepEqual(saved.blocked, { [ID_A]: "conflict" });
  assert.deepEqual(saved.conflicts, { [ID_A]: { serverRev: 2, serverDeleted: false } });
  // Nothing was sent again, and the item cannot be edited meanwhile.
  assert.equal(requests(d).length, 1);
  await assert.rejects(() => d.engine.update(ID_A, { name: "Again" }, 2), { code: "blocked", reason: "conflict" });
  d.engine.stop();
});

test("conflict_survives_restart", async () => {
  const d = await conflictWorld();
  d.engine.stop();
  const back = await reload(d);
  await back.engine.start();
  back.timers.advance(120_000);
  await settle(20);
  const item = itemOf(back);
  assert.deepEqual([item.conflict, item.blocked, item.name, item.rev], [true, true, "Server name", 2]);
  assert.equal(back.api.puts.length, 0, "a draft that waits for the user is not sent");
  const shown = await back.engine.conflict(ID_A);
  assert.deepEqual([shown.local.view.name, shown.server.view.name], ["Local name", "Server name"]);
  await shown.close();
  back.engine.stop();
});

test("conflict_survives_restart_when_the_server_deleted_the_item", async () => {
  const d = await conflictWorld({ deletedThere: true });
  assert.equal(itemOf(d).name, "Local name", "the draft stays on screen over a deleted server row");
  d.engine.stop();
  const back = await reload(d);
  await back.engine.start();
  const item = itemOf(back);
  assert.deepEqual([item.conflict, item.name], [true, "Local name"]);
  const shown = await back.engine.conflict(ID_A);
  assert.deepEqual([shown.server.deleted, shown.server.view, shown.server.handle, shown.server.rev], [true, null, null, 2]);
  await shown.close();
  back.engine.stop();
});

test("a_conflict_saved_before_the_note_existed_is_read_from_the_rows", async () => {
  const d = await conflictWorld();
  d.engine.stop();
  const saved = await savedFlags(d);
  delete saved.conflicts;
  await d.store.setSetting(d.store.database.store, settingKey(), saved);
  const back = await reload(d);
  await back.engine.start();
  assert.equal(itemOf(back).conflict, true);
  const shown = await back.engine.conflict(ID_A);
  assert.equal(shown.server.rev, 2);
  await shown.close();
  back.engine.stop();
});

test("conflict_view_data_compares_visible_fields_and_leaves_hidden_ones_unknown", async () => {
  const d = await conflictWorld({
    theirs: body("Server name", [USER("bob"), PASS("server secret"), { id: "site", label: "Site", kind: "text", value: "https://x.example" }]),
    mine: { name: "Local name", fields: [USER("alice"), PASS("local secret"), { id: "pin", label: "PIN", kind: "hidden", value: "1234" }, { id: "site", label: "Site", kind: "text", value: "https://x.example" }] },
  });
  const shown = await d.engine.conflict(ID_A);
  const same = Object.fromEntries(shown.fields.map((field) => [field.key, field.same]));
  assert.deepEqual(same, { username: false, password: null, pin: false, site: true });
  assert.deepEqual(shown.fields.find((field) => field.key === "pin"), { key: "pin", label: "PIN", kind: "hidden", same: false });
  assert.equal(JSON.stringify(shown.fields).includes("secret"), false, "no secret leaves the core in the comparison");
  assert.equal(JSON.stringify(shown.fields).includes("1234"), false);
  assert.deepEqual([shown.local.rev, shown.local.deleted, shown.local.view.name], [2, false, "Local name"]);
  assert.deepEqual([shown.server.rev, shown.server.deleted, shown.server.view.name], [2, false, "Server name"]);
  assert.equal(typeof shown.local.handle, "number");
  assert.equal(typeof shown.server.handle, "number");
  // The views carry no secret value either: that is what the handles are for.
  assert.equal(shown.local.view.fields.find((field) => field.id === "password").value, null);
  assert.equal(shown.server.view.fields.find((field) => field.id === "password").value, null);
  await shown.close();
  d.engine.stop();
});

test("compare_fields_treats_a_missing_side_a_changed_kind_and_two_hidden_values", () => {
  const view = (fields) => ({ fields });
  assert.deepEqual(compareFields(null, view([{ id: "a", label: "A", kind: "text", value: "x" }])), [{ key: "a", label: "A", kind: "text", same: false }]);
  assert.deepEqual(compareFields(view([{ id: "a", kind: "text", value: "x" }]), view([{ id: "a", kind: "password", value: null }])).map((f) => f.same), [false]);
  assert.deepEqual(compareFields(view([{ id: "a", kind: "password", value: null }]), view([{ id: "a", kind: "password", value: null }])).map((f) => f.same), [null]);
  assert.deepEqual(compareFields(view([{ id: "a", kind: "text", value: "x" }]), view([{ id: "a", kind: "text", value: "x" }])).map((f) => f.same), [true]);
  assert.deepEqual(compareFields(null, null), []);
});

test("conflict_handles_are_closed_by_close_and_by_stop", async () => {
  const d = await conflictWorld();
  const open = () => d.client.vault.handles.size;
  const before = open();
  const first = await d.engine.conflict(ID_A);
  assert.equal(open(), before + 2, "one handle for each side");
  await first.close();
  assert.equal(open(), before);
  await first.close(); // closing again is harmless
  assert.equal(open(), before);

  const second = await d.engine.conflict(ID_A);
  assert.equal(open(), before + 2);
  d.engine.stop();
  await settle(5);
  assert.equal(open(), 0, "stop closes what a screen left open");
  await second.close();
});

test("a_conflict_that_cannot_be_opened_leaves_no_handle_behind", async () => {
  const d = await conflictWorld();
  const before = d.client.vault.handles.size;
  const open = d.client.vault.item_view;
  d.client.vault.item_view = async () => {
    throw new Error("the view failed");
  };
  await assert.rejects(() => d.engine.conflict(ID_A), /view failed/);
  d.client.vault.item_view = open;
  assert.equal(d.client.vault.handles.size, before);
  d.engine.stop();
});

test("asking_for_the_conflict_of_an_item_without_one_is_not_found", async () => {
  const d = await conflictWorld();
  await assert.rejects(() => d.engine.conflict(ID_B), { code: "not_found" });
  await assert.rejects(() => d.engine.conflict("nothex"), { code: "not_found" });
  await assert.rejects(() => d.engine.resolve(ID_B, "mine"), { code: "not_found" });
  await assert.rejects(() => d.engine.resolve(ID_A, "both"), TypeError);
  d.engine.stop();
});

test("keep_theirs_discards_the_draft_and_shows_the_server_version", async () => {
  const d = await conflictWorld();
  await d.engine.resolve(ID_A, "theirs");
  assert.deepEqual(await queued(d), [], "the draft is dropped");
  const item = itemOf(d);
  assert.deepEqual([item.conflict, item.blocked, item.blockedReason, item.pending, item.name, item.rev], [false, false, null, false, "Server name", 2]);
  assert.equal(requests(d).length, 1, "nothing more is sent");
  const saved = await savedFlags(d);
  assert.equal(saved, undefined, "nothing is left of the block in storage");
  // The item can be edited again from the server's version.
  await d.engine.update(ID_A, { name: "After" }, 2);
  await until(() => d.model.items.get(ID_A).rev === 3, "the edit goes out");
  assert.equal(JSON.parse(d.model.writes.at(-1).body).base_rev, 2);
  d.engine.stop();
});

test("keep_theirs_over_a_deleted_server_row_accepts_the_deletion", async () => {
  const d = await conflictWorld({ deletedThere: true });
  await d.engine.resolve(ID_A, "theirs");
  assert.deepEqual(await queued(d), []);
  assert.equal(itemOf(d), undefined, "the item is gone from the list");
  assert.equal(d.model.items.get(ID_A).deleted, true);
  assert.equal(requests(d).length, 1);
  d.engine.stop();
});

test("keep_mine_writes_at_current_rev_plus_1_and_clears_the_conflict", async () => {
  const d = await conflictWorld();
  await d.engine.resolve(ID_A, "mine");
  // The write is the local version, sealed at revision 3, on top of the server's revision 2.
  await until(() => d.model.items.get(ID_A).rev === 3, "the server has revision 3");
  const sent = JSON.parse(d.model.writes.at(-1).body);
  assert.equal(sent.base_rev, 2);
  assert.equal(sent.resurrect, undefined, "a live row is not resurrected");
  assert.equal((await serverView(d)).name, "Local name");
  await until(() => itemOf(d)?.rev === 3 && itemOf(d).pending === false, "the row comes back");
  const item = itemOf(d);
  assert.deepEqual([item.conflict, item.blocked, item.blockedReason, item.name], [false, false, null, "Local name"]);
  assert.deepEqual(await queued(d), []);
  assert.equal(await savedFlags(d), undefined);
  assert.equal(d.engine.health().halted, null);
  d.engine.stop();
});

test("keep_mine_shows_the_local_version_as_pending_at_once", async () => {
  const d = await conflictWorld();
  d.api.faults.push({ kind: "network" }); // the write waits for its retry
  await d.engine.resolve(ID_A, "mine");
  const item = itemOf(d);
  assert.deepEqual([item.name, item.rev, item.pending, item.conflict, item.blocked], ["Local name", 3, true, false, false]);
  await until(() => d.model.items.get(ID_A).rev === 3 || d.timers.pending > 0, "retry wait");
  d.timers.advance(5_000);
  await until(() => d.model.items.get(ID_A).rev === 3, "the retry goes out");
  d.engine.stop();
});

test("there_is_no_automatic_field_merge", async () => {
  // The server changed the user name and the name; this device changed only the name. Keeping mine keeps the user name of
  // revision 1: the server's change is not mixed in.
  const d = await conflictWorld({ theirs: body("Server name", [USER("bob"), PASS("first")]), mine: { name: "Local name" } });
  const shown = await d.engine.conflict(ID_A);
  assert.equal(shown.fields.find((field) => field.key === "username").same, false);
  await shown.close();
  await d.engine.resolve(ID_A, "mine");
  await until(() => d.model.items.get(ID_A).rev === 3);
  const view = await serverView(d);
  assert.equal(view.name, "Local name");
  assert.equal(view.fields.find((field) => field.id === "username").value, "alice", "nothing of the server's version is mixed in");
  assert.equal(Object.keys(d.engine).some((name) => /merge|both/i.test(name)), false, "there is no merge on the engine");
  d.engine.stop();

  // Keeping theirs likewise leaves the server's row as it is.
  const e = await conflictWorld({ theirs: body("Server name", [USER("bob"), PASS("first")]) });
  const row = { ...e.model.items.get(ID_A) };
  await e.engine.resolve(ID_A, "theirs");
  assert.deepEqual(e.model.items.get(ID_A), row);
  assert.equal(e.model.writes.length, 0, "nothing was written by this device");
  e.engine.stop();
});

test("keep_mine_over_a_deleted_server_row_resurrects", async () => {
  const d = await conflictWorld({ deletedThere: true });
  const shown = await d.engine.conflict(ID_A);
  assert.deepEqual([shown.local.deleted, shown.server.deleted], [false, true]);
  await shown.close();
  await d.engine.resolve(ID_A, "mine");
  await until(() => d.model.items.get(ID_A).deleted === false, "the item is back on the server");
  const sent = JSON.parse(d.model.writes.at(-1).body);
  assert.deepEqual([sent.base_rev, sent.resurrect], [2, true], "built on the tombstone's revision, with the flag");
  const row = d.model.items.get(ID_A);
  assert.equal(row.rev, 3);
  assert.equal((await viewOf(d, ID_A, 3, row.blob, row.tag)).name, "Local name");
  await until(() => itemOf(d)?.rev === 3 && itemOf(d).conflict === false && itemOf(d).pending === false, "the live row comes back");
  assert.equal(itemOf(d).name, "Local name");
  d.engine.stop();
});

test("a_resurrection_is_never_asked_for_without_the_choice", async () => {
  const d = await conflictWorld({ deletedThere: true });
  await settle(60);
  d.timers.advance(600_000);
  await settle(60);
  assert.equal(d.model.writes.length, 0);
  assert.ok(requests(d).every((request) => request.resurrect === undefined), "nothing sent so far asked for one");
  assert.equal(d.model.items.get(ID_A).deleted, true);
  d.engine.stop();
});

test("local_delete_against_a_server_edit_keep_mine_deletes_at_current_rev_plus_1", async () => {
  const d = await conflictWorld({ deleteHere: true });
  const shown = await d.engine.conflict(ID_A);
  assert.deepEqual([shown.local.deleted, shown.local.view, shown.local.handle], [true, null, null]);
  assert.deepEqual([shown.server.deleted, shown.server.view.name], [false, "Server name"]);
  assert.deepEqual(shown.fields.map((field) => field.same), [false, false], "a side that is deleted has no fields in common");
  await shown.close();
  await d.engine.resolve(ID_A, "mine");
  await until(() => d.model.items.get(ID_A).deleted === true, "the deletion goes out");
  const sent = JSON.parse(d.model.writes.at(-1).body);
  assert.deepEqual([sent.base_rev, sent.deleted, sent.resurrect], [2, true, undefined]);
  assert.equal(d.model.items.get(ID_A).rev, 3);
  const made = d.client.vault.calls.filter((call) => call[0] === "make_tombstone" && call[2] === 3);
  assert.equal(made.length, 1, "a tombstone at revision 3");
  await until(() => itemOf(d) === undefined, "the item is gone from the list");
  d.engine.stop();
});

test("keep_mine_with_a_local_delete_against_a_deleted_row_drops_the_draft", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("Original"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  // The server refuses the deletion of A as a conflict (an edit by another device), then deletes A itself.
  setRow(model, client, ID_A, 2, body("Edited elsewhere"));
  await d.engine.remove(ID_A);
  await until(() => d.events.error.some((e) => e.code === "conflict"));
  await until(() => itemOf(d, ID_A)?.rev === 2);
  setTomb(model, client, ID_A, 3);
  await d.engine.syncNow();
  // Both sides are deleted now: nothing is left to choose.
  await until(() => itemOf(d, ID_A) === undefined, "the item is gone");
  assert.deepEqual(await queued(d), [], "the draft that only deleted is dropped");
  d.engine.stop();
});

test("a_conflict_from_accept_older_state_can_be_resolved", async () => {
  // A: this device holds revision 3, the restored server revision 2. B: live here, a tombstone there. C: deleted here, live there.
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 3, body("A"));
  setRow(model, client, ID_B, 3, body("B"));
  setTomb(model, client, ID_C, 4);
  setRow(model, client, ID_D, 1, body("D"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.items.clear();
  setRow(model, client, ID_A, 2, body("A old"), { seq: 1 });
  setTomb(model, client, ID_B, 2, { seq: 2 });
  setRow(model, client, ID_C, 3, body("C old"), { seq: 3 });
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 1, conflicts: 3, manifestOlder: false });
  await until(() => d.model.items.get(ID_D)?.rev === 1, "D is on the server");

  // Many at once: three items are in conflict, each with the server's version beside the sealed local one.
  const inConflict = d.engine.list().filter((item) => item.conflict);
  assert.deepEqual(inConflict.map((item) => item.id).sort(), [ID_A, ID_B, ID_C].sort());
  const shownA = await d.engine.conflict(ID_A);
  assert.deepEqual([shownA.local.view.name, shownA.server.view.name, shownA.server.rev], ["A", "A old", 2]);
  const shownB = await d.engine.conflict(ID_B);
  assert.deepEqual([shownB.local.view.name, shownB.server.deleted], ["B", true]);
  const shownC = await d.engine.conflict(ID_C);
  assert.deepEqual([shownC.local.deleted, shownC.server.view.name], [true, "C old"]);
  await Promise.all([shownA.close(), shownB.close(), shownC.close()]);

  await d.engine.resolve(ID_A, "mine"); // on top of revision 2
  await d.engine.resolve(ID_B, "mine"); // a resurrection on top of the tombstone at 2
  await d.engine.resolve(ID_C, "theirs"); // the server's live version stands
  await until(() => d.model.items.get(ID_A).rev === 3 && d.model.items.get(ID_B).rev === 3, "both choices are written");
  const writes = Object.fromEntries(d.model.writes.filter((w) => w.id !== ID_D).map((w) => [w.id, JSON.parse(w.body)]));
  assert.deepEqual([writes[ID_A].base_rev, writes[ID_A].resurrect], [2, undefined]);
  assert.deepEqual([writes[ID_B].base_rev, writes[ID_B].resurrect], [2, true]);
  assert.equal(writes[ID_C], undefined, "keeping the server's version writes nothing");
  assert.equal(d.model.items.get(ID_C).rev, 3);
  assert.equal((await serverView(d, ID_A)).name, "A");
  assert.equal((await serverView(d, ID_B)).name, "B");
  await until(() => d.engine.list().every((item) => item.conflict === false && item.pending === false), "all settled");
  assert.deepEqual(await queued(d), []);
  assert.equal(d.engine.list().find((item) => item.id === ID_C).name, "C old");
  d.engine.stop();
});

test("a_choice_is_refused_while_an_older_state_is_being_accepted", async () => {
  const d = await conflictWorld();
  // A restore that has not finished (its note is stored, and the server cannot be reached to carry it on): nothing the user
  // chooses is written meanwhile.
  await d.memory.withLock(async (state) => ({ ...state, restore: { epoch: 1, phase: "queued" } }));
  d.engine.stop();
  const back = await reload(d);
  back.api.failFeed = new ApiError(0, "network");
  back.api.failFeedTimes = 1000;
  await back.engine.start();
  await assert.rejects(() => back.engine.resolve(ID_A, "mine"), { code: "busy" });
  await assert.rejects(() => back.engine.resolve(ID_A, "theirs"), { code: "busy" });
  await assert.rejects(() => back.engine.conflict(ID_A), { code: "busy" });
  assert.equal(back.api.puts.length, 0);
  back.engine.stop();
});

test("damaged_keep_mine_writes_the_last_good_version", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("A good"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  // The server's revision 2 cannot be opened: the item is marked damaged, and the last good version is kept.
  model.set(ID_A, { rev: 2, blob: b64u.encode(new Uint8Array(40).fill(9)), tag: b64u.encode(new Uint8Array(32).fill(8)) });
  await d.engine.syncNow();
  assert.equal(itemOf(d).damaged, true);
  assert.equal(itemOf(d).name, "A good");
  await assert.rejects(() => d.engine.keepMine(ID_C), { code: "not_found" });
  await d.engine.keepMine(ID_A);
  await until(() => d.model.items.get(ID_A).rev === 3, "the good version is written on top of the damaged one");
  const sent = JSON.parse(d.model.writes.at(-1).body);
  assert.deepEqual([sent.base_rev, sent.resurrect], [2, undefined]);
  assert.equal((await serverView(d)).name, "A good");
  await until(() => itemOf(d)?.rev === 3 && itemOf(d).damaged === false && itemOf(d).pending === false, "the item is whole again");
  assert.equal((await savedFlags(d)), undefined, "the mark is gone from storage");
  d.engine.stop();
});

test("damaged_keep_mine_without_a_good_version_is_refused", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(ID_A, { rev: 2, blob: b64u.encode(new Uint8Array(40).fill(9)), tag: b64u.encode(new Uint8Array(32).fill(8)) });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal(itemOf(d).damaged, true);
  await assert.rejects(() => d.engine.keepMine(ID_A), { code: "damaged" });
  assert.equal(d.api.puts.length, 0);
  d.engine.stop();
});

test("quarantined_keep_mine_resurrects", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("A kept"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  // The server says deleted at revision 2, but the tombstone does not verify: the item is in quarantine, the copy is kept.
  model.set(ID_A, { rev: 2, deleted: true, tomb: b64u.encode(new Uint8Array(40).fill(1)) });
  await d.engine.syncNow();
  assert.equal(itemOf(d).quarantined, true);
  assert.equal(d.model.writes.length, 0);
  await d.engine.keepMine(ID_A);
  await until(() => d.model.items.get(ID_A).deleted === false, "the copy is back on the server");
  const sent = JSON.parse(d.model.writes.at(-1).body);
  assert.deepEqual([sent.base_rev, sent.resurrect], [2, true], "on top of the tombstone's revision, as a resurrection");
  const row = d.model.items.get(ID_A);
  assert.equal(row.rev, 3);
  assert.equal((await viewOf(d, ID_A, 3, row.blob, row.tag)).name, "A kept");
  await until(() => itemOf(d)?.quarantined === false && itemOf(d).rev === 3 && itemOf(d).pending === false, "the item is whole again");
  d.engine.stop();
});

test("keep_mine_is_refused_for_an_item_with_nothing_to_keep", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("Fine"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await assert.rejects(() => d.engine.keepMine(ID_A), { code: "not_found" });
  await assert.rejects(() => d.engine.keepMine("nothex"), { code: "not_found" });
  assert.equal(d.api.puts.length, 0);
  d.engine.stop();
});

test("a_blocked_draft_of_an_item_the_feed_deletes_becomes_a_conflict_with_a_deleted_server", async () => {
  // A write that was refused for another reason stays in the outbox; when the feed then deletes the item, nothing showed
  // the draft and nothing could discard it.
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("Original"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  d.api.faults.push({ kind: "status", status: 413, code: "too_large" });
  await d.engine.update(ID_A, { name: "My draft" }, 1);
  await until(() => itemOf(d)?.blockedReason === "too_large", "the draft is refused for good");
  assert.equal(itemOf(d).conflict, false, "not a conflict yet");

  setTomb(model, client, ID_A, 2);
  await d.engine.syncNow();
  const item = itemOf(d);
  assert.ok(item, "the draft is on screen");
  assert.deepEqual([item.conflict, item.blockedReason, item.name], [true, "conflict", "My draft"]);
  const shown = await d.engine.conflict(ID_A);
  assert.deepEqual([shown.server.deleted, shown.server.rev, shown.local.view.name], [true, 2, "My draft"]);
  await shown.close();
  assert.deepEqual((await savedFlags(d)).conflicts, { [ID_A]: { serverRev: 2, serverDeleted: true } });

  // After a restart it is still there, and keeping theirs ends it.
  d.engine.stop();
  const back = await reload(d);
  await back.engine.start();
  assert.deepEqual([itemOf(back).conflict, itemOf(back).name], [true, "My draft"]);
  await back.engine.resolve(ID_A, "theirs");
  assert.equal(itemOf(back), undefined);
  assert.deepEqual(await queued(back), []);
  back.engine.stop();
});

test("a_blocked_delete_of_an_item_the_feed_deletes_is_moot_and_dropped", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, body("Original"));
  const d = await syncDevice({ model, client });
  await d.engine.start();
  d.api.faults.push({ kind: "status", status: 413, code: "quota_exceeded" });
  await d.engine.remove(ID_A);
  await until(() => itemOf(d)?.blockedReason === "quota_exceeded");
  setTomb(model, client, ID_A, 2);
  await d.engine.syncNow();
  assert.deepEqual(await queued(d), [], "both sides want it deleted: nothing is left to choose");
  assert.equal(itemOf(d), undefined);
  assert.equal((await savedFlags(d)), undefined);
  d.engine.stop();
});

test("the_server_row_that_arrives_updates_the_conflict_note", async () => {
  const d = await conflictWorld();
  setRow(d.model, d.client, ID_A, 3, body("Third"));
  await d.engine.syncNow();
  assert.deepEqual((await savedFlags(d)).conflicts, { [ID_A]: { serverRev: 3, serverDeleted: false } });
  const shown = await d.engine.conflict(ID_A);
  assert.deepEqual([shown.server.rev, shown.server.view.name], [3, "Third"]);
  await shown.close();
  // Keep mine now goes on top of revision 3.
  await d.engine.resolve(ID_A, "mine");
  await until(() => d.model.items.get(ID_A).rev === 4, "written at revision 4");
  assert.equal(JSON.parse(d.model.writes.at(-1).body).base_rev, 3);
  d.engine.stop();
});

test("a_write_that_cannot_be_stored_leaves_the_conflict_as_it_was", async () => {
  const d = await conflictWorld();
  d.store.failEnqueue = 1;
  await assert.rejects(() => d.engine.resolve(ID_A, "mine"), /disk is full/);
  const item = itemOf(d);
  assert.deepEqual([item.conflict, item.blocked, item.name], [true, true, "Server name"]);
  assert.equal((await queued(d)).length, 1, "the old draft is still the only one");
  await settle(20);
  assert.equal((await savedFlags(d)).blocked[ID_A], "conflict", "and the block is still saved");
  // A second try works.
  await d.engine.resolve(ID_A, "mine");
  await until(() => d.model.items.get(ID_A).rev === 3);
  d.engine.stop();
});

test("automatic_reupload_refusal_does_not_say_you_changed_something", async () => {
  // The texts: neither language speaks of a change of the user (nothing was changed; the copy is only kept).
  for (const [lang, said] of [["en", /your change|you changed|you edited|your edit/i], ["nb", /endringen din|du har endret|du endret|redigeringen din/i]]) {
    const texts = JSON.parse(readFileSync(new URL(`../../src/locales/${lang}/sync.json`, import.meta.url), "utf8"));
    assert.doesNotMatch(texts["sync.error.reupload_refused"], said, lang);
    assert.match(texts["sync.error.conflict"], lang === "en" ? /your change/i : /endringen din/i, "the conflict text keeps speaking of the user's change");
  }
});

test("the_conflict_texts_exist_in_both_languages", () => {
  for (const lang of ["en", "nb"]) {
    const texts = JSON.parse(readFileSync(new URL(`../../src/locales/${lang}/sync.json`, import.meta.url), "utf8"));
    for (const key of ["reupload_refused", "conflict_unsettled", "busy", "invalid_state", "conflict"]) assert.ok(`sync.error.${key}` in texts, `${lang} ${key}`);
  }
});

test("the_sync_state_of_the_account_is_not_touched_by_a_choice", async () => {
  const d = await conflictWorld();
  const before = await loadSyncState(d.store.database.store, SERVER, ACCOUNT);
  await d.engine.resolve(ID_A, "theirs");
  const after = await loadSyncState(d.store.database.store, SERVER, ACCOUNT);
  assert.deepEqual(after, before, "a choice changes no floor and no warning");
  d.engine.stop();
});
