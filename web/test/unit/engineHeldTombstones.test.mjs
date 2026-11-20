// A tombstone that the server has purged: the server purges a tombstone only when its checkpoint covers it, and raises its floor (`min_valid_since`) to the
// highest `seq` it purged. A tombstone that a device holds, that the server no longer lists and that is at or below the floor is held: it stays in
// the cache and is left out of the rows given to the check of the checkpoint. A deletion that the device made and the server took, purged before the
// device read it back, counts as done. A live row the server hides, or a tombstone above the floor, is still an alarm.
// Spec: Fase 1 section 8.4 ("Retention"), section 8.6 ("What a recipient checks").
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { scope } from "./idbHelpers.mjs";
import { createFakeClient, Model, settle, syncDevice, until } from "./syncHelpers.mjs";

const hex = (n) => n.toString(16).padStart(32, "0");
const draft = (name) => ({ item_type: "login", name });
const FLAGS = (s = scope()) => `sync.flags.${s.accountId}.${s.vaultId}.${s.vkEpoch}`;
const rowsOf = (d) => cache.getRows(d.store.database.store, scope());

/** A started device, and a spy on the rows each call of the check of a checkpoint is given. */
async function started({ model = new Model(), client = createFakeClient(), db = null, locks } = {}) {
  const d = await syncDevice({ model, client, db, ...(locks ? { locks } : {}) });
  d.checked = [];
  const real = client.vault.verify_checkpoint;
  client.vault.verify_checkpoint = async (checkpoint, rows, top, memory) => {
    d.checked.push(rows.map((row) => hex16.encode(row.item_id)));
    return real(checkpoint, rows, top, memory);
  };
  await d.engine.start();
  return d;
}

/** The device has created and deleted an item, and has read both back: it holds the tombstone (rev 2, seq 2). */
async function holdingATombstone(d) {
  const id = await d.engine.create(draft("short-lived"));
  await until(() => d.model.items.get(id)?.rev === 1);
  await d.engine.remove(id);
  await until(() => d.model.items.get(id)?.rev === 2);
  await d.engine.syncNow();
  assert.equal((await rowsOf(d)).find((row) => row.itemId === id)?.deleted, true, "the device holds the tombstone");
  return id;
}

test("held_tombstones_are_left_out_of_verification_and_kept_locally", async () => {
  const d = await started();
  const id = await holdingATombstone(d);
  // 400 days later: the tombstone is purged (the checkpoint that covers it was stored), the floor is at its seq, and another device that never
  // saw the item stored a newer checkpoint that has no entry for it.
  d.model.items.delete(id);
  d.model.minValidSince = 2;
  d.model.pinCheckpoint();
  d.checked.length = 0;
  d.api.gets.length = 0;
  assert.equal(await d.engine.verifyNow(), "ok", "an honest server that has purged a tombstone is no reason for an alarm");
  assert.deepEqual(d.engine.health().warnings, []);
  assert.equal(d.checked.length, 2, "the check was made with every row first, and again without the held tombstone");
  assert.ok(d.checked[0].includes(id));
  assert.ok(!d.checked[1].includes(id), "the held tombstone is left out of the rows of the check");
  assert.ok(d.api.gets.includes("/api/sync/changes?since=1&limit=1"), "the floor is asked for, with a cursor that is below any floor that holds a tombstone");
  // Kept locally: the row is still in the cache and in the memory, and the item is still deleted.
  const row = (await rowsOf(d)).find((one) => one.itemId === id);
  assert.equal(row.deleted, true);
  assert.equal(row.rev, 2);
  assert.equal(row.tomb.length, 40);
  assert.ok(!d.engine.list().some((item) => item.id === id));
  assert.equal(d.events.error.length, 0);
  d.engine.stop();
});

test("a_tombstone_that_the_floor_does_not_cover_is_still_an_alarm", async () => {
  // The server has no row for the item and has not raised its floor: nothing says that the tombstone was purged. The server may be hiding a
  // deletion, and the check says so.
  const d = await started();
  const id = await holdingATombstone(d);
  d.model.items.delete(id);
  d.model.minValidSince = 0;
  d.model.pinCheckpoint();
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state");
  assert.deepEqual(d.engine.health().warnings, ["server_shows_older_state"]);
  // The floor is below the tombstone's seq: the same.
  const e = await started();
  const other = await holdingATombstone(e);
  e.model.items.delete(other);
  e.model.minValidSince = 1;
  e.model.pinCheckpoint();
  assert.equal(await e.engine.verifyNow(), "server_shows_older_state", "a floor below the tombstone does not hold it");
  d.engine.stop();
  e.engine.stop();
});

test("a_floor_that_cannot_be_read_holds_nothing_and_says_nothing_when_the_server_does_not_answer", async () => {
  const d = await started();
  const id = await holdingATombstone(d);
  d.model.items.delete(id);
  d.model.minValidSince = 2;
  d.model.pinCheckpoint();
  const get = d.api.get;
  // The server does not answer when asked for the floor: no warning is raised, the check is made again later.
  d.api.get = async (path, ...rest) => {
    if (path.includes("since=1&limit=1")) throw new ApiError(0, "network");
    return get(path, ...rest);
  };
  assert.equal(await d.engine.verifyNow(), "not_checked");
  assert.deepEqual(d.engine.health().warnings, [], "nothing is said about a server that could not be asked");
  d.api.get = get;
  d.timers.advance(10 * 60_000);
  assert.equal(await d.engine.verifyNow(), "ok", "asked again, the tombstone is held");
  // An answer that is not a floor holds nothing: the check fails as it would without the idea of a held tombstone.
  const e = await started();
  const other = await holdingATombstone(e);
  e.model.items.delete(other);
  e.model.minValidSince = 2;
  e.model.pinCheckpoint();
  const getE = e.api.get;
  e.api.get = async (path, ...rest) => {
    if (path.includes("since=1&limit=1")) throw new ApiError(404, "not_found");
    return getE(path, ...rest);
  };
  assert.equal(await e.engine.verifyNow(), "server_shows_older_state");
  d.engine.stop();
  e.engine.stop();
});

test("a_live_row_the_server_hides_is_still_a_warning", async () => {
  // A device that never held the item: the checkpoint lists it live, the server has no row for it, and says that it has purged everything up
  // to a seq that covers it. Only a tombstone can be purged: a live row that is not there is hidden, whatever the floor says.
  const model = new Model();
  const client = createFakeClient();
  const id = hex(0xabc);
  model.set(id, { rev: 1, ...client.wireRow(id, 1, { item_type: "login", name: "hidden" }) }); // seq 1
  model.pinCheckpoint(); // seq 1: lists the item live
  model.items.delete(id); // the server hides it, with nothing in its place
  model.minValidSince = 1;
  const d = await started({ model, client });
  d.checked.length = 0;
  assert.equal(await d.engine.verifyNow(), "server_shows_older_state");
  assert.deepEqual(d.engine.health().warnings, ["server_shows_older_state"]);
  assert.ok(d.checked.length >= 1);
  assert.ok(d.checked.every((rows) => JSON.stringify(rows) === JSON.stringify(d.checked[0])), "no row was held: every check had the same rows");
  d.engine.stop();

  // A device that holds the live row and finds it gone from a listing keeps it as "only on this device" and uploads it again, as before.
  const m2 = new Model();
  const c2 = createFakeClient();
  m2.set(id, { rev: 1, ...c2.wireRow(id, 1, { item_type: "login", name: "hidden" }) });
  m2.set(hex(2), { rev: 1, ...c2.wireRow(hex(2), 1, { item_type: "login", name: "other" }) });
  const e = await started({ model: m2, client: c2 });
  m2.items.delete(id);
  m2.seq += 2;
  m2.minValidSince = m2.seq;
  await e.engine.syncNow();
  const shown = e.engine.list().find((item) => item.id === id);
  assert.equal(shown.missingOnServer, true, "a live row that the listing does not show is marked, not held");
  e.engine.stop();
});

test("an_own_deletion_purged_before_it_was_read_back_counts_as_done", async () => {
  const d = await started();
  const id = await d.engine.create(draft("to be deleted"));
  await until(() => d.model.items.get(id)?.rev === 1);
  await d.engine.syncNow(); // the device holds the live row
  const other = hex(0x77);
  // The feed fails from here: the server takes the deletion, and the device cannot read it back.
  d.api.failFeed = new ApiError(0, "network");
  d.api.failFeedTimes = 1000;
  await d.engine.remove(id);
  await until(() => d.model.items.get(id)?.rev === 2, "the server took the deletion");
  await settle(20);
  assert.equal((await rowsOf(d)).find((row) => row.itemId === id)?.deleted, false, "the device has not read the tombstone back");
  // The server purges it (the checkpoint covers it), and the floor goes above the cursor of the device.
  d.model.pinCheckpoint();
  d.model.items.delete(id);
  d.model.minValidSince = 2;
  d.model.set(other, { rev: 1, ...d.client.wireRow(other, 1, { item_type: "login", name: "written elsewhere" }) });
  d.api.failFeed = null;
  d.api.failFeedTimes = 0;
  const putsBefore = d.api.puts.length;
  await d.engine.syncNow();
  await settle(20);
  // The deletion is done: the item is gone from the screen, the live row is in the trash, nothing is marked, nothing is uploaded again.
  assert.ok(!d.engine.list().some((item) => item.id === id), "the item stays deleted");
  assert.ok(d.engine.list().some((item) => item.id === other));
  assert.equal(d.engine.list().filter((item) => item.missingOnServer).length, 0, "the item is not marked as missing");
  assert.equal(d.api.puts.length, putsBefore, "and not uploaded again");
  assert.ok(!d.model.items.has(id), "so the server does not get the item back");
  const row = (await rowsOf(d)).find((one) => one.itemId === id);
  assert.equal(row.deleted, true, "the tombstone the device sent is the row it holds now");
  assert.equal(row.rev, 2);
  assert.equal(d.store.spy.trashed.filter((entry) => entry.itemId === id).length, 1, "the live version is in the trash for 30 days");
  assert.deepEqual(d.engine.health().warnings.filter((code) => code !== "missing_on_server"), []);
  assert.ok(!d.events.state.some((event) => event.kind === "warning" && event.code === "missing_on_server"));
  // The checkpoint of the server does not list the item (it was purged): the held tombstone is left out and the check passes.
  assert.equal(await d.engine.verifyNow(), "ok");
  assert.deepEqual(d.engine.health().warnings, []);
  d.engine.stop();
});

test("an_own_deletion_is_remembered_across_a_restart_and_a_listing_that_does_not_show_the_item_settles_it", async () => {
  const model = new Model();
  const client = createFakeClient();
  const first = await started({ model, client });
  const id = await first.engine.create(draft("to be deleted"));
  await until(() => model.items.get(id)?.rev === 1);
  await first.engine.syncNow();
  first.api.failFeed = new ApiError(0, "network");
  first.api.failFeedTimes = 1000;
  await first.engine.remove(id);
  await until(() => model.items.get(id)?.rev === 2);
  await settle(30);
  const note = await first.store.getSetting(first.store.database.store, FLAGS());
  assert.ok(note?.deleted?.[id], "the note that the deletion is done is saved with the marks");
  assert.deepEqual(Object.keys(note.deleted[id]).sort(), ["rev", "seq", "tomb"]);
  assert.equal(note.deleted[id].rev, 2);
  assert.equal(note.deleted[id].seq, 2);
  first.engine.stop();

  model.pinCheckpoint();
  model.items.delete(id);
  model.minValidSince = 2;
  model.set(hex(0x77), { rev: 1, ...client.wireRow(hex(0x77), 1, { item_type: "login", name: "written elsewhere" }) });
  const second = await started({ model, client, db: first.store.database, locks: first.locks });
  await settle(30);
  assert.ok(!second.engine.list().some((item) => item.id === id), "the item is gone after the restart too");
  assert.equal(second.engine.list().filter((item) => item.missingOnServer).length, 0);
  assert.equal(second.api.puts.length, 0, "nothing is uploaded again");
  assert.ok(!model.items.has(id));
  const after = await second.store.getSetting(second.store.database.store, FLAGS());
  assert.equal(after?.deleted, undefined, "the note goes when it has been used");
  second.engine.stop();
});

test("a_record_without_the_note_of_deletions_is_read_as_before", async () => {
  // Saved before the note existed: marks and blocks only. Nothing is read from a field that is not there, and a record without deletions is
  // written without the field, so its form is the old one.
  const model = new Model();
  const client = createFakeClient();
  const first = await started({ model, client });
  await first.store.setSetting(first.store.database.store, FLAGS(), { v: 1, marks: {}, blocked: {}, conflicts: {} });
  first.engine.stop();
  const second = await started({ model, client, db: first.store.database, locks: first.locks });
  const id = await second.engine.create(draft("kept"));
  await until(() => model.items.get(id)?.rev === 1);
  await second.engine.syncNow();
  const record = await second.store.getSetting(second.store.database.store, FLAGS());
  assert.ok(record === undefined || record === null || record.deleted === undefined);
  // A note that cannot be read (a damaged tombstone, a revision that cannot be right) is dropped, the rest is read.
  await second.store.setSetting(second.store.database.store, FLAGS(), {
    v: 1, marks: {}, blocked: {}, conflicts: {},
    deleted: { [hex(5)]: { rev: 1, seq: 1, tomb: b64u.encode(new Uint8Array(40)) }, [hex(6)]: { rev: 2, seq: 2, tomb: "not base64 !" }, [hex(7)]: { rev: 2, seq: 3, tomb: b64u.encode(new Uint8Array(12)) } },
  });
  second.engine.stop();
  const third = await started({ model, client, db: first.store.database, locks: first.locks });
  assert.ok(third.engine.list().some((item) => item.id === id), "the engine starts and shows what it had");
  third.engine.stop();
});

test("an_own_deletion_that_the_server_already_had_is_settled_too_when_its_tombstone_is_purged", async () => {
  // Two devices delete the same item. The server holds the first tombstone, and answers the second device's deletion with a conflict that says
  // "deleted at the revision this one makes", which counts as done (it carries no `seq`). The tombstone is purged before the second device has
  // read it back: its deletion is done all the same, and the item is not uploaded again.
  const model = new Model();
  const client = createFakeClient();
  const a = await started({ model, client });
  const b = await started({ model, client });
  const id = await a.engine.create(draft("deleted twice"));
  await until(() => model.items.get(id)?.rev === 1);
  await b.engine.syncNow(); // b holds the live row
  assert.ok(b.engine.list().some((item) => item.id === id));
  b.api.failFeed = new ApiError(0, "network");
  b.api.failFeedTimes = 1000;
  await a.engine.remove(id);
  await until(() => model.items.get(id)?.rev === 2);
  await b.engine.remove(id);
  await until(() => b.engine.list().every((item) => item.id !== id), "b no longer shows the item");
  await settle(30);
  assert.equal(b.api.puts.length, 1, "b's deletion was sent once, and the server said that it already had it");
  const note = await b.store.getSetting(b.store.database.store, FLAGS());
  assert.equal(note?.deleted?.[id]?.rev, 2, "the deletion is noted as done");
  assert.equal(note.deleted[id].seq, 0, "with no seq: the answer did not carry one");
  // The server purges it: the checkpoint covers it, and the floor goes above b's cursor.
  model.pinCheckpoint();
  model.items.delete(id);
  model.minValidSince = 2;
  model.set(hex(0x77), { rev: 1, ...client.wireRow(hex(0x77), 1, { item_type: "login", name: "written elsewhere" }) });
  b.api.failFeed = null;
  b.api.failFeedTimes = 0;
  await b.engine.syncNow();
  await settle(30);
  assert.ok(!b.engine.list().some((item) => item.id === id), "the item stays deleted");
  assert.equal(b.engine.list().filter((item) => item.missingOnServer).length, 0, "and is not marked as missing");
  assert.equal(b.api.puts.length, 1, "and is not uploaded again");
  assert.ok(!model.items.has(id));
  assert.equal((await rowsOf(b)).find((row) => row.itemId === id)?.deleted, true, "the tombstone b sent is the row it holds now");
  a.engine.stop();
  b.engine.stop();
});

test("an_own_deletion_stays_deleted_on_the_screen_after_a_restart_until_the_tombstone_comes_back", async () => {
  const model = new Model();
  const client = createFakeClient();
  const first = await started({ model, client });
  const id = await first.engine.create(draft("to be deleted"));
  await until(() => model.items.get(id)?.rev === 1);
  await first.engine.syncNow();
  first.api.failFeed = new ApiError(0, "network");
  first.api.failFeedTimes = 1000;
  await first.engine.remove(id);
  await until(() => model.items.get(id)?.rev === 2);
  await settle(30);
  first.engine.stop();
  // The page is opened again: the cache holds the live row, the outbox is empty (the server took the deletion), and the feed does not answer.
  const second = await syncDevice({ model, client, db: first.store.database, locks: first.locks });
  second.api.failFeed = new ApiError(0, "network");
  second.api.failFeedTimes = 1000;
  await second.engine.start();
  assert.equal((await rowsOf(second)).find((row) => row.itemId === id)?.deleted, false, "the row that is cached is the live one");
  assert.ok(!second.engine.list().some((item) => item.id === id), "but the item stays deleted on the screen");
  // The feed comes back and brings the tombstone: the note is not needed any more.
  second.api.failFeed = null;
  second.api.failFeedTimes = 0;
  await second.engine.syncNow();
  assert.equal((await rowsOf(second)).find((row) => row.itemId === id)?.deleted, true);
  assert.ok(!second.engine.list().some((item) => item.id === id));
  assert.equal((await second.store.getSetting(second.store.database.store, FLAGS()))?.deleted, undefined);
  second.engine.stop();
});
