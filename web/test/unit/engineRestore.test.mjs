// The sync engine and a restored server: what "accept older state" does in its three phases, what it queues and what it
// keeps back, what survives a crash, and what "try again" does and does not clear.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache, rowOfChange } from "../../src/store/cache.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { getSetting, setSetting } from "../../src/store/settings.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { checkRestoreRowsPage } from "../../src/sync/checkpoint.mjs";
import { encodeWireBytes } from "../../src/wire.mjs";
import { planRestore, restoreItems } from "../../src/sync/restore.mjs";
import { ACCOUNT, freshStore, scope, SERVER } from "./idbHelpers.mjs";
import { createFakeClient, memoryOf, Model, settle, signCheckpoint, syncDevice, until } from "./syncHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);
const ID_D = "44".repeat(16);
const DRAFT = { item_type: "login", name: "Written while stopped" };
const sha = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());

const setRow = (model, client, id, rev, name, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, { item_type: "login", name }), ...extra });
const setTomb = (model, client, id, rev, extra = {}) => model.set(id, { rev, deleted: true, tomb: client.wireTomb(id, rev), ...extra });
const stateOf = (d) => loadSyncState(d.store.database.store, SERVER, ACCOUNT);
const queued = (d) => outbox.all(d.store.database.store, scope());
const states = (d, kind, code) => d.events.state.filter((s) => s.kind === kind && (code === undefined || s.code === code));
const errors = (d, code) => d.events.error.filter((e) => e.code === code);
const sent = (d) => d.api.puts.map((put) => ({ id: put.id, ...JSON.parse(put.text) }));
const sentFor = (d, id) => sent(d).filter((put) => put.id === id);
/** The same browser again after the page was closed: the storage and the locks stay, everything else is new. */
const reload = (d) => syncDevice({ model: d.model, client: d.client, db: d.store.database, locks: d.locks });

/**
 * A device that holds A (rev 3), B (rev 3), C (a tombstone at rev 4) and D (rev 1), all of them in step with the server. Then
 * the server is restored from a backup and the restore is recorded (`ferret restore-epoch bump`): A is at rev 2, B is a tombstone
 * at rev 2, C is live at rev 3, D is gone, the counter is lower, the restore epoch is raised and `restore_seq` is 3 (no row has been
 * written since). One pass later the device has stopped with `server_restored`.
 */
async function restoredWorld() {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 3, "A");
  setRow(model, client, ID_B, 3, "B");
  setTomb(model, client, ID_C, 4);
  setRow(model, client, ID_D, 1, "D");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.deepEqual(d.engine.list().map((item) => item.id), [ID_A, ID_B, ID_D]);
  restoreServer(model, client);
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  return d;
}

/** The server goes back to the backup of `restoredWorld`, and the restore is recorded. */
function restoreServer(model, client) {
  model.items.clear();
  setRow(model, client, ID_A, 2, "A old", { seq: 1 });
  setTomb(model, client, ID_B, 2, { seq: 2 });
  setRow(model, client, ID_C, 3, "C old", { seq: 3 });
  model.bumpRestore();
}

/**
 * Waits until the four versions of `restoredWorld` are on the server: none of the rows has been written since the restore, so the
 * versions of this device that are higher go over them (A at 3, B brought back at 3, C deleted at 4) and D, which the server lacks, starts again.
 */
const untilDSent = (d) => until(() => d.model.items.get(ID_A)?.rev === 3 && d.model.items.get(ID_B)?.rev === 3 && d.model.items.get(ID_C)?.rev === 4 && d.model.items.get(ID_D)?.rev === 1, "the four versions are on the server");

/** The text of the request an outbox entry holds. */
const requestOf = (entry) => JSON.parse(new TextDecoder().decode(entry.bytes));

// ------------------------------------------------------------------ the doors

test("accept_older_state_is_refused_unless_halted_server_restored", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 5 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await assert.rejects(() => d.engine.acceptOlderState(), { code: "invalid_state" });
  await assert.rejects(() => d.engine.restorePreview(), { code: "invalid_state" });

  // Another stop is no restore: the floors are not lowered for it.
  model.latestSeqLie = 2;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "rollback_suspected");
  await assert.rejects(() => d.engine.acceptOlderState(), { code: "invalid_state" });
  await assert.rejects(() => d.engine.restorePreview(), { code: "invalid_state" });
  assert.equal(memoryOf((await stateOf(d)).memory).maxSeq, 5, "nothing was lowered");
  assert.equal(d.api.puts.length, 0);
  d.engine.stop();
});

test("restore_preview_counts_reuploads_and_conflicts", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 3, "A"); // will be at rev 2 on the restored server, untouched since: made again over it
  setRow(model, client, ID_B, 1, "B"); // will be gone from the restored server: sent again
  setRow(model, client, ID_C, 5, "C"); // another device writes it after the restore: kept back
  setRow(model, client, ID_D, 1, "D"); // the same on both sides: nothing to do
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const d_row = model.items.get(ID_D);
  model.items.clear();
  setRow(model, client, ID_A, 2, "A old", { seq: 1 });
  setRow(model, client, ID_C, 3, "C old", { seq: 2 });
  model.items.set(ID_D, { ...d_row, seq: 3 });
  model.seq = 3;
  model.bumpRestore(); // restore_seq 3, and the three rows frozen
  model.pinCheckpoint(); // the checkpoint of the restored state
  setRow(model, client, ID_C, 4, "C by another device"); // after the restore
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");

  const before = await stateOf(d);
  assert.deepEqual(await d.engine.restorePreview(), { reupload: 2, conflicts: 1, manifestOlder: false });
  // A preview changes nothing: no memory, no outbox, no write, still stopped.
  assert.deepEqual(await stateOf(d), before);
  assert.deepEqual(await queued(d), []);
  assert.equal(d.api.puts.length, 0);
  assert.equal(d.engine.health().halted, "server_restored");
  d.engine.stop();
});

// ------------------------------------------------------------------ the three phases

test("accept_older_state_saves_memory_then_queues_then_replaces_rows", async () => {
  const d = await restoredWorld();
  const log = d.store.spy.log;
  const from = log.length;
  const floorsBefore = memoryOf((await stateOf(d)).memory);
  assert.equal(floorsBefore.maxSeq, 4);
  assert.equal(floorsBefore.revs[ID_A], 3);

  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 4, conflicts: 0, manifestOlder: false });
  const run = log.slice(from);

  // Phase 1: the memory is stored first, as the floors of the older state, with the note that a restore is under way.
  const phases = d.store.spy.states.map((s) => s.restore?.phase ?? (s.restoreEpoch === 1 ? "done" : null));
  const first = phases.indexOf("memory_saved");
  assert.ok(first >= 0, "the memory was stored with its note");
  const lowered = memoryOf(d.store.spy.states[first].memory);
  assert.equal(lowered.maxSeq, 3, "the top of the older state");
  assert.equal(lowered.revs[ID_A], 2, "a floor went down, after the confirmation, and only here");
  assert.equal(d.store.spy.states[first].restoreEpoch, 0, "the new epoch is not stored yet");
  assert.equal(run.indexOf("state.save"), 0, "and it is the first thing that happens");

  // Phase 2: a write or a draft is queued for each item, and the note says so.
  const firstEnqueue = run.indexOf("outbox.enqueue");
  assert.ok(firstEnqueue > 0);
  assert.equal(run.filter((step) => step === "outbox.enqueue").length, 4);
  const queuedNote = phases.indexOf("queued");
  assert.ok(queuedNote > first, "the note moves on to the queued phase");
  assert.equal(d.store.spy.states[queuedNote].restoreEpoch, 0);

  // Phase 3: the rows are replaced, and only then are the epoch stored and the note removed.
  const rowsAt = run.indexOf("cache.putRows");
  assert.ok(rowsAt > firstEnqueue, "rows come after the queueing");
  assert.ok(run.lastIndexOf("outbox.enqueue") < rowsAt, "every write was queued before the rows were replaced");
  const done = phases.indexOf("done");
  assert.ok(done > queuedNote);
  assert.equal(d.store.spy.states[done].restore, null);
  assert.equal(d.store.spy.states[done].restoreEpoch, 1);
  assert.equal(d.engine.health().halted, null);
  assert.equal(states(d, "warning_cleared", "server_restored").length, 1, "the stop is announced as cleared");
  d.engine.stop();
});

test("phase_2_writes_are_held_until_phase_3_has_replaced_the_rows", async () => {
  const d = await restoredWorld();
  const log = d.store.spy.log;
  await d.engine.acceptOlderState();
  await untilDSent(d);
  const firstPut = log.indexOf("put");
  assert.ok(firstPut > 0);
  // Nothing went out before the rows of the server had replaced the old ones, though every write was stored before.
  assert.equal(log.slice(0, firstPut).filter((step) => step === "outbox.enqueue").length, 4);
  const rowsAt = log.indexOf("cache.putRows");
  assert.ok(rowsAt > 0 && rowsAt < firstPut, "the rows were replaced before the first write left");
  assert.ok(log.slice(0, firstPut).lastIndexOf("state.save") > rowsAt, "and the epoch was stored (phase 3 done) before it too");
  assert.equal(sent(d).length, 4, "all four go out: no row has been written since the restore");
  d.engine.stop();
});

test("newer_local_versions_are_queued_at_server_rev_plus_1_resurrect_tombstone_or_base_0", async () => {
  const d = await restoredWorld();
  await d.engine.acceptOlderState();
  await untilDSent(d);
  await settle(60);

  // Over the rows that have not been written since the restore each version goes out by itself, built on the server's revision.
  assert.deepEqual(sent(d).map((put) => put.id).sort(), [ID_A, ID_B, ID_C, ID_D]);
  const [dd] = sentFor(d, ID_D);
  assert.equal(dd.base_rev, 0, "the server has no row for D: it starts again");
  await d.client.vault.close_item(await d.client.vault.open_item(hex16.decode(ID_D), 1, b64u.decode(dd.blob), b64u.decode(dd.tag)));

  const [a] = sentFor(d, ID_A);
  assert.equal(a.base_rev, 2, "built on the server's revision 2");
  assert.equal(a.resurrect, undefined);
  const handle = await d.client.vault.open_item(hex16.decode(ID_A), 3, b64u.decode(a.blob), b64u.decode(a.tag));
  assert.equal((await d.client.vault.item_view(handle)).name, "A");
  await d.client.vault.close_item(handle);
  await assert.rejects(() => d.client.vault.open_item(hex16.decode(ID_A), 4, b64u.decode(a.blob), b64u.decode(a.tag)));

  const [b] = sentFor(d, ID_B);
  assert.equal(b.base_rev, 2, "the server holds a tombstone at 2");
  assert.equal(b.resurrect, true, "the item comes back");
  await d.client.vault.close_item(await d.client.vault.open_item(hex16.decode(ID_B), 3, b64u.decode(b.blob), b64u.decode(b.tag)));

  const [c] = sentFor(d, ID_C);
  assert.equal(c.base_rev, 3, "the server still holds C live at 3");
  assert.equal(c.deleted, true);
  await d.client.vault.verify_tombstone(hex16.decode(ID_C), 4, b64u.decode(c.tomb));

  for (const put of [a, b, c, dd]) assert.equal(put.restore_epoch, 1, "every write names the epoch that was accepted");
  assert.deepEqual(await queued(d), [], "all of them are done");
  assert.deepEqual(d.engine.list().filter((item) => item.blocked), [], "no conflict");
  assert.deepEqual(d.model.items.get(ID_A).rev, 3);
  assert.equal(d.model.items.get(ID_B).deleted, false);
  assert.equal(d.model.items.get(ID_C).deleted, true);
  d.engine.stop();
});

test("a_row_changed_on_the_server_after_the_restore_becomes_a_conflict_not_an_overwrite", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.seq = 10; // the counter of the server before the backup was taken
  setRow(model, client, ID_A, 5, "A five");
  setRow(model, client, ID_B, 1, "B");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const rowB = model.items.get(ID_B);
  model.items.clear();
  setRow(model, client, ID_A, 3, "A restored", { seq: 1 });
  model.items.set(ID_B, { ...rowB, seq: 2 });
  model.seq = 2;
  model.bumpRestore(); // the backup holds A at rev 3
  model.pinCheckpoint(); // what the restored server's checkpoint says
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  // Before the user confirms, another device writes A at revision 4.
  setRow(model, client, ID_A, 4, "A by another device");
  const theirs = model.items.get(ID_A);

  assert.deepEqual(await d.engine.restorePreview(), { reupload: 0, conflicts: 1, manifestOlder: false });
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 0, conflicts: 1, manifestOlder: false });
  await settle(80);
  assert.deepEqual(sentFor(d, ID_A), [], "nothing is written over the other device's version");
  assert.equal(model.items.get(ID_A), theirs);
  const item = d.engine.list().find((entry) => entry.id === ID_A);
  assert.equal(item.blocked, true);
  assert.equal(item.blockedReason, "conflict");
  assert.equal(item.rev, 4, "the screen shows the server's version");
  assert.equal(item.name, "A by another device");
  // The local version is kept as a draft in the outbox, built on the server's revision, and not sent.
  const [draft] = await queued(d);
  assert.equal(draft.itemId, ID_A);
  assert.equal(draft.baseRev, 4);
  const handle = await d.client.vault.open_item(hex16.decode(ID_A), 5, draft.body.blob, draft.body.tag);
  assert.equal((await d.client.vault.item_view(handle)).name, "A five");
  await d.client.vault.close_item(handle);
  assert.equal(errors(d, "conflict").length, 1);
  d.engine.stop();
});

test("a_second_device_with_same_rev_other_bytes_gets_the_offer_not_a_hard_warning", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.seq = 10;
  setRow(model, client, ID_A, 3, "A three");
  setRow(model, client, ID_B, 1, "B");
  const two = await syncDevice({ model, client, seed: 2 });
  await two.engine.start();
  const rowB = model.items.get(ID_B);
  model.items.clear();
  setRow(model, client, ID_A, 2, "A two", { seq: 1 });
  model.items.set(ID_B, { ...rowB, seq: 2 });
  model.seq = 2;
  model.bumpRestore(); // the backup holds A at rev 2
  // Device one has accepted the restore and kept its own copy of A: revision 3 on the server, with other bytes than device two holds.
  setRow(model, client, ID_A, 3, "A three");

  await two.engine.syncNow();
  assert.equal(two.engine.health().halted, "server_restored", "the offer");
  assert.deepEqual(two.engine.health().warnings, [], "and no hard warning");
  assert.equal((await stateOf(two)).hardWarning, null);
  assert.equal((await stateOf(two)).restoreEpoch, 0, "the new epoch waits for the user");

  assert.deepEqual(await two.engine.acceptOlderState(), { reuploaded: 0, conflicts: 1, manifestOlder: false });
  await settle(80);
  assert.deepEqual(sentFor(two, ID_A), [], "device two does not write over device one");
  const item = two.engine.list().find((entry) => entry.id === ID_A);
  assert.equal(item.blocked, true);
  assert.equal(item.blockedReason, "conflict");
  assert.equal(item.name, "A three", "the server's version, which device one wrote from its own copy");
  assert.equal(two.engine.health().halted, null);
  two.engine.stop();
});

test("server_restored_halt_survives_reload", async () => {
  const d = await restoredWorld();
  d.engine.stop();
  const again = await reload(d);
  await again.engine.start();
  assert.equal(again.engine.health().halted, "server_restored");
  assert.equal((await stateOf(again)).restoreEpoch, 0, "the higher epoch was never stored");
  assert.equal((await stateOf(again)).restore, null);
  assert.equal(again.api.puts.length, 0);
  again.engine.stop();
});

test("restored_server_with_nothing_lower_only_stores_the_new_epoch_with_a_notice", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 2, "A");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.restoreEpoch = 1; // restored from a backup that held everything this device has
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, null);
  assert.deepEqual(states(d, "warning", "restore_epoch_raised").map(({ from, to }) => ({ from, to })), [{ from: 0, to: 1 }]);
  assert.equal((await stateOf(d)).restoreEpoch, 1);
  assert.deepEqual(d.engine.list().map((item) => item.id), [ID_A]);
  d.engine.stop();
});

test("a_raised_epoch_with_a_checkpoint_that_does_not_verify_gives_the_offer", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 2, "A");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.restoreEpoch = 1;
  model.checkpoint = { ...model.autoCheckpoint(), mac: new Uint8Array(32) }; // a mac nobody with the key made
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored", "a failed verification on a restored server is an offer");
  assert.deepEqual(d.engine.health().warnings, []);
  assert.equal((await stateOf(d)).hardWarning, null, "no warning is stored for it");
  assert.equal((await stateOf(d)).restoreEpoch, 0);
  d.engine.stop();
});

// ------------------------------------------------------------------ what a restore must not do

test("accept_older_state_with_a_checkpoint_that_does_not_verify_stays_halted", async () => {
  const d = await restoredWorld();
  const before = await stateOf(d);
  const good = d.model.autoCheckpoint();
  d.model.checkpoint = { ...good, mac: new Uint8Array(32) };
  await assert.rejects(() => d.engine.acceptOlderState(), { code: "restore_not_verified", reason: "checkpoint_bad_mac" });
  await assert.rejects(() => d.engine.restorePreview(), { code: "restore_not_verified" });
  assert.equal(d.engine.health().halted, "server_restored");
  assert.deepEqual(await stateOf(d), before, "no floor was lowered and no note was stored");
  assert.deepEqual(await queued(d), []);
  d.model.checkpoint = null;
  await assert.rejects(() => d.engine.acceptOlderState(), { code: "restore_not_verified", reason: "no_checkpoint" });
  assert.deepEqual(await stateOf(d), before);

  // The user may try again when the server shows a checkpoint that verifies.
  d.model.checkpoint = "auto";
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 4, conflicts: 0, manifestOlder: false });
  assert.equal(d.engine.health().halted, null);
  d.engine.stop();
});

test("accept_older_state_does_not_lower_a_floor_unless_the_epoch_is_higher", async () => {
  const d = await restoredWorld();
  // Another tab has accepted already: the epoch that is stored is the one the server shows.
  await d.memory.withLock(async (state) => ({ ...state, restoreEpoch: 1 }));
  const before = await stateOf(d);
  await assert.rejects(() => d.engine.acceptOlderState(), { code: "invalid_state" });
  assert.deepEqual(await stateOf(d), before);
  assert.equal(memoryOf(before.memory).maxSeq, 4);
  d.engine.stop();
});

test("old_history_marks_of_every_kind_are_cleared_after_acceptance", async () => {
  const client = createFakeClient();
  const model = new Model();
  const db = await freshStore();
  const body = (name) => ({ item_type: "login", name });
  const cached = (id, rev, seq) => rowOfChange({ id, rev, seq, deleted: false, ...client.wireRow(id, rev, body(`item ${id.slice(0, 2)}`)) });
  await cache.putRows(db.store, scope(), [cached(ID_A, 3, 5), cached(ID_B, 3, 6), cached(ID_C, 3, 7), cached(ID_D, 3, 8)]);
  const key = `sync.flags.${ACCOUNT}.${scope().vaultId}.${scope().vkEpoch}`;
  await setSetting(db.store, key, {
    v: 1,
    marks: {
      [ID_A]: { kind: "damaged", rev: 4 },
      [ID_B]: { kind: "quarantined", rev: 4 },
      [ID_C]: { kind: "missing_on_server", rev: 3 },
      [ID_D]: { kind: "reuploaded", rev: 3, sent: [] },
    },
    blocked: {},
  });
  // The restored server: A and B at revision 2, D at revision 1, C gone, a lower counter and a higher epoch. The restore was not
  // recorded with a restore sequence number (a server from before): the interim rules apply, and every version over a row is kept back.
  setRow(model, client, ID_A, 2, "A old", { seq: 1 });
  setRow(model, client, ID_B, 2, "B old", { seq: 2 });
  setRow(model, client, ID_D, 1, "D old", { seq: 3 });
  model.restoreEpoch = 1;
  const d = await syncDevice({ model, client, db });
  await d.engine.start();
  assert.equal(d.engine.health().halted, "server_restored");
  const marked = d.engine.list();
  assert.equal(marked.find((i) => i.id === ID_A).damaged, true);
  assert.equal(marked.find((i) => i.id === ID_B).quarantined, true);
  assert.equal(marked.find((i) => i.id === ID_C).missingOnServer, true);

  // C is the only one the server has no row for; the other three are kept back as conflicts.
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 1, conflicts: 3, manifestOlder: false });
  const after = d.engine.list();
  assert.deepEqual(after.filter((i) => i.damaged || i.quarantined || i.missingOnServer), [], "no mark of the old history is left");
  const stored = await getSetting(db.store, key);
  assert.deepEqual(stored.marks, {}, "and none is stored");
  assert.deepEqual(Object.keys(stored.blocked).sort(), [ID_A, ID_B, ID_D], "the conflicts are blocks");
  await until(() => model.items.get(ID_C)?.rev === 1, "C is sent");
  await settle(60);
  assert.deepEqual(d.engine.list().filter((i) => i.damaged || i.quarantined || i.missingOnServer), [], "and none came back");
  d.engine.stop();
});

test("after_acceptance_the_server_rows_are_not_refused_as_lower_than_local", async () => {
  const d = await restoredWorld();
  await d.engine.acceptOlderState();
  await untilDSent(d);
  await settle(60);
  // The feed is read again from scratch (a 410): the listing shows the rows the server holds (this device's own writes among them).
  d.model.minValidSince = d.model.seq + 1;
  await d.engine.syncNow();
  await settle(60);
  const refused = d.events.state.filter((s) => ["rev_lower_than_local", "rev_below_remembered", "rev_same_row_changed", "row_damaged"].includes(s.code));
  assert.deepEqual(refused, []);
  assert.equal(d.engine.health().halted, null);
  assert.deepEqual(d.engine.health().warnings, []);
  assert.equal(d.engine.list().find((item) => item.id === ID_A).rev, 3, "the server's version: this device's own write over the restored row");
  assert.equal(memoryOf((await stateOf(d)).memory).revs[ID_A], 3);
  d.engine.stop();
});

test("a_write_while_an_older_state_is_accepted_is_refused", async () => {
  const d = await restoredWorld();
  const accepting = d.engine.acceptOlderState();
  await assert.rejects(() => d.engine.create(DRAFT), { code: "busy" });
  await assert.rejects(() => d.engine.acceptOlderState(), { code: "invalid_state" });
  await accepting;
  d.engine.stop();
});

// ------------------------------------------------------------------ a crash in each phase

/** Accepts with `crash` armed, stops the engine as a closed page would, reopens the browser and lets the restart resume. */
async function crashThenRestart({ arm, withPending = true, beforeStart = () => {} }) {
  const d = await restoredWorld();
  if (withPending) await d.engine.create(DRAFT); // a write that was waiting when the server was restored
  const waiting = await queued(d);
  arm(d);
  await assert.rejects(() => d.engine.acceptOlderState());
  assert.equal(d.api.puts.length, 0, "nothing was sent by the engine that crashed");
  const crashed = { state: await stateOf(d), queued: await queued(d), rows: await cache.getRows(d.store.database.store, scope()) };
  d.engine.stop();
  const again = await reload(d);
  beforeStart(again);
  await again.engine.start();
  return { d, again, waiting, crashed };
}

/** What every crash has to end in. */
async function assertResumed({ d, again }) {
  assert.equal(again.engine.health().halted, null);
  await untilDSent(again);
  await until(async () => (await queued(again)).length === 0, "the four versions and the item written while stopped are sent, and nothing is left in the outbox");
  const state = await stateOf(again);
  assert.equal(state.restore, null, "the note is gone");
  assert.equal(state.restoreEpoch, 1, "the epoch is stored");
  assert.equal(memoryOf(state.memory).revs[ID_A], 3, "the floors of the older state, and then this device's own write");
  for (const id of [ID_A, ID_B, ID_C, ID_D]) assert.equal(sentFor(again, id).length, 1, `one write for ${id.slice(0, 2)}`);
  assert.equal(sent(again).length, 5, "the four and the one that was written while stopped");
  for (const put of sent(again)) assert.equal(put.restore_epoch, 1, "every one names the epoch that was accepted");
  assert.equal(d.api.puts.length, 0);
}

test("a_crash_after_each_phase_resumes_at_the_next_start", async (t) => {
  await t.test("after phase 1: the memory is stored and nothing is queued", async () => {
    const run = await crashThenRestart({ arm: (d) => (d.store.failEnqueue = 1) });
    assert.equal(run.crashed.state.restore?.phase, "memory_saved");
    assert.equal(memoryOf(run.crashed.state.memory).revs[ID_A], 2, "the floors were lowered, once");
    assert.equal(run.crashed.queued.length, 1, "only the write that waited, not yet replaced");
    await assertResumed(run);
    run.again.engine.stop();
  });
  await t.test("in phase 2: the writes are queued and the note still says memory_saved", async () => {
    const run = await crashThenRestart({ arm: (d) => (d.store.failSaveWhen = (state) => state.restore?.phase === "queued") });
    assert.equal(run.crashed.state.restore?.phase, "memory_saved");
    assert.equal(run.crashed.queued.length, 5, "the writes were stored");
    await assertResumed(run);
    run.again.engine.stop();
  });
  await t.test("after phase 2: queued, the rows are not replaced", async () => {
    const run = await crashThenRestart({ arm: (d) => (d.store.failPutRows = 1) });
    assert.equal(run.crashed.state.restore?.phase, "queued");
    assert.equal(run.crashed.rows.find((row) => row.itemId === ID_A).rev, 3, "the old rows are still there");
    await assertResumed(run);
    run.again.engine.stop();
  });
  await t.test("in phase 3: the rows are replaced and the epoch is not stored", async () => {
    const run = await crashThenRestart({ arm: (d) => (d.store.failSaveWhen = (state) => state.restore === null && state.restoreEpoch === 1) });
    assert.equal(run.crashed.state.restore?.phase, "queued");
    assert.equal(run.crashed.state.restoreEpoch, 0);
    assert.equal(run.crashed.rows.find((row) => row.itemId === ID_A).rev, 2, "the rows are the server's");
    await assertResumed(run);
    run.again.engine.stop();
  });
});

test("on_restart_the_resume_runs_before_the_outbox_runner_starts", async () => {
  const { d, again } = await crashThenRestart({ arm: (d) => (d.store.failEnqueue = 1) });
  // The write that waited in the outbox would have gone out on start; it must wait for the rows of the server.
  await until(() => again.api.puts.length > 0, "writes go out after the resume");
  const log = again.store.spy.log;
  assert.ok(log.indexOf("cache.putRows") >= 0 && log.indexOf("cache.putRows") < log.indexOf("put"), "the rows were replaced before the first write left");
  assert.ok(log.lastIndexOf("state.save", log.indexOf("put")) > log.indexOf("cache.putRows"), "and the restore was recorded as done");
  assert.equal(d.api.puts.length, 0);
  again.engine.stop();
});

test("a_resume_that_cannot_reach_the_server_holds_every_write_and_tries_again", async () => {
  const run = await crashThenRestart({
    arm: (d) => (d.store.failEnqueue = 1),
    beforeStart: (again) => {
      again.api.failFeed = new ApiError(0, "network"); // the listing cannot be read twice: the start and the first pass
      again.api.failFeedTimes = 2;
    },
  });
  const { again } = run;
  assert.equal(again.api.puts.length, 0, "nothing is sent while the restore is unfinished");
  assert.equal((await stateOf(again)).restore?.phase, "memory_saved");
  assert.ok(states(again, "offline").length > 0);
  for (let turn = 0; turn < 10 && again.api.puts.length === 0; turn += 1) {
    again.timers.advance(5_000);
    await settle(30);
  }
  await assertResumed(run);
  again.engine.stop();
});

// ------------------------------------------------------------------ try again

test("resume_after_halt_halts_again_if_the_cause_remains", async () => {
  const d = await restoredWorld();
  await d.memory.withLock(async (state) => ({ ...state, hardWarning: "server_shows_older_state" }));
  const writes = d.api.puts.length;
  await d.engine.resumeAfterHalt();
  assert.equal(d.engine.health().halted, "server_restored", "the restore is still there");
  assert.equal(states(d, "halted").length, 2, "stopped again, and said so again");
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state", "a stored warning is not cleared by trying again");
  assert.equal(states(d, "warning_cleared").length, 0);
  assert.equal(d.api.puts.length, writes);
  d.engine.stop();
});

test("resume_after_halt_continues_when_the_cause_is_gone_and_makes_the_session_verify_again", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 5 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal(d.api.checkpointGets.length, 1);
  model.latestSeqLie = 2;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "rollback_suspected");
  const id = await d.engine.create(DRAFT); // stored, held
  await settle(30);
  assert.equal(d.api.puts.length, 0);

  model.latestSeqLie = null;
  await d.engine.resumeAfterHalt();
  assert.equal(d.engine.health().halted, null);
  assert.equal(d.api.checkpointGets.length, 2, "the checkpoint was checked again, though a day has not passed");
  await until(() => model.items.has(id), "the held write goes out once nothing stops the engine");
  d.engine.stop();
});

test("resume_after_halt_never_clears_a_stored_state_warning_without_a_successful_verify", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 5 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await d.memory.withLock(async (state) => ({ ...state, hardWarning: "server_shows_older_state" }));
  model.latestSeqLie = 2;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "rollback_suspected");
  model.latestSeqLie = null;
  // The checkpoint cannot be read: nothing is verified, so nothing is cleared.
  d.api.checkpointFaults.push({ kind: "network" });
  await d.engine.resumeAfterHalt();
  assert.equal(d.engine.health().halted, null);
  assert.equal((await stateOf(d)).hardWarning, "server_shows_older_state");
  assert.equal(states(d, "warning_cleared").length, 0);
  // A verification that succeeds is what clears it.
  assert.equal(await d.engine.verifyNow(), "ok");
  assert.equal((await stateOf(d)).hardWarning, null);
  d.engine.stop();
});

// ------------------------------------------------------------------ the plan, on its own

const ENTRY = (id, rev, envelope) => ({ item_id: hex16.decode(id), rev, hash: envelope === null ? null : sha(envelope) });
const bytes = (n) => new Uint8Array(32).fill(n);
const live = (id, rev, n, seq = 1) => ({ itemId: id, rev, seq, deleted: false, envelope: bytes(n), tag: bytes(n + 1), tomb: null });
const dead = (id, rev, seq = 1) => ({ itemId: id, rev, seq, deleted: true, envelope: null, tag: null, tomb: new Uint8Array(40) });
const checkpointOf = (seq, ...entries) => ({ seq, entries: signCheckpoint(Buffer.alloc(32, 7), seq, entries).entries });
const write = (id, baseRev, deleted = false) => ({
  idem: "ab".repeat(16), itemId: id, baseRev, bytes: new Uint8Array(0),
  body: deleted ? { tomb: new Uint8Array(40) } : { blob: bytes(9), tag: bytes(10) },
});

test("a_local_version_over_a_row_the_server_has_is_never_sent_by_itself", async () => {
  const server = live(ID_A, 2, 1);
  const checkpoint = checkpointOf(5, ENTRY(ID_A, 2, server.envelope));
  // Even over the very row the restored checkpoint lists: a checkpoint of a later moment would list a write that was made
  // after the restore in the same way, and nothing on this device can tell the two apart.
  const plan = await planRestore({ listing: [server], checkpoint, rows: [live(ID_A, 3, 7)], outbox: [] });
  assert.deepEqual(plan, { upload: [], conflicts: [ID_A], unchanged: 0 });
  const [item] = await restoreItems({ listing: [server], checkpoint, rows: [live(ID_A, 3, 7)], outbox: [] });
  assert.deepEqual({ kind: item.kind, baseRev: item.baseRev, conflict: item.conflict }, { kind: "reseal", baseRev: 2, conflict: true }, "the draft is still built on the server's row");
});

test("the_same_revision_with_other_bytes_is_a_conflict_and_identical_rows_are_nothing_to_do", async () => {
  const server = live(ID_A, 3, 1);
  const checkpoint = checkpointOf(5, ENTRY(ID_A, 3, server.envelope));
  const identical = await planRestore({ listing: [server], checkpoint, rows: [live(ID_A, 3, 1)], outbox: [] });
  assert.deepEqual(identical, { upload: [], conflicts: [], unchanged: 1 });
  const other = await planRestore({ listing: [server], checkpoint, rows: [live(ID_A, 3, 5)], outbox: [] });
  assert.deepEqual(other, { upload: [], conflicts: [ID_A], unchanged: 0 });
  // A lower revision here than on the server is no reason to drop the local version: after a restore the revisions are not one line.
  const lower = await planRestore({ listing: [live(ID_A, 5, 1)], checkpoint: checkpointOf(5, ENTRY(ID_A, 5, bytes(1))), rows: [live(ID_A, 4, 9)], outbox: [] });
  assert.deepEqual(lower, { upload: [], conflicts: [ID_A], unchanged: 0 });
  // Byte for byte the server's row is nothing to do, whatever the revision numbers say.
  const same = await planRestore({ listing: [live(ID_A, 5, 1)], checkpoint: checkpointOf(5, ENTRY(ID_A, 5, bytes(1))), rows: [live(ID_A, 5, 1)], outbox: [] });
  assert.deepEqual(same, { upload: [], conflicts: [], unchanged: 1 });
  // A local tombstone below a live row the server has now.
  const gone = await restoreItems({ listing: [live(ID_A, 5, 1)], checkpoint: checkpointOf(5, ENTRY(ID_A, 5, bytes(1))), rows: [dead(ID_A, 4)], outbox: [] });
  assert.deepEqual(gone.map(({ kind, conflict }) => ({ kind, conflict })), [{ kind: "tombstone", conflict: true }]);
});

test("only_an_item_the_server_has_no_row_for_is_sent_the_rest_are_drafts_of_their_kind", async () => {
  const entries = checkpointOf(5, ENTRY(ID_A, 2, null), ENTRY(ID_B, 3, bytes(2)));
  const input = {
    listing: [dead(ID_A, 2), live(ID_B, 3, 2)],
    checkpoint: entries,
    rows: [live(ID_A, 3, 1), dead(ID_B, 4), live(ID_C, 1, 3), dead(ID_D, 2)],
    outbox: [],
  };
  const plan = await planRestore(input);
  assert.deepEqual(plan.upload, [{ id: ID_C, baseRev: 0, kind: "new" }]);
  assert.deepEqual(plan.conflicts, [ID_A, ID_B]);
  assert.equal(plan.unchanged, 1, "a deletion of what the server does not have");
  const kinds = (await restoreItems(input)).map(({ id, kind, baseRev, conflict }) => ({ id, kind, baseRev, conflict }));
  assert.deepEqual(kinds, [
    { id: ID_A, kind: "resurrect", baseRev: 2, conflict: true },
    { id: ID_B, kind: "tombstone", baseRev: 3, conflict: true },
    { id: ID_C, kind: "new", baseRev: 0, conflict: false },
    { id: ID_D, kind: "skip", baseRev: 0, conflict: false },
  ]);
});

test("a_write_that_waits_in_the_outbox_is_never_dropped_and_never_sent_over_a_row_the_server_has", async () => {
  const server = live(ID_A, 4, 1);
  const checkpoint = checkpointOf(5, ENTRY(ID_A, 4, server.envelope));
  // Built on revision 4 over the row the checkpoint lists: still a draft.
  const built = await planRestore({ listing: [server], checkpoint, rows: [live(ID_A, 4, 1)], outbox: [write(ID_A, 4)] });
  assert.deepEqual(built, { upload: [], conflicts: [ID_A], unchanged: 0 });
  // Built on an older revision than the server has now.
  const behind = await planRestore({ listing: [server], checkpoint, rows: [live(ID_A, 2, 1)], outbox: [write(ID_A, 2)] });
  assert.deepEqual(behind.conflicts, [ID_A]);
  // A pending deletion against a live row.
  const deletion = await restoreItems({ listing: [server], checkpoint, rows: [live(ID_A, 4, 1)], outbox: [write(ID_A, 4, true)] });
  assert.deepEqual(deletion.map(({ kind, conflict }) => ({ kind, conflict })), [{ kind: "tombstone", conflict: true }]);
  // An item whose earlier write was refused stays a conflict.
  const refused = await planRestore({ listing: [server], checkpoint, rows: [live(ID_A, 4, 1)], outbox: [write(ID_A, 4)], blocked: [ID_A] });
  assert.deepEqual(refused.conflicts, [ID_A]);
  // A pending creation of something the server lacks is sent.
  const created = await planRestore({ listing: [], checkpoint: checkpointOf(5), rows: [], outbox: [write(ID_B, 0)] });
  assert.deepEqual(created.upload, [{ id: ID_B, baseRev: 0, kind: "new" }]);
});

test("the_manifest_is_never_sent_and_an_item_uploaded_again_is_judged_by_its_row", async () => {
  const manifest = "00".repeat(16);
  const plan = await planRestore({ listing: [], checkpoint: checkpointOf(5), rows: [live(manifest, 3, 1)], outbox: [] });
  assert.deepEqual(plan, { upload: [], conflicts: [], unchanged: 0 });
  // The copy that was uploaded again waits as a write from revision 0; the row is the version, at the revision its mark keeps.
  const server = live(ID_A, 2, 1);
  const items = await restoreItems({
    listing: [server], checkpoint: checkpointOf(5, ENTRY(ID_A, 2, server.envelope)),
    rows: [live(ID_A, 1, 7)], outbox: [write(ID_A, 0)], marks: new Map([[ID_A, { kind: "missing_on_server", rev: 6 }]]),
  });
  assert.deepEqual(items.map(({ id, kind, conflict, source, localRev }) => ({ id, kind, conflict, source, localRev })), [
    { id: ID_A, kind: "reseal", conflict: true, source: "row", localRev: 6 },
  ]);
});

// ------------------------------------------------------------------ the fix round

const MANIFEST = "00".repeat(16);

test("a_post_restore_write_covered_by_a_newer_checkpoint_is_a_conflict_not_an_overwrite", async () => {
  // The checkpoint is "auto": it always covers what the server holds now, as the checkpoint another device uploads after its own
  // writes does. Device two holds A at revision 6 from the old history. The backup held A at revision 3.
  const model = new Model();
  const client = createFakeClient();
  model.seq = 10;
  setRow(model, client, ID_A, 6, "A six");
  setRow(model, client, ID_B, 1, "B");
  const two = await syncDevice({ model, client });
  await two.engine.start();
  const rowB = model.items.get(ID_B);
  model.items.clear();
  setRow(model, client, ID_A, 3, "A restored", { seq: 1 });
  model.items.set(ID_B, { ...rowB, seq: 2 });
  model.seq = 2;
  model.bumpRestore();
  // Device one has accepted the restore, edited A to revision 4 and uploaded a checkpoint as usual (it covers A at 4).
  setRow(model, client, ID_A, 4, "A edited by device one");
  const theirs = model.items.get(ID_A);
  assert.ok(theirs.seq > model.restoreSeq, "written after the restore");
  await two.engine.syncNow();
  assert.equal(two.engine.health().halted, "server_restored");

  assert.deepEqual(await two.engine.restorePreview(), { reupload: 0, conflicts: 1, manifestOlder: false });
  assert.deepEqual(await two.engine.acceptOlderState(), { reuploaded: 0, conflicts: 1, manifestOlder: false });
  await settle(80);
  assert.deepEqual(sentFor(two, ID_A), [], "no revision 5 over device one's edit");
  assert.equal(model.items.get(ID_A), theirs);
  const item = two.engine.list().find((entry) => entry.id === ID_A);
  assert.equal(item.blockedReason, "conflict");
  assert.equal(item.name, "A edited by device one");
  const [draft] = await queued(two);
  assert.equal(draft.baseRev, 4, "device two's own version is kept as a draft on top of it");
  two.engine.stop();
});

test("a_stale_device_at_rev_5_skips_a_post_restore_rev_6_without_a_conflict", async () => {
  // The backup held A at revision 5. This device is at 5 too (it never pulled more). After the restore device one wrote revision 6.
  const model = new Model();
  const client = createFakeClient();
  model.seq = 10;
  setRow(model, client, ID_A, 5, "A five");
  setRow(model, client, ID_B, 1, "B");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const rowA = model.items.get(ID_A);
  const rowB = model.items.get(ID_B);
  model.items.clear();
  model.items.set(ID_A, { ...rowA, seq: 1 });
  model.items.set(ID_B, { ...rowB, seq: 2 });
  model.seq = 2;
  model.bumpRestore();
  setRow(model, client, ID_A, 6, "A six written after the restore");
  const theirs = model.items.get(ID_A);
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");

  assert.deepEqual(await d.engine.restorePreview(), { reupload: 0, conflicts: 0, manifestOlder: false });
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 0, conflicts: 0, manifestOlder: false });
  await settle(80);
  assert.deepEqual(sentFor(d, ID_A), [], "no write");
  assert.equal(model.items.get(ID_A), theirs);
  assert.deepEqual(await queued(d), [], "no draft and no conflict");
  assert.deepEqual(errors(d, "conflict"), []);
  const item = d.engine.list().find((entry) => entry.id === ID_A);
  assert.deepEqual([item.blocked, item.conflict, item.rev, item.name], [false, false, 6, "A six written after the restore"]);
  assert.equal(d.engine.health().halted, null);
  d.engine.stop();
});

/** A device that has A (revision 3) and a write of A that did not reach the server before the page was closed. */
async function withUnsentEdit() {
  const model = new Model();
  const client = createFakeClient();
  model.seq = 10;
  setRow(model, client, ID_A, 3, "A three");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  d.api.faults.push({ kind: "network" });
  await d.engine.update(ID_A, { name: "A edited offline" }, 3);
  await settle(30);
  assert.equal(d.api.puts.length, 1, "the write was tried and did not arrive");
  d.engine.stop();
  return d;
}

test("queued_writes_do_not_go_out_on_a_reload_before_the_first_pass_has_shown_the_server_is_not_restored", async () => {
  const d = await withUnsentEdit();
  // The server is restored: A is at revision 3 as well, with other bytes, so a write built on revision 3 would be accepted.
  d.model.items.clear();
  setRow(d.model, d.client, ID_A, 3, "A as restored", { seq: 1 });
  d.model.restoreEpoch = 1;
  const before = d.model.items.get(ID_A);
  const again = await reload(d);
  await again.engine.start();
  await settle(80);
  assert.equal(again.engine.health().halted, "server_restored");
  assert.equal(again.api.puts.length, 0, "the write waited for the first pass, which found the restore");
  assert.equal(d.model.items.get(ID_A), before);
  assert.equal((await queued(again)).length, 1, "and it is still stored");
  again.engine.stop();
});

test("queued_writes_stay_held_while_a_raised_restore_epoch_has_no_verified_checkpoint", async () => {
  const d = await withUnsentEdit();
  d.model.restoreEpoch = 1; // restored from a backup that holds everything this device has: nothing lower
  const again = await reload(d);
  again.api.checkpointFaults.push({ kind: "network" });
  await again.engine.start();
  await settle(80);
  assert.equal(again.engine.health().halted, null);
  assert.equal(again.api.puts.length, 0, "the checkpoint could not be read: the epoch is not accepted and nothing is sent");
  assert.equal((await stateOf(again)).restoreEpoch, 0);
  // The next pass reads the checkpoint, accepts the epoch and lets the write go.
  await until(() => again.timers.pending > 0);
  again.timers.advance(5_000);
  await until(() => again.api.puts.length === 1, "the write goes out once the checkpoint has verified");
  assert.equal((await stateOf(again)).restoreEpoch, 1);
  again.engine.stop();
});

test("a_resume_never_replaces_rows_from_a_listing_the_checkpoint_does_not_vouch_for", async () => {
  const d = await restoredWorld();
  d.store.failPutRows = 1;
  await assert.rejects(() => d.engine.acceptOlderState()); // crashed after phase 2: queued, rows not replaced
  d.engine.stop();
  d.model.hidden.add(ID_A); // the server now leaves A out of the listing, though its checkpoint lists it
  const again = await reload(d);
  await again.engine.start();
  assert.equal(again.engine.health().halted, "server_restored", "the user is offered the choice again");
  assert.deepEqual(errors(again, "restore_not_verified").map((e) => e.reason), ["checkpoint_hidden_or_rolled_back"]);
  const rows = await cache.getRows(again.store.database.store, scope());
  assert.equal(rows.find((row) => row.itemId === ID_A).rev, 3, "the local copy of A is still there");
  assert.ok(rows.some((row) => row.itemId === ID_D));
  assert.equal((await stateOf(again)).restore?.phase, "queued", "the note stays");
  // Nothing is retried unasked.
  const gets = again.api.gets.length;
  again.timers.advance(600_000);
  await settle(60);
  assert.equal(again.api.gets.length, gets);
  assert.equal(again.api.puts.length, 0);
  again.engine.stop();
});

test("a_live_row_the_listing_no_longer_shows_and_that_has_no_write_waiting_is_kept_and_marked", async () => {
  const model = new Model();
  const client = createFakeClient();
  const ID_X = "55".repeat(16);
  model.seq = 10;
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_X, 1, "X");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const rowA = model.items.get(ID_A);
  const rowX = model.items.get(ID_X);
  model.items.clear();
  model.items.set(ID_A, { ...rowA, seq: 1 });
  model.seq = 1;
  model.restoreEpoch = 1;
  model.pinCheckpoint(); // lists A only
  model.items.set(ID_X, { ...rowX, seq: 2 }); // in the backup, after the checkpoint
  model.seq = 2;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  d.store.failPutRows = 1;
  await assert.rejects(() => d.engine.acceptOlderState());
  d.engine.stop();
  model.hidden.add(ID_X); // the server hides X by the time the restart resumes
  const again = await reload(d);
  again.api.faults.push({ kind: "network" }); // the copy of X does not reach the server yet, so the mark can be seen
  await again.engine.start();
  assert.equal(again.engine.health().halted, null);
  assert.equal(again.engine.list().find((item) => item.id === ID_X).missingOnServer, true, "marked, to be sent again");
  const flagsKey = `sync.flags.${ACCOUNT}.${scope().vaultId}.${scope().vkEpoch}`;
  assert.equal((await getSetting(again.store.database.store, flagsKey)).marks[ID_X].kind, "missing_on_server", "and the mark is stored");
  const rows = await cache.getRows(again.store.database.store, scope());
  assert.ok(rows.some((row) => row.itemId === ID_X), "the only copy of X is not deleted on the server's word");
  assert.ok(again.engine.list().some((item) => item.id === ID_X));
  assert.ok(rows.every((row) => row.itemId !== ID_X || row.seq === 0), "and the cursor does not follow the old history");
  assert.equal((await stateOf(again)).restore, null);
  again.engine.stop();
});

test("a_write_being_made_when_the_user_confirms_is_in_the_outbox_before_the_plan_is_made", async () => {
  const d = await restoredWorld();
  const making = d.engine.create(DRAFT);
  const accepting = d.engine.acceptOlderState();
  await making;
  assert.deepEqual(await accepting, { reuploaded: 5, conflicts: 0, manifestOlder: false });
  await until(() => d.api.puts.length === 5, "the four versions and the new item are sent");
  d.engine.stop();
});

test("accepting_and_resuming_run_under_the_restore_lock_of_the_account", async () => {
  const d = await restoredWorld();
  const name = d.memory.name.replace("ferret-sync-memory:", "ferret-sync-restore:");
  const seen = [];
  const get = d.api.get;
  d.api.get = async (...args) => {
    seen.push(d.locks.held.has(name));
    return get(...args);
  };
  d.store.failPutRows = 1;
  await assert.rejects(() => d.engine.acceptOlderState());
  assert.ok(seen.length >= 2 && seen.every(Boolean), "the listing and the checkpoint are read under the lock");
  assert.equal(d.locks.held.has(name), false, "and it is let go");
  d.engine.stop();
  const again = await reload(d);
  const resumed = [];
  const read = again.api.get;
  again.api.get = async (...args) => {
    resumed.push(again.locks.held.has(name));
    return read(...args);
  };
  await again.engine.start();
  assert.ok(resumed.length >= 2 && resumed.slice(0, 2).every(Boolean), "so is the resume");
  again.engine.stop();
});

test("an_engine_that_starts_stopped_still_listens_for_focus_and_online", async () => {
  const d = await restoredWorld();
  d.engine.stop();
  const win = new EventTarget();
  const again = await syncDevice({ model: d.model, client: d.client, db: d.store.database, locks: d.locks, win });
  await again.engine.start();
  assert.equal(again.engine.health().halted, "server_restored");
  await again.engine.acceptOlderState();
  await untilDSent(again);
  await settle(80);
  const gets = again.api.gets.length;
  win.dispatchEvent(new Event("focus"));
  await until(() => again.api.gets.length > gets, "a focus makes a pass");
  again.engine.stop();
});

test("resume_after_halt_refuses_when_the_engine_is_not_stopped", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  await assert.rejects(() => d.engine.resumeAfterHalt(), { code: "invalid_state" });
  d.engine.stop();
});

test("the_preview_and_the_accept_say_when_the_restored_manifest_is_older", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.seq = 10;
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, MANIFEST, 2, "manifest two");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const rowA = model.items.get(ID_A);
  model.items.clear();
  model.items.set(ID_A, { ...rowA, seq: 1 });
  setRow(model, client, MANIFEST, 1, "manifest one", { seq: 2 });
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  assert.deepEqual(await d.engine.restorePreview(), { reupload: 0, conflicts: 0, manifestOlder: true });
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 0, conflicts: 0, manifestOlder: true });
  assert.equal(d.api.puts.length, 0, "the manifest is never sent from here");
  d.engine.stop();
});

test("without_restore_rows_the_interim_rules_still_apply", async () => {
  // A server from before restore_seq: the epoch is raised but the vault records no restore sequence number, so there is no list
  // of frozen rows to read. A local version over a row the server has is kept back, whatever its revision.
  const model = new Model();
  const client = createFakeClient();
  model.seq = 10;
  setRow(model, client, ID_A, 5, "A five from the old history");
  setRow(model, client, ID_B, 1, "B");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  const rowB = model.items.get(ID_B);
  model.items.clear();
  // After the restore another device wrote A, and the server numbers it 6.
  setRow(model, client, ID_A, 6, "A six written after the restore", { seq: 1 });
  model.items.set(ID_B, { ...rowB, seq: 2 });
  model.seq = 2;
  model.restoreEpoch = 1; // restore_seq stays 0
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  assert.deepEqual(await d.engine.restorePreview(), { reupload: 0, conflicts: 1, manifestOlder: false });
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 0, conflicts: 1, manifestOlder: false });
  assert.deepEqual(d.api.restoreRowGets, [], "the list of frozen rows is not asked for when there is no restore sequence number");
  await settle(80);
  assert.deepEqual(sentFor(d, ID_A), []);
  const item = d.engine.list().find((entry) => entry.id === ID_A);
  assert.equal(item.blockedReason, "conflict");
  assert.equal(item.name, "A six written after the restore", "the screen shows the server's version");
  const [draft] = await queued(d);
  assert.equal(draft.baseRev, 6, "the old version is kept as a draft on top of it");
  const handle = await d.client.vault.open_item(hex16.decode(ID_A), 7, draft.body.blob, draft.body.tag);
  assert.equal((await d.client.vault.item_view(handle)).name, "A five from the old history");
  await d.client.vault.close_item(handle);
  d.engine.stop();
});

test("a_first_pass_that_fails_offline_after_a_reload_keeps_the_queued_writes_held_until_a_clean_pass", async () => {
  const d = await withUnsentEdit();
  const again = await reload(d);
  again.api.failFeed = new ApiError(0, "network");
  again.api.failFeedTimes = 1;
  await again.engine.start();
  await settle(60);
  assert.ok(states(again, "offline").length > 0, "the first pass failed");
  assert.equal(again.api.puts.length, 0, "and the write stays held: nothing says yet that the server is not a restored one");
  await until(() => again.timers.pending > 0);
  again.timers.advance(5_000);
  await until(() => again.api.puts.length === 1, "the write goes out after a pass that ended well");
  again.engine.stop();
});

test("resume_after_halt_keeps_the_queued_writes_held_until_a_pass_ends_well", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 5 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.latestSeqLie = 2;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "rollback_suspected");
  const id = await d.engine.create(DRAFT);
  model.latestSeqLie = null;
  d.api.failFeed = new ApiError(0, "network");
  d.api.failFeedTimes = 1;
  await d.engine.resumeAfterHalt();
  await settle(60);
  assert.equal(d.engine.health().halted, null);
  assert.equal(model.items.has(id), false, "the pass failed: the write is still held");
  await until(() => d.timers.pending > 0);
  d.timers.advance(5_000);
  await until(() => model.items.has(id), "a clean pass lets it go");
  d.engine.stop();
});

// ------------------------------------------------------------------ the restore sequence number and the frozen rows

/** What the server froze: its `seq` at the restore and a row `[id, rev, seq, n]` for each item (`n`: the bytes of `live(id, rev, n)`, left out for a tombstone). */
const frozenOf = (restoreSeq, ...rows) => ({
  restoreSeq,
  frozen: new Map(rows.map(([id, rev, seq = 1, n]) => [id, { rev, seq, hash: n === undefined ? null : b64u.encode(sha(bytes(n))) }])),
});
const kindsOf = (items) => items.map(({ id, kind, baseRev, conflict }) => ({ id, kind, baseRev, conflict }));

test("a_byte_identical_version_is_skipped_before_the_table", async () => {
  const restore = frozenOf(5, [ID_A, 2], [ID_B, 2]);
  const items = await restoreItems({
    // A was written after the restore (seq 9) and this device's version is above the frozen one: the table alone says conflict.
    // B is untouched and this device's version is higher: the table alone says made again. The same bytes are nothing to do in both.
    listing: [live(ID_A, 6, 1, 9), live(ID_B, 2, 2, 3)],
    restore,
    rows: [live(ID_A, 6, 1, 4), live(ID_B, 7, 2, 4)],
    outbox: [],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "skip", baseRev: 6, conflict: false },
    { id: ID_B, kind: "skip", baseRev: 2, conflict: false },
  ]);
});

test("a_lost_version_over_an_untouched_row_is_resealed_without_a_conflict", async () => {
  const restore = frozenOf(5, [ID_A, 2, 1], [ID_B, 2, 2], [ID_C, 3, 3]);
  const items = await restoreItems({
    listing: [live(ID_A, 2, 1, 1), dead(ID_B, 2, 2), live(ID_C, 3, 2, 3)],
    restore,
    rows: [live(ID_A, 4, 7), live(ID_B, 3, 7), dead(ID_C, 4)],
    outbox: [],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "reseal", baseRev: 2, conflict: false },
    { id: ID_B, kind: "resurrect", baseRev: 2, conflict: false },
    { id: ID_C, kind: "tombstone", baseRev: 3, conflict: false },
  ]);
  const plan = await planRestore({ listing: [live(ID_A, 2, 1, 1)], restore, rows: [live(ID_A, 4, 7)], outbox: [] });
  assert.deepEqual(plan, { upload: [{ id: ID_A, baseRev: 2, kind: "reseal" }], conflicts: [], unchanged: 0 });
});

test("a_lower_version_over_an_untouched_row_is_skipped", async () => {
  const restore = frozenOf(5, [ID_A, 3, 1, 1], [ID_B, 3, 2, 2]);
  const items = await restoreItems({
    listing: [live(ID_A, 3, 1, 1), live(ID_B, 3, 2, 2)],
    restore,
    rows: [live(ID_A, 2, 7), live(ID_B, 1, 9)], // lower than the restored row: the restored row stands
    outbox: [],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "skip", baseRev: 3, conflict: false },
    { id: ID_B, kind: "skip", baseRev: 3, conflict: false },
  ]);
});

test("the_same_revision_with_other_bytes_over_an_untouched_row_is_a_conflict_and_not_a_skip", async () => {
  // Another line of history: a version at the very revision of the restored row, with other bytes.
  const restore = frozenOf(5, [ID_A, 3, 1, 1], [ID_B, 3, 2, 2]);
  const items = await restoreItems({
    listing: [live(ID_A, 3, 1, 1), live(ID_B, 3, 2, 2)],
    restore,
    rows: [live(ID_A, 3, 7), live(ID_B, 3, 2)], // A: other bytes. B: the same bytes (nothing to do)
    outbox: [],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "reseal", baseRev: 3, conflict: true },
    { id: ID_B, kind: "skip", baseRev: 3, conflict: false },
  ]);
});

test("a_row_written_after_the_restore_is_skipped_for_an_older_version_and_a_conflict_for_a_newer_one", async () => {
  const restore = frozenOf(5, [ID_A, 5, 1, 7], [ID_B, 5, 2, 7], [ID_C, 5, 3, 7], [ID_D, 5, 4, 7]);
  const items = await restoreItems({
    listing: [live(ID_A, 6, 1, 9), live(ID_B, 6, 2, 9), live(ID_C, 6, 3, 9), live(ID_D, 6, 4, 9)],
    restore,
    // A: at the frozen revision with the frozen bytes: older on the same line. B: above the frozen revision. C: below it.
    // D: at the frozen revision with other bytes: another line of history.
    rows: [live(ID_A, 5, 7), live(ID_B, 7, 7), live(ID_C, 4, 7), live(ID_D, 5, 8)],
    outbox: [],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "skip", baseRev: 6, conflict: false },
    { id: ID_B, kind: "reseal", baseRev: 6, conflict: true },
    { id: ID_C, kind: "skip", baseRev: 6, conflict: false },
    { id: ID_D, kind: "reseal", baseRev: 6, conflict: true },
  ]);
});

test("an_unsent_local_edit_built_on_the_restored_row_or_a_later_revision_is_resealed_over_an_untouched_row", async () => {
  const restore = frozenOf(5, [ID_A, 5, 1, 1], [ID_B, 5, 2, 1], [ID_C, 5, 3, 1], [ID_D, 5, 4, 1]);
  const items = await restoreItems({
    listing: [live(ID_A, 5, 1, 1), live(ID_B, 5, 1, 2), live(ID_C, 5, 1, 3), dead(ID_D, 5, 4)],
    restore,
    // A: built on the restored row (base 5). B: built on a later revision the restore lost (base 7). C: a pending deletion built on
    // the restored row. D: a pending edit of an item the restored server holds as a tombstone, built on its revision.
    rows: [live(ID_A, 5, 1), live(ID_B, 7, 1), live(ID_C, 5, 1), dead(ID_D, 5)],
    outbox: [write(ID_A, 5), write(ID_B, 7), write(ID_C, 5, true), write(ID_D, 5)],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "reseal", baseRev: 5, conflict: false },
    { id: ID_B, kind: "reseal", baseRev: 5, conflict: false },
    { id: ID_C, kind: "tombstone", baseRev: 5, conflict: false },
    { id: ID_D, kind: "resurrect", baseRev: 5, conflict: false },
  ]);
  assert.deepEqual(items.map((i) => i.source), ["outbox", "outbox", "outbox", "outbox"]);
});

test("an_unsent_local_edit_built_below_the_restored_row_is_a_conflict_over_an_untouched_row_and_never_dropped", async () => {
  // Another device took the item to revision 5 before the backup; this device's offline edit was built on revision 1. Without a
  // restore the server would have refused it (409), and so it is a conflict now: it must not silently overwrite revisions 2 to 5.
  const restore = frozenOf(5, [ID_A, 5, 1, 1], [ID_B, 5, 2, 1], [ID_C, 5, 3, 1], [ID_D, 5, 4, 1]);
  const items = await restoreItems({
    listing: [live(ID_A, 5, 1, 1), live(ID_B, 5, 1, 2), dead(ID_C, 5, 3), live(ID_D, 5, 1, 4)],
    restore,
    // A: an edit built on 1. B: a pending deletion built on 4. C: an edit built on 1 over a tombstone at 5 (a resurrection).
    // D: an edit built on 0 (a creation that collides with a row the restore holds).
    rows: [live(ID_A, 1, 1), live(ID_B, 4, 1), dead(ID_C, 1), live(ID_D, 1, 1)],
    outbox: [write(ID_A, 1), write(ID_B, 4, true), write(ID_C, 1), write(ID_D, 0)],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "reseal", baseRev: 5, conflict: true },
    { id: ID_B, kind: "tombstone", baseRev: 5, conflict: true },
    { id: ID_C, kind: "resurrect", baseRev: 5, conflict: true },
    { id: ID_D, kind: "reseal", baseRev: 5, conflict: true },
  ]);
  const plan = await planRestore({ listing: [live(ID_A, 5, 1, 1)], restore: frozenOf(5, [ID_A, 5, 1, 1]), rows: [live(ID_A, 1, 1)], outbox: [write(ID_A, 1)] });
  assert.deepEqual(plan, { upload: [], conflicts: [ID_A], unchanged: 0 });
});

test("an_unsent_local_edit_over_a_row_written_after_the_restore_is_a_conflict_whatever_its_base", async () => {
  const restore = frozenOf(5, [ID_A, 2, 1, 1], [ID_B, 2, 2, 1]);
  const items = await restoreItems({
    listing: [live(ID_A, 6, 2, 9), live(ID_B, 6, 3, 9)],
    restore,
    rows: [live(ID_A, 1, 7), live(ID_B, 6, 7)],
    outbox: [write(ID_A, 0), write(ID_B, 6, true)],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "reseal", baseRev: 6, conflict: true },
    { id: ID_B, kind: "tombstone", baseRev: 6, conflict: true },
  ]);
});

test("an_item_already_blocked_as_a_conflict_stays_a_conflict_even_over_an_untouched_row", async () => {
  const restore = frozenOf(5, [ID_A, 2, 1, 1]);
  const input = { listing: [live(ID_A, 2, 1, 1)], restore, rows: [live(ID_A, 2, 1)], outbox: [write(ID_A, 2)] };
  assert.deepEqual(kindsOf(await restoreItems(input)), [{ id: ID_A, kind: "reseal", baseRev: 2, conflict: false }], "built on the restored row: sent");
  assert.deepEqual(kindsOf(await restoreItems({ ...input, blocked: [ID_A] })), [{ id: ID_A, kind: "reseal", baseRev: 2, conflict: true }], "but not when it was blocked as a conflict");
});

test("an_unsent_write_that_is_the_servers_row_at_base_plus_1_is_this_devices_own_write_and_counts_as_done", async () => {
  const restore = frozenOf(5, [ID_A, 4, 1, 9], [ID_B, 4, 2, 9]);
  const mine = (n) => ({ blob: bytes(n), tag: bytes(n + 1) });
  const tombstone = { itemId: ID_B, rev: 4, seq: 2, deleted: true, envelope: null, tag: null, tomb: new Uint8Array(40).fill(3) };
  const items = await restoreItems({
    listing: [live(ID_A, 4, 5, 1), tombstone],
    restore,
    rows: [live(ID_A, 3, 1), live(ID_B, 3, 1)],
    outbox: [
      { idem: "cd".repeat(16), itemId: ID_A, baseRev: 3, bytes: new Uint8Array(0), body: mine(5) },
      { idem: "ef".repeat(16), itemId: ID_B, baseRev: 3, bytes: new Uint8Array(0), body: { tomb: new Uint8Array(40).fill(3) } },
    ],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "skip", baseRev: 4, conflict: false },
    { id: ID_B, kind: "skip", baseRev: 4, conflict: false },
  ]);
  // The same bytes at another revision are not its own write.
  const other = await restoreItems({
    listing: [live(ID_A, 4, 5, 1)], restore: frozenOf(5, [ID_A, 4, 1, 5]),
    rows: [live(ID_A, 2, 1)], outbox: [{ idem: "cd".repeat(16), itemId: ID_A, baseRev: 1, bytes: new Uint8Array(0), body: mine(5) }],
  });
  assert.deepEqual(kindsOf(other), [{ id: ID_A, kind: "reseal", baseRev: 4, conflict: true }]);
});

test("an_item_without_a_frozen_row_is_new_when_the_server_has_no_row_and_a_conflict_when_it_has_one", async () => {
  const restore = frozenOf(5, [ID_A, 2, 1]);
  const items = await restoreItems({
    // B: no row at the restore and none now. C: no row at the restore, and one now (written since). A: a row at the restore that is gone now.
    listing: [live(ID_C, 1, 2, 9)],
    restore,
    rows: [live(ID_A, 3, 7), live(ID_B, 1, 7), live(ID_C, 4, 7)],
    outbox: [],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "new", baseRev: 0, conflict: false },
    { id: ID_B, kind: "new", baseRev: 0, conflict: false },
    { id: ID_C, kind: "reseal", baseRev: 1, conflict: true },
  ]);
});

test("without_frozen_rows_the_plan_keeps_the_interim_rules", async () => {
  // The same kind of worlds, no restore argument: a version that differs is kept back, only a missing row is sent.
  const items = await restoreItems({
    listing: [live(ID_A, 2, 1, 1), live(ID_B, 6, 2, 9)],
    rows: [live(ID_A, 4, 7), live(ID_B, 5, 7), live(ID_C, 1, 7)],
    outbox: [],
  });
  assert.deepEqual(kindsOf(items), [
    { id: ID_A, kind: "reseal", baseRev: 2, conflict: true },
    { id: ID_B, kind: "reseal", baseRev: 6, conflict: true },
    { id: ID_C, kind: "new", baseRev: 0, conflict: false },
  ]);
});

/** A device whose browser holds `rows` (`[id, rev, name, seq]`, the `seq` of the old history), in its own storage. */
async function deviceHolding(model, client, rows, seed = 1) {
  const db = await freshStore();
  await cache.putRows(db.store, scope(), rows.map(([id, rev, name, seq]) => rowOfChange({ id, rev, seq, deleted: false, ...client.wireRow(id, rev, { item_type: "login", name }) })));
  return syncDevice({ model, client, db, seed });
}

test("an_old_checkpoint_does_not_cause_false_conflicts", async () => {
  const model = new Model();
  const client = createFakeClient();
  // The checkpoint is older than the backup: it lists A and B at revision 1, and both changed to revision 2 before the backup was taken.
  setRow(model, client, ID_A, 1, "A one", { seq: 1 });
  setRow(model, client, ID_B, 1, "B one", { seq: 2 });
  model.pinCheckpoint();
  setRow(model, client, ID_A, 2, "A two", { seq: 3 });
  setRow(model, client, ID_B, 2, "B two", { seq: 4 });
  model.bumpRestore(); // restore_seq 4: the backup is what the server holds, and nothing has been written since
  // The device wrote both again after the backup (revision 3) and holds those versions, which the restore lost.
  const d = await deviceHolding(model, client, [[ID_A, 3, "A three", 5], [ID_B, 3, "B three", 6]]);
  await d.engine.start();
  assert.equal(d.engine.health().halted, "server_restored");
  assert.deepEqual(await d.engine.restorePreview(), { reupload: 2, conflicts: 0, manifestOlder: false });
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 2, conflicts: 0, manifestOlder: false });
  await until(() => model.items.get(ID_A)?.rev === 3 && model.items.get(ID_B)?.rev === 3, "both lost versions are back, built on the rows of the backup");
  assert.deepEqual(errors(d, "conflict"), []);
  assert.deepEqual(sentFor(d, ID_A).map((put) => put.base_rev), [2]);
  assert.deepEqual(sentFor(d, ID_B).map((put) => put.base_rev), [2]);
  d.engine.stop();
});

test("two_devices_restore_and_nothing_is_overwritten_and_no_false_conflict", async () => {
  const model = new Model();
  const client = createFakeClient();
  // The backup: A, B and C, each at revision 2. The bytes are the ones both devices cached when they were in step with the server.
  const backup = (id, name, seq) => {
    const wire = client.wireRow(id, 2, { item_type: "login", name });
    model.items.set(id, { rev: 2, seq, deleted: false, blob: wire.blob, tag: wire.tag, tomb: null });
    return rowOfChange({ id, rev: 2, seq: seq + 10, deleted: false, ...wire }); // the old-history seq a device holds is higher
  };
  const a2 = backup(ID_A, "A", 1);
  const b2 = backup(ID_B, "B", 2);
  const c2 = backup(ID_C, "C", 3);
  model.seq = 3;
  model.bumpRestore();
  const holding = async (rows, seed) => {
    const db = await freshStore();
    await cache.putRows(db.store, scope(), rows);
    return syncDevice({ model, client, db, seed });
  };
  const edited = (id, name, seq) => rowOfChange({ id, rev: 3, seq, deleted: false, ...client.wireRow(id, 3, { item_type: "login", name }) });
  // Device one changed A after the backup, device two changed B after the backup; C is the same everywhere.
  const one = await holding([edited(ID_A, "A by one", 20), b2, c2], 1);
  const two = await holding([a2, edited(ID_B, "B by two", 21), c2], 2);
  await one.engine.start();
  await two.engine.start();
  assert.equal(one.engine.health().halted, "server_restored");
  assert.equal(two.engine.health().halted, "server_restored");

  assert.deepEqual(await one.engine.acceptOlderState(), { reuploaded: 1, conflicts: 0, manifestOlder: false });
  await until(() => model.items.get(ID_A)?.rev === 3, "device one's A is back");
  assert.ok(model.items.get(ID_A).seq > model.restoreSeq, "written after the restore");
  // Device two now sees A written after the restore, and its own version of A is the older one on the same line: skipped.
  assert.deepEqual(await two.engine.restorePreview(), { reupload: 1, conflicts: 0, manifestOlder: false });
  assert.deepEqual(await two.engine.acceptOlderState(), { reuploaded: 1, conflicts: 0, manifestOlder: false });
  await until(() => model.items.get(ID_B)?.rev === 3, "device two's B is back");
  await settle(60);

  for (const d of [one, two]) assert.deepEqual(errors(d, "conflict"), [], "no conflict on either device");
  assert.deepEqual(sentFor(two, ID_A), [], "device two does not write over device one");
  assert.deepEqual(sentFor(one, ID_B), [], "device one's B is the backup's row: nothing to do");
  assert.deepEqual([...model.items].map(([id, row]) => [id, row.rev]).sort(), [[ID_A, 3], [ID_B, 3], [ID_C, 2]].sort());
  await one.engine.syncNow();
  await two.engine.syncNow();
  for (const d of [one, two]) {
    const names = new Map(d.engine.list().map((item) => [item.id, item.name]));
    assert.deepEqual([names.get(ID_A), names.get(ID_B), names.get(ID_C)], ["A by one", "B by two", "C"], "everything is back, on both devices");
    assert.deepEqual(d.engine.list().filter((item) => item.blocked || item.pending), []);
    assert.deepEqual(await queued(d), []);
  }
  one.engine.stop();
  two.engine.stop();
});

test("restore_rows_are_read_page_by_page_and_the_decision_uses_them", async () => {
  const d = await restoredWorld();
  d.model.pageSize = 2; // three frozen rows: two pages
  const before = d.api.restoreRowGets.length;
  assert.deepEqual(await d.engine.restorePreview(), { reupload: 4, conflicts: 0, manifestOlder: false });
  const paths = d.api.restoreRowGets.slice(before);
  assert.equal(paths.length, 2, "two pages");
  assert.ok(!paths[0].includes("after="));
  assert.ok(paths[1].includes(`after=${ID_B}`), "the second page follows the last id of the first");
  d.engine.stop();
});

test("restore_rows_that_cannot_be_right_are_bad_feed_and_nothing_is_stored", async () => {
  const cases = {
    "ids that do not rise": (answer) => ({ ...answer, rows: [...answer.rows].reverse() }),
    "a revision below 1": (answer) => ({ ...answer, rows: answer.rows.map((row, i) => (i === 0 ? { ...row, rev: 0 } : row)) }),
    "a row written after the restore it was frozen at": (answer) => ({ ...answer, rows: answer.rows.map((row, i) => (i === 0 ? { ...row, seq: answer.restore_seq + 1 } : row)) }),
    "another restore epoch than the listing": (answer) => ({ ...answer, restore_epoch: answer.restore_epoch + 1 }),
    "another restore_seq than the listing": (answer) => ({ ...answer, restore_seq: answer.restore_seq - 1 }),
    "more rows claimed and no next_after": (answer) => ({ ...answer, has_more: true }),
    "a next_after that is not the last id": (answer) => ({ ...answer, has_more: true, next_after: "ff".repeat(16) }),
    "a frozen revision that is not the one of an untouched row": (answer) => ({ ...answer, rows: answer.rows.map((row, i) => (i === 0 ? { ...row, rev: row.rev + 1 } : row)) }),
    "a frozen hash that is not the one of an untouched row": (answer) => ({ ...answer, rows: answer.rows.map((row, i) => (i === 0 ? { ...row, hash: b64u.encode(new Uint8Array(32).fill(1)) } : row)) }),
    "no frozen row for an untouched row": (answer) => ({ ...answer, rows: answer.rows.slice(1) }),
    "a list that is not the shape of the wire (a 200 that is no answer)": (answer) => ({ ...answer, rows: [{ id: "not an id", rev: 1, seq: 1, hash: null }] }),
    "more rows than were asked for": (answer) => ({ ...answer, rows: Array.from({ length: 501 }, (_, i) => ({ id: i.toString(16).padStart(32, "0"), rev: 1, seq: 1, hash: null })) }),
  };
  for (const [name, tamper] of Object.entries(cases)) {
    const d = await restoredWorld();
    const before = await stateOf(d);
    d.model.tamperRestoreRows = tamper;
    await assert.rejects(() => d.engine.restorePreview(), { code: "bad_feed" }, name);
    await assert.rejects(() => d.engine.acceptOlderState(), { code: "bad_feed" }, name);
    assert.deepEqual(await stateOf(d), before, `${name}: no floor was lowered and no note was stored`);
    assert.deepEqual(await queued(d), [], name);
    assert.equal(d.engine.health().halted, "server_restored", name);
    d.engine.stop();
  }
});

test("restore_rows_that_change_between_pages_are_bad_feed", async () => {
  const cases = {
    "a second page that does not follow the first": (answer, after) => (after === null ? answer : { ...answer, rows: [{ id: "00".repeat(16), rev: 1, seq: 1, hash: null }], has_more: false, next_after: undefined }),
    "another restore epoch on the second page": (answer, after) => (after === null ? answer : { ...answer, restore_epoch: answer.restore_epoch + 1 }),
    "another restore_seq on the second page": (answer, after) => (after === null ? answer : { ...answer, restore_seq: answer.restore_seq - 1 }),
  };
  for (const [name, tamper] of Object.entries(cases)) {
    const d = await restoredWorld();
    d.model.pageSize = 2;
    d.model.tamperRestoreRows = tamper;
    await assert.rejects(() => d.engine.restorePreview(), { code: "bad_feed" }, name);
    d.engine.stop();
  }
});

test("check_restore_rows_page_refuses_what_the_listing_does_not_vouch_for", () => {
  const listed = { restoreEpoch: 1, restoreSeq: 5, asOfSeq: 9 };
  const page = (extra = {}) => ({ rows: [{ id: ID_A, rev: 1, seq: 2 }], restore_epoch: 1, restore_seq: 5, has_more: false, ...extra });
  checkRestoreRowsPage(page(), null, listed); // a good page
  checkRestoreRowsPage(page({ has_more: true, next_after: ID_A }), null, listed);
  const bad = (what, p, previous = null, l = listed, limit = 500) => assert.throws(() => checkRestoreRowsPage(p, previous, l, limit), { code: "bad_feed" }, what);
  bad("restore_seq above the top of the listing", page(), null, { ...listed, asOfSeq: 4 });
  bad("a page after the last one", page(), page());
  bad("a row at or below the position of the page before", page(), page({ has_more: true, next_after: ID_A }));
  bad("the next position is not the last id", page({ has_more: true, next_after: ID_B }));
  bad("has more and holds no rows", page({ rows: [], has_more: true, next_after: ID_A }));
  bad("a position without more rows", page({ next_after: ID_A }));
  bad("more rows than the limit", page({ rows: [{ id: ID_A, rev: 1, seq: 1 }, { id: ID_B, rev: 1, seq: 1 }] }), null, listed, 1);
});

// ------------------------------------------------------------------ the restore epoch on every write

test("every_new_write_and_checkpoint_upload_carries_the_restore_epoch", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.restoreEpoch = 2;
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  setRow(model, client, ID_B, 1, "B", { seq: 2 });
  model.pinCheckpoint();
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal((await stateOf(d)).restoreEpoch, 2, "the first contact stored the epoch");
  const created = await d.engine.create(DRAFT);
  await d.engine.update(ID_A, { name: "A changed" }, 1);
  await d.engine.remove(ID_B);
  await until(() => model.writes.length === 3, "the three writes are done");
  assert.ok(model.items.get(created));
  assert.deepEqual(sent(d).map((put) => put.restore_epoch), [2, 2, 2], "create, update and remove all name the epoch");
  // A checkpoint upload names it too.
  setRow(model, client, ID_C, 1, "C"); // another device wrote: something new to sign
  await d.engine.syncNow();
  await until(() => model.checkpointPuts.length === 1, "a checkpoint is uploaded");
  assert.equal(model.checkpointPuts[0].restore_epoch, 2);
  d.engine.stop();
});

test("a_device_that_has_stored_no_epoch_yet_writes_without_a_condition_and_names_it_once_the_first_contact_has_stored_one", async () => {
  const model = new Model();
  const d = await syncDevice({ model });
  d.api.failFeed = new ApiError(0, "network"); // no first contact yet
  d.api.failFeedTimes = 1;
  await d.engine.start();
  await d.engine.create(DRAFT);
  const [entry] = await queued(d);
  assert.equal("restore_epoch" in requestOf(entry), false, "no epoch is stored: no condition");
  assert.equal(d.api.puts.length, 0, "and it has not been sent");
  await d.engine.syncNow(); // the first contact: the epoch is stored
  await until(() => model.writes.length === 1, "the write goes out");
  assert.equal((await stateOf(d)).restoreEpoch, 0);
  const [put] = sent(d);
  assert.equal(sent(d).length, 1, "once");
  assert.equal(put.restore_epoch, 0, "naming the epoch that has been stored");
  assert.notEqual(put.idem, entry.idem, "a new key: it is a new request");
  await until(async () => (await queued(d)).length === 0, "done");
  d.engine.stop();
});

test("a_restore_epoch_changed_answer_mid_session_holds_every_lane_and_halts_server_restored", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal((await stateOf(d)).restoreEpoch, 0);
  model.restoreEpoch = 1; // the server is restored while this device is open, from a backup that holds everything it has
  const first = await d.engine.create(DRAFT);
  const second = await d.engine.create({ item_type: "login", name: "Second" });
  await until(() => d.engine.health().halted === "server_restored", "the engine stops");
  await settle(60);
  assert.equal(model.writes.length, 0, "nothing was stored");
  assert.deepEqual(errors(d, "conflict"), [], "it is not a conflict");
  assert.deepEqual(d.engine.list().filter((item) => item.blocked), [], "and nothing is blocked");
  assert.deepEqual((await queued(d)).map((entry) => entry.itemId).sort(), [first, second].sort(), "both writes wait, as they were");
  assert.equal((await stateOf(d)).restoreEpoch, 0, "the new epoch is not accepted: the user decides");
  assert.deepEqual(states(d, "warning", "restore_epoch_raised"), [], "and it is no quiet notice either");
  // Every lane is held: a write made now is stored and not sent, and no pass loops.
  const puts = d.api.puts.length;
  const gets = d.api.gets.length;
  await d.engine.create({ item_type: "login", name: "Third" });
  await settle(80);
  assert.equal(d.api.puts.length, puts);
  assert.equal(d.api.gets.length, gets, "a stopped engine does not read the feed either");
  assert.equal((await queued(d)).length, 3);

  // The user accepts: the three are made again, each with a new key and the new epoch.
  const keys = (await queued(d)).map((entry) => entry.idem);
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 3, conflicts: 0, manifestOlder: false });
  await until(() => model.writes.length === 3, "the writes go out after the restore is accepted");
  const after = sent(d).slice(puts);
  assert.equal(after.length, 3);
  for (const put of after) {
    assert.equal(put.restore_epoch, 1);
    assert.equal(keys.includes(put.idem), false, "a new key");
    assert.equal(put.base_rev, 0);
  }
  assert.equal(d.engine.health().halted, null);
  d.engine.stop();
});

test("held_writes_resealed_after_accept_get_a_fresh_idem_and_the_new_epoch", async () => {
  const d = await restoredWorld();
  await d.engine.update(ID_A, { name: "A edited while stopped" }, 3); // built on revision 3, for epoch 0
  await d.engine.create(DRAFT);
  const waiting = await queued(d);
  assert.equal(waiting.length, 2);
  for (const entry of waiting) assert.equal(requestOf(entry).restore_epoch, 0, "queued for the epoch that was accepted then");
  const oldKeys = new Set(waiting.map((entry) => entry.idem));

  await d.engine.acceptOlderState();
  await until(async () => d.model.writes.length === 5 && (await queued(d)).length === 0, "everything is sent");
  const puts = sent(d);
  assert.equal(puts.length, 5);
  for (const put of puts) {
    assert.equal(put.restore_epoch, 1, "the epoch that was accepted");
    assert.equal(oldKeys.has(put.idem), false, "a fresh idem: the epoch is part of what the server hashes under it");
  }
  const [a] = sentFor(d, ID_A);
  assert.equal(a.base_rev, 2, "built on the server's row");
  const handle = await d.client.vault.open_item(hex16.decode(ID_A), 3, b64u.decode(a.blob), b64u.decode(a.tag));
  assert.equal((await d.client.vault.item_view(handle)).name, "A edited while stopped");
  await d.client.vault.close_item(handle);
  d.engine.stop();
});

test("a_write_queued_before_the_epoch_was_accepted_is_made_again_with_the_stored_epoch", async () => {
  // The server was restored from a backup that holds everything this device has: the epoch is accepted with a notice once the
  // checkpoint has verified. A write that was made before that names the old epoch, is refused for it, and (not stored, as the
  // answer says) is made again with a new key and the accepted epoch, once.
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  d.api.faults.push({ kind: "network" }); // the first try is lost on the way: the entry waits for its retry
  const id = await d.engine.create(DRAFT);
  await until(() => d.api.puts.length === 1 && d.timers.pending > 0, "the write waits for its retry");
  const [entry] = await queued(d);
  assert.equal(requestOf(entry).restore_epoch, 0);
  model.restoreEpoch = 1; // restored with nothing lower
  await d.engine.syncNow(); // the notice path: the epoch is accepted
  assert.equal((await stateOf(d)).restoreEpoch, 1);
  d.timers.advance(2_000); // the retry: refused for the epoch
  await until(() => model.items.has(id), "the write is made again and stored");
  const puts = sentFor(d, id);
  assert.equal(puts.length, 3, "the lost try, the refused one, the new one");
  assert.equal(puts[0].idem, puts[1].idem, "the retry is byte for byte the first try");
  assert.equal(puts[0].restore_epoch, 0);
  assert.notEqual(puts[2].idem, puts[0].idem, "a new key");
  assert.equal(puts[2].restore_epoch, 1);
  assert.equal(d.engine.health().halted, null);
  assert.deepEqual(errors(d, "conflict"), []);
  d.engine.stop();
});

test("a_server_that_keeps_refusing_the_epoch_it_shows_does_not_make_a_loop", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  // Whatever the write names, the server answers "restore_epoch_changed, 0": the epoch it shows, which this device has accepted.
  const real = d.api.put;
  d.api.put = async (path, body, options) => {
    if (path.startsWith("/api/sync/items/")) {
      d.api.puts.push({ id: path.split("/").pop(), bytes: body, text: new TextDecoder().decode(body) });
      throw new ApiError(409, "restore_epoch_changed", null, { error: "restore_epoch_changed", restore_epoch: 0 });
    }
    return real(path, body, options);
  };
  await d.engine.create(DRAFT);
  await settle(200);
  assert.ok(d.api.puts.length <= 6, `a few tries, not a loop (${d.api.puts.length})`);
  assert.ok(errors(d, "restore_epoch_refused").length >= 1, "and it says so");
  assert.equal((await queued(d)).length, 1, "the write is kept");
  d.engine.stop();
});

test("a_restore_epoch_changed_answer_to_a_checkpoint_upload_halts_server_restored", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  setRow(model, client, ID_B, 1, "B", { seq: 2 });
  model.pinCheckpoint();
  const d = await syncDevice({ model, client });
  await d.engine.start();
  assert.equal(model.checkpointPuts.length, 0);
  setRow(model, client, ID_C, 1, "C"); // something to sign
  // The vault is restored between the read of the feed and the upload.
  const real = d.api.put;
  d.api.put = async (path, body, options) => {
    if (path === "/api/sync/checkpoint") model.restoreEpoch = 1;
    return real(path, body, options);
  };
  await d.engine.syncNow();
  assert.equal(d.api.checkpointPuts.length, 1, "one try");
  assert.equal(JSON.parse(d.api.checkpointPuts[0]).restore_epoch, 0);
  assert.equal(model.checkpointPuts.length, 0, "nothing was stored");
  assert.equal(d.engine.health().halted, "server_restored", "the feed is read again at once and the user decides");
  assert.equal((await stateOf(d)).restoreEpoch, 0);
  d.engine.stop();
});

// ------------------------------------------------------------------ fix round: an edit built below the restored row, many lanes, a failing pass

test("an_offline_edit_built_below_the_restored_row_is_a_conflict_and_does_not_overwrite_the_revisions_between", async () => {
  // The device holds A at revision 3 and an edit built on it that never reached the server. Another device took the item to
  // revision 5 before the backup. Without a restore the server would have refused the edit (409): after the restore it must not
  // be sent over revisions 4 and 5 either.
  const d = await withUnsentEdit();
  d.model.items.clear();
  setRow(d.model, d.client, ID_A, 5, "A five from another device", { seq: 1 });
  d.model.seq = 1;
  d.model.bumpRestore();
  const before = d.model.items.get(ID_A);
  const again = await reload(d);
  await again.engine.start();
  assert.equal(again.engine.health().halted, "server_restored");
  assert.deepEqual(await again.engine.restorePreview(), { reupload: 0, conflicts: 1, manifestOlder: false });
  assert.deepEqual(await again.engine.acceptOlderState(), { reuploaded: 0, conflicts: 1, manifestOlder: false });
  await settle(80);
  assert.deepEqual(sentFor(again, ID_A), [], "nothing is sent over the restored row");
  assert.equal(d.model.items.get(ID_A), before);
  const item = again.engine.list().find((entry) => entry.id === ID_A);
  assert.equal(item.blockedReason, "conflict");
  assert.equal(item.name, "A five from another device", "the screen shows the server's version");
  const [draft] = await queued(again);
  assert.equal(draft.baseRev, 5, "the edit is kept as a draft on top of the restored row, never dropped");
  const handle = await again.client.vault.open_item(hex16.decode(ID_A), 6, draft.body.blob, draft.body.tag);
  assert.equal((await again.client.vault.item_view(handle)).name, "A edited offline");
  await again.client.vault.close_item(handle);
  again.engine.stop();
});

test("an_offline_edit_built_on_the_restored_row_is_made_again_over_it", async () => {
  const d = await withUnsentEdit(); // an edit built on revision 3
  d.model.items.clear();
  setRow(d.model, d.client, ID_A, 3, "A as restored", { seq: 1 });
  d.model.seq = 1;
  d.model.bumpRestore();
  const again = await reload(d);
  await again.engine.start();
  assert.deepEqual(await again.engine.acceptOlderState(), { reuploaded: 1, conflicts: 0, manifestOlder: false });
  await until(() => d.model.items.get(ID_A).rev === 4, "the edit is on the server, on top of the restored row");
  const [put] = sentFor(again, ID_A);
  assert.equal(put.base_rev, 3);
  assert.equal(put.restore_epoch, 1);
  again.engine.stop();
});

test("writes_in_many_lanes_that_name_an_old_epoch_are_all_made_again_once_the_epoch_is_accepted", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  for (let i = 0; i < 5; i += 1) d.api.faults.push({ kind: "network" }); // every first try is lost: five lanes wait for their retry
  const ids = [];
  for (let i = 0; i < 5; i += 1) ids.push(await d.engine.create({ item_type: "login", name: `Item ${i}` }));
  await until(() => d.api.puts.length === 5 && d.timers.pending >= 5, "all five wait for their retry");
  model.restoreEpoch = 1; // restored with nothing lower: the epoch is accepted with a notice
  await d.engine.syncNow();
  assert.equal((await stateOf(d)).restoreEpoch, 1);
  d.timers.advance(1_000); // the retries: five refusals, one per lane
  await until(() => model.writes.length === 5, "all five are made again and stored");
  await settle(60);
  assert.equal(d.engine.health().halted, null);
  assert.deepEqual(errors(d, "restore_epoch_refused"), []);
  assert.deepEqual(errors(d, "conflict"), []);
  for (const id of ids) {
    const puts = sentFor(d, id);
    assert.deepEqual(puts.map((put) => put.restore_epoch), [0, 0, 1], "the lost try, the refused retry, the new write");
    assert.equal(puts[0].idem, puts[1].idem);
    assert.notEqual(puts[2].idem, puts[0].idem);
  }
  assert.deepEqual(await queued(d), []);
  d.engine.stop();
});

test("a_pass_that_fails_after_a_restore_epoch_changed_answer_does_not_lose_the_stop", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  const d = await syncDevice({ model, client });
  await d.engine.start();
  model.restoreEpoch = 1; // restored while this device is open, with nothing lower
  d.api.failFeed = new ApiError(0, "network"); // the pass that follows the refusal cannot read the feed
  d.api.failFeedTimes = 1;
  await d.engine.create(DRAFT);
  await until(() => states(d, "offline").length > 0, "the pass after the refusal fails");
  await settle(60);
  assert.equal(d.engine.health().halted, null);
  assert.equal(d.api.puts.length, 1, "one try, refused: the lanes stay held");
  assert.equal(model.writes.length, 0);
  assert.equal((await stateOf(d)).restoreEpoch, 0, "the epoch is not accepted");
  const [entry] = await queued(d);
  // A pass that ends well now must still stop the engine: the server refused a write for its epoch, and nothing has shown since
  // that it holds no more than this device has.
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored", "the stop, not a quiet notice and a made again write");
  assert.equal((await stateOf(d)).restoreEpoch, 0);
  assert.deepEqual(states(d, "warning", "restore_epoch_raised"), []);
  assert.equal(d.api.puts.length, 1, "nothing was sent again");
  assert.deepEqual((await queued(d)).map((e) => e.idem), [entry.idem], "and the write is as it was");
  d.engine.stop();
});

test("a_refused_checkpoint_upload_that_no_raised_epoch_follows_does_not_turn_a_later_epoch_into_a_stop", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 1 });
  setRow(model, client, ID_B, 1, "B", { seq: 2 });
  model.pinCheckpoint();
  const d = await syncDevice({ model, client });
  await d.engine.start();
  setRow(model, client, ID_C, 1, "C"); // something to sign
  // A refusal that the server's own epoch does not back up (it shows the epoch this device has accepted).
  d.api.checkpointPutFaults.push({ kind: "status", status: 409, code: "restore_epoch_changed", body: { error: "restore_epoch_changed", restore_epoch: 0 } });
  await d.engine.syncNow();
  await settle(40);
  assert.equal(d.engine.health().halted, null);
  assert.equal(model.checkpointPuts.length, 0);
  // The pass that followed found no higher epoch: the mark is gone, so a write goes out ...
  const id = await d.engine.create(DRAFT);
  await until(() => model.items.has(id), "the write goes out");
  // ... and a later restore with nothing lower is a notice and not a stop.
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, null);
  assert.equal((await stateOf(d)).restoreEpoch, 1);
  assert.equal(states(d, "warning", "restore_epoch_raised").length, 1);
  d.engine.stop();
});

test("a_write_another_tab_queues_while_an_older_state_is_accepted_is_not_dropped", async () => {
  const d = await restoredWorld();
  const db = d.store.database;
  const cachedA = (await cache.getRows(db.store, scope())).find((row) => row.itemId === ID_A);
  let injected = false;
  const real = d.client.vault.encrypt_item;
  // While the first item is being sealed again, another tab of the browser queues an edit of it (the stores are shared).
  d.client.vault.encrypt_item = async (...args) => {
    if (!injected && hex16.encode(args[0]) === ID_A) {
      injected = true;
      const handle = await d.client.vault.open_item(hex16.decode(ID_A), 3, cachedA.envelope, cachedA.tag);
      const sealed = await real(hex16.decode(ID_A), 4, { name: "A edited by another tab" }, handle);
      await d.client.vault.close_item(handle);
      const idem = "7a".repeat(16);
      const bytesOf = encodeWireBytes("put_item_req", { base_rev: 3, blob: b64u.encode(sealed.envelope), tag: b64u.encode(sealed.tag), idem, restore_epoch: 0 });
      await outbox.enqueue(db.store, scope(), { idem, itemId: ID_A, baseRev: 3, body: { blob: sealed.envelope, tag: sealed.tag }, bytes: bytesOf });
    }
    return real(...args);
  };
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 4, conflicts: 0, manifestOlder: false });
  assert.equal(injected, true);
  await untilDSent(d);
  await settle(60);
  const [a] = sentFor(d, ID_A);
  assert.equal(a.base_rev, 2, "built on the restored row");
  const handle = await d.client.vault.open_item(hex16.decode(ID_A), 3, b64u.decode(a.blob), b64u.decode(a.tag));
  assert.equal((await d.client.vault.item_view(handle)).name, "A edited by another tab", "the edit of the other tab is what was made again");
  await d.client.vault.close_item(handle);
  assert.equal(sentFor(d, ID_A).length, 1, "once");
  assert.deepEqual(await queued(d), []);
  d.engine.stop();
});
