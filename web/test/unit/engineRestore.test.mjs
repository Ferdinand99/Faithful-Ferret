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
 * the server is restored from a backup: A is at rev 2, B is a tombstone at rev 2, C is live at rev 3, D is gone, the counter is
 * lower and the restore epoch is raised. One pass later the device has stopped with `server_restored`.
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

/** The server goes back to the backup of `restoredWorld`. */
function restoreServer(model, client) {
  model.items.clear();
  setRow(model, client, ID_A, 2, "A old", { seq: 1 });
  setTomb(model, client, ID_B, 2, { seq: 2 });
  setRow(model, client, ID_C, 3, "C old", { seq: 3 });
  model.restoreEpoch = 1;
}

/** Waits until D, the one item the server has no row for, is on the server (the other three are kept back as conflicts). */
const untilDSent = (d) => until(() => d.model.items.get(ID_D)?.rev === 1, "D is on the server");

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
  setRow(model, client, ID_A, 3, "A"); // will be at rev 2 on the restored server: kept back, the server has a row
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
  model.restoreEpoch = 1;
  model.pinCheckpoint(); // the checkpoint of the restored state
  setRow(model, client, ID_C, 4, "C by another device"); // after the restore
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");

  const before = await stateOf(d);
  assert.deepEqual(await d.engine.restorePreview(), { reupload: 1, conflicts: 2, manifestOlder: false });
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

  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 1, conflicts: 3, manifestOlder: false });
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
  assert.equal(sent(d).length, 1, "only D goes out; the other three are drafts");
  d.engine.stop();
});

test("newer_local_versions_are_queued_at_server_rev_plus_1_resurrect_tombstone_or_base_0", async () => {
  const d = await restoredWorld();
  await d.engine.acceptOlderState();
  await untilDSent(d);
  await settle(60);

  // Only D, which the server has no row for, goes out by itself, built on revision 0.
  assert.deepEqual(sent(d).map((put) => put.id), [ID_D]);
  const [dd] = sentFor(d, ID_D);
  assert.equal(dd.base_rev, 0, "the server has no row for D: it starts again");
  await d.client.vault.close_item(await d.client.vault.open_item(hex16.decode(ID_D), 1, b64u.decode(dd.blob), b64u.decode(dd.tag)));

  // The three over a row the server has are drafts that are not sent, sealed at the server's revision + 1.
  const drafts = new Map((await queued(d)).map((entry) => [entry.itemId, entry]));
  assert.deepEqual([...drafts.keys()].sort(), [ID_A, ID_B, ID_C]);
  const a = drafts.get(ID_A);
  assert.equal(a.baseRev, 2, "built on the server's revision 2");
  assert.equal(requestOf(a).resurrect, undefined);
  const handle = await d.client.vault.open_item(hex16.decode(ID_A), 3, a.body.blob, a.body.tag);
  assert.equal((await d.client.vault.item_view(handle)).name, "A");
  await d.client.vault.close_item(handle);
  await assert.rejects(() => d.client.vault.open_item(hex16.decode(ID_A), 4, a.body.blob, a.body.tag));

  const b = drafts.get(ID_B);
  assert.equal(b.baseRev, 2, "the server holds a tombstone at 2");
  assert.equal(requestOf(b).resurrect, true, "the item would come back, if the user keeps it");
  await d.client.vault.close_item(await d.client.vault.open_item(hex16.decode(ID_B), 3, b.body.blob, b.body.tag));

  const c = drafts.get(ID_C);
  assert.equal(c.baseRev, 3, "the server still holds C live at 3");
  assert.equal(requestOf(c).deleted, true);
  await d.client.vault.verify_tombstone(hex16.decode(ID_C), 4, c.body.tomb);

  for (const id of [ID_A, ID_B, ID_C]) {
    const item = d.engine.list().find((entry) => entry.id === id);
    assert.equal(item === undefined || item.blockedReason === "conflict", true, "kept back as a conflict");
  }
  assert.equal(d.model.items.get(ID_A).rev, 2, "the server's rows were not touched");
  assert.equal(d.model.items.get(ID_B).deleted, true);
  assert.equal(d.model.items.get(ID_C).rev, 3);
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
  model.restoreEpoch = 1;
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
  model.restoreEpoch = 1;
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
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 1, conflicts: 3, manifestOlder: false });
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
  // The restored server: A and B at revision 2, D at revision 1, C gone, a lower counter and a higher epoch.
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
  // The feed is read again from scratch (a 410): the listing shows the rows the server holds, which are lower than the old local ones were.
  d.model.minValidSince = d.model.seq + 1;
  await d.engine.syncNow();
  await settle(60);
  const refused = d.events.state.filter((s) => ["rev_lower_than_local", "rev_below_remembered", "rev_same_row_changed", "row_damaged"].includes(s.code));
  assert.deepEqual(refused, []);
  assert.equal(d.engine.health().halted, null);
  assert.deepEqual(d.engine.health().warnings, []);
  assert.equal(d.engine.list().find((item) => item.id === ID_A).rev, 2, "the server's version");
  assert.equal(memoryOf((await stateOf(d)).memory).revs[ID_A], 2);
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
  await until(async () => (await queued(again)).length === 3, "D and the item written while stopped are sent, the three drafts stay");
  const state = await stateOf(again);
  assert.equal(state.restore, null, "the note is gone");
  assert.equal(state.restoreEpoch, 1, "the epoch is stored");
  assert.equal(memoryOf(state.memory).revs[ID_A], 2);
  assert.equal(sentFor(again, ID_D).length, 1, "one write for D");
  for (const id of [ID_A, ID_B, ID_C]) assert.equal(sentFor(again, id).length, 0, `no write for ${id.slice(0, 2)}`);
  assert.equal(sent(again).length, 2, "D and the one that was written while stopped");
  assert.equal(d.api.puts.length, 0);
  assert.equal(again.engine.list().find((item) => item.id === ID_A).name, "A old");
  for (const id of [ID_A, ID_B, ID_C]) assert.equal((await queued(again)).find((entry) => entry.itemId === id)?.itemId, id);
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

test("a_post_restore_write_covered_by_a_newer_checkpoint_is_still_a_conflict", async () => {
  // The checkpoint is "auto": it always covers what the server holds now, as the checkpoint another device uploads after
  // its own writes does. Device two holds A at revision 6 from the old history.
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
  model.restoreEpoch = 1;
  // Device one has accepted the restore, edited A to revision 4 and uploaded a checkpoint as usual.
  setRow(model, client, ID_A, 4, "A edited by device one");
  const theirs = model.items.get(ID_A);
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
  assert.deepEqual(await accepting, { reuploaded: 2, conflicts: 3, manifestOlder: false });
  await until(() => d.api.puts.length === 2, "D and the new item are sent");
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

test("a_local_version_lower_than_the_servers_row_with_other_bytes_is_a_conflict_not_a_drop", async () => {
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
  model.restoreEpoch = 1;
  await d.engine.syncNow();
  assert.equal(d.engine.health().halted, "server_restored");
  assert.deepEqual(await d.engine.restorePreview(), { reupload: 0, conflicts: 1, manifestOlder: false });
  assert.deepEqual(await d.engine.acceptOlderState(), { reuploaded: 0, conflicts: 1, manifestOlder: false });
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
