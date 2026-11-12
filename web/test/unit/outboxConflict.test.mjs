// The outbox and a 409 that only shows the write that was sent: the server forgot its idempotency key (30 days), the answer to
// the first try was lost, and the row it holds now is the one the write made. That is done, not a conflict.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { trash } from "../../src/store/trash.mjs";
import { encodeWireBytes } from "../../src/wire.mjs";
import { alreadyDone, classify, createOutboxRunner, isRestoreEpochChanged } from "../../src/sync/outbox.mjs";
import { scope } from "./idbHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, FakeTimers, Model, settle, syncDevice, until } from "./syncHelpers.mjs";

const ID_A = "11".repeat(16);
const DRAFT = { item_type: "login", name: "Written here" };

const setRow = (model, client, id, rev, name) => model.set(id, { rev, ...client.wireRow(id, rev, { item_type: "login", name }) });
const itemOf = (d, id) => d.engine.list().find((entry) => entry.id === id);
const queued = (d) => outbox.all(d.store.database.store, scope());

const live = (baseRev, fill) => ({ idem: "i".repeat(32), itemId: ID_A, baseRev, body: { blob: new Uint8Array(48).fill(fill), tag: new Uint8Array(32).fill(fill + 1) }, bytes: new Uint8Array(0) });
const tomb = (baseRev) => ({ idem: "t".repeat(32), itemId: ID_A, baseRev, body: { tomb: new Uint8Array(40).fill(5) }, bytes: new Uint8Array(0) });
const conflict = (body) => new ApiError(409, "conflict", null, body);

test("already_done_reads_the_blob_and_tag_or_the_revision_of_a_tombstone", () => {
  const entry = live(3, 7);
  const same = { current_rev: 4, deleted: false, blob: b64u.encode(entry.body.blob), tag: b64u.encode(entry.body.tag) };
  assert.deepEqual(alreadyDone(entry, conflict(same)), { rev: 4, seq: 0, replayed: true });
  assert.equal(alreadyDone(entry, conflict({ ...same, blob: b64u.encode(new Uint8Array(48).fill(8)) })), null, "another blob is a conflict");
  assert.equal(alreadyDone(entry, conflict({ ...same, current_rev: 9 })), null, "the same bytes at another revision are not our write");
  assert.equal(alreadyDone(entry, conflict({ ...same, tag: b64u.encode(new Uint8Array(32).fill(9)) })), null, "another tag is a conflict");
  assert.equal(alreadyDone(entry, conflict({ current_rev: 4, deleted: true })), null, "a deleted row is not our live write");
  assert.equal(alreadyDone(entry, conflict({ current_rev: 4, deleted: false })), null, "a body without a row says nothing");
  assert.equal(alreadyDone(entry, new ApiError(409, "conflict")), null);
  assert.equal(alreadyDone(entry, new ApiError(409, "conflict", null, { current_rev: "4" })), null);

  const gone = tomb(3);
  assert.deepEqual(alreadyDone(gone, conflict({ current_rev: 4, deleted: true })), { rev: 4, seq: 0, replayed: true });
  assert.equal(alreadyDone(gone, conflict({ current_rev: 5, deleted: true })), null, "deleted at another revision is a conflict");
  assert.equal(alreadyDone(gone, conflict({ current_rev: 4, deleted: false })), null, "a live row at that revision is not our tombstone");
});

test("409_with_a_byte_equal_blob_counts_as_done", async () => {
  const model = new Model();
  const d = await syncDevice({ model });
  await d.engine.start();
  // The server writes, but the answer never arrives; by the time the write is sent again the server has forgotten its key.
  d.api.faults.push({ kind: "lost" });
  const id = await d.engine.create(DRAFT);
  await until(() => model.items.get(id)?.rev === 1 && d.timers.pending > 0, "the server has the write and the retry waits");
  model.idems.clear();
  d.timers.advance(5_000);
  await until(async () => (await queued(d)).length === 0, "the write is done");
  assert.equal(d.api.puts.filter((put) => put.id === id).length, 2, "it was sent twice");
  assert.deepEqual(d.events.error, [], "no conflict is shown");
  assert.equal(model.writes.length, 1, "and the server wrote it once");
  await until(() => itemOf(d, id)?.pending === false, "the row comes through the feed");
  const item = itemOf(d, id);
  assert.deepEqual([item.blocked, item.conflict, item.rev, item.name], [false, false, 1, "Written here"]);
  d.engine.stop();
});

test("409_deleted_at_base_plus_1_for_an_own_tombstone_counts_as_done_and_removes_nothing_before_a_verified_tombstone", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "Kept until it is verified");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  d.api.faults.push({ kind: "lost" });
  await d.engine.remove(ID_A);
  await until(() => model.items.get(ID_A).deleted === true && d.timers.pending > 0, "the server deleted it and the retry waits");
  model.idems.clear();
  // The feed cannot be read from here on: the done write must not make the device delete anything by itself.
  d.api.failFeed = new ApiError(503, "internal");
  d.api.failFeedTimes = 1000;
  d.timers.advance(5_000);
  await until(async () => (await queued(d)).length === 0, "the write is done");
  await settle(30);
  assert.equal(d.events.error.some((e) => e.code === "conflict"), false, "no conflict");
  assert.equal(itemOf(d, ID_A), undefined, "the item is not listed: this device deleted it");
  const row = (await cache.getRows(d.store.database.store, scope())).find((r) => r.itemId === ID_A);
  assert.deepEqual([row.deleted, row.rev], [false, 1], "the live row is still the cached one");
  assert.deepEqual(await trash.all(d.store.database.store, scope()), [], "nothing is in the trash before a verified tombstone");

  // The feed comes back with the tombstone: it is verified, and only then does the live row go (to the trash).
  d.api.failFeedTimes = 0;
  await d.engine.syncNow();
  assert.ok(d.client.vault.calls.some((call) => call[0] === "verify_tombstone" && call[2] === 2));
  const after = (await cache.getRows(d.store.database.store, scope())).find((r) => r.itemId === ID_A);
  assert.deepEqual([after.deleted, after.rev], [true, 2]);
  const [entry] = await trash.all(d.store.database.store, scope());
  assert.deepEqual([entry.itemId, entry.rev, entry.tombRev], [ID_A, 1, 2]);
  d.engine.stop();
});

test("a_409_that_shows_another_row_is_a_conflict_and_not_done", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "Original");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  setRow(model, client, ID_A, 2, "By another device");
  await d.engine.update(ID_A, { name: "Mine" }, 1);
  await until(() => d.events.error.some((e) => e.code === "conflict"), "a conflict");
  assert.equal((await queued(d)).length, 1, "the draft is kept");
  d.engine.stop();
});

test("a_409_that_says_deleted_at_another_revision_is_a_conflict", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "Original");
  const d = await syncDevice({ model, client });
  await d.engine.start();
  // The server deleted it at revision 3 (it was edited and then deleted): our tombstone would have been revision 2.
  model.set(ID_A, { rev: 3, deleted: true, tomb: client.wireTomb(ID_A, 3) });
  await d.engine.remove(ID_A);
  await until(() => d.events.error.some((e) => e.code === "conflict"), "a conflict");
  assert.equal((await queued(d)).length, 1);
  d.engine.stop();
});

// ------------------------------------------------------------------ restore_epoch_changed is not a conflict

const hexId = (n) => n.toString(16).padStart(32, "0");

/** A queued live write for item `n`, as the engine builds it (the bytes are what the server hashes). */
function writeFor(n, { baseRev = 0, idem = 7000 + n, restoreEpoch } = {}) {
  const blob = new Uint8Array(48).fill(n);
  const tag = new Uint8Array(32).fill(n + 100);
  const bytes = encodeWireBytes("put_item_req", {
    base_rev: baseRev, blob: b64u.encode(blob), tag: b64u.encode(tag), idem: hexId(idem), ...(restoreEpoch === undefined ? {} : { restore_epoch: restoreEpoch }),
  });
  return { idem: hexId(idem), itemId: hexId(n), baseRev, body: { blob, tag }, bytes };
}

async function senderOf({ model = new Model() } = {}) {
  const store = await createFakeStore();
  const api = createFakeApi(model);
  const log = { done: [], blocked: [], epoch: [] };
  const run = createOutboxRunner({
    api, store, scope: scope(), timers: new FakeTimers(),
    hooks: {
      onDone: (entry) => log.done.push(entry.itemId),
      onBlocked: (entry, error, kind) => log.blocked.push([entry.itemId, error.code, kind]),
      onRestoreEpochChanged: (entry, error) => log.epoch.push([entry.itemId, error.body?.restore_epoch]),
    },
  });
  return { run, api, model, log, store, stored: () => outbox.all(store.database.store, scope()) };
}

test("restore_epoch_changed_is_classified_before_the_status_and_is_no_conflict", () => {
  const changed = new ApiError(409, "restore_epoch_changed", null, { error: "restore_epoch_changed", restore_epoch: 4 });
  assert.equal(classify(changed), "epoch_changed");
  assert.equal(classify(new ApiError(409, "conflict", null, { current_rev: 1, deleted: false })), "conflict", "another 409 is still a conflict");
  assert.equal(classify(new ApiError(409, "checkpoint_stale")), "conflict", "(a 409 of an item write that says anything else)");
  assert.equal(isRestoreEpochChanged(changed), true);
  // A batch result of that form is the same answer.
  assert.equal(isRestoreEpochChanged({ status: 409, error: "restore_epoch_changed", restore_epoch: 4 }), true);
  assert.equal(isRestoreEpochChanged({ status: 409, current_rev: 3, deleted: false }), false);
  assert.equal(isRestoreEpochChanged({ status: 200, rev: 1, seq: 1, replayed: false }), false);
  assert.equal(isRestoreEpochChanged(null), false);
  assert.equal(isRestoreEpochChanged(new ApiError(0, "network")), false);
});

test("a_restore_epoch_changed_answer_holds_every_lane_and_is_neither_done_nor_blocked", async () => {
  const model = new Model();
  model.restoreEpoch = 3;
  const t = await senderOf({ model });
  const stale = writeFor(1, { restoreEpoch: 2 });
  await t.run.enqueue(stale);
  await until(() => t.log.epoch.length === 1, "the engine hears of it");
  assert.deepEqual(t.log.epoch, [[stale.itemId, 3]], "with the epoch the server shows");
  assert.deepEqual(t.log.blocked, [], "not a conflict, not blocked");
  assert.deepEqual(t.log.done, []);
  assert.equal(model.writes.length, 0, "and nothing was stored");
  assert.deepEqual((await t.stored()).map((e) => e.idem), [stale.idem], "the write is kept");
  assert.deepEqual(t.run.entriesOf(stale.itemId).map((e) => e.idem), [stale.idem], "at the head of its lane, as it was");
  assert.equal(Buffer.from(t.run.entriesOf(stale.itemId)[0].bytes).toString("hex"), Buffer.from(stale.bytes).toString("hex"), "byte for byte");
  // Every lane is held: a write of another item that is queued now is stored and not sent.
  const other = writeFor(2, { restoreEpoch: 3 });
  await t.run.enqueue(other);
  await settle(30);
  assert.equal(t.api.puts.length, 1, "no request after the answer");
  assert.equal((await t.stored()).length, 2);
  assert.equal(t.log.epoch.length, 1);
  // Letting go sends again (the same bytes: nothing about the write was changed).
  t.run.release();
  await until(() => t.log.epoch.length === 2 && t.log.done.length === 1, "the other lane goes out, the first is refused once more");
  assert.deepEqual(t.log.done, [other.itemId]);
  t.run.stop();
});

test("a_write_that_names_the_epoch_the_server_shows_is_stored", async () => {
  const model = new Model();
  model.restoreEpoch = 3;
  const t = await senderOf({ model });
  await t.run.enqueue(writeFor(5, { restoreEpoch: 3 }));
  await until(() => t.log.done.length === 1, "done");
  assert.deepEqual(t.log.epoch, []);
  // Without a condition (a device that has not stored an epoch yet) it is stored as well.
  await t.run.enqueue(writeFor(6));
  await until(() => t.log.done.length === 2, "done without a condition");
  assert.equal(model.writes.length, 2);
  t.run.stop();
});

test("a_retry_of_a_stored_write_is_a_replay_even_after_the_epoch_has_moved", async () => {
  // The server checks the key before the epoch: a write that was stored and whose answer was lost is answered as a replay, so the
  // bytes of a write that may have been stored are never changed, and never need to be.
  const model = new Model();
  const t = await senderOf({ model });
  const entry = writeFor(7, { restoreEpoch: 0 });
  t.api.faults.push({ kind: "lost" });
  await t.run.enqueue(entry);
  await until(() => model.writes.length === 1, "stored, the answer lost");
  model.restoreEpoch = 1; // the server is restored meanwhile (to a state that still holds this write)
  await until(() => t.api.puts.length === 1);
  // The retry after the wait: the same bytes under the same key.
  t.run.stop();
  const again = await senderOf({ model });
  await again.run.enqueue(entry);
  await until(() => again.log.done.length === 1, "answered as a replay");
  assert.deepEqual(again.log.epoch, []);
  assert.equal(model.writes.length, 1, "stored once");
  again.run.stop();
});

test("restamp_replaces_only_the_writes_that_were_queued_when_it_began", async () => {
  const model = new Model();
  const t = await senderOf({ model });
  t.run.hold();
  const first = writeFor(1, { idem: 8101, restoreEpoch: 0 });
  const second = writeFor(1, { idem: 8102, baseRev: 1, restoreEpoch: 0 });
  await t.run.enqueue(first);
  await t.run.enqueue(second);
  // The swap is slow; a write of the same item is queued meanwhile.
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const swap = t.store.outbox.swap;
  t.store.outbox.swap = async (...args) => {
    await gate;
    return swap(...args);
  };
  const remade = (old) => writeFor(1, { idem: 9000 + old.baseRev, baseRev: old.baseRev, restoreEpoch: 1 });
  const restamping = t.run.restamp(first.itemId, remade);
  await settle(10);
  const later = writeFor(1, { idem: 8103, baseRev: 2, restoreEpoch: 0 });
  await t.run.enqueue(later);
  release();
  const gone = await restamping;
  assert.deepEqual(gone.sort(), [first.idem, second.idem].sort());
  assert.deepEqual(t.run.entriesOf(first.itemId).map((e) => e.baseRev), [0, 1, 2], "the write queued meanwhile is still in the lane, last");
  assert.equal(t.run.entriesOf(first.itemId).at(-1).idem, later.idem);
  assert.ok(!t.run.entriesOf(first.itemId).some((e) => gone.includes(e.idem)));
  const stored = await t.stored();
  assert.ok(stored.some((e) => e.idem === later.idem), "and in the store");
  assert.ok(!stored.some((e) => gone.includes(e.idem)));
  t.run.stop();
});

test("replace_with_expect_swaps_exactly_the_writes_that_were_looked_at_in_one_transaction", async () => {
  const t = await senderOf();
  t.run.hold();
  const [one, two] = [writeFor(1, { idem: 8201 }), writeFor(1, { idem: 8202, baseRev: 1 })];
  await t.run.enqueue(one);
  await t.run.enqueue(two);
  const other = writeFor(2, { idem: 8210 });
  await t.run.enqueue(other); // another item: never touched
  const fresh = writeFor(1, { idem: 8203, baseRev: 5 });
  const dropped = await t.run.replace(fresh, [one.idem, two.idem]);
  assert.deepEqual(dropped.sort(), [one.idem, two.idem].sort());
  assert.deepEqual((await t.stored()).map((e) => e.idem), [other.idem, fresh.idem]);
  assert.deepEqual(t.run.entriesOf(fresh.itemId).map((e) => e.idem), [fresh.idem]);
  t.run.stop();
});

test("replace_with_expect_does_not_drop_a_write_another_tab_queued_between_the_look_and_the_removal", async () => {
  const t = await senderOf();
  t.run.hold();
  const mine = writeFor(1, { idem: 8301 });
  await t.run.enqueue(mine);
  // The caller has looked at the store and sees only `mine`. Just before the swap another tab of the browser queues a write of the item.
  const theirs = writeFor(1, { idem: 8302, baseRev: 1 });
  const swap = t.store.outbox.swap;
  t.store.outbox.swap = async (db, scope, ...rest) => {
    await outbox.enqueue(db, scope, theirs);
    return swap(db, scope, ...rest);
  };
  const fresh = writeFor(1, { idem: 8303, baseRev: 3 });
  await assert.rejects(() => t.run.replace(fresh, [mine.idem]), { code: "outbox_changed" });
  assert.deepEqual((await t.stored()).map((e) => e.idem), [mine.idem, theirs.idem], "nothing was added and nothing was removed");
  assert.deepEqual(t.run.entriesOf(mine.itemId).map((e) => e.idem), [mine.idem], "and the lane is as it was");
  t.run.stop();
});
