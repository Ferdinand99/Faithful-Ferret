// The outbox and a 409 that only shows the write that was sent: the server forgot its idempotency key (30 days), the answer to
// the first try was lost, and the row it holds now is the one the write made. That is done, not a conflict.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { trash } from "../../src/store/trash.mjs";
import { alreadyDone } from "../../src/sync/outbox.mjs";
import { scope } from "./idbHelpers.mjs";
import { createFakeClient, Model, settle, syncDevice, until } from "./syncHelpers.mjs";

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
