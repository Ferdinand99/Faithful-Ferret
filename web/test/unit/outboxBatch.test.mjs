// The outbox sender and the writes of an import: they go in batches (POST /api/sync/batch with the id of the import window), at most
// 100 operations and 5 MiB to a request, each result is handled as the answer to a PUT would be, and everything else still goes with PUT.
// Spec: Fase 1 section 8.2 (batch), 8.3 (idempotency).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { encodeWireBytes } from "../../src/wire.mjs";
import { batchBody, batchOp, createOutboxRunner, errorOfResult, MAX_BATCH_BYTES } from "../../src/sync/outbox.mjs";
import { scope } from "./idbHelpers.mjs";
import { createFakeApi, createFakeStore, FakeTimers, Model, settle, until } from "./syncHelpers.mjs";
import { web } from "./helpers.mjs";

const hex = (n) => n.toString(16).padStart(32, "0");

/** A queued write of item `n`, as the engine builds it; `window` makes it a write of an import (a new item, a live row). */
function entryFor(n, { window = null, baseRev = 0, idem = 5000 + n, fill = n, size = 48, epoch = null } = {}) {
  const blob = new Uint8Array(size).fill(fill % 256);
  const tag = new Uint8Array(32).fill((fill + 100) % 256);
  const bytes = encodeWireBytes("put_item_req", {
    base_rev: baseRev, blob: b64u.encode(blob), tag: b64u.encode(tag), idem: hex(idem), ...(epoch === null ? {} : { restore_epoch: epoch }),
  });
  return { idem: hex(idem), itemId: hex(n), baseRev, body: { blob, tag }, bytes, ...(window === null ? {} : { import: window }) };
}

async function runner({ hooks = {}, model = new Model() } = {}) {
  const order = [];
  const store = await createFakeStore({ order });
  const api = createFakeApi(model, { order });
  const timers = new FakeTimers();
  const log = { done: [], blocked: [], retry: [], closed: [], batchEnds: 0, epoch: [], storage: [] };
  const run = createOutboxRunner({
    api, store, scope: scope(), timers,
    hooks: {
      onDone: (entry, answer) => log.done.push([entry.itemId, answer]),
      onBlocked: (entry, error, kind) => log.blocked.push([entry.itemId, error.code, kind]),
      onRetry: (entry, ms) => log.retry.push([entry.itemId, ms]),
      onImportWindowClosed: (info) => log.closed.push(info),
      onBatchEnd: () => { log.batchEnds += 1; },
      onRestoreEpochChanged: (entry, error) => log.epoch.push([entry.itemId, error.body?.restore_epoch]),
      onStorageError: (error) => log.storage.push(error.message),
      ...hooks,
    },
  });
  const stored = () => outbox.all(store.database.store, scope());
  return { run, api, model, store, timers, log, order, stored };
}

test("import_entries_go_in_batches_of_at_most_100_ops_and_5_mib", async () => {
  const model = new Model();
  const t = await runner({ model });
  const window = model.openImportWindow(1000);
  const entries = Array.from({ length: 250 }, (_, at) => entryFor(at + 1, { window }));
  await t.run.enqueueMany(entries);
  await until(() => t.log.done.length === 250, "the whole import");
  assert.deepEqual(t.api.batches.map((batch) => batch.ids.length), [100, 100, 50], "100 operations to a request, then what is left");
  assert.deepEqual(t.api.batches.flatMap((batch) => batch.ids), entries.map((e) => e.itemId), "in the order they were queued");
  assert.ok(t.api.batches.every((batch) => batch.window === window), "every batch names the window");
  assert.equal(t.api.puts.length, 0, "nothing of an import goes with PUT");
  assert.equal(model.items.size, 250);
  assert.equal((await t.stored()).length, 0, "an entry that the server has taken leaves the store");
  assert.equal(t.log.batchEnds, 3);
  assert.deepEqual(t.log.done.map(([id]) => id), entries.map((e) => e.itemId));
  assert.ok(t.log.done.every(([, answer]) => answer.replayed === false));

  // The bytes: a batch never holds more than 5 MiB of operations, however few operations that is.
  const model2 = new Model();
  const big = await runner({ model: model2 });
  const window2 = model2.openImportWindow(100);
  const heavy = Array.from({ length: 12 }, (_, at) => entryFor(at + 1, { window: window2, size: 1_100_000 }));
  await big.run.enqueueMany(heavy);
  await until(() => big.log.done.length === 12, "the heavy import");
  assert.deepEqual(big.api.batches.map((batch) => batch.ids.length), [3, 3, 3, 3], "1.1 MB of ciphertext is 1.5 MB on the wire: three to a batch, and four would be over 5 MiB");
  assert.ok(big.api.batches.every((batch) => batch.bytes <= MAX_BATCH_BYTES), "no request is over 5 MiB");
  assert.equal(MAX_BATCH_BYTES, 5 * 1024 * 1024);
  // One entry alone that is over the limit still goes (the server decides: it takes 6 MiB), and never together with another.
  const model3 = new Model();
  const alone = await runner({ model: model3 });
  const window3 = model3.openImportWindow(10);
  await alone.run.enqueueMany([entryFor(1, { window: window3, size: 4_000_000 }), entryFor(2, { window: window3, size: 4_000_000 })]);
  await until(() => alone.log.done.length === 2, "two big entries");
  assert.deepEqual(alone.api.batches.map((batch) => batch.ids.length), [1, 1]);
});

test("a_batch_is_the_operations_of_its_entries_with_the_item_ids_and_the_window", async () => {
  const entry = entryFor(7, { window: hex(99), epoch: 1700000000 });
  const op = JSON.parse(batchOp(entry));
  assert.deepEqual(Object.keys(op), ["id", "base_rev", "blob", "tag", "idem", "restore_epoch"], "the id first, then the fields of the single write, as they were");
  assert.equal(op.id, hex(7));
  assert.equal(batchOp(entry), batchOp(entry), "the same entry always gives the same text");
  const body = JSON.parse(new TextDecoder().decode(batchBody([entry, entryFor(8, { window: hex(99) })], hex(99))));
  assert.deepEqual(Object.keys(body), ["ops", "import_window"]);
  assert.equal(body.import_window, hex(99));
  assert.equal(body.ops.length, 2);
  assert.throws(() => batchOp({ ...entry, bytes: new TextEncoder().encode("[]") }), (e) => e.code === "outbox_entry");
});

test("ordinary_edits_still_use_put", async () => {
  const t = await runner();
  await t.run.enqueue(entryFor(1));
  await t.run.enqueue(entryFor(2));
  await until(() => t.log.done.length === 2);
  assert.equal(t.api.puts.length, 2);
  assert.equal(t.api.batches.length, 0, "a write that is not part of an import is never put into a batch");
  assert.deepEqual(t.order.filter((step) => step === "put" || step === "batch"), ["put", "put"]);
});

test("an_edit_of_an_item_that_the_import_made_waits_for_the_import_and_goes_with_put", async () => {
  const model = new Model();
  const t = await runner({ model });
  const window = model.openImportWindow(10);
  // The import entry is held until the edit has been queued behind it: the lane of the item sends them one after the other.
  t.run.hold();
  await t.run.enqueueMany([entryFor(1, { window }), entryFor(2, { window })]);
  await t.run.enqueue(entryFor(1, { baseRev: 1, idem: 9001, fill: 77 }));
  t.run.release();
  await until(() => t.log.done.length === 3, "the import and the edit");
  assert.deepEqual(t.order.filter((step) => step === "put" || step === "batch"), ["batch", "put"], "the batch first, the edit after it, with PUT");
  assert.deepEqual(t.api.batches[0].ids, [hex(1), hex(2)], "one operation for each item");
  assert.equal(model.items.get(hex(1)).rev, 2);
});

test("outbox_entries_without_an_import_mark_still_send_with_put", async () => {
  // The golden entries of version 2 of the database have no import mark: they are ordinary writes, whatever else the code sends in batches.
  const file = JSON.parse(readFileSync(join(web, "test", "fixtures", "stored", "v2", "outbox.json"), "utf8"));
  const fromHex = (x) => Uint8Array.from(Buffer.from(x.$bytes, "hex"));
  const entries = file.records
    .map(({ value }) => value)
    .filter((value) => value.vkEpoch === 2)
    .map((value) => ({
      idem: value.idem, itemId: value.itemId, baseRev: value.baseRev, bytes: fromHex(value.bytes),
      body: value.body.tomb ? { tomb: fromHex(value.body.tomb) } : { blob: fromHex(value.body.blob), tag: fromHex(value.body.tag) },
    }));
  assert.ok(entries.length >= 3);
  const model = new Model();
  model.restoreEpoch = 1700000000; // the one the golden writes name
  const t = await runner({ model });
  // The store of the runner is the one of scope 1; the golden entries are for epoch 2, so they are put into the queue as a restart would.
  const db = t.store.database.store;
  const epoch2 = { accountId: scope().accountId, vaultId: scope().vaultId, vkEpoch: 2 };
  for (const entry of entries) await outbox.enqueue(db, epoch2, entry);
  const run2 = createOutboxRunner({ api: t.api, store: t.store, scope: epoch2, timers: t.timers, hooks: { onDone: (entry) => t.log.done.push([entry.itemId]), onBlocked: (entry, error, kind) => t.log.blocked.push([entry.itemId, error.code, kind]) } });
  const loaded = await run2.load();
  assert.equal(loaded.length, entries.length);
  assert.ok(loaded.every((entry) => entry.import === undefined));
  // Each is for an item the model does not have at that revision: the answers do not matter here, only the way they are sent.
  run2.start();
  await until(() => t.api.puts.length === entries.length, "every entry sent");
  await settle(10);
  assert.equal(t.api.batches.length, 0, "an entry without the mark is never sent in a batch");
  assert.deepEqual(t.api.puts.map((put) => put.id), entries.map((entry) => entry.itemId), "with PUT, one by one, in the order of the store");
  assert.deepEqual(t.api.puts.map((put) => put.text), entries.map((entry) => new TextDecoder().decode(entry.bytes)), "the exact bytes of the entry");
  run2.stop();
});

test("each_batch_result_is_handled_like_a_put_answer", async () => {
  const model = new Model();
  const t = await runner({ model });
  const window = model.openImportWindow(1000);
  // Item 2 is already on the server with the very write this entry makes (the answer to it was lost, and the key has expired): done, no conflict.
  // Item 3 is on the server with something else: a conflict, refused for good, the draft stays. Item 4 is refused for its size. Item 5 breaks
  // inside the server (the others are not held back, and it is sent again). Item 1 and 6 are stored; 6 was stored before (a replay).
  const one = entryFor(1, { window });
  const two = entryFor(2, { window });
  const three = entryFor(3, { window });
  const four = entryFor(4, { window });
  const five = entryFor(5, { window });
  const six = entryFor(6, { window });
  model.set(hex(2), { rev: 1, blob: b64u.encode(two.body.blob), tag: b64u.encode(two.body.tag) });
  model.set(hex(3), { rev: 1, blob: b64u.encode(new Uint8Array(48).fill(9)), tag: b64u.encode(new Uint8Array(32).fill(9)) });
  model.idems.set(six.idem, { body: JSON.stringify(JSON.parse(batchOp(six))), result: { rev: 1, seq: 77, replayed: false } });
  model.set(hex(6), { rev: 1, blob: b64u.encode(six.body.blob), tag: b64u.encode(six.body.tag) });
  const real = model.batch.bind(model);
  model.batch = (body) => {
    const answer = real(body);
    const request = JSON.parse(body);
    const at = (id) => request.ops.findIndex((op) => op.id === id);
    if (at(hex(4)) >= 0) answer.results[at(hex(4))] = { status: 422, error: "unsupported_envelope" };
    if (at(hex(5)) >= 0 && !model.fixedFive) answer.results[at(hex(5))] = { status: 500, error: "internal" };
    return answer;
  };
  await t.run.enqueueMany([one, two, three, four, five, six]);
  await until(() => t.log.batchEnds >= 1 && t.log.retry.length === 1, "the first batch is answered");
  const done = Object.fromEntries(t.log.done.map(([id, answer]) => [id, answer]));
  assert.deepEqual(Object.keys(done).sort(), [hex(1), hex(2), hex(6)].sort(), "stored, already there, and replayed are done");
  assert.equal(done[hex(1)].replayed, false);
  assert.equal(done[hex(2)].rev, 1, "the write of an item that holds the very row is done at its revision");
  assert.equal(done[hex(2)].replayed, true);
  assert.equal(done[hex(6)].replayed, true, "a replay is done");
  assert.deepEqual(t.log.blocked, [
    [hex(3), "conflict", "conflict"],
    [hex(4), "unsupported_envelope", "terminal"],
  ], "a conflict and a refusal stay with their draft");
  assert.deepEqual(t.log.retry, [[hex(5), 1000]], "a failure inside the server is waited for, then sent again, alone");
  const left = await t.stored();
  assert.deepEqual(left.map((entry) => entry.itemId).sort(), [hex(3), hex(4), hex(5)].sort(), "only what is not done stays in the store");
  assert.ok(left.every((entry) => entry.import === window), "with its mark, its key and its bytes");

  // The wait is over: item 5 goes again in a batch of its own, under the same key.
  model.fixedFive = true;
  t.timers.advance(1000);
  await until(() => t.log.done.some(([id]) => id === hex(5)), "item 5 sent again");
  assert.deepEqual(t.api.batches.at(-1).ids, [hex(5)], "the lanes that are blocked are left out");
  assert.equal(JSON.parse(t.api.batches.at(-1).text).ops[0].idem, five.idem, "under the same key");
  assert.deepEqual((await t.stored()).map((entry) => entry.itemId).sort(), [hex(3), hex(4)].sort());
});

test("a_batch_that_the_server_stored_but_never_answered_comes_back_as_replays", async () => {
  const model = new Model();
  const t = await runner({ model });
  const window = model.openImportWindow(1000);
  const entries = Array.from({ length: 5 }, (_, at) => entryFor(at + 1, { window }));
  t.api.batchFaults.push({ kind: "lost" });
  await t.run.enqueueMany(entries);
  await until(() => t.log.retry.length === 1, "the answer is lost");
  assert.equal(model.items.size, 5, "the server stored all of it");
  assert.equal((await t.stored()).length, 5, "the entries stay until an answer comes");
  t.timers.advance(1000);
  await until(() => t.log.done.length === 5, "sent again");
  assert.deepEqual(t.log.done.map(([, answer]) => answer.replayed), [true, true, true, true, true]);
  assert.equal(new Set(t.api.batches.map((batch) => batch.text)).size, 1, "the same bytes");
  assert.equal(model.importWindows.get(window).used, 5, "a replay does not use the window again");
});

test("a_network_failure_waits_and_a_401_waits_for_the_user_and_a_refusal_of_the_whole_batch_blocks", async () => {
  const model = new Model();
  const t = await runner({ model });
  const window = model.openImportWindow(1000);
  t.api.batchFaults.push({ kind: "network" }, { kind: "status", status: 503, code: "busy", retryAfter: 4 });
  await t.run.enqueueMany([entryFor(1, { window }), entryFor(2, { window })]);
  await until(() => t.log.retry.length === 1);
  assert.deepEqual(t.log.retry[0][1], 1000);
  t.timers.advance(1000);
  await until(() => t.log.retry.length === 2);
  assert.deepEqual(t.log.retry[1][1], 4000, "a Retry-After that is longer than the wait is followed");
  t.timers.advance(4000);
  await until(() => t.log.done.length === 2);

  const model2 = new Model();
  const u = await runner({ model: model2 });
  const window2 = model2.openImportWindow(10);
  u.api.batchFaults.push({ kind: "status", status: 401, code: "unauthorized" });
  await u.run.enqueueMany([entryFor(1, { window: window2 })]);
  await until(() => u.log.blocked.length === 1);
  assert.deepEqual(u.log.blocked[0], [hex(1), "unauthorized", "unauthorized"]);
  assert.equal(u.api.batches.length, 1, "nothing is sent while the session is gone");
  u.run.resume();
  await until(() => u.log.done.length === 1);

  const model3 = new Model();
  const v = await runner({ model: model3 });
  const window3 = model3.openImportWindow(10);
  v.api.batchFaults.push({ kind: "status", status: 413, code: "too_large" });
  await v.run.enqueueMany([entryFor(1, { window: window3 }), entryFor(2, { window: window3 })]);
  await until(() => v.log.blocked.length === 2);
  assert.deepEqual(v.log.blocked.map((b) => b[2]), ["terminal", "terminal"]);
  assert.equal((await v.stored()).length, 2, "the drafts stay");
});

test("a_restore_epoch_that_changed_holds_every_lane_and_the_writes_stay_as_they_were", async () => {
  const model = new Model();
  model.restoreEpoch = 3;
  const t = await runner({ model });
  const window = model.openImportWindow(10);
  await t.run.enqueueMany([entryFor(1, { window, epoch: 2 }), entryFor(2, { window, epoch: 2 })]);
  await until(() => t.log.epoch.length === 2);
  assert.deepEqual(t.log.epoch, [[hex(1), 3], [hex(2), 3]]);
  assert.equal(model.items.size, 0, "nothing was stored");
  assert.equal(t.api.batches.length, 1, "and nothing more is sent until the runner is let go");
  assert.equal((await t.stored()).length, 2);
});

test("the_result_of_an_operation_has_the_error_of_the_answer_to_a_single_write", () => {
  const conflict = errorOfResult({ status: 409, current_rev: 4, blob: "AAAA", tag: "BBBB", deleted: false });
  assert.ok(conflict instanceof ApiError);
  assert.equal(conflict.status, 409);
  assert.equal(conflict.code, "conflict");
  assert.deepEqual(conflict.body, { current_rev: 4, blob: "AAAA", tag: "BBBB", deleted: false });
  const epoch = errorOfResult({ status: 409, error: "restore_epoch_changed", restore_epoch: 6 });
  assert.equal(epoch.code, "restore_epoch_changed");
  assert.equal(epoch.body.restore_epoch, 6);
  const refused = errorOfResult({ status: 422, error: "idem_reuse" });
  assert.equal(refused.status, 422);
  assert.equal(refused.code, "idem_reuse");
  assert.equal(refused.terminal, true);
  assert.equal(errorOfResult({ status: 500, error: "internal" }).status, 500);
});

test("the_batch_of_import_entries_needs_no_other_path_than_the_lanes_after_a_discard", async () => {
  const model = new Model();
  const t = await runner({ model });
  const window = model.openImportWindow(10);
  t.run.hold();
  await t.run.enqueueMany([entryFor(1, { window }), entryFor(2, { window })]);
  assert.deepEqual(t.run.itemsWithEntries().sort(), [hex(1), hex(2)].sort());
  assert.equal(t.run.importState().queued, 2);
  const dropped = await t.run.discard(hex(1));
  assert.equal(dropped.length, 1);
  t.run.release();
  await until(() => t.log.done.length === 1);
  assert.deepEqual(t.api.batches[0].ids, [hex(2)]);
  assert.equal(t.run.importState().queued, 0);
});
