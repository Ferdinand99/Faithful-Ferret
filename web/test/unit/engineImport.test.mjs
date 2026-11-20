// The import through the engine: items that are sealed already are stored in the outbox with the mark of the import window before anything is
// sent, go out in batches, show as pending, and carry on under their own keys after a closed window or a reload.
// Spec: Fase 1 section 8.2 (batch), 8.3 (idempotency).
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u, hex16 } from "../../src/b64.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { scope } from "./idbHelpers.mjs";
import { createFakeClient, Model, settle, syncDevice, until } from "./syncHelpers.mjs";

const hex = (n) => n.toString(16).padStart(32, "0");

/** The items the import worker would hand over: sealed by the core, `{ id, rev: 1, envelope, tag }`. */
async function sealed(client, count, from = 1) {
  const items = [];
  for (let n = from; n < from + count; n += 1) {
    const id = hex(0x1000 + n);
    const made = await client.vault.encrypt_item(hex16.decode(id), 1, { item_type: "login", name: `Imported ${n}` });
    items.push({ id, rev: 1, envelope: made.envelope, tag: made.tag });
  }
  return items;
}

async function started({ model = new Model(), client = createFakeClient(), db = null, locks } = {}) {
  const d = await syncDevice({ model, client, db, ...(locks ? { locks } : {}) });
  d.imports = [];
  d.closed = [];
  d.engine.on("import", (progress) => d.imports.push(progress));
  d.engine.on("import_window_closed", (info) => d.closed.push(info));
  await d.engine.start();
  return d;
}

const stored = (d) => outbox.all(d.store.database.store, scope());

test("an_import_is_stored_before_anything_is_sent_and_shows_as_pending", async () => {
  const d = await started();
  const window = d.model.openImportWindow(10);
  const items = await sealed(d.client, 5);
  d.api.batchFaults.push({ kind: "network" }); // the first request fails, so the state before any answer can be looked at
  const result = await d.engine.importItems(items, { windowId: window });
  assert.deepEqual(result, { queued: 5 });
  await until(() => d.api.batches.length === 1);
  const queued = await stored(d);
  assert.equal(queued.length, 5, "all five are in the store while the request is out");
  assert.ok(queued.every((entry) => entry.import === window && entry.baseRev === 0));
  assert.deepEqual(d.engine.list().map((item) => [item.name, item.pending, item.rev]).sort(), items.map((_, n) => [`Imported ${n + 1}`, true, 1]).sort());
  assert.equal(d.model.items.size, 0);
  assert.deepEqual(d.imports.at(-1), { sent: 0, total: 5, failed: 0 });
  // The first answer was a failure: it is sent again, and the whole import goes through.
  d.timers.advance(1000);
  await until(() => d.model.items.size === 5, "the server has all five");
  await until(async () => (await stored(d)).length === 0, "the outbox is empty");
  await until(() => d.engine.list().every((item) => !item.pending), "the feed brought the rows back");
  assert.deepEqual(d.imports.at(-1), { sent: 5, total: 5, failed: 0 });
  assert.equal(d.api.puts.length, 0, "nothing of an import goes with PUT");
  assert.ok(d.engine.list().every((item) => item.rev === 1 && !item.blocked));
  d.engine.stop();
});

test("a_big_import_goes_in_batches_and_reports_how_far_it_is", async () => {
  const d = await started();
  const window = d.model.openImportWindow(1000);
  const items = await sealed(d.client, 250);
  await d.engine.importItems(items, { windowId: window });
  await until(() => d.model.items.size === 250, "all 250");
  assert.deepEqual(d.api.batches.map((batch) => batch.ids.length), [100, 100, 50]);
  await until(() => d.imports.at(-1)?.sent === 250);
  assert.deepEqual(d.imports.at(-1), { sent: 250, total: 250, failed: 0 });
  assert.deepEqual(d.imports.map((progress) => progress.sent), [0, 100, 200, 250], "one report when it is queued and one after each batch");
  await until(() => d.engine.list().length === 250 && d.engine.list().every((item) => !item.pending), "the rows are back");
  d.engine.stop();
});

test("a_closed_window_holds_the_lane_and_resume_sends_the_rest_with_a_new_window", async () => {
  const d = await started();
  const first = d.model.openImportWindow(100); // enough for the first batch only: the second is refused
  const items = await sealed(d.client, 250);
  await d.engine.importItems(items, { windowId: first });
  await until(() => d.closed.length === 1, "the server refuses the second batch");
  assert.deepEqual(d.closed, [{ remaining: 150 }], "the engine says how many are left");
  assert.equal(d.model.items.size, 100, "the first batch was taken");
  const batchesBefore = d.api.batches.length;
  assert.equal(batchesBefore, 2, "the refused batch was sent once");
  const left = await stored(d);
  assert.equal(left.length, 150);
  assert.ok(left.every((entry) => entry.import === first));
  const keys = left.map((entry) => entry.idem);

  // The lane is held: nothing more is sent, whatever else happens, and the other writes go on with PUT.
  d.timers.advance(10 * 60_000);
  await settle(30);
  assert.equal(d.api.batches.length, batchesBefore, "nothing of the import is sent while the window is closed");
  const other = await d.engine.create({ item_type: "login", name: "Written by hand" });
  await until(() => d.model.items.has(other), "an ordinary write still goes with PUT");
  assert.equal(d.api.puts.length, 1);
  assert.equal((await stored(d)).length, 150);

  // "Continue the import": a new window for what is left. The keys and the bytes are the same.
  const second = d.model.openImportWindow(150);
  await d.engine.resumeImport({ windowId: second });
  await until(() => d.model.items.size === 251, "the rest of the import and the item written by hand");
  await until(async () => (await stored(d)).length === 0);
  const resent = d.api.batches.slice(batchesBefore);
  assert.deepEqual(resent.map((batch) => [batch.window, batch.ids.length]), [[second, 100], [second, 50]]);
  assert.deepEqual(resent.flatMap((batch) => JSON.parse(batch.text).ops.map((op) => op.idem)).sort(), [...keys].sort(), "under the keys the entries had");
  assert.equal(new Set(d.api.batches.flatMap((batch) => batch.ids)).size, 250, "every item went once");
  assert.deepEqual(d.imports.at(-1), { sent: 250, total: 250, failed: 0 });
  d.engine.stop();
});

test("a_reload_resumes_the_import_with_the_same_idem", async () => {
  const model = new Model();
  const client = createFakeClient();
  const first = await started({ model, client });
  const window = model.openImportWindow(100);
  const items = await sealed(client, 30);
  first.api.batchFaults.push({ kind: "lost" }); // the server takes the batch and the answer never comes
  await first.engine.importItems(items, { windowId: window });
  await until(() => first.api.batches.length === 1 && model.items.size === 30, "the server took the batch");
  await settle(20);
  assert.equal((await stored(first)).length, 30, "the answer was lost: the entries are still in the store");
  const idems = (await stored(first)).map((entry) => entry.idem);
  const sentFirst = JSON.parse(first.api.batches[0].text).ops.map((op) => op.idem);
  assert.deepEqual(sentFirst, idems, "the keys of the first try are the ones in the store");
  first.engine.stop();

  // The page is opened again over the same storage: the entries are read back with their mark, and go out as they were.
  const second = await started({ model, client, db: first.store.database, locks: first.locks });
  await until(() => second.api.batches.length >= 1, "the import goes on after the reload");
  await until(async () => (await stored(second)).length === 0, "the outbox is empty");
  const sentAgain = JSON.parse(second.api.batches[0].text);
  assert.equal(sentAgain.import_window, window, "under the window it had");
  assert.deepEqual(sentAgain.ops.map((op) => op.idem), idems, "under the same keys");
  assert.equal(second.api.puts.length, 0);
  assert.equal(model.items.size, 30, "nothing is stored twice");
  assert.equal(model.importWindows.get(window).used, 30, "and the replays do not use the window again");
  assert.deepEqual(second.imports.at(-1), { sent: 30, total: 30, failed: 0 });
  await until(() => second.engine.list().length === 30 && second.engine.list().every((item) => !item.pending));
  second.engine.stop();
});

test("a_reload_after_the_window_closed_waits_for_a_new_window", async () => {
  const model = new Model();
  const client = createFakeClient();
  const first = await started({ model, client });
  const window = model.openImportWindow(100);
  await first.engine.importItems(await sealed(client, 150), { windowId: window });
  await until(() => first.closed.length === 1, "the window closes after 100");
  first.engine.stop();

  const second = await started({ model, client, db: first.store.database, locks: first.locks });
  await until(() => second.closed.length === 1, "the old window is refused again");
  assert.deepEqual(second.closed, [{ remaining: 50 }]);
  assert.equal(model.items.size, 100);
  const next = model.openImportWindow(50);
  await second.engine.resumeImport({ windowId: next });
  await until(() => model.items.size === 150, "the rest");
  assert.equal(second.api.puts.length, 0);
  second.engine.stop();
});

test("an_item_that_does_not_open_or_has_an_id_in_use_keeps_the_whole_import_from_being_stored", async () => {
  const d = await started();
  const window = d.model.openImportWindow(10);
  const items = await sealed(d.client, 3);
  const damaged = [items[0], { ...items[1], tag: new Uint8Array(32).fill(1) }, items[2]];
  await assert.rejects(d.engine.importItems(damaged, { windowId: window }), (e) => e.code === "invalid_item");
  assert.equal((await stored(d)).length, 0, "nothing is stored when one does not open");
  assert.equal(d.engine.list().length, 0);
  assert.equal(d.api.batches.length, 0);

  await d.engine.importItems([items[0]], { windowId: window });
  await assert.rejects(d.engine.importItems([items[0]], { windowId: window }), (e) => e.code === "invalid_state", "an id that is in use");
  await assert.rejects(d.engine.importItems([], { windowId: window }), TypeError);
  await assert.rejects(d.engine.importItems(items, { windowId: "nope" }), TypeError);
  await assert.rejects(d.engine.importItems([{ ...items[1], rev: 2 }], { windowId: window }), TypeError);
  await assert.rejects(d.engine.importItems([{ ...items[1], id: "00000000000000000000000000000000" }], { windowId: window }), TypeError, "the manifest is not an item");
  await assert.rejects(d.engine.importItems([items[1], items[1]], { windowId: window }), TypeError, "an item once");
  d.engine.stop();
});

test("an_import_item_that_the_server_refuses_is_counted_as_failed_and_stays_as_a_draft", async () => {
  const d = await started();
  const window = d.model.openImportWindow(10);
  const items = await sealed(d.client, 3);
  const real = d.model.batch.bind(d.model);
  d.model.batch = (body) => {
    const answer = real(body);
    answer.results[1] = { status: 422, error: "unsupported_envelope" };
    return answer;
  };
  await d.engine.importItems(items, { windowId: window });
  await until(() => d.imports.at(-1)?.sent + d.imports.at(-1)?.failed === 3, "every item answered");
  assert.deepEqual(d.imports.at(-1), { sent: 2, total: 3, failed: 1 }, JSON.stringify(d.imports));
  const left = await stored(d);
  assert.deepEqual(left.map((entry) => entry.itemId), [items[1].id], "the draft stays in the outbox");
  const shown = d.engine.list().find((item) => item.id === items[1].id);
  assert.equal(shown.blocked, true);
  assert.equal(shown.blockedReason, "unsupported_envelope");
  // What the server refused is not waiting to be sent: the import is over for the page, with one refused item that stays as a draft.
  assert.deepEqual(d.engine.importStatus(), { queued: 0, refused: 1, sent: 2, total: 3, failed: 1, windowClosed: false });
  d.engine.stop();
});

test("a_refused_import_item_is_not_sent_again_with_a_new_window_and_is_still_refused_after_a_reload", async () => {
  const model = new Model();
  const client = createFakeClient();
  const first = await started({ model, client });
  const window = model.openImportWindow(100);
  const items = await sealed(client, 150);
  const real = model.batch.bind(model);
  model.batch = (body) => {
    const answer = real(body);
    // The first item of the first batch is refused for good.
    if (answer.results.length === 100 && answer.results[0].status === 200 && !model.refusedOnce) {
      model.refusedOnce = true;
      answer.results[0] = { status: 422, error: "unsupported_envelope" };
    }
    return answer;
  };
  model.closeImportWindow(window); // the window is closed from the start: nothing is stored under it
  await first.engine.importItems(items, { windowId: window });
  await until(() => first.closed.length === 1, "the server refuses the window");
  const next = model.openImportWindow(150);
  await first.engine.resumeImport({ windowId: next });
  await until(() => first.engine.importStatus().queued === 0, "nothing is left to send");
  // (The model stored the refused item; only the answer was changed. What matters is what the engine counts.)
  const status = first.engine.importStatus();
  assert.deepEqual([status.queued, status.refused, status.sent, status.windowClosed], [0, 1, 149, false]);
  first.engine.stop();

  // After a reload the refused item is still counted as refused and not as waiting.
  const second = await started({ model, client, db: first.store.database, locks: first.locks });
  const again = second.engine.importStatus();
  assert.deepEqual([again.queued, again.refused], [0, 1]);
  second.engine.stop();
});

test("a_new_import_beside_a_refused_draft_still_goes_through", async () => {
  const d = await started();
  const window = d.model.openImportWindow(10);
  const items = await sealed(d.client, 4);
  const real = d.model.batch.bind(d.model);
  d.model.batch = (body) => {
    const answer = real(body);
    answer.results[0] = { status: 422, error: "unsupported_envelope" };
    return answer;
  };
  await d.engine.importItems(items, { windowId: window });
  await until(() => d.engine.importStatus().queued === 0 && d.engine.importStatus().refused === 1);
  d.model.batch = real;
  d.model.closeImportWindow(window);
  // A new import while the refused one is a draft: the window it needs is for the new items only.
  const more = await sealed(d.client, 2, 100);
  await d.engine.importItems(more, { windowId: d.model.openImportWindow(2) });
  await until(() => d.model.items.size === 6);
  assert.equal(d.engine.importStatus().refused, 1);
  d.engine.stop();
});

test("an_import_item_after_a_listing_is_not_confused_with_a_missing_item", async () => {
  // The server's floor moves above the cursor while the import is under way: a listing is made, and what the server has not got yet is no
  // reason to mark an item that was only imported (it is in the outbox, not a row).
  const model = new Model();
  const client = createFakeClient();
  model.set(hex(1), { rev: 1, ...client.wireRow(hex(1), 1, { item_type: "login", name: "Existing" }) }); // the device has read something: a cursor
  const d = await started({ model, client });
  const window = model.openImportWindow(10);
  const items = await sealed(client, 4);
  d.api.batchFaults.push({ kind: "network" });
  await d.engine.importItems(items, { windowId: window });
  await until(() => d.api.batches.length === 1);
  model.seq += 3;
  model.minValidSince = model.seq;
  d.api.gets.length = 0;
  await d.engine.syncNow();
  assert.ok(d.api.gets.some((path) => path.startsWith("/api/sync/items")), "the floor is above the cursor: the vault is listed");
  assert.ok(d.engine.list().every((item) => !item.missingOnServer), "no item of the import is marked as missing");
  assert.equal(d.engine.list().length, 5);
  d.timers.advance(1000);
  await until(() => model.items.size === 5);
  d.engine.stop();
});

test("the_import_mark_is_never_in_a_request_to_the_server_and_the_bytes_are_those_of_the_entry", async () => {
  const d = await started();
  const window = d.model.openImportWindow(10);
  const items = await sealed(d.client, 2);
  await d.engine.importItems(items, { windowId: window });
  await until(() => d.api.batches.length === 1);
  const text = d.api.batches[0].text;
  const body = JSON.parse(text);
  assert.deepEqual(Object.keys(body).sort(), ["import_window", "ops"]);
  for (const [at, op] of body.ops.entries()) {
    assert.deepEqual(Object.keys(op).sort(), ["base_rev", "blob", "id", "idem", "restore_epoch", "tag"].sort(), "the fields of a single write, with the epoch the device has accepted");
    assert.equal(op.id, items[at].id);
    assert.equal(op.base_rev, 0);
    assert.equal(op.blob, b64u.encode(items[at].envelope));
    assert.equal(op.tag, b64u.encode(items[at].tag));
  }
  assert.ok(!text.includes('"import":'), "the mark is the engine's own");
  d.engine.stop();
});

test("the_page_can_ask_how_an_import_stands_also_after_a_reload", async () => {
  const model = new Model();
  const client = createFakeClient();
  const first = await started({ model, client });
  assert.deepEqual(first.engine.importStatus(), { queued: 0, refused: 0, sent: 0, total: 0, failed: 0, windowClosed: false });
  const window = model.openImportWindow(100);
  await first.engine.importItems(await sealed(client, 150), { windowId: window });
  await until(() => first.closed.length === 1, "the window closes after 100");
  assert.deepEqual(first.engine.importStatus(), { queued: 50, refused: 0, sent: 100, total: 150, failed: 0, windowClosed: true });
  first.engine.stop();

  // After a reload the engine finds the rest in the outbox and says that the window is closed once the server has said so again.
  const second = await started({ model, client, db: first.store.database, locks: first.locks });
  await until(() => second.closed.length === 1, "the old window is refused again");
  assert.deepEqual(second.engine.importStatus(), { queued: 50, refused: 0, sent: 0, total: 50, failed: 0, windowClosed: true });
  await second.engine.resumeImport({ windowId: model.openImportWindow(50) });
  await until(() => model.items.size === 150, "the rest");
  await until(() => second.engine.importStatus().queued === 0);
  assert.deepEqual(second.engine.importStatus(), { queued: 0, refused: 0, sent: 50, total: 50, failed: 0, windowClosed: false });
  second.engine.stop();
});
