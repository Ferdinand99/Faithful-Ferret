// The sync engine and its memory: the floors that outlive the cache, what a refused row
// does (nothing), what stops the engine, and the small settings of this step.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u, hex16 } from "../../src/b64.mjs";
import { cache, rowOfChange } from "../../src/store/cache.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { createSyncEngine, MANIFEST_ID, SyncError } from "../../src/sync/engine.mjs";
import { memoryStore, unavailableMemory } from "../../src/sync/memory.mjs";
import { ACCOUNT, freshStore, scope, SERVER } from "./idbHelpers.mjs";
import {
  counterRand, createFakeApi, createFakeClient, createFakeStore, fakeMemory, FakeLocks, FakeTimers, memoryOf, Model, settle, until,
} from "./syncHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);
const ID_X = "aa".repeat(16);
const ID_Y = "bb".repeat(16);
const DRAFT = { item_type: "login", name: "Bank" };

/** One browser tab: an engine over a fake store (shared with other tabs through `db`) and the locks of the browser. */
async function tab({ model, client = createFakeClient(), db = null, locks = new FakeLocks(), seed = 1, pollMs, deviceName, win = null, memory = null } = {}) {
  const store = await createFakeStore({ db });
  const api = createFakeApi(model);
  const timers = new FakeTimers();
  const events = { changed: [], error: [], state: [] };
  const mem = memory ?? fakeMemory({ store, client, locks });
  const engine = createSyncEngine({
    api, client: { vault: client.vault }, store, scope: scope(), memory: mem, timers, rand: counterRand(seed), win, deviceName,
    ...(pollMs === undefined ? {} : { pollMs }),
    now: () => 1_700_000_000_000 + timers.time,
  });
  for (const name of Object.keys(events)) engine.on(name, (payload) => events[name].push(payload));
  return { model, client, store, api, timers, engine, events, locks, memory: mem };
}

const setRow = (model, client, id, rev, name, extra = {}) => model.set(id, { rev, ...client.wireRow(id, rev, { item_type: "login", name }), ...extra });
const stateOf = (t) => loadSyncState(t.store.database.store, SERVER, ACCOUNT);
const floorsOf = async (t) => memoryOf((await stateOf(t)).memory);
const rowsOf = (t) => cache.getRows(t.store.database.store, scope());
const warnings = (t, code) => t.events.state.filter((s) => s.kind === "warning" && (code === undefined || s.code === code));
const halts = (t) => t.events.state.filter((s) => s.kind === "halted");

/** Raises the floor of an item in the stored memory, as if this device had seen that revision once. */
async function raiseFloor(t, id, rev) {
  const row = t.client.wireRow(id, rev, { item_type: "login", name: "seen once" });
  await t.memory.withLock(async (state) => {
    const { newSyncMemory } = await t.client.vault.accept_rows(
      [{ item_id: hex16.decode(id), rev, state: "live", envelope: b64u.decode(row.blob), tag: b64u.decode(row.tag) }], memoryOf(state.memory).maxSeq, state.memory,
    );
    return { ...state, memory: newSyncMemory };
  });
}

// ------------------------------------------------------------ the order of saving

test("memory_is_saved_before_the_rows_are_cached", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const t = await tab({ model, client });
  await t.engine.start();
  const log = t.store.spy.log;
  const firstCache = log.indexOf("cache.putRows");
  assert.ok(firstCache > 0, "the rows were cached");
  assert.equal(log[firstCache - 1], "state.save", "the memory was stored right before");
  const savedBefore = t.store.spy.states.at(-1);
  assert.equal(memoryOf(savedBefore.memory).revs[ID_A], 1, "and it already knew the row");
  assert.equal(t.engine.list().length, 1);
  t.engine.stop();
});

test("a_failed_memory_save_caches_nothing_and_the_pass_fails", async () => {
  const model = new Model();
  const client = createFakeClient();
  const t = await tab({ model, client });
  await t.engine.start();
  setRow(model, client, ID_A, 1, "A");
  t.store.failSaveState = 1;
  await t.engine.syncNow();
  assert.equal(t.store.spy.putRows.length, 0, "no row reached the cache");
  assert.deepEqual(t.engine.list(), [], "no row reached the screen");
  assert.deepEqual(await rowsOf(t), []);
  assert.ok(t.events.state.some((s) => s.kind === "failed"), "the pass failed");
  assert.deepEqual((await floorsOf(t)).revs, {}, "the stored memory is as it was");
  await t.engine.syncNow();
  assert.equal(t.engine.list().length, 1, "the next pass does it all");
  assert.equal((await floorsOf(t)).revs[ID_A], 1);
  t.engine.stop();
});

// ------------------------------------------------------------ tabs and locks

test("two_engines_on_one_store_never_lower_a_floor", async () => {
  const client = createFakeClient();
  const db = await freshStore();
  const locks = new FakeLocks();
  const modelA = new Model();
  const modelB = new Model();
  setRow(modelA, client, ID_X, 3, "X", { seq: 5 });
  setRow(modelB, client, ID_Y, 2, "Y", { seq: 6 });
  const a = await tab({ model: modelA, client, db, locks, seed: 1 });
  const b = await tab({ model: modelB, client, db, locks, seed: 2 });
  await Promise.all([a.engine.start(), b.engine.start()]);
  const floors = await floorsOf(a);
  assert.deepEqual(floors.revs, { [ID_X]: 3, [ID_Y]: 2 }, "neither tab's save wiped the other's");
  assert.equal(floors.maxSeq, 6);

  // The server of the second tab now shows X at an older revision: it is refused against what the first tab saved.
  setRow(modelB, client, ID_X, 2, "X old", { seq: 7 });
  await b.engine.syncNow();
  assert.deepEqual(b.engine.list().map((i) => i.id), [ID_Y], "refused, though this tab never held X");
  assert.equal(warnings(b, "rev_below_remembered").length, 1);
  assert.equal((await floorsOf(a)).revs[ID_X], 3, "the floor stays");

  // The same for the other fields of the state: a save from one tab never wipes a field another tab has just written.
  await Promise.all([
    a.memory.withLock(async (state) => {
      await settle(10); // the second tab asks for the lock in the meantime
      return { ...state, uploadedSeq: 9, uploadedAt: 90 };
    }),
    b.memory.withLock(async (state) => ({ ...state, verifiedAt: 5 })),
  ]);
  const state = await stateOf(a);
  assert.deepEqual([state.uploadedSeq, state.uploadedAt, state.verifiedAt], [9, 90, 5]);
  assert.deepEqual(memoryOf(state.memory).revs, { [ID_X]: 3, [ID_Y]: 2 });
  a.engine.stop();
  b.engine.stop();
});

test("every_read_modify_write_runs_inside_the_lock", async () => {
  const model = new Model();
  const client = createFakeClient();
  const t = await tab({ model, client });
  const log = [];
  const { loadSyncState: load, saveSyncState: save } = t.store;
  t.store.loadSyncState = async (...args) => {
    log.push(["load", t.locks.held.has(t.memory.name)]);
    return load(...args);
  };
  t.store.saveSyncState = async (...args) => {
    log.push(["save", t.locks.held.has(t.memory.name)]);
    return save(...args);
  };
  setRow(model, client, ID_A, 1, "A");
  await t.engine.start();
  await t.engine.create(DRAFT);
  await until(() => [...model.items.values()].length === 2, "the new item is on the server");
  await t.engine.syncNow();
  const saves = log.filter(([op]) => op === "save");
  const locked = log.filter(([, held]) => held);
  assert.ok(saves.length >= 2, "the memory was saved");
  assert.ok(saves.every(([, held]) => held), "every save ran inside the lock");
  assert.ok(locked.filter(([op]) => op === "load").length >= saves.length, "and each was preceded by a read inside it");
  assert.equal(t.locks.held.size, 0, "the lock is released");
  t.engine.stop();
});

test("no_web_locks_halts_with_unsupported", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A");
  const probe = await createFakeStore();
  let error;
  try {
    memoryStore({ store: probe, serverUrl: SERVER, accountId: ACCOUNT, locks: null });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof SyncError && error.code === "unsupported", "no Web Locks, no memory");

  const t = await tab({ model, client, memory: unavailableMemory(error) });
  await t.engine.start();
  assert.deepEqual(halts(t), [{ kind: "halted", code: "unsupported" }]);
  assert.deepEqual(t.engine.health(), { halted: "unsupported", warnings: [] });
  assert.equal(t.api.gets.length, 0, "nothing was pulled");
  assert.equal(t.timers.pending, 0, "no poll is waiting");
  // Nothing is sent either, but what the user writes is kept.
  await t.engine.create(DRAFT);
  await settle();
  assert.equal(t.api.puts.length, 0, "nothing was sent");
  assert.equal((await outbox.all(t.store.database.store, scope())).length, 1, "the write is kept in the outbox");
  assert.equal(t.engine.list().length, 1);
  t.engine.stop();
});

test("an_engine_without_a_memory_is_refused", async () => {
  const client = createFakeClient();
  const store = await createFakeStore();
  assert.throws(() => createSyncEngine({ api: createFakeApi(new Model()), client: { vault: client.vault }, store, scope: scope() }), TypeError);
});

// ------------------------------------------------------------ refused rows

test("a_row_below_the_remembered_rev_is_refused_and_the_others_on_the_page_are_accepted", async () => {
  const client = createFakeClient();
  const db = await freshStore();
  const first = new Model();
  setRow(first, client, ID_X, 5, "X five");
  const t0 = await tab({ model: first, client, db });
  await t0.engine.start();
  t0.engine.stop();
  await cache.clear(db.store, scope()); // the cache is gone; the memory is not

  const model = new Model();
  setRow(model, client, ID_X, 3, "X three");
  setRow(model, client, ID_Y, 1, "Y one");
  setRow(model, client, ID_C, 1, "C one");
  const t = await tab({ model, client, db, seed: 2 });
  await t.engine.start();
  assert.deepEqual(t.engine.list().map((i) => i.id).sort(), [ID_C, ID_Y], "the others are accepted");
  assert.deepEqual((await rowsOf(t)).map((r) => r.itemId).sort(), [ID_C, ID_Y], "and cached");
  assert.equal(warnings(t, "rev_below_remembered").length, 1);
  assert.equal(warnings(t, "rev_below_remembered")[0].id, ID_X);
  const floors = await floorsOf(t);
  assert.deepEqual(floors.revs, { [ID_X]: 5, [ID_Y]: 1, [ID_C]: 1 }, "the floor of X stays, the others are remembered");
  assert.equal(t.engine.health().halted, null, "a refused row is not a stop");
  t.engine.stop();
});

test("a_refused_row_changes_no_row_index_overlay_or_mark", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 2, "Server two");
  const t = await tab({ model, client });
  await t.engine.start();
  await raiseFloor(t, ID_A, 5);
  // A local edit that the server cannot take now, so the screen shows it as an overlay.
  t.api.faults.push({ kind: "network", only: ID_A });
  await t.engine.update(ID_A, { name: "Local edit" }, 2);
  setRow(model, client, ID_A, 3, "Server three"); // above the local row, below the remembered floor
  const flagsKey = `sync.flags.${ACCOUNT}.${scope().vaultId}.${scope().vkEpoch}`;
  const snapshot = async () => ({
    list: t.engine.list(),
    rows: await rowsOf(t),
    marks: await t.store.getSetting(t.store.database.store, flagsKey),
  });
  const before = await snapshot();
  const heard = t.events.changed.length;
  await t.engine.syncNow();
  assert.deepEqual(await snapshot(), before, "rows, index, overlay and marks are as they were");
  assert.equal(before.list[0].name, "Local edit");
  assert.equal(before.list[0].pending, true);
  assert.equal(t.events.changed.length, heard, "nothing changed on screen");
  assert.equal(warnings(t, "rev_below_remembered").length, 1);
  assert.equal((await floorsOf(t)).revs[ID_A], 5);
  t.engine.stop();
});

test("manifest_row_with_a_bad_tag_is_not_cached_and_sets_no_floor", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.set(MANIFEST_ID, { rev: 1, blob: b64u.encode(new Uint8Array(64).fill(3)), tag: b64u.encode(new Uint8Array(32).fill(4)) });
  setRow(model, client, ID_A, 1, "A");
  const t = await tab({ model, client });
  await t.engine.start();
  assert.deepEqual((await rowsOf(t)).map((r) => r.itemId), [ID_A], "the manifest row is not cached");
  assert.equal(MANIFEST_ID in (await floorsOf(t)).revs, false, "and sets no floor");
  assert.equal(t.engine.list().length, 1, "the item next to it is accepted");
  assert.ok(warnings(t, "row_damaged").some((w) => w.id === MANIFEST_ID));
  // A good manifest row afterwards is accepted like any other row.
  setRow(model, client, MANIFEST_ID, 2, "unlock methods");
  await t.engine.syncNow();
  assert.ok((await rowsOf(t)).some((r) => r.itemId === MANIFEST_ID && r.rev === 2));
  assert.equal((await floorsOf(t)).revs[MANIFEST_ID], 2);
  t.engine.stop();
});

// ------------------------------------------------------------ rollback and restore

test("an_empty_page_with_a_lower_top_seq_halts_with_rollback_suspected", async () => {
  const model = new Model();
  const client = createFakeClient();
  setRow(model, client, ID_A, 1, "A", { seq: 5 });
  const t = await tab({ model, client });
  await t.engine.start();
  model.items.clear(); // the server forgot everything and counts from an older point: an empty page with a low top
  model.seq = 2;
  await t.engine.syncNow();
  assert.deepEqual(halts(t), [{ kind: "halted", code: "rollback_suspected" }]);
  assert.equal(t.engine.health().halted, "rollback_suspected");
  assert.equal(t.engine.list().length, 1, "the local data stays");
  assert.equal((await floorsOf(t)).maxSeq, 5, "the floor is not lowered");
  t.engine.stop();
});

test("top_seq_below_the_remembered_halts_pull_and_push_and_keeps_local_data", async () => {
  const model = new Model();
  const client = createFakeClient();
  const win = new EventTarget();
  setRow(model, client, ID_A, 1, "A", { seq: 5 });
  const t = await tab({ model, client, win });
  await t.engine.start();
  setRow(model, client, ID_B, 1, "B", { seq: 6 });
  model.latestSeqLie = 3; // a page with a new row and a top below what this device has seen
  await t.engine.syncNow();
  assert.equal(t.engine.health().halted, "rollback_suspected");
  assert.deepEqual(t.engine.list().map((i) => i.id), [ID_A], "the new row was not taken");
  assert.deepEqual((await rowsOf(t)).map((r) => r.itemId), [ID_A]);

  // Nothing is pulled: not by a call, a focus, the clock or a write.
  const gets = t.api.gets.length;
  await t.engine.syncNow();
  win.dispatchEvent(new Event("focus"));
  win.dispatchEvent(new Event("online"));
  t.timers.advance(600_000);
  await settle();
  assert.equal(t.api.gets.length, gets);
  // Nothing is sent, but the local write is kept and shown.
  const id = await t.engine.create(DRAFT);
  await settle();
  assert.equal(t.api.puts.length, 0);
  assert.equal((await outbox.all(t.store.database.store, scope())).length, 1);
  assert.ok(t.engine.list().some((i) => i.id === id && i.pending));
  assert.equal(halts(t).length, 1, "said once");
  t.engine.stop();
});

test("higher_restore_epoch_with_something_lower_halts_and_without_only_notifies", async () => {
  // Something lower than the device has: the row is below its local row.
  {
    const model = new Model();
    const client = createFakeClient();
    setRow(model, client, ID_A, 3, "A three");
    const t = await tab({ model, client });
    await t.engine.start();
    setRow(model, client, ID_A, 2, "A two");
    model.restoreEpoch = 1;
    await t.engine.syncNow();
    assert.equal(t.engine.health().halted, "server_restored");
    assert.deepEqual(halts(t), [{ kind: "halted", code: "server_restored" }]);
    assert.equal((await stateOf(t)).restoreEpoch, 0, "the higher epoch is not accepted");
    assert.equal(t.engine.list()[0].rev, 3, "nothing was lowered");
    t.engine.stop();
  }
  // Something lower than the memory holds, on a device whose cache is gone.
  {
    const client = createFakeClient();
    const db = await freshStore();
    const first = new Model();
    setRow(first, client, ID_A, 4, "A four");
    const t0 = await tab({ model: first, client, db });
    await t0.engine.start();
    t0.engine.stop();
    await cache.clear(db.store, scope());
    const model = new Model();
    setRow(model, client, ID_A, 2, "A two");
    model.restoreEpoch = 1;
    const t = await tab({ model, client, db, seed: 2 });
    await t.engine.start();
    assert.equal(t.engine.health().halted, "server_restored");
    assert.equal(t.engine.list().length, 0, "nothing of that page is used");
    assert.equal((await stateOf(t)).restoreEpoch, 0);
    t.engine.stop();
  }
  // Only a lower top seq (a restore also makes the counter smaller).
  {
    const model = new Model();
    const client = createFakeClient();
    setRow(model, client, ID_A, 1, "A", { seq: 5 });
    const t = await tab({ model, client });
    await t.engine.start();
    model.items.clear();
    model.seq = 2;
    model.restoreEpoch = 1;
    await t.engine.syncNow();
    assert.equal(t.engine.health().halted, "server_restored", "a restore, not a plain rollback");
    t.engine.stop();
  }
  // Nothing lower: the epoch is stored, with a message, and the engine goes on.
  {
    const model = new Model();
    const client = createFakeClient();
    setRow(model, client, ID_A, 1, "A");
    const t = await tab({ model, client });
    await t.engine.start();
    model.restoreEpoch = 2;
    setRow(model, client, ID_B, 1, "B");
    await t.engine.syncNow();
    assert.equal(t.engine.health().halted, null);
    assert.ok(warnings(t, "restore_epoch_raised").some((w) => w.from === 0 && w.to === 2));
    assert.equal((await stateOf(t)).restoreEpoch, 2, "stored");
    assert.equal(t.engine.list().length, 2, "the new row was taken");
    await t.engine.syncNow();
    assert.equal(warnings(t, "restore_epoch_raised").length, 1, "said once");
    t.engine.stop();
  }
});

test("lower_restore_epoch_halts", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.restoreEpoch = 2;
  setRow(model, client, ID_A, 1, "A");
  const t = await tab({ model, client });
  await t.engine.start();
  assert.equal((await stateOf(t)).restoreEpoch, 2);
  model.restoreEpoch = 1;
  setRow(model, client, ID_B, 1, "B");
  await t.engine.syncNow();
  assert.deepEqual(halts(t), [{ kind: "halted", code: "restore_epoch_lowered" }]);
  assert.equal((await stateOf(t)).restoreEpoch, 2, "never lowered");
  assert.deepEqual(t.engine.list().map((i) => i.id), [ID_A], "the page was not used");
  t.engine.stop();
});

test("first_restore_epoch_is_stored", async () => {
  const model = new Model();
  const client = createFakeClient();
  model.restoreEpoch = 3;
  setRow(model, client, ID_A, 1, "A");
  const t = await tab({ model, client });
  await t.engine.start();
  assert.equal((await stateOf(t)).restoreEpoch, 3);
  assert.equal(t.engine.health().halted, null);
  assert.deepEqual(warnings(t), [], "a first epoch is not news");
  t.engine.stop();
});

// ------------------------------------------------------------ start and size

test("first_m2_start_seeds_the_memory_from_the_cached_rows", async () => {
  const client = createFakeClient();
  const model = new Model();
  setRow(model, client, ID_B, 2, "gone", { deleted: true, blob: null, tag: null, tomb: client.wireTomb(ID_B, 2), seq: 6 });
  setRow(model, client, ID_A, 3, "A three", { seq: 7 });
  const db = await freshStore();
  // The device has cached rows from before the memory existed: no stored state.
  await cache.putRows(db.store, scope(), [
    rowOfChange({ id: ID_B, rev: 2, seq: 6, deleted: true, tomb: client.wireTomb(ID_B, 2) }),
    rowOfChange({ id: ID_A, rev: 3, seq: 7, deleted: false, ...client.wireRow(ID_A, 3, { item_type: "login", name: "A three" }) }),
  ]);
  const t = await tab({ model, client, db });
  assert.equal(await stateOf(t), null);
  t.api.failFeed = new ApiError(0, "network"); // the server is not reached: the seed is all there is
  t.api.failFeedTimes = 1;
  await t.engine.start();
  const floors = await floorsOf(t);
  assert.deepEqual(floors.revs, { [ID_A]: 3, [ID_B]: 2 }, "a floor for every cached row, tombstones too");
  assert.equal(floors.maxSeq, 7);
  t.engine.stop();

  // And the floors work: the cache is gone, and the server shows an older row.
  await cache.clear(db.store, scope());
  setRow(model, client, ID_A, 2, "A two", { seq: 8 });
  const again = await tab({ model, client, db, seed: 2 });
  await again.engine.start();
  assert.deepEqual(again.engine.list(), []);
  assert.equal(warnings(again, "rev_below_remembered").length, 1);
  again.engine.stop();
});

test("a_stored_state_is_not_seeded_again", async () => {
  const client = createFakeClient();
  const model = new Model();
  const db = await freshStore();
  setRow(model, client, ID_A, 1, "A");
  const t0 = await tab({ model, client, db });
  await t0.engine.start();
  t0.engine.stop();
  await raiseFloor(t0, ID_B, 9); // a floor with no row in the cache
  await cache.putRows(db.store, scope(), [rowOfChange({ id: ID_C, rev: 4, seq: 1, deleted: false, ...client.wireRow(ID_C, 4, { item_type: "login", name: "C" }) })]);
  const t = await tab({ model, client, db, seed: 2 });
  await t.engine.start();
  assert.equal(ID_C in (await floorsOf(t)).revs, false, "the state that is stored is the memory, not the cache");
  assert.equal((await floorsOf(t)).revs[ID_B], 9);
  t.engine.stop();
});

test("full_memory_halts_with_sync_memory_full", async () => {
  const client = createFakeClient({ memoryLimit: 2 });
  const model = new Model();
  setRow(model, client, ID_A, 1, "A");
  setRow(model, client, ID_B, 1, "B");
  setRow(model, client, ID_C, 1, "C");
  const t = await tab({ model, client });
  await t.engine.start();
  assert.deepEqual(halts(t), [{ kind: "halted", code: "sync_memory_full" }]);
  assert.equal(t.engine.health().halted, "sync_memory_full");
  assert.deepEqual(t.engine.list(), [], "nothing of the page was used");
  assert.deepEqual(await rowsOf(t), []);
  assert.deepEqual((await floorsOf(t)).revs, {}, "nothing was stored");
  assert.equal(t.timers.pending, 0);
  t.engine.stop();
});

// ------------------------------------------------------------ device name, poll, idle

test("create_and_update_stamp_the_device_name", async () => {
  const model = new Model();
  const client = createFakeClient();
  const t = await tab({ model, client, deviceName: "Firefox on Windows" });
  await t.engine.start();
  const id = await t.engine.create(DRAFT);
  let open = await t.engine.open(id);
  assert.equal(open.view.device, "Firefox on Windows");
  await open.close();
  await until(() => model.items.get(id)?.rev === 1 && t.engine.list()[0].pending === false);
  await t.engine.update(id, { name: "Renamed", device: "someone else" }, 1);
  open = await t.engine.open(id);
  assert.equal(open.view.name, "Renamed");
  assert.equal(open.view.device, "Firefox on Windows", "the engine's name, whatever the draft says");
  await open.close();
  t.engine.stop();

  // The name may come from a function, asked once when the engine starts.
  let asked = 0;
  const other = await tab({ model: new Model(), client, seed: 5, deviceName: async () => { asked += 1; return "Safari on iOS"; } });
  await other.engine.start();
  const second = await other.engine.create(DRAFT);
  await other.engine.update(second, { name: "Again" }, 1);
  assert.equal(asked, 1);
  const view = await other.engine.open(second);
  assert.equal(view.view.device, "Safari on iOS");
  await view.close();
  other.engine.stop();

  // Without a name, nothing is written.
  const bare = await tab({ model: new Model(), client, seed: 6 });
  await bare.engine.start();
  const third = await bare.engine.create(DRAFT);
  const bareView = await bare.engine.open(third);
  assert.equal(bareView.view.device, null);
  await bareView.close();
  bare.engine.stop();
});

test("poll_interval_is_five_minutes_and_focus_online_and_own_writes_still_sync", async () => {
  const model = new Model();
  const client = createFakeClient();
  const win = new EventTarget();
  setRow(model, client, ID_A, 1, "A");
  const t = await tab({ model, client, win });
  await t.engine.start();
  assert.deepEqual(t.timers.delays, [300_000], "the poll waits five minutes");

  let gets = t.api.gets.length;
  win.dispatchEvent(new Event("focus"));
  await until(() => t.api.gets.length > gets, "a pass after focus");
  gets = t.api.gets.length;
  win.dispatchEvent(new Event("online"));
  await until(() => t.api.gets.length > gets, "a pass after the network came back");
  await settle();
  gets = t.api.gets.length;
  const id = await t.engine.create(DRAFT);
  await until(() => model.items.get(id)?.rev === 1 && t.api.gets.length > gets, "the write went out and its row was read back");

  await settle();
  gets = t.api.gets.length;
  t.timers.advance(299_999);
  await settle();
  assert.equal(t.api.gets.length, gets, "not before the five minutes");
  t.timers.advance(1);
  await until(() => t.api.gets.length > gets, "after them");
  t.engine.stop();
});

test("idle_is_emitted_after_every_pass", async () => {
  const model = new Model();
  const client = createFakeClient();
  const t = await tab({ model, client });
  await t.engine.start();
  const idles = () => t.events.state.filter((s) => s.kind === "idle").length;
  assert.equal(idles(), 1, "after the first pass");
  await t.engine.syncNow();
  assert.equal(idles(), 2, "also when nothing came");
  setRow(model, client, ID_A, 1, "A");
  await t.engine.syncNow();
  assert.equal(idles(), 3);
  t.engine.stop();
});
