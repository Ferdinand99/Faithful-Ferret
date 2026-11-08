// The adapter between the engine and the core's sync memory: the rows it hands over, what it does
// with a refusal, the lock around every read-modify-write, and the service that wires it up.
import assert from "node:assert/strict";
import { test } from "node:test";
import { hex16 } from "../../src/b64.mjs";
import { rowOfChange } from "../../src/store/cache.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import syncService from "../../src/services/sync.service.mjs";
import { cleanDeviceName, defaultDeviceName, deviceNameFor } from "../../src/sync/deviceName.mjs";
import { SyncError } from "../../src/sync/engine.mjs";
import { acceptPage, coreRow, memoryStore, seedMemory } from "../../src/sync/memory.mjs";
import { ACCOUNT, SERVER, VAULT } from "./idbHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, FakeLocks, fakeMemory, memoryOf, Model } from "./syncHelpers.mjs";

const ID_A = "11".repeat(16);
const ID_B = "22".repeat(16);
const ID_C = "33".repeat(16);

/** A cached row of a live item, valid for the fake core. */
const live = (client, id, rev, seq = rev) => rowOfChange({ id, rev, seq, deleted: false, ...client.wireRow(id, rev, { item_type: "login", name: id.slice(0, 4) }) });

async function rig({ memoryLimit } = {}) {
  const client = createFakeClient({ ...(memoryLimit === undefined ? {} : { memoryLimit }) });
  const store = await createFakeStore();
  const locks = new FakeLocks();
  const memory = fakeMemory({ store, client, locks });
  const stored = async () => loadSyncState(store.database.store, SERVER, ACCOUNT);
  return { client, store, locks, memory, stored };
}

test("core_row_has_the_shape_the_core_takes", async () => {
  const { client } = await rig();
  const row = live(client, ID_A, 3);
  assert.deepEqual(coreRow(row), { item_id: hex16.decode(ID_A), rev: 3, state: "live", envelope: row.envelope, tag: row.tag });
  const gone = rowOfChange({ id: ID_B, rev: 4, seq: 9, deleted: true, tomb: client.wireTomb(ID_B, 4) });
  assert.deepEqual(coreRow(gone), { item_id: hex16.decode(ID_B), rev: 4, state: "deleted", tomb: gone.tomb });
  assert.ok(coreRow(row).item_id instanceof Uint8Array && coreRow(row).item_id.length === 16);
});

test("accept_page_stores_the_new_memory_before_it_answers_and_runs_inside_the_lock", async () => {
  const { client, store, locks, memory, stored } = await rig();
  const calls = [];
  const watched = {
    ...memory,
    withLock: (fn) => memory.withLock(async (state, info) => {
      calls.push(["in", locks.held.has(memory.name)]);
      return fn(state, info);
    }),
  };
  const result = await acceptPage({ client, memory: watched, rows: [live(client, ID_A, 2)], topSeq: 7 });
  assert.equal(result.accepted.length, 1);
  assert.deepEqual(result.refused, []);
  assert.deepEqual(calls, [["in", true]]);
  assert.equal(locks.held.size, 0, "the lock is released when the answer comes");
  const floors = memoryOf((await stored()).memory);
  assert.deepEqual([floors.revs[ID_A], floors.maxSeq], [2, 7], "the bytes were stored by then");
  assert.equal(store.spy.states.length, 1);
});

test("accept_page_runs_for_an_empty_page_and_stores_only_what_changed", async () => {
  const { client, store, memory, stored } = await rig();
  await acceptPage({ client, memory, rows: [], topSeq: 4 });
  assert.equal(memoryOf((await stored()).memory).maxSeq, 4, "the top seq of an empty page is remembered");
  await acceptPage({ client, memory, rows: [], topSeq: 4 });
  assert.equal(store.spy.states.length, 1, "the same bytes are not stored again");
  await assert.rejects(
    acceptPage({ client, memory, rows: [], topSeq: 3 }),
    (error) => error instanceof SyncError && error.code === "rollback_suspected" && error.message.length > 10,
  );
  assert.equal(memoryOf((await stored()).memory).maxSeq, 4, "nothing was lowered");
});

test("accept_page_isolates_a_row_below_its_floor_and_a_row_that_does_not_verify", async () => {
  const { client, memory, stored } = await rig();
  await acceptPage({ client, memory, rows: [live(client, ID_A, 5)], topSeq: 5 });
  const forged = { ...live(client, ID_C, 1), tag: new Uint8Array(32).fill(9) };
  const rows = [live(client, ID_A, 4, 6), live(client, ID_B, 1, 7), forged, live(client, ID_C, 2, 8)];
  const result = await acceptPage({ client, memory, rows, topSeq: 8 });
  assert.deepEqual(result.accepted.map((r) => r.itemId), [ID_B, ID_C]);
  assert.deepEqual(result.refused.map(({ row, code }) => [row.itemId, row.rev, code]), [
    [ID_A, 4, "checkpoint_rev_below_remembered"],
    [ID_C, 1, "decrypt"],
  ]);
  const floors = memoryOf((await stored()).memory);
  assert.deepEqual(floors.revs, { [ID_A]: 5, [ID_B]: 1, [ID_C]: 2 });
  assert.equal(floors.maxSeq, 8);

  // All refused: the top is still checked and remembered.
  const none = await acceptPage({ client, memory, rows: [live(client, ID_A, 1, 9)], topSeq: 9 });
  assert.deepEqual([none.accepted.length, none.refused.length], [0, 1]);
  assert.equal(memoryOf((await stored()).memory).maxSeq, 9);
});

test("accept_page_stores_nothing_when_the_memory_is_full", async () => {
  const { client, memory, stored } = await rig({ memoryLimit: 1 });
  await acceptPage({ client, memory, rows: [live(client, ID_A, 1)], topSeq: 1 });
  const before = await stored();
  await assert.rejects(
    acceptPage({ client, memory, rows: [live(client, ID_B, 1, 2), live(client, ID_C, 1, 3)], topSeq: 3 }),
    (error) => error instanceof SyncError && error.code === "sync_memory_full" && error.message.length > 10,
  );
  assert.deepEqual((await stored()).memory, before.memory);
});

test("accept_page_does_not_answer_when_the_store_fails", async () => {
  const { client, store, memory, stored } = await rig();
  store.failSaveState = 1;
  await assert.rejects(acceptPage({ client, memory, rows: [live(client, ID_A, 1)], topSeq: 1 }), /disk is full/);
  assert.equal(await stored(), null, "nothing is stored");
  const result = await acceptPage({ client, memory, rows: [live(client, ID_A, 1)], topSeq: 1 });
  assert.equal(result.accepted.length, 1, "and the next try works");
});

test("seed_memory_makes_the_state_once_from_the_rows_it_is_given", async () => {
  const { client, memory, stored } = await rig();
  const first = await seedMemory({ client, memory, rows: [live(client, ID_A, 3, 5)], topSeq: 5 });
  assert.equal(memoryOf(first.memory).revs[ID_A], 3);
  assert.equal(memoryOf((await stored()).memory).maxSeq, 5);
  const second = await seedMemory({ client, memory, rows: [live(client, ID_B, 9, 9)], topSeq: 9 });
  assert.deepEqual(memoryOf(second.memory).revs, { [ID_A]: 3 }, "a stored state is not touched");
});

test("memory_store_reads_again_inside_the_lock_and_stores_nothing_for_null", async () => {
  const { client, store, locks, memory, stored } = await rig();
  assert.equal(memory.name, `ferret-sync-memory:${SERVER}:${ACCOUNT}`);
  const seen = [];
  await memory.withLock(async (state, info) => {
    seen.push(info.existed);
    return null;
  });
  assert.deepEqual(seen, [false]);
  assert.equal(await stored(), null, "null stores nothing");
  assert.deepEqual((await memory.load()).restoreEpoch, null, "a state that was never stored reads as a new one");
  await memory.withLock(async (state) => ({ ...state, uploadedSeq: 4 }));
  await memory.withLock(async (state, info) => {
    seen.push(info.existed, state.uploadedSeq);
    return null;
  });
  assert.deepEqual(seen, [false, true, 4]);
  assert.equal(store.spy.states.length, 1);

  // Two callers at once are served one after the other, and the second sees the first one's state.
  const order = [];
  await Promise.all([
    memory.withLock(async (state) => {
      order.push("a:start");
      await new Promise((resolve) => setImmediate(resolve));
      order.push("a:end");
      return { ...state, uploadedSeq: 8 };
    }),
    memory.withLock(async (state) => {
      order.push(`b:sees ${state.uploadedSeq}`);
      return null;
    }),
  ]);
  assert.deepEqual(order, ["a:start", "a:end", "b:sees 8"]);
  assert.equal(locks.held.size, 0);
  assert.equal(client.vault.calls.length, 0);
});

test("memory_store_refuses_a_missing_account_or_server_and_needs_new_memory_for_a_new_state", async () => {
  const store = await createFakeStore();
  const locks = new FakeLocks();
  assert.throws(() => memoryStore({ store, serverUrl: "not a url", accountId: ACCOUNT, locks }), TypeError);
  assert.throws(() => memoryStore({ store, serverUrl: SERVER, accountId: "nope", locks }), TypeError);
  for (const none of [null, {}, { request: 1 }]) {
    assert.throws(() => memoryStore({ store, serverUrl: SERVER, accountId: ACCOUNT, locks: none }), (e) => e instanceof SyncError && e.code === "unsupported");
  }
  const bare = memoryStore({ store, serverUrl: SERVER, accountId: ACCOUNT, locks });
  await assert.rejects(bare.load(), TypeError);
});

// ------------------------------------------------------------ the service

const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };

async function service(overrides = {}) {
  const store = overrides.store ?? (await createFakeStore());
  const client = createFakeClient();
  const sync = syncService.create({
    api: createFakeApi(new Model()), store, client: { vault: client.vault }, serverUrl: SERVER, locks: new FakeLocks(), nav: { userAgent: "" }, ...overrides,
  });
  return { sync, store, client };
}

test("service_without_web_locks_starts_an_engine_that_halts_with_unsupported", async () => {
  const { sync } = await service({ locks: null });
  const heard = [];
  sync.onEngine((engine) => heard.push(engine));
  const engine = await sync.start(scope);
  assert.deepEqual(engine.health(), { halted: "unsupported", warnings: [] });
  assert.equal(heard.length, 1, "the engine is announced; the screen reads why it stands still");
  sync.stop();
});

test("service_stamps_the_saved_device_name_or_the_default", async () => {
  const store = await createFakeStore();
  const { sync } = await service({ store, nav: { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0" } });
  let engine = await sync.start(scope);
  let id = await engine.create({ item_type: "login", name: "A" });
  let open = await engine.open(id);
  assert.equal(open.view.device, "Firefox on Windows", "the default");
  await open.close();
  sync.stop();

  await store.setSetting(await store.open(), "device.name", "Work laptop");
  engine = await sync.start(scope);
  id = await engine.create({ item_type: "login", name: "B" });
  open = await engine.open(id);
  assert.equal(open.view.device, "Work laptop", "the setting");
  await open.close();
  sync.stop();
});

test("device_name_comes_from_the_setting_or_from_what_the_browser_says", async () => {
  const agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0": "Firefox on Windows",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15": "Safari on macOS",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36": "Chrome on Linux",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0": "Edge on Windows",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1": "Safari on iOS",
    "": "Web vault",
  };
  for (const [userAgent, name] of Object.entries(agents)) assert.equal(defaultDeviceName({ userAgent }), name, userAgent);
  assert.equal(defaultDeviceName(undefined) !== "", true);

  assert.equal(cleanDeviceName("  Work laptop "), "Work laptop");
  for (const bad of ["", "   ", 5, null, "a".repeat(65), "tab\there", "zero​width"]) assert.equal(cleanDeviceName(bad), null, String(bad));

  const store = await createFakeStore();
  const nav = { userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0" };
  assert.equal(await deviceNameFor(store, nav), "Firefox on Linux");
  await store.setSetting(await store.open(), "device.name", "x".repeat(65));
  assert.equal(await deviceNameFor(store, nav), "Firefox on Linux", "a name that cannot be used is ignored");
  await store.setSetting(await store.open(), "device.name", "Kitchen tablet");
  assert.equal(await deviceNameFor(store, nav), "Kitchen tablet");
});
