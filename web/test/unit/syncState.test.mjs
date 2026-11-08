// The sync state of an account on a server.
import assert from "node:assert/strict";
import { test } from "node:test";
import { cache } from "../../src/store/cache.mjs";
import { StoreError } from "../../src/store/idb.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { ACCOUNT, SERVER, freshStore, scope } from "./idbHelpers.mjs";

const OTHER_ACCOUNT = "ffeeddccbbaa99887766554433221100";

const state = (overrides = {}) => ({
  memory: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
  restoreEpoch: 2,
  verifiedAt: 1_700_000_000_000,
  verifiedSeq: 40,
  uploadedAt: 1_700_000_100_000,
  uploadedSeq: 41,
  hardWarning: null,
  restore: null,
  ...overrides,
});

/** Every record of the sync_state store, read straight from the database. */
function rawStates(store) {
  return new Promise((resolve, reject) => {
    const request = store.db.transaction("sync_state", "readonly").objectStore("sync_state").getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

test("sync_state_round_trips_and_is_null_before_the_first_save", async () => {
  const db = await freshStore();
  assert.equal(await loadSyncState(db.store, SERVER, ACCOUNT), null);
  const full = state({ hardWarning: "checkpoint_rolled_back", restore: { epoch: 3, phase: "memory_saved" } });
  await saveSyncState(db.store, SERVER, ACCOUNT, full);
  assert.deepEqual(await loadSyncState(db.store, SERVER, ACCOUNT), full);
  // A later save replaces the whole state.
  const next = state({ restoreEpoch: null, verifiedAt: null, verifiedSeq: null, uploadedAt: null, uploadedSeq: null, restore: { epoch: 3, phase: "queued" } });
  await saveSyncState(db.store, SERVER, ACCOUNT, next);
  assert.deepEqual(await loadSyncState(await db.reopen(), SERVER, ACCOUNT), next);
});

test("sync_state_is_kept_per_server_origin_and_account", async () => {
  const db = await freshStore();
  await saveSyncState(db.store, SERVER, ACCOUNT, state({ uploadedSeq: 1 }));
  await saveSyncState(db.store, "https://other.example", ACCOUNT, state({ uploadedSeq: 2 }));
  await saveSyncState(db.store, SERVER, OTHER_ACCOUNT, state({ uploadedSeq: 3 }));
  assert.equal((await loadSyncState(db.store, SERVER, ACCOUNT)).uploadedSeq, 1);
  assert.equal((await loadSyncState(db.store, `${SERVER}/some/path?x=1`, ACCOUNT)).uploadedSeq, 1, "one server, however its address is written");
  assert.equal((await loadSyncState(db.store, "https://other.example", ACCOUNT)).uploadedSeq, 2);
  assert.equal((await loadSyncState(db.store, SERVER, OTHER_ACCOUNT)).uploadedSeq, 3);
  assert.equal(await loadSyncState(db.store, "https://third.example", ACCOUNT), null);
  await assert.rejects(() => loadSyncState(db.store, SERVER, "not-an-account"), TypeError);
  await assert.rejects(() => saveSyncState(db.store, "nonsense", ACCOUNT, state()), TypeError);
});

test("sync_state_survives_cache_clear_and_sign_out", async () => {
  const db = await freshStore();
  const kept = state({ hardWarning: "server_shows_older_state" });
  await saveSyncState(db.store, SERVER, ACCOUNT, kept);
  const row = { itemId: "11".repeat(16), rev: 1, seq: 1, deleted: false, envelope: new Uint8Array(8), tag: new Uint8Array(32), tomb: null };
  await cache.putRows(db.store, scope(1), [row]);

  await cache.clear(db.store, scope(1));
  assert.deepEqual(await loadSyncState(db.store, SERVER, ACCOUNT), kept);
  await cache.putRows(db.store, scope(1), [row]);
  await cache.clearAccount(db.store, ACCOUNT);
  assert.deepEqual(await cache.getRows(db.store, scope(1)), []);
  assert.deepEqual(await loadSyncState(db.store, SERVER, ACCOUNT), kept);
  assert.deepEqual(await loadSyncState(await db.reopen(), SERVER, ACCOUNT), kept);
});

test("sync_state_stores_a_copy_of_the_memory_bytes", async () => {
  const db = await freshStore();
  // A view over a larger buffer: only its own bytes are stored.
  const buffer = new Uint8Array(1024).fill(0xee).buffer;
  const view = new Uint8Array(buffer, 100, 6);
  view.set([9, 8, 7, 6, 5, 4]);
  await saveSyncState(db.store, SERVER, ACCOUNT, state({ memory: view }));
  const [raw] = await rawStates(db.store);
  assert.equal(raw.memory.buffer.byteLength, 6, "not the whole buffer behind the view");
  assert.deepEqual(Array.from(raw.memory), [9, 8, 7, 6, 5, 4]);

  // Changing the caller's bytes afterwards changes nothing that is stored.
  view.fill(0);
  assert.deepEqual(Array.from((await loadSyncState(db.store, SERVER, ACCOUNT)).memory), [9, 8, 7, 6, 5, 4]);

  // And the bytes that a load gives are the caller's to change.
  const loaded = await loadSyncState(db.store, SERVER, ACCOUNT);
  loaded.memory.fill(1);
  assert.deepEqual(Array.from((await loadSyncState(db.store, SERVER, ACCOUNT)).memory), [9, 8, 7, 6, 5, 4]);
});

test("sync_state_rejects_non_bytes_fractional_numbers_and_unknown_phases", async () => {
  const db = await freshStore();
  const refused = async (value, why) => {
    await assert.rejects(
      saveSyncState(db.store, SERVER, ACCOUNT, value),
      (error) => error instanceof StoreError && error.code === "sync_state_malformed",
      why,
    );
  };
  // Memory is bytes.
  for (const memory of [[1, 2, 3], "abc", new ArrayBuffer(4), null, undefined, { 0: 1, length: 1 }, new Uint16Array(2)]) {
    await refused(state({ memory }), `memory ${String(memory)}`);
  }
  // Numbers are whole, not negative, and numbers.
  for (const field of ["restoreEpoch", "verifiedAt", "verifiedSeq", "uploadedAt", "uploadedSeq"]) {
    // A state from before `verifiedSeq` existed has none, and reads as null.
    for (const bad of [1.5, -1, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, 5n, "7", ...(field === "verifiedSeq" ? [] : [undefined])]) {
      await refused(state({ [field]: bad }), `${field} ${String(bad)}`);
    }
  }
  // The warning is a non-empty code or null.
  for (const bad of ["", 5, {}, undefined, false]) await refused(state({ hardWarning: bad }), `hardWarning ${String(bad)}`);
  // A restore is { epoch, phase } with a known phase.
  const restores = [
    { epoch: 1, phase: "done" },
    { epoch: 1, phase: "" },
    { epoch: 1, phase: undefined },
    { epoch: 1.5, phase: "queued" },
    { epoch: -1, phase: "queued" },
    { epoch: "1", phase: "queued" },
    { epoch: 1 },
    { phase: "queued" },
    { epoch: 1, phase: "queued", extra: true },
    [1, "queued"],
    "queued",
    undefined,
  ];
  for (const restore of restores) await refused(state({ restore }), `restore ${JSON.stringify(restore)}`);
  // Nothing else may be in the state, and nothing may be missing.
  await refused(state({ secret: "x" }), "an extra field");
  const { memory: _memory, ...withoutMemory } = state();
  await refused(withoutMemory, "no memory");
  await refused(null, "null");
  await refused([], "an array");
  await refused("state", "a string");

  assert.equal(await loadSyncState(db.store, SERVER, ACCOUNT), null, "nothing of a refused state is stored");
  // The good values are still good.
  for (const phase of ["memory_saved", "queued"]) {
    await saveSyncState(db.store, SERVER, ACCOUNT, state({ restore: { epoch: 0, phase } }));
  }
  await saveSyncState(db.store, SERVER, ACCOUNT, state({ memory: new Uint8Array(0), restoreEpoch: 0 }));
});

test("a_refused_state_leaves_the_stored_one_alone", async () => {
  const db = await freshStore();
  const good = state();
  await saveSyncState(db.store, SERVER, ACCOUNT, good);
  await assert.rejects(() => saveSyncState(db.store, SERVER, ACCOUNT, state({ uploadedSeq: 0.5 })), StoreError);
  assert.deepEqual(await loadSyncState(db.store, SERVER, ACCOUNT), good);
});

test("a_damaged_stored_state_is_refused_on_load", async () => {
  const db = await freshStore();
  const put = (record) => new Promise((resolve, reject) => {
    const tx = db.store.db.transaction("sync_state", "readwrite");
    tx.objectStore("sync_state").put({ serverUrl: SERVER, accountId: ACCOUNT, ...record });
    tx.oncomplete = () => resolve(undefined);
    tx.onerror = () => reject(tx.error);
  });
  const refused = () => assert.rejects(
    loadSyncState(db.store, SERVER, ACCOUNT),
    (error) => error instanceof StoreError && error.code === "sync_state_malformed",
  );
  const good = state();
  await put(good);
  assert.deepEqual(await loadSyncState(db.store, SERVER, ACCOUNT), good);
  for (const damage of [
    { memory: [1, 2, 3] }, { memory: undefined }, { uploadedSeq: 1.5 }, { verifiedAt: -3 }, { restoreEpoch: "2" },
    { hardWarning: "" }, { restore: { epoch: 1, phase: "later" } }, { restore: undefined }, { extra: "field" },
  ]) {
    await put({ ...good, ...damage });
    await refused();
  }
});

test("a_state_stored_before_the_verified_seq_existed_reads_with_none", async () => {
  const db = await freshStore();
  const { verifiedSeq: _none, ...old } = state();
  await saveSyncState(db.store, SERVER, ACCOUNT, old);
  assert.equal((await loadSyncState(db.store, SERVER, ACCOUNT)).verifiedSeq, null);
  await saveSyncState(db.store, SERVER, ACCOUNT, state({ verifiedSeq: 7 }));
  assert.equal((await loadSyncState(db.store, SERVER, ACCOUNT)).verifiedSeq, 7);
});
