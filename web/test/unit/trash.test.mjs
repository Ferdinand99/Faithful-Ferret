// The local trash: ciphertext copies of deleted items, kept for a while.
import assert from "node:assert/strict";
import { test } from "node:test";
import { cache } from "../../src/store/cache.mjs";
import { StoreError } from "../../src/store/idb.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { trash } from "../../src/store/trash.mjs";
import { ACCOUNT, SERVER, VAULT, freshStore, scope } from "./idbHelpers.mjs";

const id = (n) => n.toString(16).padStart(32, "0");
const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const entry = (n, deletedAt, overrides = {}) => ({
  itemId: id(n), rev: 3, envelope: bytes(64, n), tag: bytes(32, n + 50), tombRev: 4, deletedAt, ...overrides,
});

/** Every record of the trash store, read straight from the database. */
function rawTrash(store) {
  return new Promise((resolve, reject) => {
    const request = store.db.transaction("trash", "readonly").objectStore("trash").getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

const refusedWith = (code, promise) => assert.rejects(promise, (error) => error instanceof StoreError && error.code === code);

test("trash_round_trips_entries_newest_first_and_survives_reopen", async () => {
  const db = await freshStore();
  const entries = [entry(1, 1_000), entry(2, 3_000), entry(3, 2_000)];
  for (const e of entries) await trash.put(db.store, scope(), e);
  const store = await db.reopen();
  assert.deepEqual((await trash.all(store, scope())).map((e) => e.itemId), [id(2), id(3), id(1)]);
  assert.deepEqual(await trash.get(store, scope(), id(3)), entries[2]);
  assert.equal(await trash.get(store, scope(), id(9)), null);
  // The same item again replaces the entry.
  await trash.put(store, scope(), entry(3, 5_000, { rev: 4, tombRev: 6 }));
  const all = await trash.all(store, scope());
  assert.equal(all.length, 3);
  assert.deepEqual(all[0], entry(3, 5_000, { rev: 4, tombRev: 6 }));
  await trash.remove(store, scope(), id(3));
  await trash.remove(store, scope(), id(3));
  assert.equal(await trash.get(store, scope(), id(3)), null);
  assert.equal((await trash.all(store, scope())).length, 2);
});

test("trash_keeps_scopes_apart", async () => {
  const db = await freshStore();
  await trash.put(db.store, scope(1), entry(1, 10));
  await trash.put(db.store, scope(2), entry(2, 10));
  await trash.put(db.store, scope(1, ACCOUNT, id(0xabc)), entry(3, 10));
  await trash.put(db.store, scope(1, id(0xdef), VAULT), entry(4, 10));
  assert.deepEqual((await trash.all(db.store, scope(1))).map((e) => e.itemId), [id(1)]);
  assert.deepEqual((await trash.all(db.store, scope(2))).map((e) => e.itemId), [id(2)]);
  assert.equal(await trash.get(db.store, scope(2), id(1)), null);
  await trash.clear(db.store, scope(1));
  assert.deepEqual(await trash.all(db.store, scope(1)), []);
  assert.equal((await trash.all(db.store, scope(2))).length, 1);
  assert.equal((await trash.all(db.store, scope(1, ACCOUNT, id(0xabc)))).length, 1);
  assert.equal((await trash.all(db.store, scope(1, id(0xdef), VAULT))).length, 1);
});

test("trash_holds_only_ciphertext_fields", async () => {
  const db = await freshStore();
  await trash.put(db.store, scope(), entry(1, 1_000));
  const allowed = new Set(["accountId", "vaultId", "vkEpoch", "itemId", "rev", "envelope", "tag", "tombRev", "deletedAt"]);
  const stored = await rawTrash(db.store);
  assert.equal(stored.length, 1);
  for (const key of Object.keys(stored[0])) assert.ok(allowed.has(key), `unexpected field ${key}`);
  assert.ok(stored[0].envelope instanceof Uint8Array && stored[0].tag instanceof Uint8Array);

  // A field of a decrypted item, or anything else, is refused and not dropped.
  for (const extra of [{ name: "Bank" }, { body: { password: "hunter2" } }, { tomb: bytes(40, 1) }, { seq: 4 }]) {
    await refusedWith("trash_field", trash.put(db.store, scope(), { ...entry(2, 1_000), ...extra }));
  }
  // Fields have the right types.
  const bad = [
    { itemId: "not-hex" }, { rev: 0 }, { rev: 1.5 }, { rev: "3" }, { tombRev: 3 }, { tombRev: 2.5 },
    { deletedAt: -1 }, { deletedAt: 1.5 }, { deletedAt: "now" },
    { envelope: [1, 2] }, { envelope: "ciphertext" }, { envelope: null }, { tag: null }, { tag: new ArrayBuffer(32) },
  ];
  for (const overrides of bad) {
    await refusedWith("trash_malformed", trash.put(db.store, scope(), entry(2, 1_000, overrides)));
  }
  await refusedWith("trash_malformed", trash.put(db.store, scope(), null));
  assert.equal((await rawTrash(db.store)).length, 1, "nothing of a refused entry is stored");
  await assert.rejects(() => trash.put(db.store, { accountId: ACCOUNT }, entry(2, 1)), TypeError);
  await assert.rejects(() => trash.get(db.store, scope(), "nope"), TypeError);
});

test("trash_stores_a_copy_of_the_bytes", async () => {
  const db = await freshStore();
  const e = entry(1, 1_000);
  await trash.put(db.store, scope(), e);
  e.envelope.fill(0);
  e.tag.fill(0);
  const back = await trash.get(db.store, scope(), id(1));
  assert.deepEqual(back.envelope, bytes(64, 1));
  assert.deepEqual(back.tag, bytes(32, 51));
});

test("trash_purge_removes_only_entries_older_than_the_cutoff", async () => {
  const db = await freshStore();
  for (const [n, at] of [[1, 100], [2, 999], [3, 1_000], [4, 1_001], [5, 5_000]]) await trash.put(db.store, scope(1), entry(n, at));
  await trash.put(db.store, scope(2), entry(6, 1));
  await trash.put(db.store, scope(1, id(0xdef), VAULT), entry(7, 1));

  assert.equal(await trash.purgeBefore(db.store, scope(1), 1_000), 2, "deleted before the cutoff");
  assert.deepEqual((await trash.all(db.store, scope(1))).map((e) => e.itemId).sort(), [id(3), id(4), id(5)], "an entry at the cutoff stays");
  assert.equal(await trash.purgeBefore(db.store, scope(1), 1_000), 0);
  assert.equal(await trash.purgeBefore(db.store, scope(3), 10_000), 0, "an empty scope");
  assert.equal((await trash.all(db.store, scope(2))).length, 1, "another epoch is not touched");
  assert.equal((await trash.all(db.store, scope(1, id(0xdef), VAULT))).length, 1, "another account is not touched");
  assert.equal(await trash.purgeBefore(db.store, scope(1), 10_000), 3);
  assert.deepEqual(await trash.all(db.store, scope(1)), []);
  for (const cutoff of [-1, 1.5, Number.NaN, "5", null]) {
    await assert.rejects(() => trash.purgeBefore(db.store, scope(1), cutoff), TypeError, String(cutoff));
  }
});

test("clearing_the_cache_clears_the_trash_and_keeps_sync_state", async () => {
  const db = await freshStore();
  const memory = bytes(8, 9);
  const kept = { memory, restoreEpoch: 1, verifiedAt: 5, verifiedSeq: null, uploadedAt: null, uploadedSeq: null, hardWarning: null, restore: null };
  await saveSyncState(db.store, SERVER, ACCOUNT, kept);
  const row = { itemId: id(1), rev: 1, seq: 1, deleted: false, envelope: bytes(8, 1), tag: bytes(32, 2), tomb: null };
  await cache.putRows(db.store, scope(1), [row]);
  await trash.put(db.store, scope(1), entry(1, 10));
  await trash.put(db.store, scope(2), entry(2, 10));

  await cache.clear(db.store, scope(1));
  assert.deepEqual(await cache.getRows(db.store, scope(1)), []);
  assert.deepEqual(await trash.all(db.store, scope(1)), []);
  assert.equal((await trash.all(db.store, scope(2))).length, 1, "another epoch keeps its trash");
  assert.deepEqual(await loadSyncState(db.store, SERVER, ACCOUNT), kept);

  // Signing out clears every vault and epoch of the account, but not another account.
  await trash.put(db.store, scope(1), entry(3, 10));
  await trash.put(db.store, scope(1, id(0xabc), VAULT), entry(4, 10));
  await cache.clearAccount(db.store, ACCOUNT);
  assert.deepEqual(await trash.all(db.store, scope(1)), []);
  assert.deepEqual(await trash.all(db.store, scope(2)), []);
  assert.equal((await trash.all(db.store, scope(1, id(0xabc), VAULT))).length, 1);
  assert.deepEqual(await loadSyncState(await db.reopen(), SERVER, ACCOUNT), kept);
});
