// The local copy of the sync feed.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { cache, rowOfChange } from "../../src/store/cache.mjs";
import { StoreError } from "../../src/store/idb.mjs";
import { loadPinned, savePinned } from "../../src/store/pinned.mjs";
import { deviceId } from "../../src/store/settings.mjs";
import { ACCOUNT, SERVER, VAULT, freshStore, pinnedRecord, scope } from "./idbHelpers.mjs";

const id = (n) => n.toString(16).padStart(32, "0");
const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const live = (n, seq, rev = 1) => ({ itemId: id(n), rev, seq, deleted: false, envelope: bytes(64, n), tag: bytes(32, n), tomb: null });
const gone = (n, seq, rev = 2) => ({ itemId: id(n), rev, seq, deleted: true, envelope: null, tag: null, tomb: bytes(40, n) });

/** Every record of the rows store, read straight from the database. */
function rawRows(store) {
  return new Promise((resolve, reject) => {
    const request = store.db.transaction("rows", "readonly").objectStore("rows").getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

test("cache_round_trips_rows_in_seq_order_and_survives_reopen", async () => {
  const db = await freshStore();
  const rows = [live(2, 7), live(1, 3), gone(3, 9)];
  await cache.putRows(db.store, scope(), rows);
  const store = await db.reopen();
  const back = await cache.getRows(store, scope());
  assert.deepEqual(back.map((r) => r.seq), [3, 7, 9]);
  assert.deepEqual(back, [rows[1], rows[0], rows[2]]);
  assert.equal(await cache.maxSeq(store, scope()), 9);
});

test("cache_replaces_the_row_of_the_same_item_and_keeps_scopes_apart", async () => {
  const db = await freshStore();
  await cache.putRows(db.store, scope(1), [live(1, 1, 1), live(2, 2, 1)]);
  await cache.putRows(db.store, scope(1), [live(1, 5, 2)]);
  const rows = await cache.getRows(db.store, scope(1));
  assert.equal(rows.length, 2);
  assert.equal(rows.find((r) => r.itemId === id(1)).rev, 2);

  // Another epoch, vault or account has its own rows.
  await cache.putRows(db.store, scope(2), [live(9, 20)]);
  await cache.putRows(db.store, scope(1, ACCOUNT, id(0xabc)), [live(8, 30)]);
  await cache.putRows(db.store, scope(1, id(0xdef), VAULT), [live(7, 40)]);
  assert.deepEqual((await cache.getRows(db.store, scope(1))).map((r) => r.itemId), [id(2), id(1)]);
  assert.equal(await cache.maxSeq(db.store, scope(2)), 20);
  assert.equal(await cache.maxSeq(db.store, scope(3)), 0);
  assert.deepEqual(await cache.getRows(db.store, scope(3)), []);
});

test("cache_holds_only_ciphertext_fields", async () => {
  const db = await freshStore();
  await cache.putRows(db.store, scope(), [live(1, 1), gone(2, 2)]);
  const allowed = new Set(["itemId", "rev", "seq", "deleted", "envelope", "tag", "tomb"]);
  const stored = await rawRows(db.store);
  assert.equal(stored.length, 2);
  for (const row of stored) {
    for (const key of Object.keys(row)) assert.ok(allowed.has(key), `stored field ${key}`);
  }

  // A field that is not on the list is refused, not quietly dropped or kept.
  for (const extra of ["title", "name", "summary", "plaintext", "url"]) {
    await assert.rejects(
      cache.putRows(db.store, scope(), [{ ...live(3, 3), [extra]: "x" }]),
      (error) => error instanceof StoreError && error.code === "row_field",
      extra,
    );
  }
  assert.equal((await rawRows(db.store)).length, 2, "the refused rows were not written");
});

test("cache_refuses_a_row_that_is_both_live_and_deleted_or_neither", async () => {
  const db = await freshStore();
  const bad = [
    { ...live(1, 1), tomb: bytes(40, 1) },
    { ...gone(1, 1), envelope: bytes(8, 1) },
    { ...live(1, 1), tag: null },
    { ...live(1, 1), deleted: true },
    { ...live(1, 1), itemId: "ABC" },
    { ...live(1, 1), rev: -1 },
    { ...live(1, 1), seq: 1.5 },
    { ...live(1, 1), envelope: "text" },
  ];
  for (const row of bad) {
    await assert.rejects(cache.putRows(db.store, scope(), [row]), (e) => e instanceof StoreError && e.code === "row_malformed");
  }
  // One bad row in a batch writes none of the batch.
  await assert.rejects(cache.putRows(db.store, scope(), [live(1, 1), { ...live(2, 2), tag: null }]));
  assert.deepEqual(await cache.getRows(db.store, scope()), []);
});

test("cache_reads_a_row_of_the_changes_feed", () => {
  const blob = bytes(64, 5);
  const tag = bytes(32, 6);
  const row = rowOfChange({ id: id(4), rev: 3, seq: 11, deleted: false, blob: b64u.encode(blob), tag: b64u.encode(tag) });
  assert.deepEqual(row, { itemId: id(4), rev: 3, seq: 11, deleted: false, envelope: blob, tag, tomb: null });
  const tomb = bytes(40, 7);
  const dead = rowOfChange({ id: id(4), rev: 4, seq: 12, deleted: true, tomb: b64u.encode(tomb), blob: null });
  assert.deepEqual(dead, { itemId: id(4), rev: 4, seq: 12, deleted: true, envelope: null, tag: null, tomb });
  assert.throws(() => rowOfChange({ id: id(4), rev: 1, seq: 1, deleted: false, blob: "AA==", tag: "AA" }));
});

test("clearing_the_cache_keeps_pinned", async () => {
  const db = await freshStore();
  const email = "ada@example.org";
  await savePinned(db.store, SERVER, ACCOUNT, email, pinnedRecord({ vk: 2 }));
  const device = await deviceId(db.store);
  await cache.putRows(db.store, scope(1), [live(1, 1)]);
  await cache.putRows(db.store, scope(2), [live(2, 2)]);

  await cache.clear(db.store, scope(1));
  assert.deepEqual(await cache.getRows(db.store, scope(1)), []);
  assert.equal((await cache.getRows(db.store, scope(2))).length, 1, "another epoch is not touched");

  await cache.clearAccount(db.store, ACCOUNT);
  assert.deepEqual(await cache.getRows(db.store, scope(2)), []);

  const store = await db.reopen();
  assert.equal((await loadPinned(store, SERVER, email)).vk_epoch_max, 2);
  assert.equal(await deviceId(store), device);
});

test("a_scope_must_name_the_account_vault_and_epoch", async () => {
  const db = await freshStore();
  for (const bad of [null, {}, { accountId: ACCOUNT, vaultId: VAULT }, { accountId: "x", vaultId: VAULT, vkEpoch: 1 }, scope(-1), scope(1.5)]) {
    await assert.rejects(cache.getRows(db.store, bad), TypeError);
  }
});

test("cache_removes_only_the_named_rows_of_the_scope", async () => {
  const db = await freshStore();
  await cache.putRows(db.store, scope(1), [live(1, 1), live(2, 2), gone(3, 3)]);
  await cache.putRows(db.store, scope(2), [live(1, 1)]);
  await cache.removeRows(db.store, scope(1), [id(2), id(9)]);
  assert.deepEqual((await cache.getRows(db.store, scope(1))).map((r) => r.itemId), [id(1), id(3)]);
  assert.equal((await cache.getRows(db.store, scope(2))).length, 1, "another epoch is untouched");
  await assert.rejects(cache.removeRows(db.store, scope(1), ["nothex"]), TypeError);
});
