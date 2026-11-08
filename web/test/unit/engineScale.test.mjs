// The engine with ten thousand items: a cold start reads the feed, a start from the cache is quick, a full listing after a 410 and an
// incremental read are within budget, and the sizes are those of the design (the sync memory 21 + 24 bytes per item, a checkpoint 56
// bytes per item). The core here is the fake of the sync tests with the real layout of the sync memory (Fase 1 section 8.6), so the
// size is the real one; the real binding at this size is tested in `tests/node/scale.test.mjs`. The times are printed.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { loadSyncState } from "../../src/store/syncState.mjs";
import { ACCOUNT, SERVER } from "./idbHelpers.mjs";
import { createFakeClient, memoryBytes, memoryOf, settle, until } from "./syncHelpers.mjs";
import { SimServer, simEngine } from "./syncModel.mjs";

const ITEMS = 10_000;
/** The start from the cache must take less than this (ms). The budget is five seconds. */
const START_BUDGET_MS = 5_000;
/** A cold read of the whole feed, and a full listing after a 410, are slower; these are ceilings with room, not goals. */
const COLD_BUDGET_MS = 120_000;
const LISTING_BUDGET_MS = 120_000;
const INCREMENTAL_BUDGET_MS = 5_000;

const MEMORY_HEADER = 21; // version 1, top seq 8, checkpoint seq 8, count 4
const MEMORY_ENTRY = 24; // item id 16, revision 8
const CHECKPOINT_ENTRY = 56; // item id 16, revision 8, hash 32

/** The sync memory as the core lays it out: header, then (id, rev) per item, in the order of the ids. */
function layout(json) {
  const memory = memoryOf(json);
  const ids = Object.keys(memory.revs).sort();
  const out = Buffer.alloc(MEMORY_HEADER + MEMORY_ENTRY * ids.length);
  out.writeUInt8(1, 0);
  out.writeBigUInt64BE(BigInt(memory.maxSeq), 1);
  out.writeBigUInt64BE(BigInt(memory.checkpointSeq), 9);
  out.writeUInt32BE(ids.length, 17);
  ids.forEach((id, at) => {
    const start = MEMORY_HEADER + MEMORY_ENTRY * at;
    Buffer.from(id, "hex").copy(out, start);
    out.writeBigUInt64BE(BigInt(memory.revs[id]), start + 16);
  });
  return new Uint8Array(out);
}

function unlayout(bytes) {
  const buffer = Buffer.from(bytes);
  const count = buffer.readUInt32BE(17);
  const revs = {};
  for (let at = 0; at < count; at += 1) {
    const start = MEMORY_HEADER + MEMORY_ENTRY * at;
    revs[buffer.subarray(start, start + 16).toString("hex")] = Number(buffer.readBigUInt64BE(start + 16));
  }
  return memoryBytes({ maxSeq: Number(buffer.readBigUInt64BE(1)), checkpointSeq: Number(buffer.readBigUInt64BE(9)), revs });
}

/** The fake core, with the sync memory in the real layout. */
function realLayoutClient() {
  const client = createFakeClient();
  const vault = client.vault;
  const original = { new: vault.sync_memory_new, rows: vault.accept_rows, verify: vault.verify_checkpoint, older: vault.accept_older_state };
  vault.sync_memory_new = async () => layout(await original.new());
  vault.accept_rows = async (rows, top, memory) => ({ newSyncMemory: layout((await original.rows(rows, top, unlayout(memory))).newSyncMemory) });
  vault.verify_checkpoint = async (checkpoint, rows, top, memory) => ({ newSyncMemory: layout((await original.verify(checkpoint, rows, top, unlayout(memory))).newSyncMemory) });
  vault.accept_older_state = async (checkpoint, rows, top) => ({ newSyncMemory: layout((await original.older(checkpoint, rows, top)).newSyncMemory) });
  return client;
}

const idOf = (n) => (n + 1).toString(16).padStart(32, "0");

test("ten_thousand_items_start_list_and_sync_within_budget", async () => {
  const client = realLayoutClient();
  const server = new SimServer();
  const times = {};
  const timed = async (name, work) => {
    const began = performance.now();
    const result = await work();
    times[name] = Math.round(performance.now() - began);
    return result;
  };

  // The server holds ten thousand items. The checkpoint it holds is one that only knows the first, so the first device that has read
  // the whole feed stores a new one with an entry for every item.
  await timed("build the server", async () => {
    for (let n = 0; n < ITEMS; n += 1) {
      const id = idOf(n);
      server.set(id, { rev: 1, ...client.wireRow(id, 1, { item_type: "login", name: `Item ${n}` }) });
      if (n === 0) server.pinCheckpoint();
    }
  });
  assert.equal(server.seq, ITEMS);

  // A cold start: the whole feed, twenty pages of five hundred.
  const device = await simEngine({ model: server, client, seed: 1, deviceName: "scale" });
  await timed("cold start", () => device.engine.start());
  assert.equal(device.engine.list().length, ITEMS);
  assert.equal(device.engine.health().halted, null);
  assert.deepEqual(device.engine.health().warnings, []);
  assert.ok(times["cold start"] < COLD_BUDGET_MS, `a cold start took ${times["cold start"]} ms`);

  // The sizes of the design: the memory, and the entries of the checkpoint the device stored.
  const state = await loadSyncState(device.store.database.store, SERVER, ACCOUNT);
  assert.equal(state.memory.length, MEMORY_HEADER + MEMORY_ENTRY * ITEMS, "the sync memory is 21 + 24 bytes per item");
  assert.equal(server.checkpointPuts.length, 1, "the device stored a checkpoint");
  const stored = server.checkpointPuts[0];
  assert.equal(stored.seq, ITEMS);
  assert.equal(b64u.decode(stored.entries).length, CHECKPOINT_ENTRY * ITEMS, "the checkpoint has 56 bytes per item");
  assert.equal(CHECKPOINT_ENTRY * ITEMS, 560_000);
  device.engine.stop();
  await settle(10);

  // A start from the cache: nothing to read, ten thousand rows to open.
  const again = await simEngine({ model: server, client, seed: 2, db: device.store.database, locks: device.locks, deviceName: "scale" });
  await timed("start from the cache", () => again.engine.start());
  assert.equal(again.engine.list().length, ITEMS);
  assert.equal(again.engine.health().halted, null);
  assert.ok(times["start from the cache"] < START_BUDGET_MS, `a start from the cache took ${times["start from the cache"]} ms, the budget is ${START_BUDGET_MS}`);
  assert.equal(again.api.gets.filter((path) => path.startsWith("/api/sync/changes")).length, 1, "one read of the feed, which is empty");

  // An incremental read: a hundred changes made by another device.
  const other = await simEngine({ model: server, client, seed: 3, deviceName: "other" });
  await other.engine.start();
  const changed = await Promise.all(Array.from({ length: 100 }, (_, n) => other.engine.create({ item_type: "login", name: `New ${n}` })));
  await until(() => changed.every((id) => server.items.has(id)), "the hundred new items are on the server");
  assert.equal(server.seq, ITEMS + 100);
  await timed("read 100 new rows", () => again.engine.syncNow());
  assert.equal(again.engine.list().length, ITEMS + 100);
  assert.ok(times["read 100 new rows"] < INCREMENTAL_BUDGET_MS, `reading 100 new rows took ${times["read 100 new rows"]} ms`);
  other.engine.stop();

  // A full listing after a 410: the retention floor goes above the cursor, and the device lists the vault again, twenty pages.
  server.set(idOf(ITEMS + 100), { rev: 1, ...client.wireRow(idOf(ITEMS + 100), 1, { item_type: "login", name: "After the floor" }) });
  server.minValidSince = server.seq;
  const listings = again.api.gets.filter((path) => path.startsWith("/api/sync/items")).length;
  await timed("list after a 410", () => again.engine.syncNow());
  assert.equal(again.api.gets.filter((path) => path.startsWith("/api/sync/items")).length - listings, Math.ceil((ITEMS + 101) / 500), "the vault was listed");
  assert.equal(again.engine.list().length, ITEMS + 101);
  assert.equal(again.engine.list().some((item) => item.missingOnServer), false, "the listing showed every item");
  assert.ok(times["list after a 410"] < LISTING_BUDGET_MS, `a listing took ${times["list after a 410"]} ms`);
  assert.equal(again.engine.health().halted, null);
  again.engine.stop();
  console.log("ten thousand items, ms:", JSON.stringify(times));
});
