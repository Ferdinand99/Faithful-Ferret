// "Forget this server": everything of one account on one server goes, in one
// transaction, and nothing of another account or server.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u } from "../../src/b64.mjs";
import { cache } from "../../src/store/cache.mjs";
import { forgetServer, pendingWrites } from "../../src/store/forget.mjs";
import { StoreError } from "../../src/store/idb.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { loadPinnedByAccount, savePinned } from "../../src/store/pinned.mjs";
import { deviceId, deviceSecrets, getSetting, setSetting } from "../../src/store/settings.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { trash } from "../../src/store/trash.mjs";
import { ACCOUNT, SERVER, VAULT, freshStore, pinnedRecord, scope } from "./idbHelpers.mjs";

const OTHER_SERVER = "https://other.example";
const OTHER_ACCOUNT = "ffeeddccbbaa99887766554433221100";
const id = (n) => n.toString(16).padStart(32, "0");
const bytes = (n, fill) => new Uint8Array(n).fill(fill);

const row = (n, seq) => ({ itemId: id(n), rev: 1, seq, deleted: false, envelope: bytes(16, n), tag: bytes(32, n), tomb: null });
const trashed = (n) => ({ itemId: id(n), rev: 1, envelope: bytes(16, n), tag: bytes(32, n), tombRev: 2, deletedAt: 1_000 });
const syncState = (seq) => ({ memory: bytes(8, seq), restoreEpoch: 1, verifiedAt: 10, uploadedAt: 20, uploadedSeq: seq, hardWarning: null, restore: null });

/** A queued write the way the outbox wants it. */
function queued(n) {
  const blob = bytes(48, n);
  const tag = bytes(32, n + 100);
  const fields = { base_rev: 0, blob: b64u.encode(blob), tag: b64u.encode(tag), idem: id(n + 1000) };
  return { idem: id(n + 1000), itemId: id(n), baseRev: 0, body: { blob, tag }, bytes: new TextEncoder().encode(JSON.stringify(fields)) };
}

const sealing = async () => ({
  key: await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
  iv: bytes(12, 1),
  sealed: bytes(40, 2),
});

/** Everything the account keeps on the server: some of each of the seven stores. */
async function populate(store, server, accountId, n) {
  const email = `user${n}@example.org`;
  const rec = pinnedRecord({ accountId, server });
  await savePinned(store, server, accountId, email, rec);
  await saveSyncState(store, server, accountId, syncState(n));
  await deviceSecrets.put(store, server, accountId, await sealing());
  for (const [epoch, vault] of [[1, VAULT], [2, VAULT], [1, id(0xabc)]]) {
    await cache.putRows(store, scope(epoch, accountId, vault), [row(n, 1), row(n + 1, 2)]);
    await trash.put(store, scope(epoch, accountId, vault), trashed(n + 2));
    await outbox.enqueue(store, scope(epoch, accountId, vault), { ...queued(n * 10 + epoch + (vault === VAULT ? 0 : 5)) });
    await setSetting(store, `sync.flags.${accountId}.${vault}.${epoch}`, { v: 1, marks: {}, blocked: {} });
  }
}

/** The numbers of records the account has in each store (the outbox and trash by scope). */
async function counts(store, server, accountId) {
  const sc = [scope(1, accountId, VAULT), scope(2, accountId, VAULT), scope(1, accountId, id(0xabc))];
  let rows = 0;
  let trashN = 0;
  let queue = 0;
  let flags = 0;
  for (const s of sc) {
    rows += (await cache.getRows(store, s)).length;
    trashN += (await trash.all(store, s)).length;
    queue += (await outbox.all(store, s)).length;
    flags += (await getSetting(store, `sync.flags.${accountId}.${s.vaultId}.${s.vkEpoch}`)) === undefined ? 0 : 1;
  }
  return {
    pinned: (await loadPinnedByAccount(store, server, accountId)) === null ? 0 : 1,
    sync_state: (await loadSyncState(store, server, accountId)) === null ? 0 : 1,
    device_secrets: (await deviceSecrets.get(store, server, accountId)) === null ? 0 : 1,
    rows, trash: trashN, outbox: queue, settings: flags,
  };
}

const ALL_THERE = { pinned: 1, sync_state: 1, device_secrets: 1, rows: 6, trash: 3, outbox: 3, settings: 3 };
const NONE = { pinned: 0, sync_state: 0, device_secrets: 0, rows: 0, trash: 0, outbox: 0, settings: 0 };

test("forget_server_removes_everything_of_the_account_and_nothing_of_another_account_or_server", async () => {
  const db = await freshStore();
  const { store } = db;
  await populate(store, SERVER, ACCOUNT, 1);
  await populate(store, SERVER, OTHER_ACCOUNT, 2);
  await populate(store, OTHER_SERVER, id(0x77), 3);
  await setSetting(store, "device.name", "Firefox on Windows");
  for (const [server, account] of [[SERVER, ACCOUNT], [SERVER, OTHER_ACCOUNT], [OTHER_SERVER, id(0x77)]]) {
    assert.deepEqual(await counts(store, server, account), ALL_THERE);
  }

  const result = await forgetServer(store, SERVER, ACCOUNT);
  assert.deepEqual(result, { removed: ALL_THERE });
  assert.deepEqual(Object.keys(result.removed), ["pinned", "sync_state", "rows", "outbox", "trash", "settings", "device_secrets"], "the report names the stores");

  assert.deepEqual(await counts(store, SERVER, ACCOUNT), NONE);
  assert.deepEqual(await counts(store, SERVER, OTHER_ACCOUNT), ALL_THERE, "another account on the server");
  assert.deepEqual(await counts(store, OTHER_SERVER, id(0x77)), ALL_THERE, "another server");
  assert.equal(await getSetting(store, "device.name"), "Firefox on Windows", "unrelated settings stay");

  // It is the same after a reopen, and forgetting again finds nothing.
  const again = await forgetServer(await db.reopen(), SERVER, ACCOUNT);
  assert.deepEqual(again, { removed: NONE });
  assert.deepEqual(await counts(db.store, SERVER, OTHER_ACCOUNT), ALL_THERE);
});

/** Pinned record, sync state and device secrets of the account under another origin of the same server. */
async function pinUnder(store, server, accountId, n) {
  await savePinned(store, server, accountId, `alias${n}@example.org`, pinnedRecord({ accountId, server }));
  await saveSyncState(store, server, accountId, syncState(n));
  await deviceSecrets.put(store, server, accountId, await sealing());
}

test("forget_server_keeps_the_records_of_the_same_account_under_another_origin", async () => {
  const db = await freshStore();
  const { store } = db;
  await populate(store, SERVER, ACCOUNT, 1);
  await pinUnder(store, OTHER_SERVER, ACCOUNT, 2);

  const result = await forgetServer(store, `${SERVER}/anything`, ACCOUNT);
  assert.equal(result.shared, true, "another origin has this account");
  assert.deepEqual(result.removed, { ...NONE, pinned: 1, sync_state: 1, device_secrets: 1 }, "only the records of this origin went");

  // What this origin held by key is gone; what is kept per account stays for the other origin.
  assert.deepEqual(await counts(store, SERVER, ACCOUNT), { ...ALL_THERE, pinned: 0, sync_state: 0, device_secrets: 0 });
  assert.ok(await loadPinnedByAccount(store, OTHER_SERVER, ACCOUNT));
  assert.equal((await loadSyncState(store, OTHER_SERVER, ACCOUNT)).uploadedSeq, 2);
  assert.ok(await deviceSecrets.get(store, OTHER_SERVER, ACCOUNT));
  assert.equal(await pendingWrites(store, ACCOUNT), 3, "the queued writes are still there");

  // Forgetting the last origin takes the rest.
  const last = await forgetServer(store, OTHER_SERVER, ACCOUNT);
  assert.equal(last.shared, undefined);
  assert.deepEqual(last.removed, { ...ALL_THERE, pinned: 1, sync_state: 1, device_secrets: 1 });
  assert.deepEqual(await counts(store, OTHER_SERVER, ACCOUNT), NONE);
  assert.equal(await pendingWrites(store, ACCOUNT), 0);
});

test("forget_server_is_not_shared_by_another_account_on_another_origin", async () => {
  const db = await freshStore();
  const { store } = db;
  await populate(store, SERVER, ACCOUNT, 1);
  await pinUnder(store, OTHER_SERVER, OTHER_ACCOUNT, 2);
  const result = await forgetServer(store, SERVER, ACCOUNT);
  assert.equal(result.shared, undefined);
  assert.deepEqual(result.removed, ALL_THERE);
  assert.ok(await loadPinnedByAccount(store, OTHER_SERVER, OTHER_ACCOUNT));
});

test("forget_server_keeps_the_device_id", async () => {
  const db = await freshStore();
  const device = await deviceId(db.store);
  await populate(db.store, SERVER, ACCOUNT, 1);
  await forgetServer(db.store, SERVER, ACCOUNT);
  assert.equal(await deviceId(db.store), device);
  assert.equal(await getSetting(db.store, "device_id"), device);
  assert.equal(await deviceId(await db.reopen()), device);
});

test("forget_is_atomic_when_one_store_fails", async () => {
  for (const failing of ["trash", "outbox", "device_secrets", "settings"]) {
    const db = await freshStore();
    await populate(db.store, SERVER, ACCOUNT, 1);
    await populate(db.store, SERVER, OTHER_ACCOUNT, 2);

    // A store whose transactions hand out one object store that fails on every call.
    const broken = {
      ...db.store,
      db: new Proxy(db.store.db, {
        get(target, prop) {
          if (prop !== "transaction") {
            const value = Reflect.get(target, prop);
            return typeof value === "function" ? value.bind(target) : value;
          }
          return (...args) => {
            const tx = target.transaction(...args);
            return new Proxy(tx, {
              get(txTarget, txProp) {
                if (txProp !== "objectStore") {
                  const value = Reflect.get(txTarget, txProp);
                  return typeof value === "function" ? value.bind(txTarget) : value;
                }
                return (name) => {
                  const real = txTarget.objectStore(name);
                  if (name !== failing) return real;
                  return new Proxy(real, {
                    get() {
                      return () => {
                        throw new StoreError("disk_error", "the disk failed");
                      };
                    },
                  });
                };
              },
              set(txTarget, txProp, value) {
                txTarget[txProp] = value;
                return true;
              },
            });
          };
        },
      }),
    };
    await assert.rejects(() => forgetServer(broken, SERVER, ACCOUNT), (error) => error instanceof StoreError && error.code === "disk_error", failing);
    assert.deepEqual(await counts(db.store, SERVER, ACCOUNT), ALL_THERE, `nothing went when ${failing} failed`);
    assert.deepEqual(await counts(db.store, SERVER, OTHER_ACCOUNT), ALL_THERE);
    // The same call on the working store then removes it all.
    assert.deepEqual((await forgetServer(db.store, SERVER, ACCOUNT)).removed, ALL_THERE);
  }
});

test("pending_writes_counts_the_outbox_entries_of_the_account", async () => {
  const db = await freshStore();
  assert.equal(await pendingWrites(db.store, ACCOUNT), 0);
  await outbox.enqueue(db.store, scope(1), queued(1));
  await outbox.enqueue(db.store, scope(1), queued(2));
  await outbox.enqueue(db.store, scope(2), queued(3));
  await outbox.enqueue(db.store, scope(1, ACCOUNT, id(0xabc)), queued(4));
  await outbox.enqueue(db.store, scope(1, OTHER_ACCOUNT, VAULT), queued(5));
  assert.equal(await pendingWrites(db.store, ACCOUNT), 4, "every vault and epoch of the account");
  assert.equal(await pendingWrites(db.store, OTHER_ACCOUNT), 1);
  assert.equal(await pendingWrites(db.store, id(0x99)), 0);
  await outbox.remove(db.store, scope(1), id(1001));
  assert.equal(await pendingWrites(db.store, ACCOUNT), 3);
  await assert.rejects(() => pendingWrites(db.store, "nope"), TypeError);
  await assert.rejects(() => forgetServer(db.store, SERVER, "nope"), TypeError);
  await assert.rejects(() => forgetServer(db.store, "nonsense", ACCOUNT), TypeError);
});
