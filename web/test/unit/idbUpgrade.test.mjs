// Opening the database at version 2, fresh and from version 1.
import assert from "node:assert/strict";
import { test } from "node:test";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { DB_VERSION, openStore, STORES } from "../../src/store/idb.mjs";
import { ACCOUNT, VAULT, SERVER, freshStore } from "./idbHelpers.mjs";

const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const sorted = (names) => [...names].sort();

/**
 * A browser tab that still runs version 1: the schema as it was, and the same
 * answer to another tab's upgrade (let go and report it).
 */
function openVersion1(factory, onclose = () => {}) {
  return new Promise((resolve, reject) => {
    const request = factory.open("ferret", 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      const pinned = db.createObjectStore("pinned", { keyPath: ["serverUrl", "accountId"] });
      pinned.createIndex("by_email", ["serverUrl", "email"]);
      db.createObjectStore("rows");
      const outbox = db.createObjectStore("outbox", { autoIncrement: true });
      outbox.createIndex("by_scope", ["accountId", "vaultId", "vkEpoch"]);
      outbox.createIndex("by_idem", ["accountId", "vaultId", "vkEpoch", "idem"], { unique: true });
      db.createObjectStore("settings");
      db.createObjectStore("device_secrets");
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        db.close();
        onclose();
      };
      resolve(db);
    };
    request.onerror = () => reject(request.error);
  });
}

/** Puts records in stores of an open database, in one transaction. */
function fill(db, records) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(Object.keys(records), "readwrite");
    for (const [name, list] of Object.entries(records)) {
      for (const [value, key] of list) tx.objectStore(name).put(value, key);
    }
    tx.oncomplete = () => resolve(undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/** Every key and value of each named store, read straight from the database. */
function dump(db, names) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(names, "readonly");
    const out = {};
    for (const name of names) {
      const table = tx.objectStore(name);
      out[name] = {};
      table.getAllKeys().onsuccess = (event) => {
        out[name].keys = event.target.result;
      };
      table.getAll().onsuccess = (event) => {
        out[name].values = event.target.result;
      };
    }
    tx.oncomplete = () => resolve(out);
    tx.onerror = () => reject(tx.error);
  });
}

const OLD_STORES = ["pinned", "rows", "outbox", "settings", "device_secrets"];

test("fresh_open_creates_seven_stores", async () => {
  const db = await freshStore();
  assert.equal(DB_VERSION, 2);
  assert.equal(db.store.db.version, 2);
  assert.equal(STORES.length, 7);
  assert.deepEqual(sorted(db.store.db.objectStoreNames), sorted(STORES));
  assert.deepEqual(sorted(STORES), ["device_secrets", "outbox", "pinned", "rows", "settings", "sync_state", "trash"]);

  const tx = db.store.db.transaction(["sync_state", "trash", "outbox", "pinned"], "readonly");
  assert.deepEqual(tx.objectStore("sync_state").keyPath, ["serverUrl", "accountId"]);
  assert.deepEqual(tx.objectStore("trash").keyPath, ["accountId", "vaultId", "vkEpoch", "itemId"]);
  assert.deepEqual(sorted(tx.objectStore("outbox").indexNames), ["by_idem", "by_scope"]);
  assert.deepEqual(sorted(tx.objectStore("pinned").indexNames), ["by_email"]);
});

test("upgrade_from_version_1_keeps_every_record_and_adds_two_empty_stores", async () => {
  const factory = new IDBFactory();
  const old = await openVersion1(factory);
  assert.deepEqual(sorted(old.objectStoreNames), sorted(OLD_STORES));
  const idem = "ab".repeat(16);
  await fill(old, {
    pinned: [[{ serverUrl: SERVER, accountId: ACCOUNT, email: "ada@example.org", record: { vk_epoch_max: 3 } }]],
    rows: [
      [{ itemId: "11".repeat(16), rev: 2, seq: 5, deleted: false, envelope: bytes(64, 1), tag: bytes(32, 2), tomb: null }, [ACCOUNT, VAULT, 1, "11".repeat(16)]],
      [{ itemId: "22".repeat(16), rev: 3, seq: 6, deleted: true, envelope: null, tag: null, tomb: bytes(40, 3) }, [ACCOUNT, VAULT, 1, "22".repeat(16)]],
    ],
    outbox: [[{ accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1, idem, itemId: "33".repeat(16), baseRev: 0, body: { tomb: bytes(40, 4) }, bytes: bytes(10, 5) }]],
    settings: [["a-device-id", "device_id"], [{ v: 1, marks: {}, blocked: {} }, `sync.flags.${ACCOUNT}.${VAULT}.1`]],
    device_secrets: [[{ iv: bytes(12, 6), sealed: bytes(40, 7) }, [SERVER, ACCOUNT]]],
  });
  const before = await dump(old, OLD_STORES);
  old.close();

  const store = await openStore(factory, "ferret", IDBKeyRange);
  assert.equal(store.db.version, 2);
  assert.deepEqual(sorted(store.db.objectStoreNames), sorted(STORES));
  assert.deepEqual(await dump(store.db, OLD_STORES), before, "every old record is as it was");
  const added = await dump(store.db, ["sync_state", "trash"]);
  assert.deepEqual(added.sync_state, { keys: [], values: [] });
  assert.deepEqual(added.trash, { keys: [], values: [] });

  // The indexes of version 1 still work, and the outbox counter goes on.
  const tx = store.db.transaction(["outbox", "pinned"], "readwrite");
  assert.equal(await new Promise((resolve) => {
    tx.objectStore("outbox").index("by_idem").count([ACCOUNT, VAULT, 1, idem]).onsuccess = (e) => resolve(e.target.result);
  }), 1);
  assert.equal(await new Promise((resolve) => {
    tx.objectStore("pinned").index("by_email").count([SERVER, "ada@example.org"]).onsuccess = (e) => resolve(e.target.result);
  }), 1);
  const added2 = await new Promise((resolve, reject) => {
    const request = tx.objectStore("outbox").add({ accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1, idem: "cd".repeat(16), itemId: "44".repeat(16) });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  assert.equal(typeof added2, "number");
  assert.ok(added2 > before.outbox.keys[0]);
  store.close();
});

test("a_tab_on_version_1_is_closed_by_the_upgrade_and_reports_it", async () => {
  const factory = new IDBFactory();
  let closed = 0;
  const old = await openVersion1(factory, () => {
    closed += 1;
  });
  await fill(old, { settings: [["kept", "device_id"]] });

  // The upgrade is not held up by the old tab: that tab is asked to let go, and does.
  const opened = await Promise.race([
    openStore(factory, "ferret", IDBKeyRange),
    new Promise((_, reject) => setTimeout(() => reject(new Error("the upgrade was blocked by the old tab")), 2000)),
  ]);
  assert.equal(closed, 1, "the old tab was told");
  assert.equal(opened.db.version, 2);
  assert.deepEqual((await dump(opened.db, ["settings"])).settings.values, ["kept"]);

  // The new tab in turn lets a later version in, and tells the code that opened it.
  let newClosed = 0;
  opened.close();
  const store = await openStore(factory, "ferret", IDBKeyRange, () => {
    newClosed += 1;
  });
  const later = factory.open("ferret", DB_VERSION + 1);
  await new Promise((resolve, reject) => {
    later.onsuccess = () => {
      later.result.close();
      resolve(undefined);
    };
    later.onerror = () => reject(later.error);
  });
  assert.equal(newClosed, 1);
  store.close();
});
