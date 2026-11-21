// Opening a database of version 2 at version 3: one new store (`device_keys`),
// and every record of version 2 is as it was (every golden record of
// test/fixtures/stored/v2/ is written by the version-2 schema first).
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { isDeepStrictEqual } from "node:util";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { loadSecretKey } from "../../src/flows/deviceSecret.mjs";
import { DB_VERSION, openStore, STORES } from "../../src/store/idb.mjs";
import { web } from "./helpers.mjs";

const GOLDEN = join(web, "test", "fixtures", "stored", "v2");
const sorted = (names) => [...names].sort();

/** The seven stores of version 2 and how each is keyed (as storedFormats.test.mjs freezes them). */
const V2 = Object.freeze({
  pinned: { keyPath: ["serverUrl", "accountId"], indexes: [["by_email", ["serverUrl", "email"], {}]] },
  rows: {},
  outbox: {
    autoIncrement: true,
    indexes: [
      ["by_scope", ["accountId", "vaultId", "vkEpoch"], {}],
      ["by_idem", ["accountId", "vaultId", "vkEpoch", "idem"], { unique: true }],
    ],
  },
  settings: {},
  device_secrets: {},
  sync_state: { keyPath: ["serverUrl", "accountId"] },
  trash: { keyPath: ["accountId", "vaultId", "vkEpoch", "itemId"] },
});

/** A value from a golden file, with its tagged types. */
async function decode(x) {
  if (x === null || typeof x !== "object") return x;
  if (Array.isArray(x)) return Promise.all(x.map(decode));
  const keys = Object.keys(x);
  if (keys.length === 1 && keys[0] === "$bytes") return Uint8Array.from(Buffer.from(x.$bytes, "hex"));
  if (keys.length === 1 && keys[0] === "$bigint") return BigInt(x.$bigint);
  if (keys.length === 1 && keys[0] === "$aesGcmKey") {
    return crypto.subtle.importKey("raw", Buffer.from(x.$aesGcmKey, "hex"), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
  const out = {};
  for (const key of keys) out[key] = await decode(x[key]);
  return out;
}

/** Every golden record of version 2, per store (outbox.json and outbox-import.json both go to the outbox). */
async function goldenRecords() {
  /** @type {Record<string, { key: unknown, value: unknown }[]>} */
  const out = Object.fromEntries(Object.keys(V2).map((name) => [name, []]));
  for (const file of readdirSync(GOLDEN).sort()) {
    const data = JSON.parse(readFileSync(join(GOLDEN, file), "utf8"));
    assert.equal(data.dbVersion, 2, file);
    for (const { key, value } of data.records) {
      out[data.store].push({ key: key === undefined ? undefined : await decode(key), value: await decode(value) });
    }
  }
  return out;
}

/** A database of version 2 with every golden record, as version-2 code wrote it. `onclose` runs when another tab upgrades it. */
function openVersion2(factory, onclose = () => {}) {
  return new Promise((resolve, reject) => {
    const request = factory.open("ferret", 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      for (const [name, { keyPath, autoIncrement, indexes }] of Object.entries(V2)) {
        const table = db.createObjectStore(name, { ...(keyPath ? { keyPath } : {}), ...(autoIncrement ? { autoIncrement } : {}) });
        for (const [index, path, options] of indexes ?? []) table.createIndex(index, path, options);
      }
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

function fill(db, records) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(Object.keys(records), "readwrite");
    for (const [name, list] of Object.entries(records)) {
      for (const { key, value } of list) {
        if (key === undefined) tx.objectStore(name).put(value);
        else tx.objectStore(name).put(value, key);
      }
    }
    tx.oncomplete = () => resolve(undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/** Every key and value of each named store, and how the store is made, read straight from the database. */
function dump(db, names) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(names, "readonly");
    const out = {};
    for (const name of names) {
      const table = tx.objectStore(name);
      out[name] = {
        keyPath: table.keyPath,
        autoIncrement: table.autoIncrement,
        indexes: [...table.indexNames].sort().map((index) => {
          const at = table.index(index);
          return [index, at.keyPath, at.unique, at.multiEntry];
        }),
      };
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

test("idb_upgrade_adds_one_store_and_keeps_every_record", async () => {
  const factory = new IDBFactory();
  const old = await openVersion2(factory);
  const golden = await goldenRecords();
  await fill(old, golden);
  const before = await dump(old, Object.keys(V2));
  for (const name of Object.keys(V2)) {
    assert.ok(before[name].values.length > 0, `${name}: the golden records are in the old database`);
    assert.equal(before[name].values.length, golden[name].length, name);
  }
  old.close();

  const store = await openStore(factory, "ferret", IDBKeyRange);
  assert.equal(DB_VERSION, 3);
  assert.equal(store.db.version, 3);
  // One store more, and only that one.
  assert.deepEqual(sorted(store.db.objectStoreNames), sorted([...Object.keys(V2), "device_keys"]));
  assert.deepEqual(sorted(STORES), sorted([...Object.keys(V2), "device_keys"]));
  const after = await dump(store.db, [...Object.keys(V2), "device_keys"]);
  assert.deepEqual(after.device_keys, { keyPath: "serverUrl", autoIncrement: false, indexes: [], keys: [], values: [] });

  // Every store of version 2 is made as it was and holds the same keys and values.
  for (const name of Object.keys(V2)) {
    const { values: valuesBefore, ...restBefore } = before[name];
    const { values: valuesAfter, ...restAfter } = after[name];
    assert.deepEqual(restAfter, restBefore, name);
    assert.equal(valuesAfter.length, valuesBefore.length, name);
    for (const [i, value] of valuesAfter.entries()) {
      if (name === "device_secrets") {
        // A CryptoKey has no fields to compare: the nonce and the sealed bytes stand for the record, and the
        // key still opens them (below).
        assert.ok(isDeepStrictEqual(value.iv, valuesBefore[i].iv) && isDeepStrictEqual(value.sealed, valuesBefore[i].sealed), name);
        assert.equal(value.key.extractable, false);
      } else {
        assert.deepEqual(value, valuesBefore[i], `${name}: record ${i} is as it was`);
      }
    }
  }
  const [secretKey] = golden.device_secrets;
  assert.equal(
    await loadSecretKey(store, /** @type {string[]} */ (secretKey.key)[0], /** @type {string[]} */ (secretKey.key)[1]),
    "FFS1-TESTA-TESTB-TESTC-TESTD-TESTE-TESTF",
  );

  // The outbox counter goes on after the old entries.
  const next = await new Promise((resolve, reject) => {
    const request = store.db.transaction(["outbox"], "readwrite").objectStore("outbox").add({ accountId: "a", vaultId: "b", vkEpoch: 1, idem: "c", itemId: "d" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  assert.ok(next > Math.max(...before.outbox.keys));
  store.close();

  // Opening it again changes nothing more.
  const again = await openStore(factory, "ferret", IDBKeyRange);
  assert.equal(again.db.version, 3);
  assert.deepEqual(sorted(again.db.objectStoreNames), sorted(STORES));
  again.close();
});

test("a_tab_on_version_2_is_closed_by_the_upgrade_to_version_3", async () => {
  const factory = new IDBFactory();
  let closed = 0;
  const old = await openVersion2(factory, () => {
    closed += 1;
  });
  await fill(old, { settings: [{ key: "device_id", value: "kept" }] });
  const opened = await Promise.race([
    openStore(factory, "ferret", IDBKeyRange),
    new Promise((_, reject) => setTimeout(() => reject(new Error("the upgrade was blocked by the old tab")), 2000)),
  ]);
  assert.equal(closed, 1, "the old tab was told");
  assert.equal(opened.db.version, 3);
  assert.deepEqual((await dump(opened.db, ["settings"])).settings.values, ["kept"]);
  opened.close();
});
