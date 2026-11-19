// The frozen stored formats: golden records of version 2 of the browser's database, one file per store in
// test/fixtures/stored/v2/. They are written into a database that has the version-2 schema (frozen in this
// file), and then read by the code as it is now. A change to what a store holds, or to the schema, needs a
// reader (or a migration) for these records and a new golden file for the new version; it never changes
// these files. The outbox entries have no import mark: the field does not exist in version 2, and an entry
// without it is an ordinary write.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { isDeepStrictEqual } from "node:util";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { hex16 } from "../../src/b64.mjs";
import { loadSecretKey, hasSecretKey } from "../../src/flows/deviceSecret.mjs";
import { deviceNameFor } from "../../src/sync/deviceName.mjs";
import { cache, ROW_FIELDS } from "../../src/store/cache.mjs";
import { DB_VERSION, openStore, run, req, STORES } from "../../src/store/idb.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { forgetPinned, loadPinned, loadPinnedAccount, loadPinnedByAccount, pinnedForSignIn, savePinned } from "../../src/store/pinned.mjs";
import { loadRestoreNote, saveRestoreNote } from "../../src/store/restoreNote.mjs";
import { deviceId, deviceSecrets, getSetting } from "../../src/store/settings.mjs";
import { loadSyncState, saveSyncState, STATE_FIELDS } from "../../src/store/syncState.mjs";
import { trash, TRASH_FIELDS } from "../../src/store/trash.mjs";
import { web } from "./helpers.mjs";

const GOLDEN = join(web, "test", "fixtures", "stored", "v2");
const ACCOUNT = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const OTHER = "f0e1d2c3b4a5968778695a4b3c2d1e0f";
const VAULT = "f9e8d7c6b5a4938271605f4e3d2c1b0a";
const SERVER = "https://vault.example";
const ITEM = { A: "a1a2a3a4a5a6a7a8a9aaabacadaeafb0", B: "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0", C: "c1c2c3c4c5c6c7c8c9cacbcccdcecfd0", D: "d1d2d3d4d5d6d7d8d9dadbdcdddedfe0" };
const SK_CODE = "FFS1-TESTA-TESTB-TESTC-TESTD-TESTE-TESTF";
const scope = (vkEpoch) => ({ accountId: ACCOUNT, vaultId: VAULT, vkEpoch });

/** The seven stores of version 2, and how each is keyed. Frozen: a later version adds its own list. */
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

// ------------------------------------------------------------------ golden files

/** A value from a golden file: {$bytes}, {$bigint} and {$aesGcmKey} (a test key, imported non-extractable) become their types. */
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

async function golden(store) {
  const file = JSON.parse(readFileSync(join(GOLDEN, `${store}.json`), "utf8"));
  assert.equal(file.format, "ferret-stored-golden/1");
  assert.equal(file.dbVersion, 2);
  assert.equal(file.store, store);
  return Promise.all(file.records.map(async ({ key, value }) => ({ key: key === undefined ? undefined : await decode(key), value: await decode(value) })));
}

// ------------------------------------------------------------------ the version-2 database

function openVersion2(factory) {
  return new Promise((resolve, reject) => {
    const request = factory.open("ferret", 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      for (const [name, { keyPath, autoIncrement, indexes }] of Object.entries(V2)) {
        const table = db.createObjectStore(name, { ...(keyPath ? { keyPath } : {}), ...(autoIncrement ? { autoIncrement } : {}) });
        for (const [index, path, options] of indexes ?? []) table.createIndex(index, path, options);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** A database that version-2 code wrote: the schema above and every golden record. Opened by the current code. */
async function goldenStore() {
  const factory = new IDBFactory();
  const raw = await openVersion2(factory);
  const all = {};
  for (const name of Object.keys(V2)) all[name] = await golden(name);
  await new Promise((resolve, reject) => {
    const tx = raw.transaction(Object.keys(V2), "readwrite");
    for (const [name, records] of Object.entries(all)) {
      const table = tx.objectStore(name);
      for (const { key, value } of records) {
        if (key === undefined) table.add(value);
        else table.put(value, key);
      }
    }
    tx.oncomplete = () => resolve(undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
  raw.close();
  return { store: await openStore(factory, "ferret", IDBKeyRange), factory, all };
}

async function freshStore() {
  return openStore(new IDBFactory(), "ferret", IDBKeyRange);
}

/** Every record of a store as read from the database: [{ key, value }] in key order. */
function dump(store, name) {
  return run(store, [name], "readonly", async ([table]) => {
    const out = [];
    await new Promise((resolve, reject) => {
      const cursor = table.openCursor();
      cursor.onsuccess = () => {
        const at = cursor.result;
        if (!at) return resolve(undefined);
        out.push({ key: at.key, value: at.value });
        at.continue();
      };
      cursor.onerror = () => reject(cursor.error);
    });
    return out;
  });
}

/** The form of a value: field names and types, never the content. */
function shapeOf(value) {
  if (value === null) return "null";
  if (value instanceof Uint8Array) return "bytes";
  if (typeof value === "bigint") return "bigint";
  if (typeof CryptoKey !== "undefined" && value instanceof CryptoKey) return "CryptoKey";
  if (Array.isArray(value)) return value.map(shapeOf);
  if (typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((k) => [k, shapeOf(value[k])]));
  return typeof value;
}

const sortedKeys = (value) => Object.keys(value).sort();

// ------------------------------------------------------------------ tests

test("stored_records_of_version_2_are_read_by_the_current_code", async () => {
  // Every store of version 2 has a golden file, and the code still opens the same seven.
  assert.deepEqual(readdirSync(GOLDEN).sort(), Object.keys(V2).map((n) => `${n}.json`).sort());
  for (const name of Object.keys(V2)) assert.ok(STORES.includes(name), `${name} is still a store`);
  assert.ok(DB_VERSION >= 2);

  const { store, all } = await goldenStore();

  // Opening the database with the current code changes no record.
  for (const name of Object.keys(V2)) {
    const stored = await dump(store, name);
    const expected = all[name];
    assert.equal(stored.length, expected.length, name);
    for (const [i, record] of expected.entries()) {
      const found = stored.some((s) => {
        if (record.key !== undefined && !isDeepStrictEqual(s.key, record.key)) return false;
        // A CryptoKey has no fields to compare: its nonce and sealed bytes stand for the record.
        if (name === "device_secrets") return isDeepStrictEqual(s.value.iv, record.value.iv) && isDeepStrictEqual(s.value.sealed, record.value.sealed);
        return isDeepStrictEqual(s.value, record.value);
      });
      assert.ok(found, `${name}: record ${i} is as it was written`);
    }
  }

  // pinned: by e-mail, by account, for a sign-in; and the record passes the checks of a save.
  const [alice, other] = all.pinned.map((r) => r.value);
  assert.deepEqual(await loadPinned(store, SERVER, "alice@example.test"), alice.record);
  assert.deepEqual(await loadPinned(store, SERVER, "  Alice@Example.TEST "), alice.record, "the e-mail index is the normalized form");
  assert.deepEqual(await loadPinnedByAccount(store, SERVER, ACCOUNT), alice.record);
  assert.deepEqual(await loadPinnedByAccount(store, SERVER, OTHER), other.record);
  assert.deepEqual(await loadPinnedAccount(store, SERVER, ACCOUNT), { email: "alice@example.test" });
  assert.deepEqual(await loadPinnedAccount(store, SERVER, OTHER), { email: null });
  assert.equal(await loadPinned(store, SERVER, "nobody@example.test"), null);
  assert.deepEqual(await pinnedForSignIn(store, SERVER, "alice@example.test", ACCOUNT), alice.record);
  assert.deepEqual(await pinnedForSignIn(store, SERVER, "moved@example.test", OTHER), other.record, "an account whose e-mail changed elsewhere is found by its id");
  await savePinned(store, SERVER, ACCOUNT, "alice@example.test", alice.record);
  await savePinned(store, SERVER, OTHER, "other@example.test", other.record);
  assert.deepEqual(await loadPinned(store, SERVER, "other@example.test"), other.record);
  assert.equal(typeof alice.record.kek_generation_max[1].generation, "bigint", "the core's u64 can be a bigint");

  // rows: in seq order per scope, and the rows pass the checks of a write.
  const rows2 = await cache.getRows(store, scope(2));
  assert.deepEqual(rows2.map((r) => r.itemId), [ITEM.B, ITEM.A, ITEM.C]);
  assert.deepEqual(rows2.map((r) => r.seq), [7, 12, 20]);
  assert.deepEqual(rows2, all.rows.filter((r) => r.key[2] === 2).map((r) => r.value).sort((a, b) => a.seq - b.seq));
  assert.equal(rows2[2].deleted, true);
  assert.equal(rows2[2].tomb.length, 40);
  assert.equal(await cache.maxSeq(store, scope(2)), 20);
  assert.deepEqual((await cache.getRows(store, scope(1))).map((r) => r.itemId), [ITEM.D]);
  assert.deepEqual(await cache.getRows(store, scope(9)), []);
  const rewritten = await freshStore();
  await cache.putRows(rewritten, scope(2), rows2);
  assert.deepEqual(await cache.getRows(rewritten, scope(2)), rows2);

  // outbox: oldest first, exact bytes, no import mark; the entries pass the checks of a queue.
  const queued = await outbox.all(store, scope(2));
  assert.equal(queued.length, 4);
  assert.deepEqual(queued.map((e) => e.idem), all.outbox.slice(0, 4).map((r) => r.value.idem));
  assert.deepEqual(queued.map((e) => e.baseRev), [0, 3, 4, 5]);
  for (const entry of queued) {
    assert.deepEqual(sortedKeys(entry), ["baseRev", "body", "bytes", "idem", "itemId"], "an entry of version 2 has no import mark");
    assert.ok(hex16.is(entry.idem) && hex16.is(entry.itemId));
  }
  for (const record of all.outbox) assert.equal(Object.hasOwn(record.value, "import"), false);
  const body = JSON.parse(new TextDecoder().decode(queued[1].bytes));
  assert.equal(body.base_rev, 3);
  assert.equal(body.restore_epoch, 1700000000);
  assert.deepEqual(Object.keys(JSON.parse(new TextDecoder().decode(queued[2].bytes))).sort(), ["base_rev", "deleted", "idem", "tomb"]);
  assert.equal(JSON.parse(new TextDecoder().decode(queued[3].bytes)).resurrect, true);
  assert.equal((await outbox.all(store, scope(3))).length, 1);
  assert.deepEqual(await outbox.all(store, scope(4)), []);
  const requeued = await freshStore();
  for (const entry of queued) await outbox.enqueue(requeued, scope(2), entry);
  assert.deepEqual(await outbox.all(requeued, scope(2)), queued);
  await outbox.remove(store, scope(2), queued[0].idem);
  assert.equal((await outbox.all(store, scope(2))).length, 3);

  // settings: the device id is kept, the note is read, the name is used.
  const id = await deviceId(store, () => assert.fail("the stored device id is used, a new one is not made"));
  assert.equal(id, "7e3a9c1f5b2d48a6b0c4d8e2f6a1b3c5");
  const note = await loadRestoreNote(store, SERVER, ACCOUNT, 1767225600000 + 1000);
  assert.deepEqual(note, { acceptedAt: 1767225600000, restoreEpoch: 1767225000, manifestOlder: true });
  assert.equal(await loadRestoreNote(store, SERVER, OTHER, 1767225600000 + 1000), null);
  assert.equal(await deviceNameFor({ open: async () => store, getSetting }, { userAgent: "x" }), "Firefox on Linux");

  // device_secrets: the sealed secret key opens under the stored key, for its own account only.
  const secret = await deviceSecrets.get(store, SERVER, ACCOUNT);
  assert.deepEqual(sortedKeys(secret), ["iv", "key", "sealed"]);
  assert.equal(secret.key.extractable, false);
  assert.equal(secret.key.algorithm.name, "AES-GCM");
  assert.equal(secret.iv.length, 12);
  assert.equal(await hasSecretKey(store, SERVER, ACCOUNT), true);
  assert.equal(await loadSecretKey(store, SERVER, ACCOUNT), SK_CODE);
  assert.equal(await loadSecretKey(store, SERVER, OTHER), null);
  assert.equal(await deviceSecrets.get(store, SERVER, OTHER), null);

  // sync_state: the full record, and a record from before verifiedSeq existed (read as null).
  const [full, old] = all.sync_state.map((r) => r.value);
  const { serverUrl: _s1, accountId: _a1, ...fullState } = full;
  assert.deepEqual(await loadSyncState(store, SERVER, ACCOUNT), fullState);
  const { serverUrl: _s2, accountId: _a2, ...oldState } = old;
  assert.equal(Object.hasOwn(oldState, "verifiedSeq"), false);
  assert.deepEqual(await loadSyncState(store, SERVER, OTHER), { ...oldState, verifiedSeq: null });
  assert.equal(await loadSyncState(store, SERVER, "00000000000000000000000000000001"), null);
  const resaved = await freshStore();
  await saveSyncState(resaved, SERVER, ACCOUNT, fullState);
  assert.deepEqual(await loadSyncState(resaved, SERVER, ACCOUNT), fullState);

  // trash: the most recently deleted first, per scope.
  const bin = await trash.all(store, scope(2));
  assert.deepEqual(bin.map((e) => e.itemId), [ITEM.B, ITEM.A]);
  assert.deepEqual(sortedKeys(bin[0]), ["deletedAt", "envelope", "itemId", "rev", "tag", "tombRev"]);
  assert.deepEqual((await trash.get(store, scope(2), ITEM.A)).tombRev, 4);
  assert.deepEqual((await trash.all(store, scope(1))).map((e) => e.itemId), [ITEM.D]);
  const rebinned = await freshStore();
  for (const entry of bin) await trash.put(rebinned, scope(2), entry);
  assert.deepEqual(await trash.all(rebinned, scope(2)), bin);

  // Forgetting one account removes its record and leaves the other.
  await forgetPinned(store, SERVER, OTHER);
  assert.equal(await loadPinnedByAccount(store, SERVER, OTHER), null);
  assert.deepEqual(await loadPinnedByAccount(store, SERVER, ACCOUNT), alice.record);
});

test("a_changed_stored_shape_without_a_reader_fails", async () => {
  const { all } = await goldenStore();
  const fresh = await freshStore();
  const first = (name) => all[name][0].value;

  // 1. What the code writes today has the form of the golden records. A writer that adds, renames or retypes a
  //    field makes one of these fail, until the new form has a reader for the old one and its own golden file.
  const [alice] = all.pinned.map((r) => r.value);
  await savePinned(fresh, SERVER, ACCOUNT, "alice@example.test", alice.record);
  assert.deepEqual(shapeOf((await dump(fresh, "pinned"))[0].value), shapeOf(alice), "pinned");

  await cache.putRows(fresh, scope(2), all.rows.filter((r) => r.key[2] === 2).map((r) => r.value));
  for (const { key, value } of all.rows.filter((r) => r.key[2] === 2)) {
    const written = (await dump(fresh, "rows")).find((r) => JSON.stringify(r.key) === JSON.stringify(key));
    assert.deepEqual(shapeOf(written.value), shapeOf(value), "rows");
  }

  for (const { value } of all.outbox.filter((r) => r.value.vkEpoch === 2)) {
    await outbox.enqueue(fresh, scope(2), { idem: value.idem, itemId: value.itemId, baseRev: value.baseRev, body: value.body, bytes: value.bytes });
  }
  const written = await dump(fresh, "outbox");
  assert.deepEqual(written.map((r) => shapeOf(r.value)), all.outbox.filter((r) => r.value.vkEpoch === 2).map((r) => shapeOf(r.value)), "outbox");

  const noteKey = `restore.note.${SERVER}.${ACCOUNT}`;
  const noteRecord = all.settings.find((r) => r.key === noteKey);
  await saveRestoreNote(fresh, SERVER, ACCOUNT, noteRecord.value);
  const idRecord = all.settings.find((r) => r.key === "device_id");
  await deviceId(fresh, () => Uint8Array.from(Buffer.from(idRecord.value, "hex")));
  const settings = await dump(fresh, "settings");
  for (const record of [noteRecord, idRecord]) {
    const at = settings.find((r) => r.key === record.key);
    assert.ok(at, `${record.key} is written under the key of the golden record`);
    assert.deepEqual(shapeOf(at.value), shapeOf(record.value), "settings");
  }

  const secret = first("device_secrets");
  await deviceSecrets.put(fresh, SERVER, ACCOUNT, secret);
  assert.deepEqual(shapeOf((await dump(fresh, "device_secrets"))[0].value), shapeOf(secret), "device_secrets");

  const { serverUrl: _s, accountId: _a, ...state } = first("sync_state");
  await saveSyncState(fresh, SERVER, ACCOUNT, state);
  assert.deepEqual(shapeOf((await dump(fresh, "sync_state"))[0].value), shapeOf(first("sync_state")), "sync_state");

  const { accountId: _t1, vaultId: _t2, vkEpoch: _t3, ...entry } = first("trash");
  await trash.put(fresh, scope(2), entry);
  assert.deepEqual(shapeOf((await dump(fresh, "trash"))[0].value), shapeOf(first("trash")), "trash");

  // 2. The field lists that the code declares are the fields of the golden records.
  assert.deepEqual([...ROW_FIELDS].sort(), sortedKeys(first("rows")));
  assert.deepEqual([...TRASH_FIELDS, "accountId", "vaultId", "vkEpoch"].sort(), sortedKeys(first("trash")));
  assert.deepEqual([...STATE_FIELDS, "serverUrl", "accountId"].sort(), sortedKeys(first("sync_state")));

  // 3. The comparison itself catches an added field, a renamed one, a retyped one and a lost one.
  const base = first("trash");
  const same = shapeOf(base);
  for (const changed of [
    { ...base, extra: 1 },
    (({ rev, ...rest }) => ({ ...rest, revision: rev }))(base),
    { ...base, rev: String(base.rev) },
    { ...base, envelope: Array.from(base.envelope) },
    (({ tag, ...rest }) => rest)(base),
  ]) {
    assert.notDeepEqual(shapeOf(changed), same);
  }

  // 4. A stored record that has a shape the reader does not know is refused, not guessed at.
  const damaged = await freshStore();
  const key = [SERVER, ACCOUNT];
  const putRaw = (name, value) => run(damaged, [name], "readwrite", async ([table]) => { await req(table.put(value)); });
  const syncState = { serverUrl: SERVER, accountId: ACCOUNT, ...state };
  for (const record of [
    { ...syncState, extraField: 1 },
    { ...syncState, verifiedAt: "yesterday" },
    { ...syncState, memory: "not bytes" },
    { ...syncState, restore: { epoch: 1, phase: "unknown" } },
  ]) {
    await putRaw("sync_state", record);
    await assert.rejects(loadSyncState(damaged, key[0], key[1]), (e) => e.code === "sync_state_malformed");
  }
  // The rows and the trash refuse a field they do not hold when they are written, so a new field cannot slip in beside the old ones.
  await assert.rejects(cache.putRows(damaged, scope(2), [{ ...first("rows"), extra: 1 }]), (e) => e.code === "row_field");
  await assert.rejects(trash.put(damaged, scope(2), { ...entry, extra: 1 }), (e) => e.code === "trash_field");
});
