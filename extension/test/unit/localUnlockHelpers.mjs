// Helpers for the tests of the local PIN store: a small in-memory IndexedDB that
// logs its transactions, a `storage.session` stand-in, a clock, and a world that
// joins them with the store. Not a test file (the runner picks up *.test.mjs only).
import { createLocalUnlock, PIN_STORE, UNLOCK_DB_NAME } from "../../src/background/localUnlock.mjs";
import { createClock, createSessionStorage } from "./backgroundHelpers.mjs";

export const SERVER = "https://vault.example.com";
export const OTHER_SERVER = "https://other.example.com";
export const ACCOUNT = "a1".repeat(16);
export const ACCOUNT_2 = "b2".repeat(16);
export const DAY = 24 * 3600 * 1000;

const tick = () => new Promise((resolve) => setImmediate(resolve));

/** @param {unknown} key */
const encodeKey = (key) => JSON.stringify(key);

/**
 * An in-memory IndexedDB with what the PIN store uses: databases with out-of-line-key object stores, `get`, `put`,
 * `delete`, `getAllKeys`, `getAll` and `clear`, transactions that run one after the other, abort, and a log of every
 * transaction with its options. `acceptDurability: false` makes `transaction()` throw a TypeError for the options
 * argument, as an engine does that does not know them.
 */
export function createFakeIdb({ acceptDurability = true } = {}) {
  /** @type {Map<string, { version: number, stores: Map<string, Map<string, { key: unknown, value: unknown }>> }>} */
  const databases = new Map();
  /** @type {Array<{ db: string, stores: string[], mode: string, options: unknown, ops: string[], committed: boolean }>} */
  const log = [];
  const opens = { names: /** @type {string[]} */ ([]) };
  /** @type {Promise<void>} */
  let chain = Promise.resolve();
  const state = {
    /** @type {null | ((tx: { mode: string, ops: string[] }, op: string) => Error | null)} */
    failOp: null,
    opens: 0,
  };

  function makeDb(/** @type {string} */ name) {
    const data = /** @type {NonNullable<ReturnType<databases["get"]>>} */ (databases.get(name));
    const db = {
      name,
      version: data.version,
      objectStoreNames: { contains: (/** @type {string} */ n) => data.stores.has(n) },
      createObjectStore(/** @type {string} */ n) {
        data.stores.set(n, new Map());
      },
      close() {},
      onversionchange: null,
      onclose: null,
      transaction(/** @type {string[]} */ stores, /** @type {string} */ mode, /** @type {unknown} */ options) {
        if (options !== undefined && !acceptDurability) throw new TypeError("transaction: options not supported");
        return makeTransaction(name, data, stores, mode, options);
      },
    };
    return db;
  }

  /**
   * @param {string} dbName
   * @param {{ stores: Map<string, Map<string, { key: unknown, value: unknown }>> }} data
   * @param {string[]} storeNames @param {string} mode @param {unknown} options
   */
  function makeTransaction(dbName, data, storeNames, mode, options) {
    const entry = { db: dbName, stores: [...storeNames], mode, options, ops: /** @type {string[]} */ ([]), committed: false };
    log.push(entry);
    /** @type {Array<{ run: () => unknown, request: any, label: string }>} */
    const queue = [];
    /** @type {Map<string, Map<string, { key: unknown, value: unknown }>>} */
    let snapshot = new Map();
    const tx = /** @type {any} */ ({
      error: null,
      oncomplete: null,
      onerror: null,
      onabort: null,
      aborted: false,
      objectStore(/** @type {string} */ n) {
        const store = data.stores.get(n);
        if (!store || !storeNames.includes(n)) throw new Error(`no store ${n} in this transaction`);
        const add = (/** @type {string} */ label, /** @type {() => unknown} */ run) => {
          if (mode === "readonly" && label !== "get" && label !== "getAllKeys" && label !== "getAll") throw new Error("write in a readonly transaction");
          const request = { result: undefined, error: null, onsuccess: null, onerror: null };
          queue.push({ run, request, label: `${label}:${n}` });
          return request;
        };
        return {
          get: (/** @type {unknown} */ key) => add("get", () => structuredClone(store.get(encodeKey(key))?.value)),
          put: (/** @type {unknown} */ value, /** @type {unknown} */ key) =>
            add("put", () => {
              store.set(encodeKey(key), { key: structuredClone(key), value: structuredClone(value) });
              return structuredClone(key);
            }),
          delete: (/** @type {unknown} */ key) =>
            add("delete", () => {
              store.delete(encodeKey(key));
              return undefined;
            }),
          getAllKeys: () => add("getAllKeys", () => [...store.values()].map((e) => structuredClone(e.key))),
          getAll: () => add("getAll", () => [...store.values()].map((e) => structuredClone(e.value))),
          clear: () => add("clear", () => store.clear()),
        };
      },
      abort() {
        if (tx.finished) throw new Error("InvalidStateError");
        tx.aborted = true;
      },
    });
    tx.finished = false;
    chain = chain.then(async () => {
      snapshot = new Map([...data.stores].map(([n, m]) => [n, new Map(m)]));
      await tick();
      while (queue.length > 0 && !tx.aborted) {
        const item = queue.shift();
        if (!item) break;
        const injected = state.failOp?.({ mode, ops: entry.ops }, item.label) ?? null;
        if (injected) {
          item.request.error = injected;
          tx.error = injected;
          item.request.onerror?.({});
          tx.aborted = true;
          break;
        }
        entry.ops.push(item.label);
        item.request.result = item.run();
        item.request.onsuccess?.({});
        await tick();
      }
      tx.finished = true;
      if (tx.aborted) {
        data.stores = snapshot;
        tx.onabort?.({});
      } else {
        entry.committed = true;
        tx.oncomplete?.({});
      }
    });
    return tx;
  }

  const factory = /** @type {any} */ ({
    open(/** @type {string} */ name, /** @type {number} */ version = 1) {
      state.opens += 1;
      opens.names.push(name);
      const request = /** @type {any} */ ({ result: null, error: null, onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null });
      queueMicrotask(() => {
        let data = databases.get(name);
        const fresh = !data;
        if (!data) {
          data = { version, stores: new Map() };
          databases.set(name, data);
        }
        request.result = makeDb(name);
        if (fresh) request.onupgradeneeded?.({});
        request.onsuccess?.({});
      });
      return request;
    },
  });

  return {
    factory,
    log,
    opens,
    state,
    databases,
    /** The raw records of a store (decoded keys). @param {string} db @param {string} store */
    dump(db, store) {
      return [...(databases.get(db)?.stores.get(store)?.values() ?? [])].map((e) => ({ key: e.key, value: e.value }));
    },
    /** Puts a value straight into a store (a record a test wants to find). */
    plant(/** @type {string} */ db, /** @type {string} */ store, /** @type {unknown} */ key, /** @type {unknown} */ value) {
      let data = databases.get(db);
      if (!data) {
        data = { version: 1, stores: new Map() };
        databases.set(db, data);
      }
      let map = data.stores.get(store);
      if (!map) {
        map = new Map();
        data.stores.set(store, map);
      }
      map.set(encodeKey(key), { key: structuredClone(key), value: structuredClone(value) });
    },
  };
}

/** `storage.session` with a log of what was written. */
export function createSession() {
  const area = createSessionStorage();
  const writes = /** @type {string[]} */ ([]);
  return {
    data: area.data,
    writes,
    get: async (/** @type {string | string[] | null | undefined} */ keys) => {
      if (keys === null || keys === undefined) return Object.fromEntries(area.data);
      if (Array.isArray(keys)) return Object.fromEntries(keys.filter((k) => area.data.has(k)).map((k) => [k, area.data.get(k)]));
      return area.get(keys);
    },
    set: async (/** @type {Record<string, unknown>} */ items) => {
      for (const [k, v] of Object.entries(items)) writes.push(k);
      await area.set(items);
    },
    remove: async (/** @type {string | string[]} */ keys) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) await area.remove(key);
    },
  };
}

/** A blob the way the core hands it over after `wrap_pin`: no PIN, no kind, no length. */
export function makeBlob({ fill = 7, minLength = 6, vkEpoch = 3, pinProfile = 1 } = {}) {
  return {
    methodId: new Uint8Array(16).fill(fill),
    wrap: new Uint8Array(104).fill(fill + 1),
    deviceSalt: new Uint8Array(16).fill(fill + 2),
    pinProfile,
    vkEpoch,
    rule: { minLength },
  };
}

/** A fresh world: store, fake IndexedDB, fake session storage, clock. */
export function createWorld(options = {}) {
  const idb = createFakeIdb(options);
  const session = createSession();
  const clock = createClock(1_700_000_000_000);
  const store = createLocalUnlock({ idb: idb.factory, session, now: clock.now });
  /** A second store over the same data: the extension after a restart of the background (the session data stays). */
  const another = () => createLocalUnlock({ idb: idb.factory, session, now: clock.now });
  return { idb, session, clock, store, another };
}

/** A fake unlock that answers from a script and records how often it ran. @param {Array<"ok" | "wrong" | "stale" | "out_of_memory" | "throw">} script */
export function fakeUnlock(script) {
  const calls = { count: 0, blobs: /** @type {any[]} */ ([]) };
  const run = async (/** @type {any} */ blob) => {
    calls.count += 1;
    calls.blobs.push(blob);
    const step = script[Math.min(calls.count - 1, script.length - 1)];
    if (step === "throw") throw new Error("the unlock failed");
    if (step === "ok") return { ok: true };
    return { ok: false, reason: step };
  };
  return { run, calls };
}

export { PIN_STORE, UNLOCK_DB_NAME };
