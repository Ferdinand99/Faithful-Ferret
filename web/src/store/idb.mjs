// The browser's local storage for the vault: one IndexedDB database with seven
// object stores.
//
//   pinned          the non-secret record of what this device has seen of an account
//   rows            ciphertext rows of the sync feed (and nothing else)
//   outbox          writes that are waiting for the server, with their exact bytes
//   settings        small values, such as this browser's device id
//   device_secrets  the sealing key and the sealed secret key code of a device
//   sync_state      the non-secret sync memory of a server and account (what the
//                   device has seen, so a server cannot roll it back unnoticed)
//   trash           the last live row of an item that a verified tombstone deleted,
//                   kept as ciphertext for a while so the user can restore it
//
// Nothing here holds a master password, a recovery key or a vault key, and the
// decrypted item index never comes here: it lives in memory and is dropped on
// lock. Clearing the rows (and the trash, which is a copy of rows) leaves the
// other stores alone.
//
// The database is at version 2. Version 1 had the first five stores; the upgrade
// from it adds the last two and touches no existing record.

/** An error of the local store. `code` is a word for the caller to switch on. */
export class StoreError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "StoreError";
    /** @type {string} */
    this.code = code;
  }
}

export const STORES = Object.freeze(["pinned", "rows", "outbox", "settings", "device_secrets", "sync_state", "trash"]);

/** The version of the database that this code opens (and creates). */
export const DB_VERSION = 2;

/**
 * @typedef {object} Store
 * @property {IDBDatabase} db
 * @property {() => void} close
 * @property {typeof IDBKeyRange} keyRange the key range class that goes with the factory
 */

/**
 * Opens (and on first use creates) the database.
 * @param {IDBFactory} [factory]
 * @param {string} [name]
 * @param {typeof IDBKeyRange} [keyRange]
 * @param {() => void} [onclose] called when the browser closes the connection (another tab upgrades the database)
 * @returns {Promise<Store>}
 */
export function openStore(factory = indexedDB, name = "ferret", keyRange = globalThis.IDBKeyRange, onclose = () => {}) {
  return new Promise((resolve, reject) => {
    let request;
    try {
      request = factory.open(name, DB_VERSION);
    } catch (error) {
      reject(error);
      return;
    }
    request.onupgradeneeded = (event) => {
      const db = request.result;
      // Each step runs when the database is older than the version it makes, and
      // creates stores only: no existing record is read, moved or changed.
      if (event.oldVersion < 1) {
        // Version 1.
        const pinned = db.createObjectStore("pinned", { keyPath: ["serverUrl", "accountId"] });
        pinned.createIndex("by_email", ["serverUrl", "email"]);
        db.createObjectStore("rows");
        const outbox = db.createObjectStore("outbox", { autoIncrement: true });
        outbox.createIndex("by_scope", ["accountId", "vaultId", "vkEpoch"]);
        outbox.createIndex("by_idem", ["accountId", "vaultId", "vkEpoch", "idem"], { unique: true });
        db.createObjectStore("settings");
        db.createObjectStore("device_secrets");
      }
      if (event.oldVersion < 2) {
        // Version 2.
        db.createObjectStore("sync_state", { keyPath: ["serverUrl", "accountId"] });
        db.createObjectStore("trash", { keyPath: ["accountId", "vaultId", "vkEpoch", "itemId"] });
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      // Another tab upgrading the database must not be held up by this one.
      db.onversionchange = () => {
        db.close();
        onclose();
      };
      db.onclose = () => onclose();
      resolve({ db, close: () => db.close(), keyRange });
    };
    request.onerror = () => reject(request.error ?? new StoreError("open_failed", "the database did not open"));
  });
}

/**
 * The key a server is stored under: the origin of its address, so that
 * `https://vault.example` and `https://vault.example/` are one server.
 * @param {unknown} serverUrl
 * @returns {string}
 */
export function serverKey(serverUrl) {
  let url;
  try {
    url = new URL(/** @type {string} */ (serverUrl));
  } catch {
    throw new TypeError("a server address is a URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new TypeError("a server address is an http(s) URL");
  return url.origin;
}

/**
 * The result of a request, as a promise. A failing request does not abort the
 * transaction on its own: the caller's work rejects, and `run` aborts.
 * @template T
 * @param {IDBRequest<T>} request
 * @returns {Promise<T>}
 */
export function req(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = (event) => {
      event.preventDefault();
      reject(request.error ?? new StoreError("request_failed", "a request failed"));
    };
  });
}

/**
 * Runs `work` in one transaction over the object stores `names`; resolves with
 * its result once the transaction has committed. If `work` throws, nothing it
 * wrote stays. `work` may await `req(...)` results and nothing else.
 * @template T
 * @param {Store} store
 * @param {readonly string[]} names
 * @param {"readonly" | "readwrite"} mode
 * @param {(stores: IDBObjectStore[]) => Promise<T>} work
 * @returns {Promise<T>}
 */
export function run(store, names, mode, work) {
  return new Promise((resolve, reject) => {
    /** @type {IDBTransaction} */
    let tx;
    try {
      tx = store.db.transaction([...names], mode);
    } catch (error) {
      reject(error);
      return;
    }
    /** @type {T | undefined} */
    let result;
    /** @type {unknown} */
    let failure;
    let failed = false;
    tx.oncomplete = () => resolve(/** @type {T} */ (result));
    tx.onabort = () => {
      reject(failed ? failure : (tx.error ?? new StoreError("aborted", "the transaction was aborted")));
    };
    (async () => work(names.map((n) => tx.objectStore(n))))().then(
      (value) => {
        result = value;
      },
      (error) => {
        failed = true;
        failure = error;
        try {
          tx.abort();
        } catch {
          // already finished
        }
      },
    );
  });
}
