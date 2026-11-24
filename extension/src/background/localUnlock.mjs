// The local PIN store of the extension: the only code that holds the wrapped vault key
// that a PIN opens, of its attempt counter and of the offline window (design
// document, sections 7.1, 7.2 and 7.6).
//
// What this module is
//
//  * A record per `[server, account]` that holds the PIN wrap (a ciphertext, no
//    secret in clear text), the device salt, the PIN profile, the vault-key
//    epoch, the rule it was made under and the counters below. The PIN itself,
//    its length and its kind (digits or text) are never stored: the record has
//    no field for them and `save` refuses a blob that has one.
//  * Two places for the record. `disk` (the default): the extension's own
//    IndexedDB database `ferret-unlock`, store `pin`, so the PIN works after a
//    restart. `session`: `storage.session`, gone after a restart. Nothing is
//    ever written to the extension's local storage area (a content process can write there), and
//    never to the shared `ferret` database. A record lives in exactly one of
//    the two places; moving it removes it from the old one.
//  * The attempt counter (`failures`) in the same record. `attempt` raises it
//    and writes it (durability "strict") BEFORE the unlock runs, so killing the
//    process during the Argon2id run still costs an attempt. Five failures wipe
//    the record; a record found with five failures is wiped without any
//    unlock. The result is written in a separate transaction: a success
//    resets the counter, a failure sets the time of the failure. One attempt at
//    a time (a mutex). A master-password unlock calls `resetFailures`.
//  * The waits 0, 0, 5, 15 and 30 seconds before attempts 1 to 5, counted from
//    the last failure in the record.
//  * The offline window: without the server a PIN opens the vault only within
//    seven days of the last contact (`lastContactAt`, set by `markContact`
//    after a successful token renewal, also while the vault is locked) and only
//    while the clock has not been set back below the highest time the
//    extension has seen (`highestSeenAt`, moved by `tick`). `highestSeenAt`
//    never extends the window; it only guards against a clock set back.
//    `lastOnlineAt` (`markOnline`) is for display and plays no part in the
//    window.
//
// What this module cannot do (said plainly)
//
//  * A copy of the browser profile holds the record. The counter and the
//    window live in that copy too, so whoever has the copy resets them by
//    restoring the copy, and tries PINs on their own computer, one Argon2id
//    per guess, without the limit of five. That is the documented risk of
//    keeping the PIN on disk; the strength of the PIN profile and the length
//    of the PIN are the only defence there. The same holds for a PIN kept in
//    `storage.session` while the browser runs and the profile is read.
//  * The counter cannot be reset by a web page, by a content script or by
//    deleting a single key: pages cannot reach the extension's IndexedDB or
//    `storage.session`, a record with a missing, malformed or extra field is
//    wiped (fail closed), and the counter sits in the same record as the wrap.
//    Deleting the whole record is a wipe: the PIN is gone, which is the safe
//    direction.
//  * A wipe is not a secure delete. IndexedDB in Firefox keeps SQLite's free
//    pages (the probe found no `secure_delete`), and an overwrite before the
//    delete is not reliable there either (one release kept the old bytes, the
//    ESR did not). A wipe here overwrites the record (and marks it as used up,
//    so a crash between the two steps still ends in a wipe) and then deletes
//    it; do not read that as proof that the bytes are gone from the disk.
//  * The clock is the machine's. Someone who controls it before the extension
//    has seen a later time can pick the time; the window and the rollback
//    guard are a limit on a revoked device that is kept offline, not a defence
//    against whoever controls the machine.
//
// The module imports nothing: it takes the IndexedDB factory, the session
// storage area and the clock from its caller, and it neither logs nor puts a
// value of a record into an error.

/** The attempts a record survives: the fifth failure wipes it. */
export const MAX_PIN_FAILURES = 5;

/** The wait before attempt 1 to 5, counted from the last failure in the record. */
export const PIN_WAIT_MS = Object.freeze([0, 0, 5_000, 15_000, 30_000]);

/** How long after the last contact with the server a PIN works without it. */
export const OFFLINE_PIN_WINDOW_MS = 7 * 24 * 3600 * 1000;

/** The extension's own database for the PIN record and the cached rule. Opened here and nowhere else. */
export const UNLOCK_DB_NAME = "ferret-unlock";
/** The object store of the PIN records (out-of-line key `[serverOrigin, accountId]`). */
export const PIN_STORE = "pin";
/** The object store of the cached admin rules (out-of-line key: the server origin). */
export const POLICY_STORE = "policy";
/** The start of every key this module writes to the session storage. */
export const SESSION_KEY_PREFIX = "ferretPin|";

/** `highestSeenAt` is written at most this often by `tick` (a disk write per tick would be a waste). */
const TICK_STEP_MS = 60_000;

/** The size of a PIN wrap (nonce, ciphertext and tag of a 32-byte key) and of the device salt. */
const WRAP_BYTES = 104;
const DEVICE_SALT_BYTES = 16;
const MAX_ID_BYTES = 64;

/** Why a record is wiped. A wipe never counts as an attempt and never runs the unlock. */
export const WIPE_REASONS = Object.freeze([
  "failures", //            five failures
  "pin_off", //             the user turned the PIN off
  "signed_out", //          sign-out (also without a network)
  "forgot_server", //       "forget this server"
  "device_revoked", //      the renewal of the tokens answered `device_revoked`
  "token_reused", //        ... `token_reused`
  "token_expired", //       ... `token_expired`
  "new_sign_in", //         a new sign-in with the master password
  "vk_epoch", //            the pinned record has a higher vault-key epoch
  "pinned_missing", //      the pinned record is missing
  "pinned_rejected", //     the pinned record rejects the blob
  "pk_mismatch", //         the blob's vault key does not give the pinned `pk_a`
  "rule_stricter", //       the admin's rule is stricter than the one the PIN was made under
  "pin_forbidden", //       the admin turned PIN off
  "after_restart_off", //   the admin turned "PIN after restart" off (the disk record)
  "unknown_profile", //     the PIN profile is unknown or too low
  "stale", //               the core says the blob is stale
  "moved", //               the record moved to the other place
  "corrupt", //             the record has the wrong shape (a record is never repaired)
]);

/** @typedef {typeof WIPE_REASONS[number]} WipeReason */
/** @typedef {"disk" | "session"} Location */

/** @typedef {{ minLength: number }} PinRule */

/**
 * What the core hands over after `wrap_pin` (and gets back at an unlock): no PIN, no length, no kind.
 * @typedef {object} PinBlob
 * @property {Uint8Array} methodId
 * @property {Uint8Array} wrap
 * @property {Uint8Array} deviceSalt
 * @property {number} pinProfile
 * @property {number} vkEpoch
 * @property {PinRule} rule
 */

/**
 * The stored record: the blob and the counters.
 * @typedef {PinBlob & {
 *   failures: number,
 *   lastFailureAt: number | null,
 *   lastContactAt: number | null,
 *   lastOnlineAt: number | null,
 *   highestSeenAt: number,
 *   createdAt: number,
 * }} PinRecord
 */

/**
 * The admin's rule as `GET /api/vault/policy` gives it.
 * @typedef {{ pin: { allowed: boolean, after_restart: boolean, min_length: number }, prf: { enabled: boolean } }} Policy
 */

/**
 * What the caller's unlock (the core's `pin_unlock` over the vault worker) answers. `stale`: the blob is not
 * valid any more (unknown profile, lower epoch); it is wiped and not counted. Anything else than `{ ok: true }` or one
 * of these reasons counts as a wrong PIN, as does a throw.
 * @typedef {{ ok: true } | { ok: false, reason: "wrong" | "stale" | "out_of_memory" }} UnlockAnswer
 */

/** @typedef {(blob: PinBlob) => Promise<UnlockAnswer>} TryUnlock */

/**
 * @typedef {object} SessionArea the shape of `storage.session`
 * @property {(keys?: string | string[] | null) => Promise<Record<string, any>>} get
 * @property {(items: Record<string, any>) => Promise<void>} set
 * @property {(keys: string | string[]) => Promise<void>} remove
 */

/**
 * @typedef {object} PinStatus
 * @property {boolean} set whether a record exists
 * @property {Location | null} location
 * @property {number} failuresLeft
 * @property {number} waitMs how long until the next attempt is allowed
 * @property {boolean} offlineOk whether a PIN works without the server now
 * @property {number | null} lastOnlineAt for display only
 */

/** @typedef {"ok" | "wrong" | "wiped" | "stale" | "wait" | "offline_expired" | "out_of_memory" | "none"} AttemptResult */

/** The error of this module: a short code, never a value of a record. */
export class PinStoreError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "PinStoreError";
    this.code = code;
  }
}

// ------------------------------------------------------------------ helpers

/**
 * A Uint8Array, also one that was made in another realm (a value that comes back from IndexedDB or from a message may
 * not be an instance of this realm's constructor, and `instanceof` would call a good record bad).
 * @param {unknown} value @returns {value is Uint8Array}
 */
const isBytes = (value) => ArrayBuffer.isView(value) && Object.prototype.toString.call(value) === "[object Uint8Array]";

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value) && !isBytes(value);

/** @param {unknown} value @param {number} min @param {number} max */
const isInt = (value, min, max) => typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;

/** @param {unknown} value */
const isTime = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;

/** @param {Uint8Array} bytes */
function toB64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** @param {unknown} text @returns {Uint8Array | null} */
function fromB64(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) return null;
  try {
    const raw = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** The origin of a server address, as the other stores key it. @param {string} serverUrl */
function serverOrigin(serverUrl) {
  let url;
  try {
    url = new URL(serverUrl);
  } catch {
    throw new PinStoreError("bad_server");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new PinStoreError("bad_server");
  return url.origin;
}

/** @param {string} accountId */
function accountKey(accountId) {
  if (typeof accountId !== "string" || !/^[0-9a-f]{32}$/.test(accountId)) throw new PinStoreError("bad_account");
  return accountId;
}

/** @param {string} server an origin @param {string} account */
const sessionKey = (server, account) => `${SESSION_KEY_PREFIX}${encodeURIComponent(server)}|${account}`;

/** Overwrites the byte arrays of a record with zeros: the buffers of a record never stay around. @param {Partial<PinBlob> | null | undefined} blob */
function zeroBlob(blob) {
  if (!blob) return;
  for (const field of /** @type {const} */ (["methodId", "wrap", "deviceSalt"])) {
    const bytes = blob[field];
    if (isBytes(bytes)) bytes.fill(0);
  }
}

/** @param {Uint8Array} a @param {Uint8Array} b */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const BLOB_KEYS = Object.freeze(["methodId", "wrap", "deviceSalt", "pinProfile", "vkEpoch", "rule"]);
const RECORD_KEYS = Object.freeze([...BLOB_KEYS, "failures", "lastFailureAt", "lastContactAt", "lastOnlineAt", "highestSeenAt", "createdAt"].sort());

/** @param {Record<string, unknown>} object @param {readonly string[]} keys the exact set, sorted or not */
function hasExactKeys(object, keys) {
  const own = Object.keys(object).sort();
  const want = [...keys].sort();
  return own.length === want.length && own.every((key, i) => key === want[i]);
}

/**
 * Checks the blob a caller wants to save and copies it. No field for a PIN, its length or its kind: an extra key is
 * refused, whatever its name.
 * @param {unknown} blob
 * @returns {PinBlob}
 */
function copyBlob(blob) {
  if (!isObject(blob) || !hasExactKeys(blob, BLOB_KEYS)) throw new PinStoreError("bad_blob");
  const { methodId, wrap, deviceSalt, pinProfile, vkEpoch, rule } = blob;
  if (!isBytes(methodId) || methodId.length < 1 || methodId.length > MAX_ID_BYTES) throw new PinStoreError("bad_blob");
  if (!isBytes(wrap) || wrap.length !== WRAP_BYTES) throw new PinStoreError("bad_blob");
  if (!isBytes(deviceSalt) || deviceSalt.length !== DEVICE_SALT_BYTES) throw new PinStoreError("bad_blob");
  if (!isInt(pinProfile, 1, 255) || !isInt(vkEpoch, 0, Number.MAX_SAFE_INTEGER)) throw new PinStoreError("bad_blob");
  if (!isObject(rule) || !hasExactKeys(rule, ["minLength"]) || !isInt(rule.minLength, 4, 64)) throw new PinStoreError("bad_blob");
  return {
    methodId: methodId.slice(),
    wrap: wrap.slice(),
    deviceSalt: deviceSalt.slice(),
    pinProfile: /** @type {number} */ (pinProfile),
    vkEpoch: /** @type {number} */ (vkEpoch),
    rule: { minLength: /** @type {number} */ (rule.minLength) },
  };
}

/**
 * Checks a record read from a store. Anything that does not have exactly the shape of a record is not repaired and
 * not trusted: the caller wipes it.
 * @param {unknown} value
 * @returns {PinRecord | null}
 */
function checkRecord(value) {
  if (!isObject(value) || !hasExactKeys(value, RECORD_KEYS)) return null;
  const { methodId, wrap, deviceSalt, pinProfile, vkEpoch, rule, failures, lastFailureAt, lastContactAt, lastOnlineAt, highestSeenAt, createdAt } = value;
  if (!isBytes(methodId) || methodId.length < 1 || methodId.length > MAX_ID_BYTES) return null;
  if (!isBytes(wrap) || wrap.length !== WRAP_BYTES) return null;
  if (!isBytes(deviceSalt) || deviceSalt.length !== DEVICE_SALT_BYTES) return null;
  if (!isInt(pinProfile, 1, 255) || !isInt(vkEpoch, 0, Number.MAX_SAFE_INTEGER)) return null;
  if (!isObject(rule) || !hasExactKeys(rule, ["minLength"]) || !isInt(rule.minLength, 4, 64)) return null;
  if (!isInt(failures, 0, MAX_PIN_FAILURES)) return null;
  for (const time of [lastFailureAt, lastContactAt, lastOnlineAt]) if (time !== null && !isTime(time)) return null;
  if (!isTime(highestSeenAt) || !isTime(createdAt)) return null;
  return /** @type {PinRecord} */ (value);
}

/** A record for the session storage: bytes as base64url (storage areas differ in what they clone). @param {PinRecord} record */
function encodeRecord(record) {
  return { ...record, methodId: toB64(record.methodId), wrap: toB64(record.wrap), deviceSalt: toB64(record.deviceSalt) };
}

/** @param {unknown} value @returns {unknown} */
function decodeRecord(value) {
  if (!isObject(value)) return null;
  const methodId = fromB64(value.methodId);
  const wrap = fromB64(value.wrap);
  const deviceSalt = fromB64(value.deviceSalt);
  if (!methodId || !wrap || !deviceSalt) return null;
  return { ...value, methodId, wrap, deviceSalt };
}

/**
 * The record with its secrets-to-be overwritten and marked as used up (failures at the limit): what a wipe writes
 * before it deletes, so a crash in between leaves a record that the next attempt wipes without any unlock.
 * @param {PinRecord} record
 * @returns {PinRecord}
 */
function spent(record) {
  return {
    methodId: new Uint8Array(record.methodId.length),
    wrap: new Uint8Array(record.wrap.length),
    deviceSalt: new Uint8Array(record.deviceSalt.length),
    pinProfile: record.pinProfile,
    vkEpoch: record.vkEpoch,
    rule: { minLength: record.rule.minLength },
    failures: MAX_PIN_FAILURES,
    lastFailureAt: record.lastFailureAt,
    lastContactAt: null,
    lastOnlineAt: null,
    highestSeenAt: record.highestSeenAt,
    createdAt: record.createdAt,
  };
}

/** @param {unknown} policy @returns {Policy} */
function checkPolicy(policy) {
  if (!isObject(policy) || !isObject(policy.pin) || !isObject(policy.prf)) throw new PinStoreError("bad_policy");
  const { allowed, after_restart: afterRestart, min_length: minLength } = policy.pin;
  if (typeof allowed !== "boolean" || typeof afterRestart !== "boolean" || !isInt(minLength, 4, 64) || typeof policy.prf.enabled !== "boolean") {
    throw new PinStoreError("bad_policy");
  }
  return { pin: { allowed, after_restart: afterRestart, min_length: /** @type {number} */ (minLength) }, prf: { enabled: policy.prf.enabled } };
}

/**
 * The reason a record may not stay under a rule, or null.
 * @param {Policy} policy
 * @param {PinRecord} record
 * @param {Location} location
 * @returns {WipeReason | null}
 */
function ruleForbids(policy, record, location) {
  if (!policy.pin.allowed) return "pin_forbidden";
  if (location === "disk" && !policy.pin.after_restart) return "after_restart_off";
  if (record.rule.minLength < policy.pin.min_length) return "rule_stricter";
  return null;
}

/** @param {PinRecord} record @param {number} t the wait left before the next attempt */
function waitLeft(record, t) {
  if (record.failures === 0 || record.failures >= MAX_PIN_FAILURES || record.lastFailureAt === null) return 0;
  const wait = PIN_WAIT_MS[record.failures];
  // A clock set back must not lock a PIN for longer than the longest wait.
  return Math.min(wait, Math.max(0, record.lastFailureAt + wait - t));
}

/** Whether a PIN may work without the server at time `t`. @param {PinRecord} record @param {number} t */
function offlineOk(record, t) {
  if (record.lastContactAt === null) return false;
  if (t < record.highestSeenAt || t < record.lastContactAt) return false; // the clock was set back
  return t - record.lastContactAt <= OFFLINE_PIN_WINDOW_MS;
}

// ---------------------------------------------------------------- IndexedDB

/** @template T @param {IDBRequest<T>} request @returns {Promise<T>} */
function req(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("request failed"));
  });
}

/**
 * Opens a transaction. A write asks for `durability: "strict"`; an engine that refuses the option gets the default
 * (Firefox's default flushes before `complete`, so the counter is on disk either way).
 * @param {IDBDatabase} db @param {string[]} stores @param {IDBTransactionMode} mode
 */
function openTransaction(db, stores, mode) {
  if (mode === "readwrite") {
    try {
      return db.transaction(stores, mode, { durability: "strict" });
    } catch (error) {
      if (/** @type {Error} */ (error)?.name !== "TypeError") throw error;
    }
  }
  return db.transaction(stores, mode);
}

/**
 * Runs `work` in one transaction and resolves when the transaction has committed. `work` may await IndexedDB requests
 * only.
 * @template T
 * @param {IDBDatabase} db @param {string[]} stores @param {IDBTransactionMode} mode
 * @param {(tx: IDBTransaction) => Promise<T>} work
 * @returns {Promise<T>}
 */
async function inTransaction(db, stores, mode, work) {
  const tx = openTransaction(db, stores, mode);
  /** @type {Promise<Error | null>} */
  const finished = new Promise((resolve) => {
    tx.oncomplete = () => resolve(null);
    tx.onerror = () => resolve(tx.error ?? new Error("transaction failed"));
    tx.onabort = () => resolve(tx.error ?? new Error("transaction aborted"));
  });
  /** @type {T} */
  let value;
  try {
    value = await work(tx);
  } catch (error) {
    try {
      tx.abort();
    } catch {
      // already finished
    }
    await finished;
    throw error;
  }
  const problem = await finished;
  if (problem) throw problem;
  return value;
}

// ------------------------------------------------------------------ factory

/**
 * @param {object} options
 * @param {IDBFactory} [options.idb] the extension's IndexedDB (the default is the global one)
 * @param {SessionArea} options.session `storage.session`
 * @param {() => number} [options.now] the clock, in ms since the epoch
 */
export function createLocalUnlock({ idb, session, now = Date.now }) {
  const factory = idb ?? globalThis.indexedDB;

  /** @type {Promise<IDBDatabase> | null} */
  let opened = null;
  /** The database, opened on first use. The only open of `ferret-unlock`. */
  function database() {
    opened ??= new Promise((resolve, reject) => {
      const request = factory.open(UNLOCK_DB_NAME, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(PIN_STORE)) db.createObjectStore(PIN_STORE);
        if (!db.objectStoreNames.contains(POLICY_STORE)) db.createObjectStore(POLICY_STORE);
      };
      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => {
          db.close();
          opened = null;
        };
        db.onclose = () => {
          opened = null;
        };
        resolve(db);
      };
      request.onerror = () => reject(request.error ?? new Error("open failed"));
      request.onblocked = () => reject(new Error("open blocked"));
    }).catch((error) => {
      opened = null;
      throw error;
    });
    return opened;
  }

  // One short lock for every read-modify-write (the session storage has no transactions).
  /** @type {Promise<unknown>} */
  let writeTail = Promise.resolve();
  /** @template T @param {() => Promise<T>} fn @returns {Promise<T>} */
  function writing(fn) {
    const result = writeTail.then(fn);
    writeTail = result.then(() => {}, () => {});
    return result;
  }

  // One attempt at a time.
  /** @type {Promise<unknown>} */
  let attemptTail = Promise.resolve();
  /** @template T @param {() => Promise<T>} fn @returns {Promise<T>} */
  function exclusive(fn) {
    const result = attemptTail.then(fn);
    attemptTail = result.then(() => {}, () => {});
    return result;
  }

  // -------------------------------------------------------------- the records

  /**
   * Reads a record from one place. A record of the wrong shape is wiped on the spot and counts as absent.
   * @param {Location} location @param {string} server @param {string} account
   * @returns {Promise<PinRecord | null>}
   */
  async function read(location, server, account) {
    /** @type {unknown} */
    let value;
    if (location === "disk") {
      const db = await database();
      value = await inTransaction(db, [PIN_STORE], "readonly", (tx) => req(tx.objectStore(PIN_STORE).get([server, account])));
    } else {
      const key = sessionKey(server, account);
      const raw = (await session.get(key))[key];
      value = raw === undefined ? undefined : (decodeRecord(raw) ?? { corrupt: true });
    }
    if (value === undefined || value === null) return null;
    const record = checkRecord(value);
    if (record) return record;
    await remove(location, server, account, null);
    return null;
  }

  /**
   * The record of an account and where it is. A record in both places (a crash during a move) keeps the newer one.
   * @param {string} server @param {string} account
   * @returns {Promise<{ location: Location, record: PinRecord } | null>}
   */
  async function locate(server, account) {
    const disk = await read("disk", server, account);
    const mem = await read("session", server, account);
    if (disk && mem) {
      const keepDisk = disk.createdAt >= mem.createdAt;
      const [gone, keep] = keepDisk ? ["session", disk] : ["disk", mem];
      await wipeAt(/** @type {Location} */ (gone), server, account, "moved");
      zeroBlob(keepDisk ? mem : disk);
      return { location: keepDisk ? "disk" : "session", record: keep };
    }
    if (disk) return { location: "disk", record: disk };
    if (mem) return { location: "session", record: mem };
    return null;
  }

  /**
   * Replaces a record in one place with `next(current)`; `next` returns the new record (or `undefined` to keep the
   * current one) and a value for the caller. On disk the read and the write are one transaction.
   * @template V
   * @param {Location} location @param {string} server @param {string} account
   * @param {(current: PinRecord | null) => { next?: PinRecord, value: V }} next
   * @returns {Promise<V>}
   */
  function mutate(location, server, account, next) {
    return writing(async () => {
      /** @type {PinRecord | null} */
      let current = null;
      try {
        if (location === "disk") {
          const db = await database();
          return await inTransaction(db, [PIN_STORE], "readwrite", async (tx) => {
            const store = tx.objectStore(PIN_STORE);
            current = checkRecord(await req(store.get([server, account])));
            const step = next(current);
            if (step.next) await req(store.put(step.next, [server, account]));
            return step.value;
          });
        }
        const key = sessionKey(server, account);
        current = checkRecord(decodeRecord((await session.get(key))[key]));
        const step = next(current);
        if (step.next) await session.set({ [key]: encodeRecord(step.next) });
        return step.value;
      } finally {
        zeroBlob(current);
      }
    });
  }

  /**
   * Overwrites a record with zeros (marked as used up) and deletes it. Not a secure delete (see the top of this file).
   * @param {Location} location @param {string} server @param {string} account
   * @param {PinRecord | null} known
   */
  function remove(location, server, account, known) {
    return writing(async () => {
      if (location === "disk") {
        const db = await database();
        try {
          await inTransaction(db, [PIN_STORE], "readwrite", async (tx) => {
            const store = tx.objectStore(PIN_STORE);
            const current = await req(store.get([server, account]));
            if (current === undefined) return;
            const record = checkRecord(current);
            await req(store.put(record ? spent(record) : { corrupt: true }, [server, account]));
          });
        } catch {
          // The overwrite is a courtesy; the delete below is what counts.
        }
        await inTransaction(db, [PIN_STORE], "readwrite", (tx) => req(tx.objectStore(PIN_STORE).delete([server, account])));
        return;
      }
      const key = sessionKey(server, account);
      try {
        const record = known ?? checkRecord(decodeRecord((await session.get(key))[key]));
        if (record) await session.set({ [key]: encodeRecord(spent(record)) });
      } catch {
        // as above
      }
      await session.remove(key);
    });
  }

  /** @param {Location} location @param {string} server @param {string} account @param {WipeReason} reason */
  async function wipeAt(location, server, account, reason) {
    if (!WIPE_REASONS.includes(reason)) throw new PinStoreError("bad_reason");
    await remove(location, server, account, null);
  }

  /** The account ids with a record under a server (or under any server when `server` is null), in both places. @param {string | null} server */
  async function accounts(server) {
    /** @type {Array<[string, string]>} */
    const found = [];
    const db = await database();
    const keys = await inTransaction(db, [PIN_STORE], "readonly", (tx) => req(tx.objectStore(PIN_STORE).getAllKeys()));
    for (const key of keys) {
      if (Array.isArray(key) && typeof key[0] === "string" && typeof key[1] === "string" && (server === null || key[0] === server)) {
        found.push([key[0], key[1]]);
      }
    }
    const all = await session.get(null);
    for (const key of Object.keys(all)) {
      if (!key.startsWith(SESSION_KEY_PREFIX)) continue;
      const [encoded, account] = key.slice(SESSION_KEY_PREFIX.length).split("|");
      let origin;
      try {
        origin = decodeURIComponent(encoded);
      } catch {
        continue;
      }
      if (account && (server === null || origin === server)) found.push([origin, account]);
    }
    return found;
  }

  /** @param {Array<[string, string]>} list @param {WipeReason} reason */
  async function wipeList(list, reason) {
    if (!WIPE_REASONS.includes(reason)) throw new PinStoreError("bad_reason");
    for (const [server, account] of list) {
      await remove("disk", server, account, null);
      await remove("session", server, account, null);
    }
  }

  // ------------------------------------------------------------- the policy

  /** @param {string} server @returns {Promise<Policy | null>} */
  async function readPolicy(server) {
    const db = await database();
    const value = await inTransaction(db, [POLICY_STORE], "readonly", (tx) => req(tx.objectStore(POLICY_STORE).get(server)));
    try {
      return checkPolicy(value);
    } catch {
      return null;
    }
  }

  // ---------------------------------------------------------------- the API

  return {
    /**
     * What the popup may show: whether a PIN is set, where, the attempts left, the wait and whether it works offline.
     * It never counts and never wipes a good record (it only clears a record of the wrong shape, as every read does).
     * @param {string} serverUrl @param {string} accountId
     * @returns {Promise<PinStatus>}
     */
    async status(serverUrl, accountId) {
      const server = serverOrigin(serverUrl);
      const account = accountKey(accountId);
      const found = await locate(server, account);
      if (!found) return { set: false, location: null, failuresLeft: 0, waitMs: 0, offlineOk: false, lastOnlineAt: null };
      const { record, location } = found;
      const t = now();
      const out = {
        set: true,
        location,
        failuresLeft: MAX_PIN_FAILURES - record.failures,
        waitMs: waitLeft(record, t),
        offlineOk: offlineOk(record, t),
        lastOnlineAt: record.lastOnlineAt,
      };
      zeroBlob(record);
      return out;
    },

    /**
     * Stores the blob of a new PIN. A disk record needs the user's acknowledgement of the warning. The record starts
     * with a clean counter; the old record of the account, in either place, is replaced and the other place emptied.
     * @param {string} serverUrl @param {string} accountId @param {PinBlob} blob
     * @param {{ location: Location, acknowledged?: boolean }} options
     */
    async save(serverUrl, accountId, blob, { location, acknowledged }) {
      const server = serverOrigin(serverUrl);
      const account = accountKey(accountId);
      if (location !== "disk" && location !== "session") throw new PinStoreError("bad_location");
      if (location === "disk" && acknowledged !== true) throw new PinStoreError("acknowledgement_required");
      const copy = copyBlob(blob);
      try {
        const policy = await readPolicy(server);
        if (policy) {
          const draft = /** @type {PinRecord} */ ({ ...copy, failures: 0 });
          const why = ruleForbids(policy, draft, location);
          if (why) throw new PinStoreError("rule_forbids");
        }
        const t = now();
        /** @type {PinRecord} */
        const record = { ...copy, failures: 0, lastFailureAt: null, lastContactAt: t, lastOnlineAt: t, highestSeenAt: t, createdAt: t };
        await mutate(location, server, account, () => ({ next: record, value: null }));
        await remove(location === "disk" ? "session" : "disk", server, account, null);
      } finally {
        zeroBlob(copy);
      }
    },

    /**
     * One attempt to open the vault with the PIN. `tryUnlock(blob)` is the caller's unlock (the core's `pin_unlock`);
     * it gets a copy of the blob whose buffers are zeroed afterwards, and runs only after the raised counter is
     * written. `online`: the server can be reached now, so the offline window does not apply (the caller then runs
     * the checks that follow every unlock).
     * @param {string} serverUrl @param {string} accountId
     * @param {{ online: boolean }} state
     * @param {TryUnlock} tryUnlock
     * @returns {Promise<{ result: AttemptResult, failuresLeft: number, waitMs: number }>}
     */
    attempt(serverUrl, accountId, { online }, tryUnlock) {
      const server = serverOrigin(serverUrl);
      const account = accountKey(accountId);
      /** @param {AttemptResult} result @param {number} failuresLeft @param {number} [waitMs] */
      const answer = (result, failuresLeft, waitMs = 0) => ({ result, failuresLeft, waitMs });
      return exclusive(async () => {
        const found = await locate(server, account);
        if (!found) return answer("none", 0);
        const { location, record } = found;
        /** @type {PinRecord | null} */
        let held = record;
        /** @type {PinBlob | null} */
        let copy = null;
        try {
          const policy = await readPolicy(server);
          const why = policy ? ruleForbids(policy, record, location) : null;
          if (why) {
            await remove(location, server, account, record);
            return answer("wiped", 0);
          }
          // A record that already stands at the limit (an interrupted fifth attempt): wipe it, no unlock.
          if (record.failures >= MAX_PIN_FAILURES) {
            await remove(location, server, account, record);
            return answer("wiped", 0);
          }
          const t = now();
          if (!online && !offlineOk(record, t)) return answer("offline_expired", MAX_PIN_FAILURES - record.failures);
          const wait = waitLeft(record, t);
          if (wait > 0) return answer("wait", MAX_PIN_FAILURES - record.failures, wait);

          // The counter goes up and is written before the unlock starts.
          const raised = await mutate(location, server, account, (current) => {
            if (!current || !sameBytes(current.methodId, record.methodId)) return { value: /** @type {"gone" | "full" | "raised"} */ ("gone") };
            if (current.failures >= MAX_PIN_FAILURES) return { value: "full" };
            return {
              next: { ...current, failures: current.failures + 1, lastFailureAt: t, highestSeenAt: Math.max(current.highestSeenAt, t) },
              value: "raised",
            };
          });
          if (raised === "gone") return answer("none", 0);
          if (raised === "full") {
            await remove(location, server, account, record);
            return answer("wiped", 0);
          }

          copy = { methodId: record.methodId.slice(), wrap: record.wrap.slice(), deviceSalt: record.deviceSalt.slice(), pinProfile: record.pinProfile, vkEpoch: record.vkEpoch, rule: { minLength: record.rule.minLength } };
          /** @type {"ok" | "wrong" | "stale" | "out_of_memory"} */
          let outcome = "wrong";
          try {
            const reply = await tryUnlock(copy);
            if (isObject(reply)) {
              if (reply.ok === true) outcome = "ok";
              else if (reply.reason === "stale" || reply.reason === "out_of_memory") outcome = reply.reason;
            }
          } catch {
            outcome = "wrong"; // a failed unlock is a counted attempt
          } finally {
            zeroBlob(copy);
          }

          if (outcome === "stale") {
            // The blob is no good: deleted, and the raised counter dies with it. Not counted.
            await remove(location, server, account, record);
            return answer("stale", 0);
          }

          const after = now();
          if (outcome === "ok") {
            // The reset is its own transaction. If it fails, the raised counter stays (the safe direction) and the
            // unlock that succeeded is still reported.
            /** @type {"reset" | "gone"} */
            let reset = "reset";
            try {
              reset = await mutate(location, server, account, (current) => {
                if (!current || !sameBytes(current.methodId, record.methodId)) return { value: /** @type {"reset" | "gone"} */ ("gone") };
                return {
                  next: { ...current, failures: 0, lastFailureAt: null, highestSeenAt: Math.max(current.highestSeenAt, after) },
                  value: "reset",
                };
              });
            } catch {
              reset = "reset";
            }
            // The record was wiped while the unlock ran (sign-out, revocation): the caller must not trust the unlock.
            if (reset === "gone") return answer("none", 0);
            return answer("ok", MAX_PIN_FAILURES);
          }

          // A wrong PIN (or an out-of-memory attempt, which counts the same): the counter is already up. Note the
          // time of the failure, and wipe at five.
          const left = await mutate(location, server, account, (current) => {
            if (!current || !sameBytes(current.methodId, record.methodId)) return { value: /** @type {number | "gone"} */ ("gone") };
            if (current.failures >= MAX_PIN_FAILURES) return { value: 0 };
            return { next: { ...current, lastFailureAt: after, highestSeenAt: Math.max(current.highestSeenAt, after) }, value: MAX_PIN_FAILURES - current.failures };
          });
          if (left === "gone") return answer("none", 0);
          if (left === 0) {
            await remove(location, server, account, record);
            return answer("wiped", 0);
          }
          const failures = MAX_PIN_FAILURES - left;
          return answer(outcome, left, PIN_WAIT_MS[failures]);
        } finally {
          zeroBlob(held);
          held = null;
          zeroBlob(copy);
        }
      });
    },

    /**
     * A token renewal succeeded (also while the vault is locked): the device is not revoked, and the offline window
     * counts from now. The clock guard is reset too: a server contact is how a device that saw a wrong clock gets
     * its PIN back. Call it only after a successful renewal, never after an unlock.
     * @param {string} serverUrl @param {string} accountId
     */
    async markContact(serverUrl, accountId) {
      const server = serverOrigin(serverUrl);
      const account = accountKey(accountId);
      const found = await locate(server, account);
      if (!found) return;
      zeroBlob(found.record);
      const t = now();
      await mutate(found.location, server, account, (current) =>
        current ? { next: { ...current, lastContactAt: t, highestSeenAt: t }, value: null } : { value: null });
    },

    /**
     * A PIN or master-password unlock passed the checks that follow every unlock, while online. For display only:
     * it does not move the window.
     * @param {string} serverUrl @param {string} accountId
     */
    async markOnline(serverUrl, accountId) {
      const server = serverOrigin(serverUrl);
      const account = accountKey(accountId);
      const found = await locate(server, account);
      if (!found) return;
      zeroBlob(found.record);
      const t = now();
      await mutate(found.location, server, account, (current) =>
        current ? { next: { ...current, lastOnlineAt: t, highestSeenAt: Math.max(current.highestSeenAt, t) }, value: null } : { value: null });
    },

    /** Moves `highestSeenAt` of every record up to the clock (called at start and by the lock timer). */
    async tick() {
      const t = now();
      for (const [server, account] of await accounts(null)) {
        for (const location of /** @type {const} */ (["disk", "session"])) {
          const record = await read(location, server, account);
          if (!record) continue;
          const due = t - record.highestSeenAt >= TICK_STEP_MS;
          zeroBlob(record);
          if (!due) continue;
          await mutate(location, server, account, (current) =>
            current && t > current.highestSeenAt ? { next: { ...current, highestSeenAt: t }, value: null } : { value: null });
        }
      }
    },

    /**
     * A successful unlock with the master password: the PIN counter starts again.
     * @param {string} serverUrl @param {string} accountId
     */
    async resetFailures(serverUrl, accountId) {
      const server = serverOrigin(serverUrl);
      const account = accountKey(accountId);
      const found = await locate(server, account);
      if (!found) return;
      zeroBlob(found.record);
      await mutate(found.location, server, account, (current) =>
        current && (current.failures !== 0 || current.lastFailureAt !== null)
          ? { next: { ...current, failures: 0, lastFailureAt: null }, value: null }
          : { value: null });
    },

    /**
     * Deletes the record of one account, in both places. Never counts, never runs an unlock, and never waits for an
     * attempt that is running.
     * @param {string} serverUrl @param {string} accountId @param {WipeReason} reason
     */
    async wipe(serverUrl, accountId, reason) {
      const server = serverOrigin(serverUrl);
      const account = accountKey(accountId);
      await wipeList([[server, account]], reason);
    },

    /** Deletes the records of every account of one server. @param {string} serverUrl @param {WipeReason} reason */
    async wipeServer(serverUrl, reason) {
      const server = serverOrigin(serverUrl);
      await wipeList(await accounts(server), reason);
    },

    /** Deletes every record. The cached rules stay. @param {WipeReason} reason */
    async wipeAll(reason) {
      await wipeList(await accounts(null), reason);
    },

    /**
     * Caches the admin's rule of a server and applies it at once: a rule that forbids PINs wipes them, one that
     * forbids PINs after a restart wipes the disk records, a stricter minimum wipes the records made under a weaker
     * one.
     * @param {string} serverUrl @param {Policy} policy
     */
    async cachePolicy(serverUrl, policy) {
      const server = serverOrigin(serverUrl);
      const rule = checkPolicy(policy);
      const db = await database();
      await inTransaction(db, [POLICY_STORE], "readwrite", (tx) => req(tx.objectStore(POLICY_STORE).put(rule, server)));
      for (const [origin, account] of await accounts(server)) {
        for (const location of /** @type {const} */ (["disk", "session"])) {
          const record = await read(location, origin, account);
          if (!record) continue;
          const why = ruleForbids(rule, record, location);
          zeroBlob(record);
          if (why) await remove(location, origin, account, null);
        }
      }
    },

    /** The cached rule of a server, or null. @param {string} serverUrl @returns {Promise<Policy | null>} */
    async cachedPolicy(serverUrl) {
      return readPolicy(serverOrigin(serverUrl));
    },
  };
}
