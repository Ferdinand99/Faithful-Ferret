// The pinned record: what this device has seen of an account (server address,
// highest key epoch and unlock-method generations, KDF profile, the secret-key
// bit). It is not secret. The core keeps the rules for it (spec Fase 1 § 8.6);
// this file keeps the record across sessions and adds a second guard in JS: a
// save that would lower the key epoch, a floor or the KDF profile is refused,
// so a bug or a server that starts again from nothing cannot quietly write the
// floors back.
//
// The record is kept under (server address, account id). A second index maps
// the e-mail the user types to that account for the same server, so a sign-in
// can find its pinned record before the server has said who the account is.
// Changing the e-mail moves the index; the record stays where it is.
import { hex16 } from "../b64.mjs";
import { req, run, StoreError } from "./idb.mjs";

/**
 * The record as the core hands it over (bindings/wasm convert.rs, PinnedDto):
 * the store reads `vk_epoch_max`, `ksf_profile` and `kek_generation_max`.
 * @typedef {Record<string, any>} PinnedRecord
 */

/**
 * The form of an e-mail the index is keyed on: trimmed, NFKC, lower case.
 * @param {string} email
 */
export function indexEmail(email) {
  return email.trim().normalize("NFKC").toLowerCase();
}

/** @param {unknown} serverUrl */
function checkServer(serverUrl) {
  if (typeof serverUrl !== "string" || serverUrl === "") throw new TypeError("a server address is needed");
}

/** @param {unknown} accountId */
function checkAccount(accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
}

/**
 * @param {unknown} a
 * @param {unknown} b
 * @returns {boolean} whether a is lower than b (both whole numbers)
 */
function lower(a, b) {
  return BigInt(/** @type {number} */ (a)) < BigInt(/** @type {number} */ (b));
}

/** @param {unknown} value */
function wholeNumber(value) {
  return (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) || typeof value === "bigint";
}

/**
 * The identity of one unlock-method floor: its type and, for a passkey, the
 * credential.
 * @param {Record<string, any>} floor
 */
function floorKey(floor) {
  const id = floor.credential_id;
  let credential = "";
  if (id instanceof Uint8Array) credential = Array.from(id, (n) => n.toString(16).padStart(2, "0")).join("");
  else if (Array.isArray(id)) credential = id.map((n) => Number(n).toString(16).padStart(2, "0")).join("");
  else if (typeof id === "string") credential = id;
  return `${floor.type}:${credential}`;
}

/** @param {PinnedRecord} record */
function checkRecord(record) {
  const ok =
    record !== null &&
    typeof record === "object" &&
    wholeNumber(record.vk_epoch_max) &&
    wholeNumber(record.ksf_profile) &&
    Array.isArray(record.kek_generation_max) &&
    record.kek_generation_max.every(
      (/** @type {any} */ f) => f !== null && typeof f === "object" && typeof f.type === "string" && wholeNumber(f.generation),
    );
  if (!ok) throw new StoreError("pinned_malformed", "not a pinned record");
}

/**
 * Throws when `next` would lower something `old` already holds.
 * @param {PinnedRecord} old
 * @param {PinnedRecord} next
 */
function checkNotLower(old, next) {
  if (lower(next.vk_epoch_max, old.vk_epoch_max)) {
    throw new StoreError("pinned_epoch_downgrade", "the key epoch is lower than the pinned one");
  }
  if (lower(next.ksf_profile, old.ksf_profile)) {
    throw new StoreError("pinned_profile_downgrade", "the KDF profile is lower than the pinned one");
  }
  /** @type {Map<string, unknown>} */
  const now = new Map(next.kek_generation_max.map((/** @type {any} */ f) => [floorKey(f), f.generation]));
  for (const floor of old.kek_generation_max) {
    const was = now.get(floorKey(floor));
    if (was !== undefined && lower(was, floor.generation)) {
      throw new StoreError("pinned_floor_downgrade", "an unlock-method generation is lower than the pinned one");
    }
  }
}

/**
 * Saves the record of an account on this device. Refuses a record that lowers
 * the key epoch, the KDF profile or an unlock-method generation of the one
 * already saved for the account (`StoreError`, code `pinned_epoch_downgrade`,
 * `pinned_profile_downgrade` or `pinned_floor_downgrade`). Another account
 * that was indexed under the same e-mail loses that index entry.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl the address exactly as the client states it
 * @param {string} accountId 32 hex characters
 * @param {string} email
 * @param {PinnedRecord} record
 * @returns {Promise<void>}
 */
export async function savePinned(store, serverUrl, accountId, email, record) {
  checkServer(serverUrl);
  checkAccount(accountId);
  if (typeof email !== "string" || indexEmail(email) === "") throw new TypeError("an e-mail is needed");
  checkRecord(record);
  const mail = indexEmail(email);
  await run(store, ["pinned"], "readwrite", async ([pinned]) => {
    const old = await req(pinned.get([serverUrl, accountId]));
    if (old) checkNotLower(old.record, record);
    // An e-mail belongs to one account on a server: another account that held
    // it (its owner changed it) no longer resolves under it.
    const holders = await req(pinned.index("by_email").getAll([serverUrl, mail]));
    for (const other of holders) {
      if (other.accountId !== accountId) await req(pinned.put({ ...other, email: null }));
    }
    await req(pinned.put({ serverUrl, accountId, email: mail, record }));
  });
}

/**
 * The pinned record for the account that this e-mail maps to on this server, or
 * null on a device that has not signed in to it.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} email
 * @returns {Promise<PinnedRecord | null>}
 */
export async function loadPinned(store, serverUrl, email) {
  checkServer(serverUrl);
  if (typeof email !== "string") throw new TypeError("an e-mail is needed");
  const rows = await run(store, ["pinned"], "readonly", ([pinned]) =>
    req(pinned.index("by_email").getAll([serverUrl, indexEmail(email)])),
  );
  return rows.length === 1 ? rows[0].record : null;
}

/**
 * The pinned record of an account by its id, or null. A sign-in that found no
 * record by e-mail but learns the account id from the server should look here:
 * an account whose e-mail changed on another device is still pinned on this one.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<PinnedRecord | null>}
 */
export async function loadPinnedByAccount(store, serverUrl, accountId) {
  checkServer(serverUrl);
  checkAccount(accountId);
  const row = await run(store, ["pinned"], "readonly", ([pinned]) => req(pinned.get([serverUrl, accountId])));
  return row ? row.record : null;
}

/**
 * Removes the record of an account. Only an explicit "forget this server" does
 * this; signing out and clearing the cache leave it.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<void>}
 */
export async function forgetPinned(store, serverUrl, accountId) {
  checkServer(serverUrl);
  checkAccount(accountId);
  await run(store, ["pinned"], "readwrite", async ([pinned]) => {
    await req(pinned.delete([serverUrl, accountId]));
  });
}
