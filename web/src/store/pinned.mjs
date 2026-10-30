// The pinned record: what this device has seen of an account (server address,
// highest key epoch and unlock-method generations, KDF profile, the secret-key
// bit). It is not secret. The core keeps the rules for it (spec Fase 1 § 8.6);
// this file keeps the record across sessions and adds a second guard in JS, so
// a bug or a server that starts again from nothing cannot quietly write the
// floors back. A save is refused when it
//   - lowers the key epoch, the KDF profile or a floor, or drops a floor;
//   - changes the server address, the account, the vault or the secret-key bit;
//   - changes a server public key that is already set, or the account key
//     `pk_a` at the same epoch;
//   - names another account or server than the one it is stored under.
//
// The record is kept under (server origin, account id). A second index maps
// the e-mail the user types to that account for the same server. Changing the
// e-mail moves the index; the record stays where it is. A sign-in uses
// `pinnedForSignIn`, which also covers an e-mail that changed on another device.
import { hex16 } from "../b64.mjs";
import { req, run, serverKey, StoreError } from "./idb.mjs";

/**
 * The record as the core hands it over (bindings/wasm convert.rs, PinnedDto):
 * `server_url`, `account_id` and `vault_id` (16 bytes), `ksf_profile`,
 * `kek_generation_max` (`{type, credential_id, generation}`), `vk_epoch_max`,
 * `sk_bit`, `pk_a` (32 bytes) and `server_public_key` (32 bytes or null).
 * @typedef {Record<string, any>} PinnedRecord
 */

/**
 * The form of an e-mail the index is keyed on: trimmed, NFKC, lower case.
 * @param {string} email
 */
export function indexEmail(email) {
  return email.trim().normalize("NFKC").toLowerCase();
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

/** A whole number from 0, as a number or a bigint (the core's u64). @param {unknown} value */
function wholeNumber(value) {
  return (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) || (typeof value === "bigint" && value >= 0n);
}

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * @param {unknown} value
 * @param {number} length
 */
const bytesOf = (value, length) => value instanceof Uint8Array && value.length === length;

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

const RECORD_FIELDS = [
  "account_id", "kek_generation_max", "ksf_profile", "pk_a", "server_public_key", "server_url", "sk_bit", "vault_id", "vk_epoch_max",
].join();
const FLOOR_FIELDS = "credential_id,generation,type";

/**
 * Whether `floors` is a list of well-formed floors with no method twice: type
 * password or recovery without a credential, or prf with a credential id.
 * @param {unknown} floors
 */
function floorsOk(floors) {
  if (!Array.isArray(floors)) return false;
  const seen = new Set();
  for (const floor of floors) {
    if (floor === null || typeof floor !== "object" || Object.keys(floor).sort().join() !== FLOOR_FIELDS) return false;
    const { type, credential_id: credential, generation } = floor;
    if (!wholeNumber(generation)) return false;
    if (type === "prf" ? !(credential instanceof Uint8Array && credential.length > 0) : !(type === "password" || type === "recovery") || credential !== null) {
      return false;
    }
    const id = floorKey(floor);
    if (seen.has(id)) return false;
    seen.add(id);
  }
  return true;
}

/**
 * Throws unless `record` has the form of the core's PinnedDto and nothing else.
 * @param {PinnedRecord} record
 */
function checkRecord(record) {
  const ok =
    record !== null &&
    typeof record === "object" &&
    Object.keys(record).sort().join() === RECORD_FIELDS &&
    typeof record.server_url === "string" &&
    bytesOf(record.account_id, 16) &&
    bytesOf(record.vault_id, 16) &&
    wholeNumber(record.vk_epoch_max) &&
    wholeNumber(record.ksf_profile) && record.ksf_profile <= 255 &&
    typeof record.sk_bit === "boolean" &&
    bytesOf(record.pk_a, 32) &&
    (record.server_public_key === null || bytesOf(record.server_public_key, 32)) &&
    floorsOk(record.kek_generation_max);
  if (!ok) throw new StoreError("pinned_malformed", "not a pinned record");
}

/**
 * Throws when `next` would lower, drop or change something `old` already holds.
 * @param {PinnedRecord} old
 * @param {PinnedRecord} next
 */
function checkNotLower(old, next) {
  if (
    old.server_url !== next.server_url ||
    !sameBytes(old.account_id, next.account_id) ||
    !sameBytes(old.vault_id, next.vault_id) ||
    old.sk_bit !== next.sk_bit
  ) {
    throw new StoreError("pinned_identity_changed", "the server, account, vault or secret-key bit differs from the pinned one");
  }
  if (old.server_public_key !== null && !sameBytes(old.server_public_key, next.server_public_key)) {
    throw new StoreError("pinned_server_key_changed", "the server public key differs from the pinned one");
  }
  if (lower(next.vk_epoch_max, old.vk_epoch_max)) {
    throw new StoreError("pinned_epoch_downgrade", "the key epoch is lower than the pinned one");
  }
  if (!lower(old.vk_epoch_max, next.vk_epoch_max) && !sameBytes(old.pk_a, next.pk_a)) {
    throw new StoreError("pinned_pk_a_changed", "the account key differs from the pinned one at the same epoch");
  }
  if (lower(next.ksf_profile, old.ksf_profile)) {
    throw new StoreError("pinned_profile_downgrade", "the KDF profile is lower than the pinned one");
  }
  /** @type {Map<string, unknown>} */
  const now = new Map(next.kek_generation_max.map((/** @type {any} */ f) => [floorKey(f), f.generation]));
  for (const floor of old.kek_generation_max) {
    const was = now.get(floorKey(floor));
    if (was === undefined) {
      throw new StoreError("pinned_floor_missing", "an unlock-method generation that was pinned is not in the record");
    }
    if (lower(was, floor.generation)) {
      throw new StoreError("pinned_floor_downgrade", "an unlock-method generation is lower than the pinned one");
    }
  }
}

/**
 * Saves the record of an account on this device. The record must be for the
 * account and server it is saved under, and must not lower, drop or change
 * anything the account already has pinned (`StoreError`; the codes are
 * `pinned_key_mismatch`, `pinned_identity_changed`, `pinned_server_key_changed`,
 * `pinned_epoch_downgrade`, `pinned_pk_a_changed`, `pinned_profile_downgrade`,
 * `pinned_floor_missing` and `pinned_floor_downgrade`). Another account that was
 * indexed under the same e-mail loses that index entry.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl the address exactly as the client states it
 * @param {string} accountId 32 hex characters
 * @param {string} email
 * @param {PinnedRecord} record
 * @returns {Promise<void>}
 */
export async function savePinned(store, serverUrl, accountId, email, record) {
  const server = serverKey(serverUrl);
  checkAccount(accountId);
  if (typeof email !== "string" || indexEmail(email) === "") throw new TypeError("an e-mail is needed");
  checkRecord(record);
  if (record.server_url !== serverUrl || hex16.encode(record.account_id) !== accountId) {
    throw new StoreError("pinned_key_mismatch", "the record is for another server or account than the one it is saved under");
  }
  const mail = indexEmail(email);
  await run(store, ["pinned"], "readwrite", async ([pinned]) => {
    const old = await req(pinned.get([server, accountId]));
    if (old) checkNotLower(old.record, record);
    // An e-mail belongs to one account on a server: another account that held
    // it (its owner changed it) no longer resolves under it.
    const holders = await req(pinned.index("by_email").getAll([server, mail]));
    for (const other of holders) {
      if (other.accountId !== accountId) await req(pinned.put({ ...other, email: null }));
    }
    await req(pinned.put({ serverUrl: server, accountId, email: mail, record }));
  });
}

/**
 * The pinned record for the account that this e-mail maps to on this server, or
 * null. It is null on a new device, and also when the e-mail was changed on
 * another device: a sign-in should call {@link pinnedForSignIn} instead.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} email
 * @returns {Promise<PinnedRecord | null>}
 */
export async function loadPinned(store, serverUrl, email) {
  const server = serverKey(serverUrl);
  if (typeof email !== "string") throw new TypeError("an e-mail is needed");
  const rows = await run(store, ["pinned"], "readonly", ([pinned]) =>
    req(pinned.index("by_email").getAll([server, indexEmail(email)])),
  );
  return rows.length === 1 ? rows[0].record : null;
}

/**
 * The pinned record of an account by its id, or null.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<PinnedRecord | null>}
 */
export async function loadPinnedByAccount(store, serverUrl, accountId) {
  const server = serverKey(serverUrl);
  checkAccount(accountId);
  const row = await run(store, ["pinned"], "readonly", ([pinned]) => req(pinned.get([server, accountId])));
  return row ? row.record : null;
}

/**
 * The record to sign in with, found once the server has said which account the
 * e-mail is (the `account_id` of the login answer):
 *   1. the record the e-mail maps to;
 *   2. if that record is for another account than the server named, the sign-in
 *      is refused (`pinned_account_mismatch`);
 *   3. if no record maps from the e-mail, the record of the named account (its
 *      e-mail changed on another device);
 *   4. else null: only then is this a first use on this device.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} email
 * @param {string} accountId the account id from the server's login answer
 * @returns {Promise<PinnedRecord | null>}
 */
export async function pinnedForSignIn(store, serverUrl, email, accountId) {
  checkAccount(accountId);
  const byEmail = await loadPinned(store, serverUrl, email);
  if (byEmail) {
    if (!bytesOf(byEmail.account_id, 16) || hex16.encode(byEmail.account_id) !== accountId) {
      throw new StoreError("pinned_account_mismatch", "the server names another account than the one pinned for this e-mail");
    }
    return byEmail;
  }
  return loadPinnedByAccount(store, serverUrl, accountId);
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
  const server = serverKey(serverUrl);
  checkAccount(accountId);
  await run(store, ["pinned"], "readwrite", async ([pinned]) => {
    await req(pinned.delete([server, accountId]));
  });
}
