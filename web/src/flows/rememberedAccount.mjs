// Which account this browser signed in to last, so that the page it shows after the server session has ended is
// "Unlock" (the master password only) and not the full sign-in page (spec Fase 1 § 7.3 and § 7.6).
//
// What is kept: one setting per server, `signin.remembered.<server>`, whose value is the account id (32 hex
// characters) and nothing else. The e-mail address the page shows is not kept here: it is the one the pinned record
// of that account is indexed under (`store/pinned.mjs`), which this device holds already. So no new personal data is
// stored, and nothing is stored that is secret.
//
// What it decides: only which page is shown. The Unlock page runs the full sign-in of `flows/signin.mjs` with that
// e-mail, the typed master password and the secret key sealed on this device; every check of a sign-in (OPAQUE, the
// pinned record, the manifest, `pinnedElsewhere`) runs as it does from the sign-in page. A wrong password changes
// nothing here.
//
// When it goes (the next page is the full sign-in page):
//   - an explicit "Sign out", on any page (the vault session's `signOut`);
//   - "Forget this server" (the forget page removes it; a marker whose pinned record is gone removes itself);
//   - a refusal of the pinned checks on the Unlock page (the sign-in page then shows the refusal);
//   - nothing else: a lock, an ended or revoked session and a reload keep it.
// Without a pinned record of the account, or when the account has a secret key and this device holds none, the full
// sign-in page is shown although the marker is there.
import { hex16 } from "../b64.mjs";
import { serverKey } from "../store/idb.mjs";
import { hasSecretKey } from "./deviceSecret.mjs";

/**
 * The settings key of the marker of a server.
 * @param {string} serverUrl
 * @returns {string}
 */
export function rememberedKey(serverUrl) {
  return `signin.remembered.${serverKey(serverUrl)}`;
}

/**
 * The store service as this file uses it.
 * @typedef {{
 *   open(): Promise<any>,
 *   getSetting(db: any, key: string): Promise<unknown>,
 *   setSetting(db: any, key: string, value: unknown): Promise<void>,
 *   deleteSetting(db: any, key: string): Promise<void>,
 *   loadPinnedAccount(db: any, serverUrl: string, accountId: string): Promise<{ email: string | null } | null>,
 *   pinHintForEmail(db: any, serverUrl: string, email: string): Promise<Record<string, any> | null>,
 * }} RememberStore
 */

/**
 * What this device remembers for the server: the account and the e-mail its pinned record is indexed under, the
 * account's secret key bit and whether the sealed secret key is kept. Null when nothing is remembered, or the marker
 * no longer matches a pinned record of this device.
 * @typedef {{ accountId: string, email: string, skBit: boolean, skStored: boolean }} Remembered
 */

/**
 * Notes the account that has just been opened. Best effort: a store that fails only means the next page is the full
 * sign-in page.
 * @param {RememberStore} store
 * @param {string} serverUrl
 * @param {unknown} accountId
 * @returns {Promise<void>}
 */
export async function rememberAccount(store, serverUrl, accountId) {
  if (!hex16.is(accountId)) return;
  try {
    await store.setSetting(await store.open(), rememberedKey(serverUrl), accountId);
  } catch {
    // Not remembered: the next page asks for the e-mail too.
  }
}

/**
 * Forgets the marker of the server. With `accountId`, only when the marker names that account.
 * @param {RememberStore} store
 * @param {string} serverUrl
 * @param {string} [accountId]
 * @returns {Promise<void>}
 */
export async function forgetRememberedAccount(store, serverUrl, accountId) {
  const db = await store.open();
  const key = rememberedKey(serverUrl);
  if (accountId !== undefined && (await store.getSetting(db, key)) !== accountId) return;
  await store.deleteSetting(db, key);
}

/**
 * The account id the marker names, or null (no marker, or a value of another shape).
 * @param {RememberStore} store
 * @param {string} serverUrl
 * @returns {Promise<string | null>}
 */
export async function rememberedAccountId(store, serverUrl) {
  const value = await store.getSetting(await store.open(), rememberedKey(serverUrl));
  return hex16.is(value) ? /** @type {string} */ (value) : null;
}

/**
 * What the marker leads to on this device (see `Remembered`). A marker of another shape, or one whose pinned record is
 * gone (the server was forgotten), is removed.
 * @param {RememberStore} store
 * @param {string} serverUrl
 * @returns {Promise<Remembered | null>}
 */
export async function findRemembered(store, serverUrl) {
  const db = await store.open();
  const key = rememberedKey(serverUrl);
  const value = await store.getSetting(db, key);
  if (value === undefined || value === null) return null;
  const drop = async () => {
    await store.deleteSetting(db, key).catch(() => undefined);
    return null;
  };
  if (!hex16.is(value)) return drop();
  const accountId = /** @type {string} */ (value);
  const account = await store.loadPinnedAccount(db, serverUrl, accountId);
  if (account === null) return drop();
  // Another account took the e-mail over on this device: the address is not known for sure, so the page asks for it.
  if (typeof account.email !== "string" || account.email === "") return null;
  const record = await store.pinHintForEmail(db, serverUrl, account.email);
  if (!record || !(record.account_id instanceof Uint8Array) || hex16.encode(record.account_id) !== accountId) return null;
  const skBit = record.sk_bit === true;
  const skStored = skBit ? await hasSecretKey(db, serverUrl, accountId) : false;
  return { accountId, email: account.email, skBit, skStored };
}

/**
 * The page for a visit, from what the server says and what this device remembers:
 *   - `"unlock"`: the server session is live, so the master password opens the vault again in it (as before);
 *   - `"unlock_remembered"`: there is no session, and this device remembers the account, holds its pinned record and,
 *     when the account has a secret key, the sealed key: the master password alone, and a full sign-in behind it;
 *   - `"signin"`: anything else (a new device, a sign-out, a forgotten server, a missing secret key): the full sign-in
 *     page.
 * A revoked browser has no live session and is shown `"unlock_remembered"`: the server keeps no record that a browser
 * was revoked (its sessions end), and the Unlock page's full sign-in is what the sign-in page would run.
 * @param {{ info: unknown, remembered: Remembered | null }} facts `info`: the live vault session, or null
 * @returns {"unlock" | "unlock_remembered" | "signin"}
 */
export function entryPage({ info, remembered }) {
  if (info !== null && info !== undefined) return "unlock";
  if (remembered === null || remembered === undefined) return "signin";
  if (remembered.skBit && !remembered.skStored) return "signin";
  return "unlock_remembered";
}

/** Codes after which the Unlock page gives way to the full sign-in page (a refused pin, a missing secret key). */
const LEAVE_CODES = Object.freeze([
  "epoch_mismatch", "kdf_profile_downgrade", "method_list_changed", "method_list_missing", "method_list_unknown",
  "methods_invalid", "profile_rejected", "sk_answer_required", "sk_required",
]);

/**
 * Whether a refusal on the Unlock page is one that the full sign-in page shows instead: every refusal of the pinned
 * checks (`pinned_…`, the manifest, the epoch, the profile) and a secret key that is not there. A wrong password, a
 * throttle, a network failure and the like stay on the Unlock page.
 * @param {string} code
 * @returns {boolean}
 */
export function leavesUnlock(code) {
  return code.startsWith("pinned_") || LEAVE_CODES.includes(code);
}

/** A refusal handed from the Unlock page to the sign-in page it gave way to (memory only, read once). @type {unknown} */
let held = null;

/**
 * Hands a refusal to the next sign-in page.
 * @param {unknown} error
 */
export function holdRefusal(error) {
  held = error;
}

/**
 * The refusal the last Unlock page handed over, once; null when there is none.
 * @returns {unknown}
 */
export function takeRefusal() {
  const error = held;
  held = null;
  return error;
}
