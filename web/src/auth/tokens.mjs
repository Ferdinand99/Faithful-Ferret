// The tokens of a device client (spec Fase 1 § 7.6; RFC 9449). A device signs
// in with OPAQUE and gets an access token (15 minutes) and a refresh token,
// both bound to its device key; every request with a token carries a new DPoP
// proof signed by that key.
//
// Where the tokens live: the access token in memory only, in this closure; the
// refresh token in the device's record in IndexedDB (`device_keys`) and nowhere
// else, read from there for each renewal. Neither is ever put in a URL,
// localStorage, sessionStorage, the console or an error.
//
// The rules:
// - One renewal at a time, across every context that shares the record (the
//   pages and workers of an extension or of an origin): each renewal holds an
//   exclusive Web Lock named after the server and reads the stored refresh
//   token inside it, so it always sends the newest one. The new refresh token
//   is written to the record before the new access token is used, and only
//   while the stored token is still the one that was sent (compare and swap in
//   one transaction), so a late answer never rolls the record back to a used
//   token, also in an engine without Web Locks. A renewal whose answer is lost
//   is sent again with the same refresh token (the server's grace gives the
//   same successor for 60 seconds).
// - `device_revoked` and `token_reused` are final: the tokens are forgotten and
//   the state is "revoked". `token_expired` on the renewal itself means the
//   refresh token is dead too: the device is signed out at the server when it
//   can be (so it leaves the device quota), the tokens are forgotten and the
//   state is "signed_out" (the master password signs the device in again).
// - The clock follows the server only from a `401 dpop_invalid` answer of the
//   server itself (not redirected, `no-store`): once per refused request, then
//   the request is sent once more with a new proof.
// - A new sign-in signs the older device of the same server out first, when
//   the server can be reached, and only then stores the new record.
// - The sign-in itself (`startSignIn`, `finishSignIn`): `login/start` carries
//   no cookie, no token and no proof; `login/finish` carries the device body
//   and a proof of this key without `ath` (the key goes in the proof's `jwk`,
//   never in the body), and its answer is accepted once. A key is sent in one
//   sign-in only: the server binds its thumbprint to the new device, so a
//   later sign-in makes a new key.
import { ApiError, createApi } from "../api.mjs";
import { serverKey, StoreError } from "../store/idb.mjs";
import { SHAPES, shape } from "../wire.mjs";
import { deleteDeviceKey, isToken, loadDeviceKey, sameKey, saveDeviceKey, saveRefreshToken } from "./deviceKey.mjs";
import { createProof } from "./dpop.mjs";

/** The renewal of the tokens. */
export const REFRESH_PATH = "/api/auth/token/refresh";
/** The sign-out of a device. */
export const REVOKE_PATH = "/api/auth/token/revoke";
/** The first step of a sign-in: KE1 for KE2. */
export const LOGIN_START_PATH = "/api/auth/opaque/login/start";
/** The last step of a sign-in: KE3, and for a device its tokens. */
export const LOGIN_FINISH_PATH = "/api/auth/opaque/login/finish";

/** The codes after which a device's tokens are never used again. */
const FINAL_CODES = Object.freeze(["device_revoked", "token_reused"]);

/**
 * The name of the Web Lock that a renewal of a server's tokens holds, in every
 * context of the origin.
 * @param {string} serverUrl
 */
export const renewLockName = (serverUrl) => `ferret-device-renew ${serverKey(serverUrl)}`;

/** The `no-store` directive in a `Cache-Control` header. */
const NO_STORE = /(^|,)\s*no-store\s*(,|$)/i;

/**
 * @typedef {"signed_out" | "ok" | "revoked"} TokenState
 *
 * @typedef {object} TokenAuth
 * @property {(method: string, url: string) => Promise<Record<string, string>>} prepare
 *   the headers of one attempt of a request to the server: `Authorization: DPoP <access token>` and a new DPoP proof
 * @property {(response: Response) => void} observe
 *   takes the server's clock from the `Date` of a `401` answer of the server (not redirected, `no-store`); the API client
 *   calls it for a `dpop_invalid` answer only
 * @property {(used?: Record<string, string> | null) => Promise<void>} refresh
 *   renews the tokens, one renewal at a time; with `used` (the headers of the refused attempt), nothing is renewed when the
 *   access token has changed since
 * @property {(deviceLoginRes: unknown) => Promise<void>} accept takes the answer of a device sign-in
 * @property {() => Promise<void>} revoke signs the device out at the server, then forgets its tokens
 * @property {(body: string) => Promise<any>} startSignIn
 *   posts `login/start` (the text of a `login_start_req`) with no cookie, no token and no proof; gives the `login_start_res`
 * @property {(body: string) => Promise<{ account_id: string, vault_id: string, vk_epoch: number, device_id: string }>} finishSignIn
 *   posts `login/finish` (the text of a `login_finish_req_device`) with a proof of this key and accepts the answer; gives
 *   the answer without its tokens. Once per key
 * @property {(code: string) => Promise<void>} refused
 *   tells the tokens the code a request with them was refused with; `device_revoked` and `token_reused` end them
 * @property {TokenState} state
 */

/**
 * The origin of a URL, or null when it is not an absolute URL.
 * @param {unknown} url
 */
function originOf(url) {
  try {
    return new URL(/** @type {string} */ (url)).origin;
  } catch {
    return null;
  }
}

/**
 * The tokens of a device client for one server and one device key.
 *
 * `key` is the device key: a new one from `generateDeviceKey` before a sign-in
 * (state "signed_out" until `accept`), or the stored one from `loadDeviceKey`
 * (state "ok"; the first request renews the tokens, because the access token
 * is never stored).
 * @param {object} options
 * @param {string} options.serverUrl the server
 * @param {import("../store/idb.mjs").Store} options.store the local store with `device_keys`
 * @param {import("./deviceKey.mjs").DeviceKey} options.key the device key of this server
 * @param {import("./dpop.mjs").Clock} options.clock the server's clock
 * @param {typeof fetch} [options.fetchImpl]
 * @param {Pick<Crypto, "getRandomValues">} [options.rand] the source of the proofs' `jti`
 * @param {Pick<LockManager, "request"> | null} [options.locks] the Web Locks of the origin (`navigator.locks`); without
 *   them, renewals are one at a time in this context only, and the compare and swap of the record keeps it right
 * @returns {TokenAuth}
 */
export function createTokenAuth({
  serverUrl,
  store,
  key,
  clock,
  fetchImpl = fetch,
  rand = crypto,
  locks = globalThis.navigator?.locks ?? null,
}) {
  const server = serverKey(serverUrl);
  if (key === null || typeof key !== "object" || key.serverUrl !== server) throw new TypeError("the device key is this server's");
  if (clock === null || typeof clock !== "object" || typeof clock.resync !== "function") throw new TypeError("the tokens need the server's clock");

  /** @type {TokenState} */
  let state = isToken(key.refreshToken) ? "ok" : "signed_out";
  /** The access token: in memory only. @type {string | null} */
  let access = null;
  /** Moves on each sign-in and each end of the tokens; a renewal begun before a move changes nothing. */
  let epoch = 0;
  /** The renewal under way. @type {Promise<void> | null} */
  let renewing = null;
  /** Whether this key was sent in a sign-in: it is bound to a device then, and never signs in again. */
  let spent = false;

  /** The error for a request made without tokens. */
  const withoutTokens = () => new ApiError(401, state === "revoked" ? "device_revoked" : "signed_out");

  /**
   * The API client for the requests that carry a proof and no access token (a
   * renewal, a sign-out), signed by `signer`.
   * @param {{ privateKey: CryptoKey, publicJwk: import("./deviceKey.mjs").PublicJwk }} signer
   */
  const proofOnly = (signer) =>
    createApi({
      base: server,
      fetchImpl,
      auth: {
        prepare: async (method, url) => ({ DPoP: await createProof(signer, { method, url, clock, rand }) }),
        observe,
        refresh: async () => {
          throw new TypeError("a request without an access token is never renewed");
        },
        refused: async () => {},
      },
    });

  /**
   * The API client for the requests of a device that has no tokens yet and
   * proves nothing (`login/start`): no cookie, no token and no proof, and
   * `Ferret-Protocol: 1` on every method.
   */
  const anonymous = () =>
    createApi({
      base: server,
      fetchImpl,
      auth: {
        prepare: async () => ({}),
        observe: () => {},
        refresh: async () => {
          throw new TypeError("a request without an access token is never renewed");
        },
        refused: async () => {},
      },
    });

  /**
   * Takes the server's clock from a `401` answer of the server: not
   * redirected, from this server's origin, and `no-store` (an answer from a
   * cache carries an old `Date`, a redirected one another host's).
   * @param {Response} response
   */
  function observe(response) {
    if (response === null || typeof response !== "object" || response.status !== 401) return;
    if (response.redirected || response.type === "opaqueredirect") return;
    if (originOf(response.url) !== server) return;
    if (!NO_STORE.test(response.headers.get("cache-control") ?? "")) return;
    clock.resync(response.headers.get("date"));
  }

  /**
   * Forgets the tokens: the access token, and the record of this key with the
   * refresh token (another key's record is left as it is).
   * @param {TokenState} next
   * @param {number} [at] the epoch this end belongs to; when it has moved on, nothing happens
   */
  async function end(next, at = epoch) {
    if (epoch !== at) return;
    epoch += 1;
    access = null;
    state = next;
    try {
      await deleteDeviceKey(store, server, { publicJwk: key.publicJwk });
    } catch {
      // The stored refresh token is dead either way: the server refuses it again on the next start.
    }
  }

  /**
   * The stored record of this key, or null: there is none, it is another
   * key's (a newer sign-in on this server), or it was damaged (then removed).
   */
  async function ownRecord() {
    /** @type {import("./deviceKey.mjs").DeviceKey | null} */
    let record;
    try {
      record = await loadDeviceKey(store, server);
    } catch (error) {
      if (!(error instanceof StoreError) || error.code !== "device_key_malformed") throw error;
      // Removed only when it is this key's: a record this code cannot read may be another key's.
      await deleteDeviceKey(store, server, { publicJwk: key.publicJwk });
      return null;
    }
    return record !== null && sameKey(record.publicJwk, key.publicJwk) ? record : null;
  }

  async function renew() {
    const at = epoch;
    const record = await ownRecord();
    if (record === null || record.refreshToken === null) {
      await end("signed_out", at);
      throw withoutTokens();
    }
    const sent = record.refreshToken;
    /** @type {{ access_token: string, refresh_token: string }} */
    let answer;
    try {
      answer = await proofOnly(key).post(REFRESH_PATH, { refresh_token: sent }, { shape: "token_res" });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        if (error.code === "token_expired") {
          // The server may still count the device (a token it lost in a restart): sign it out with the same token, so it
          // leaves the device quota. Best effort; the answer is 204 whatever the server knows.
          await proofOnly(key).post(REVOKE_PATH, { refresh_token: sent }).catch(() => {});
          await end("signed_out", at);
        } else if (FINAL_CODES.includes(error.code)) {
          await end("revoked", at);
        }
      }
      throw error;
    }
    if (epoch !== at) throw withoutTokens();
    // The new refresh token is in the record before the new access token is used, and only in place of the token that
    // was sent: when another context has moved the record on already, its newer token stays (the new access token is
    // valid all the same).
    try {
      await saveRefreshToken(store, server, answer.refresh_token, { publicJwk: key.publicJwk, replaces: sent });
    } catch (error) {
      if (error instanceof StoreError && error.code === "device_key_missing") await end("signed_out", at);
      throw error;
    }
    if (epoch !== at) throw withoutTokens();
    access = answer.access_token;
  }

  /** @param {Record<string, string> | null} [used] */
  async function refresh(used = null) {
    if (state !== "ok") throw withoutTokens();
    if (used !== null && access !== null && used.Authorization !== `DPoP ${access}`) return;
    if (renewing === null) {
      // Inside the lock the record is read afresh, so a context that waited sends the token the one before it stored.
      const once =
        locks === null
          ? renew()
          : /** @type {Promise<void>} */ (locks.request(renewLockName(server), { mode: "exclusive" }, () => renew()));
      renewing = once.finally(() => {
        renewing = null;
      });
    }
    return renewing;
  }

  /**
   * @param {string} method
   * @param {string} url
   */
  async function prepare(method, url) {
    if (originOf(url) !== server) throw new TypeError("a token goes to its own server only");
    if (state !== "ok") throw withoutTokens();
    if (access === null) await refresh();
    const token = access;
    if (state !== "ok" || token === null) throw withoutTokens();
    const proof = await createProof(key, { method, url, accessToken: token, clock, rand });
    return { Authorization: `DPoP ${token}`, DPoP: proof };
  }

  /** @param {string} code */
  async function refused(code) {
    if (FINAL_CODES.includes(code)) await end("revoked");
  }

  /**
   * Signs the older device of this server out (when the server can be
   * reached; otherwise it ends at its idle limit). Its record is replaced by
   * the new one right after.
   */
  async function signOutOlder() {
    /** @type {import("./deviceKey.mjs").DeviceKey | null} */
    let older;
    try {
      older = await loadDeviceKey(store, server);
    } catch {
      return;
    }
    if (older === null || older.refreshToken === null || sameKey(older.publicJwk, key.publicJwk)) return;
    try {
      await proofOnly(older).post(REVOKE_PATH, { refresh_token: older.refreshToken });
    } catch {
      // Best effort: the new device does not wait for the old one.
    }
  }

  /** @param {unknown} deviceLoginRes */
  async function accept(deviceLoginRes) {
    if (deviceLoginRes === null || typeof deviceLoginRes !== "object") throw new TypeError("not the answer of a device sign-in");
    // Each field is read once, and the copy is what is checked and kept.
    const answer = /** @type {Record<string, any>} */ ({ ...deviceLoginRes });
    try {
      shape(SHAPES.login_finish_res_device, answer);
    } catch {
      throw new TypeError("not the answer of a device sign-in");
    }
    // The key is bound to a device now: it never signs in again.
    spent = true;
    await signOutOlder();
    const at = ++epoch;
    access = null;
    try {
      await saveDeviceKey(store, key, { deviceId: answer.device_id, accountId: answer.account_id, refreshToken: answer.refresh_token });
    } catch (error) {
      // A device whose record cannot be kept is signed out again (when it can be), so it does not hold a place in the quota.
      await proofOnly(key).post(REVOKE_PATH, { refresh_token: answer.refresh_token }).catch(() => {});
      throw error;
    }
    if (epoch !== at) throw withoutTokens();
    access = answer.access_token;
    state = "ok";
  }

  /** @param {string} body the text of a `login_start_req` */
  async function startSignIn(body) {
    if (typeof body !== "string") throw new TypeError("a sign-in sends the text of its body");
    if (state !== "signed_out" || spent) throw new TypeError("this device key has signed in already; a new sign-in makes a new key");
    return anonymous().post(LOGIN_START_PATH, body, { shape: "login_start_res" });
  }

  /**
   * Finishes the sign-in of this device: the body with a proof of this key
   * (no `ath`; a `dpop_invalid` takes the server's clock once and sends a new
   * proof, and the server keeps the sign-in state for that), then the answer
   * is accepted as it came.
   * @param {string} body the text of a `login_finish_req_device`
   */
  async function finishSignIn(body) {
    if (typeof body !== "string") throw new TypeError("a sign-in sends the text of its body");
    if (state !== "signed_out" || spent) throw new TypeError("this device key has signed in already; a new sign-in makes a new key");
    spent = true;
    const answer = await proofOnly(key).post(LOGIN_FINISH_PATH, body, { shape: "login_finish_res_device" });
    await accept(answer);
    // The tokens stay here: the caller gets the account, the vault, the epoch and the device.
    return { account_id: answer.account_id, vault_id: answer.vault_id, vk_epoch: answer.vk_epoch, device_id: answer.device_id };
  }

  async function revoke() {
    if (renewing !== null) await renewing.catch(() => {});
    try {
      const record = await ownRecord();
      if (record !== null && record.refreshToken !== null) {
        await proofOnly(key).post(REVOKE_PATH, { refresh_token: record.refreshToken });
      }
    } finally {
      await end("signed_out");
    }
  }

  return Object.freeze({
    prepare,
    observe,
    refresh,
    accept,
    revoke,
    refused,
    startSignIn,
    finishSignIn,
    get state() {
      return state;
    },
  });
}
