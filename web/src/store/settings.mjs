// Small values this browser keeps: its device id, and the two stores that the
// sign-in flows use. Neither holds a master password, a recovery key or a vault
// key. `device_secrets` is the one place where a secret may be kept at all: the
// secret key code of the account, sealed with AES-GCM under a non-extractable
// WebCrypto key that is stored next to it (spec Fase 1 § 6.2). The sealing
// is the caller's; this file keeps the result and accepts nothing but the sealed
// form, so a clear-text secret cannot be stored there by mistake. Clearing the
// row cache or the outbox never touches it.
import { hex16 } from "../b64.mjs";
import { req, run, serverKey, StoreError } from "./idb.mjs";

const DEVICE_ID_KEY = "device_id";

/**
 * @param {import("./idb.mjs").Store} store
 * @param {string} key
 * @returns {Promise<any>} the value, or undefined
 */
export async function getSetting(store, key) {
  if (typeof key !== "string" || key === "") throw new TypeError("a setting has a name");
  return run(store, ["settings"], "readonly", ([table]) => req(table.get(key)));
}

/**
 * @param {import("./idb.mjs").Store} store
 * @param {string} key
 * @param {unknown} value anything the structured clone can copy
 * @returns {Promise<void>}
 */
export async function setSetting(store, key, value) {
  if (typeof key !== "string" || key === "") throw new TypeError("a setting has a name");
  await run(store, ["settings"], "readwrite", async ([table]) => {
    await req(table.put(value, key));
  });
}

/**
 * @param {import("./idb.mjs").Store} store
 * @param {string} key
 * @returns {Promise<void>}
 */
export async function deleteSetting(store, key) {
  await run(store, ["settings"], "readwrite", async ([table]) => {
    await req(table.delete(key));
  });
}

/**
 * This browser's device id: 16 random bytes, made once and kept, as 32 hex
 * characters (the form `register/finish` and `login/finish` take). The read and
 * the first write are one transaction, so two tabs agree on the same id.
 * @param {import("./idb.mjs").Store} store
 * @param {(bytes: Uint8Array) => Uint8Array} [rand] fills the bytes with random values
 * @returns {Promise<string>}
 */
export async function deviceId(store, rand = (bytes) => crypto.getRandomValues(bytes)) {
  return run(store, ["settings"], "readwrite", async ([table]) => {
    const kept = await req(table.get(DEVICE_ID_KEY));
    if (hex16.is(kept)) return kept;
    const made = hex16.encode(rand(new Uint8Array(16)));
    await req(table.put(made, DEVICE_ID_KEY));
    return made;
  });
}

/**
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {[string, string]}
 */
function secretKey(serverUrl, accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
  return [serverKey(serverUrl), accountId];
}

/** The AES-GCM nonce is 12 bytes; a sealed value is at least the 16-byte tag, and a secret key code is short. */
const IV_LENGTH = 12;
const SEALED_MIN = 16;
const SEALED_MAX = 1024;

/**
 * Checks that `value` is exactly `{ key, iv, sealed }`: a non-extractable
 * AES-GCM `CryptoKey`, a 12-byte nonce and the sealed bytes. Each field is read
 * once, and the result holds copies: the stored nonce and sealed bytes never
 * share a buffer with the caller's (a view over a larger buffer would otherwise
 * store the whole buffer), and a getter cannot show another value after the
 * check.
 * @param {unknown} value
 * @returns {{ key: CryptoKey, iv: Uint8Array, sealed: Uint8Array }}
 */
function checkSealed(value) {
  const bad = () => new StoreError("device_secrets_shape", "device secrets are { key, iv, sealed } and nothing else");
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw bad();
  if (Object.keys(value).sort().join() !== "iv,key,sealed") throw bad();
  const record = /** @type {Record<string, any>} */ (value);
  const key = record.key;
  const iv = record.iv;
  const sealed = record.sealed;
  const keyOk =
    typeof CryptoKey !== "undefined" &&
    key instanceof CryptoKey &&
    key.type === "secret" &&
    key.extractable === false &&
    key.algorithm?.name === "AES-GCM";
  const ok =
    keyOk &&
    iv instanceof Uint8Array && iv.length === IV_LENGTH &&
    sealed instanceof Uint8Array && sealed.length >= SEALED_MIN && sealed.length <= SEALED_MAX;
  if (!ok) throw bad();
  return { key, iv: iv.slice(), sealed: sealed.slice() };
}

/**
 * The device secrets of an account on a server: one object per account,
 * `{ key, iv, sealed }` (the non-extractable sealing `CryptoKey`, its nonce and
 * the sealed secret key code). Nothing else is accepted.
 */
export const deviceSecrets = Object.freeze({
  /**
   * @param {import("./idb.mjs").Store} store
   * @param {string} serverUrl
   * @param {string} accountId
   * @param {{ key: CryptoKey, iv: Uint8Array, sealed: Uint8Array }} value
   * @returns {Promise<void>}
   */
  async put(store, serverUrl, accountId, value) {
    const key = secretKey(serverUrl, accountId);
    const checked = checkSealed(value);
    await run(store, ["device_secrets"], "readwrite", async ([table]) => {
      await req(table.put(checked, key));
    });
  },

  /**
   * @param {import("./idb.mjs").Store} store
   * @param {string} serverUrl
   * @param {string} accountId
   * @returns {Promise<Record<string, any> | null>}
   */
  async get(store, serverUrl, accountId) {
    const key = secretKey(serverUrl, accountId);
    const value = await run(store, ["device_secrets"], "readonly", ([table]) => req(table.get(key)));
    return value ?? null;
  },

  /**
   * @param {import("./idb.mjs").Store} store
   * @param {string} serverUrl
   * @param {string} accountId
   * @returns {Promise<void>}
   */
  async delete(store, serverUrl, accountId) {
    const key = secretKey(serverUrl, accountId);
    await run(store, ["device_secrets"], "readwrite", async ([table]) => {
      await req(table.delete(key));
    });
  },
});
