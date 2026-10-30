// The secret key on this device (spec Fase 1 § 6.2). After a first sign-in the
// user may let the browser remember the account's secret key code, so that it
// is not typed each time. It is sealed with AES-GCM under a non-extractable
// WebCrypto key; the sealed code and the key sit together in the
// `device_secrets` store, and the additional data is (server address, account
// id), so a sealed code cannot be moved to another account or server.
//
// What this protects: the code is not readable as text in the browser's
// storage viewers or in a support dump, and the key bytes cannot be exported by
// script. What it does not protect: a copy of the whole browser profile on
// Chromium or Firefox (the key bytes sit in the profile's storage files), or
// code that runs on the vault origin (it can call the decryption). Where the
// key cannot be stored (a private window, evicted storage) nothing is
// remembered, the page asks for the secret key each time, and the secret key
// bit is never guessed.
import { serverKey } from "../store/idb.mjs";
import { deviceSecrets } from "../store/settings.mjs";

/**
 * @typedef {object} Env
 * @property {SubtleCrypto | undefined} [subtle]
 * @property {(bytes: Uint8Array) => Uint8Array} [rand] fills the bytes with random values
 */

/** @param {string} serverUrl @param {string} accountId */
function additionalData(serverUrl, accountId) {
  return new TextEncoder().encode(`${serverKey(serverUrl)}\n${accountId}`);
}

/**
 * Seals the secret key code and stores it. `'unavailable'` when the browser
 * cannot keep the key; then nothing is stored.
 * @param {import("../store/idb.mjs").Store} db
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {string} skCode
 * @param {Env} [env]
 * @returns {Promise<"saved" | "unavailable">}
 */
export async function saveSecretKey(db, serverUrl, accountId, skCode, env = {}) {
  const subtle = env.subtle ?? globalThis.crypto?.subtle;
  const rand = env.rand ?? ((/** @type {Uint8Array} */ bytes) => globalThis.crypto.getRandomValues(bytes));
  try {
    if (!subtle || typeof skCode !== "string" || skCode === "") return "unavailable";
    const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = /** @type {Uint8Array<ArrayBuffer>} */ (rand(new Uint8Array(12)));
    const plain = new TextEncoder().encode(skCode);
    /** @type {Uint8Array} */
    let sealed;
    try {
      sealed = new Uint8Array(
        await subtle.encrypt({ name: "AES-GCM", iv, additionalData: additionalData(serverUrl, accountId) }, key, plain),
      );
    } finally {
      plain.fill(0);
    }
    await deviceSecrets.put(db, serverUrl, accountId, { key, iv, sealed });
    // The browser can store the row and still not give the key back (evicted
    // or partitioned storage): only a round trip shows that it works.
    if ((await loadSecretKey(db, serverUrl, accountId, env)) !== skCode) {
      await deviceSecrets.delete(db, serverUrl, accountId);
      return "unavailable";
    }
    return "saved";
  } catch {
    try {
      await deviceSecrets.delete(db, serverUrl, accountId);
    } catch {
      // nothing left to do
    }
    return "unavailable";
  }
}

/**
 * The secret key code of this account on this device, or null when none is
 * kept or it cannot be opened (another account, another server, a changed
 * byte, a lost key). Null means: ask the user.
 * @param {import("../store/idb.mjs").Store} db
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {Env} [env]
 * @returns {Promise<string | null>}
 */
export async function loadSecretKey(db, serverUrl, accountId, env = {}) {
  const subtle = env.subtle ?? globalThis.crypto?.subtle;
  try {
    const row = await deviceSecrets.get(db, serverUrl, accountId);
    if (!row || !subtle) return null;
    const plain = new Uint8Array(
      await subtle.decrypt(
        { name: "AES-GCM", iv: row.iv, additionalData: additionalData(serverUrl, accountId) },
        row.key,
        row.sealed,
      ),
    );
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(plain);
    } finally {
      plain.fill(0);
    }
  } catch {
    return null;
  }
}

/**
 * Whether a sealed secret key is stored for the account (not whether it opens).
 * @param {import("../store/idb.mjs").Store} db
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<boolean>}
 */
export async function hasSecretKey(db, serverUrl, accountId) {
  try {
    return (await deviceSecrets.get(db, serverUrl, accountId)) !== null;
  } catch {
    return false;
  }
}

/**
 * Removes the sealed secret key and its sealing key.
 * @param {import("../store/idb.mjs").Store} db
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<void>}
 */
export async function forgetSecretKey(db, serverUrl, accountId) {
  await deviceSecrets.delete(db, serverUrl, accountId);
}
