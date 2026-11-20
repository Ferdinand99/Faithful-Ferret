// The key of a device client (spec Fase 1 § 7.6; RFC 9449). A device that
// signs in with tokens proves each request with a DPoP proof signed by its own
// P-256 key. The private key is made by WebCrypto as non-extractable: script
// can sign with it, and nothing can read its bytes. The browser keeps it in
// IndexedDB (store `device_keys`) by structured clone, one record per server:
//
//   { serverUrl, privateKey, publicJwk, deviceId, accountId, refreshToken }
//
// A new key is made in memory before each sign-in, and its record is written
// only once the sign-in has succeeded, replacing the record of an older device
// on the same server. The refresh token lives in this record and nowhere else;
// the access token is never stored. Nothing here writes to localStorage,
// sessionStorage or the console.
//
// What this protects: a page or a support dump cannot read the key, and a
// stolen token is useless without it. What it does not protect: a copy of the
// whole browser profile holds the key and the refresh token; the vault still
// needs the master password.
import { b64u, hex16 } from "../b64.mjs";
import { req, run, serverKey, StoreError } from "../store/idb.mjs";

/** The length of a token on the wire: 32 bytes as base64url without padding. */
const TOKEN_CHARS = 43;
/** The length of a P-256 coordinate as base64url without padding (32 bytes). */
const COORD_CHARS = 43;

/** The fields of a stored record, and nothing else. */
export const DEVICE_KEY_FIELDS = Object.freeze(["serverUrl", "privateKey", "publicJwk", "deviceId", "accountId", "refreshToken"]);

/**
 * The public key of a device as a JWK: exactly the four members a DPoP proof
 * carries, so a server that refuses any other member accepts it.
 * @typedef {{ kty: "EC", crv: "P-256", x: string, y: string }} PublicJwk
 */

/**
 * A device key. `deviceId`, `accountId` and `refreshToken` are null until the
 * sign-in has succeeded; a stored record always has all three.
 * @typedef {object} DeviceKey
 * @property {string} serverUrl the origin of the server
 * @property {CryptoKey} privateKey the non-extractable ECDSA P-256 signing key
 * @property {PublicJwk} publicJwk
 * @property {string | null} deviceId the id the server gave the device (32 hex characters)
 * @property {string | null} accountId
 * @property {string | null} refreshToken
 */

/**
 * Whether `value` is a coordinate of P-256 in canonical base64url (43
 * characters that decode to 32 bytes, spare bits zero).
 * @param {unknown} value
 */
function isCoordinate(value) {
  if (typeof value !== "string" || value.length !== COORD_CHARS) return false;
  try {
    return b64u.decode(value).length === 32;
  } catch {
    return false;
  }
}

/**
 * Checks a public JWK and returns a copy with exactly `kty`, `crv`, `x` and
 * `y`. With `exact`, any other member is refused; without it, other members
 * (such as `ext` and `key_ops` from `exportKey`) are left out of the copy.
 * A private member (`d`) is always refused.
 * @param {unknown} jwk
 * @param {boolean} exact
 * @returns {PublicJwk}
 */
function publicJwkOf(jwk, exact) {
  const bad = () => new StoreError("device_key_jwk", "a device key is a public P-256 JWK");
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) throw bad();
  const record = /** @type {Record<string, unknown>} */ (jwk);
  if (Object.hasOwn(record, "d")) throw bad();
  if (exact && Object.keys(record).sort().join() !== "crv,kty,x,y") throw bad();
  const { kty, crv, x, y } = record;
  if (kty !== "EC" || crv !== "P-256" || !isCoordinate(x) || !isCoordinate(y)) throw bad();
  return { kty: "EC", crv: "P-256", x: /** @type {string} */ (x), y: /** @type {string} */ (y) };
}

/**
 * Whether `key` is a non-extractable ECDSA P-256 private key that can sign.
 * @param {unknown} key
 */
function isSigningKey(key) {
  if (typeof CryptoKey === "undefined" || !(key instanceof CryptoKey)) return false;
  const algorithm = /** @type {EcKeyAlgorithm} */ (key.algorithm);
  return (
    key.type === "private" &&
    key.extractable === false &&
    algorithm?.name === "ECDSA" &&
    algorithm.namedCurve === "P-256" &&
    key.usages.length === 1 &&
    key.usages[0] === "sign"
  );
}

/**
 * Whether `value` is the origin of a server, as {@link serverKey} writes it.
 * @param {unknown} value
 * @returns {value is string}
 */
function isOrigin(value) {
  try {
    return typeof value === "string" && serverKey(value) === value;
  } catch {
    return false;
  }
}

/** @param {unknown} token */
function isToken(token) {
  if (typeof token !== "string" || token.length !== TOKEN_CHARS) return false;
  try {
    return b64u.decode(token).length === 32;
  } catch {
    return false;
  }
}

/**
 * Makes a new device key for a server, in memory only: nothing is stored until
 * {@link saveDeviceKey} is called after a successful sign-in. The private key
 * is non-extractable; the public JWK is copied out of a real `exportKey("jwk")`
 * with exactly `kty`, `crv`, `x` and `y` (the export adds `ext` and `key_ops`,
 * which a DPoP proof must not carry).
 * @param {string} serverUrl
 * @param {{ subtle?: SubtleCrypto }} [options]
 * @returns {Promise<DeviceKey>}
 */
export async function generateDeviceKey(serverUrl, { subtle = crypto.subtle } = {}) {
  const server = serverKey(serverUrl);
  const pair = /** @type {CryptoKeyPair} */ (
    await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
  );
  if (!isSigningKey(pair.privateKey)) {
    throw new StoreError("device_key_extractable", "the browser did not make a non-extractable P-256 signing key");
  }
  const exported = await subtle.exportKey("jwk", pair.publicKey);
  return {
    serverUrl: server,
    privateKey: pair.privateKey,
    publicJwk: publicJwkOf(exported, false),
    deviceId: null,
    accountId: null,
    refreshToken: null,
  };
}

/**
 * Checks a record for the store and returns the value to store. Each field is
 * read once, so a getter cannot show another value after the check.
 * @param {unknown} value
 * @returns {DeviceKey}
 */
function checkRecord(value) {
  const bad = (/** @type {string} */ message) => new StoreError("device_key_malformed", message);
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw bad("a device key is an object");
  const record = /** @type {Record<string, unknown>} */ (value);
  if (Object.keys(record).sort().join() !== [...DEVICE_KEY_FIELDS].sort().join()) {
    throw bad("a device key has exactly the fields serverUrl, privateKey, publicJwk, deviceId, accountId and refreshToken");
  }
  const { serverUrl, privateKey, publicJwk, deviceId, accountId, refreshToken } = record;
  if (!isOrigin(serverUrl)) throw bad("serverUrl is the origin of a server");
  if (!isSigningKey(privateKey)) throw bad("privateKey is a non-extractable P-256 signing key");
  let jwk;
  try {
    jwk = publicJwkOf(publicJwk, true);
  } catch {
    throw bad("publicJwk is exactly kty, crv, x and y of a P-256 key");
  }
  if (!hex16.is(deviceId) || !hex16.is(accountId)) throw bad("deviceId and accountId are ids");
  if (!isToken(refreshToken)) throw bad("refreshToken is a token");
  return {
    serverUrl,
    privateKey: /** @type {CryptoKey} */ (privateKey),
    publicJwk: jwk,
    deviceId,
    accountId,
    refreshToken: /** @type {string} */ (refreshToken),
  };
}

/**
 * Stores a device key after a successful sign-in, with what the server
 * answered, and replaces the record of an older device on the same server.
 * Refused (`StoreError`) when any of the three is missing or has the wrong form,
 * so a key whose sign-in did not finish is never stored.
 * @param {import("../store/idb.mjs").Store} store
 * @param {DeviceKey} key from {@link generateDeviceKey}
 * @param {{ deviceId: string, accountId: string, refreshToken: string }} signedIn
 * @returns {Promise<void>}
 */
export async function saveDeviceKey(store, key, { deviceId, accountId, refreshToken }) {
  const record = checkRecord({
    serverUrl: key?.serverUrl,
    privateKey: key?.privateKey,
    publicJwk: key?.publicJwk,
    deviceId,
    accountId,
    refreshToken,
  });
  await run(store, ["device_keys"], "readwrite", async ([table]) => {
    await req(table.put(record));
  });
}

/**
 * The stored device key of a server, or null when there is none. A stored
 * record that does not pass the checks of a save is refused (`StoreError`,
 * code `device_key_malformed`), never handed on.
 * @param {import("../store/idb.mjs").Store} store
 * @param {string} serverUrl
 * @returns {Promise<DeviceKey | null>}
 */
export async function loadDeviceKey(store, serverUrl) {
  const server = serverKey(serverUrl);
  const row = await run(store, ["device_keys"], "readonly", ([table]) => req(table.get(server)));
  if (row === undefined) return null;
  return checkRecord(row);
}

/**
 * Removes the device key of a server (signing out of the device, or forgetting
 * the server). Removing a key that is not there is not an error.
 * @param {import("../store/idb.mjs").Store} store
 * @param {string} serverUrl
 * @returns {Promise<void>}
 */
export async function deleteDeviceKey(store, serverUrl) {
  const server = serverKey(serverUrl);
  await run(store, ["device_keys"], "readwrite", async ([table]) => {
    await req(table.delete(server));
  });
}

/**
 * Replaces the refresh token of the stored device key of a server, in one
 * transaction. A renewal writes the new refresh token here before the new
 * access token is used. Refused (`StoreError`) when there is no stored key or
 * the token has the wrong form; then nothing changes.
 * @param {import("../store/idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} refreshToken
 * @returns {Promise<void>}
 */
export async function saveRefreshToken(store, serverUrl, refreshToken) {
  const server = serverKey(serverUrl);
  if (!isToken(refreshToken)) throw new StoreError("device_key_malformed", "refreshToken is a token");
  await run(store, ["device_keys"], "readwrite", async ([table]) => {
    const row = await req(table.get(server));
    if (row === undefined) throw new StoreError("device_key_missing", "there is no device key for this server");
    const record = checkRecord(row);
    await req(table.put({ ...record, refreshToken }));
  });
}

/**
 * The JWK SHA-256 thumbprint of a public key (RFC 7638 § 3), as base64url
 * without padding: SHA-256 of `{"crv":"P-256","kty":"EC","x":…,"y":…}`, the
 * required members in lexical order and no white space. It is the `jkt` the
 * server binds the device to.
 * @param {PublicJwk} publicJwk
 * @returns {Promise<string>}
 */
export async function thumbprint(publicJwk) {
  const { crv, kty, x, y } = publicJwkOf(publicJwk, true);
  // The members are fixed words and base64url, so no character needs escaping.
  const canonical = `{"crv":"${crv}","kty":"${kty}","x":"${x}","y":"${y}"}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return b64u.encode(new Uint8Array(digest));
}
