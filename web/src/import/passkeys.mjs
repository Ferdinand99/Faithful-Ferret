// The passkeys of an import file: what a reader makes of the passkey of a login in an unencrypted export of
// Bitwarden (`login.fido2Credentials`) or of AliasVault (`items[].passkeys`), for the vault's `passkey_import`.
//
// The formats (the names of the members, how an id and a key are written) were read from the sources of
// both programs and are written down in the notes of the reader files; nothing here is copied from them.
//
// What this file does and does not do:
//
// * It reads. It checks the shape of what the file says and turns it into the arguments of `passkey_import`
//   (bytes, text and numbers); the vault's core checks the key itself (a P-256 key, the site's name, the
//   lengths) and has the last word. A key never leaves the import worker except over the port to the vault
//   worker, and it is never put in a draft, a report, an error or a log (Global Constraint 46, L6).
// * It counts what it leaves out, by reason, and says nothing of the file but counts and a position.
//   Ferret's passkeys are all discoverable, so a passkey that is not (`discoverable: "false"`, or no user
//   handle) is left out. A key that is not ECDSA on P-256 (RSA, Ed25519, another curve) is left out too.
// * The credential id of Bitwarden is a GUID (16 bytes, in the order the text is written, RFC 4122) or
//   `b64.` and a base64url text; AliasVault's is standard base64 with padding, or, when it has none, the
//   16 bytes of the GUID in `id` in the same order. Standard base64 and base64url are told apart and not
//   mixed. A PRF key of AliasVault gives both PRF seeds (the same formula as Ferret's) only when it is 32
//   bytes; any other length drops the PRF, with a warning, and keeps the passkey.
// * A passkey that Ferret already has (the same site and credential id, in the vault, in the trash, or earlier
//   in this file) is left out; the dedupe key is `passkeyKey`.

import { scalar, warn } from "./map.mjs";

/**
 * @typedef {{
 *   cred_id: Uint8Array, rp_id: string, user_handle: Uint8Array, user_name: string, rp_name?: string,
 *   user_display_name?: string, created: number, counter: number,
 *   key_pkcs8?: Uint8Array, key_jwk?: string, prf_seed_uv?: Uint8Array, prf_seed_nouv?: Uint8Array,
 * }} PasskeyInput the `passkey` argument of `passkey_import`
 * @typedef {{ index: number, input: PasskeyInput, extra: boolean }} PasskeyTask `index` is the position of the
 *   login's draft in the list of drafts; `extra` says that the passkey gets an item of its own (it is the second
 *   or later of its login, or its item is not a login)
 */

/** The reasons a passkey is left out, in the order the page lists them (`import.skipped.passkey_<reason>`). */
export const PASSKEY_SKIP_REASONS = Object.freeze(["not_discoverable", "other_key", "bad_site", "unreadable", "duplicate"]);

/** The most sites a report names for the passkeys that must be registered again. */
export const MAX_SITES = 20;

/** The longest credential id, user handle and key document the core takes (and a little room for the text of a key). */
const MAX_CRED_ID = 1023;
const MAX_HANDLE = 64;
const MAX_PKCS8 = 1024;
const MAX_JWK_TEXT = 4096;
const MAX_CREATED = Number.MAX_SAFE_INTEGER;

const STD = /^[A-Za-z0-9+/]*={0,2}$/;
const URL_SAFE = /^[A-Za-z0-9_-]*={0,2}$/;
const GUID = /^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$/;

/**
 * The bytes of a base64 text, or null when it is not one: the alphabet is the standard one (`+` and `/`) or the URL one
 * (`-` and `_`), as `urlSafe` says, and the padding is optional but, when there is some, whole.
 * @param {unknown} text
 * @param {boolean} urlSafe
 * @returns {Uint8Array | null}
 */
export function decodeBase64(text, urlSafe) {
  if (typeof text !== "string" || text === "" || text.length > 8192) return null;
  if (!(urlSafe ? URL_SAFE : STD).test(text)) return null;
  const bare = text.replace(/=+$/, "");
  const padding = text.length - bare.length;
  if (bare.length % 4 === 1 || (padding > 0 && text.length % 4 !== 0)) return null;
  const std = urlSafe ? bare.replace(/-/g, "+").replace(/_/g, "/") : bare;
  let binary;
  try {
    binary = atob(std);
  } catch {
    return null;
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * The 16 bytes of a GUID text, in the order the text is written (RFC 4122), or null. Not the mixed-endian order of .NET's
 * `Guid.ToByteArray`.
 * @param {unknown} text
 * @returns {Uint8Array | null}
 */
export function guidBytes(text) {
  if (typeof text !== "string") return null;
  const m = GUID.exec(text.trim());
  if (m === null) return null;
  const hex = m.slice(1).join("");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** @param {Uint8Array} bytes */
function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * The identity of a passkey for the dedupe: the site (as the core stores it, canonical) and the credential id.
 * @param {string} rpId
 * @param {Uint8Array} credId
 */
export function passkeyKey(rpId, credId) {
  return `${rpId}\n${toHex(credId)}`;
}

/**
 * The counter of a source: whole decimal text (or a whole number) from 0 to 2^32 - 1; none is 0.
 * @param {unknown} raw
 * @returns {number | null} null for a value that is none of these
 */
function counterOf(raw) {
  if (raw === undefined || raw === null || raw === "") return 0;
  const text = typeof raw === "number" ? String(raw) : typeof raw === "string" ? raw.trim() : "";
  if (!/^\d{1,10}$/.test(text)) return null;
  const n = Number(text);
  return n <= 0xffffffff ? n : null;
}

/**
 * A moment in the file as milliseconds, or `fallback`.
 * @param {unknown} raw
 * @param {number} fallback
 */
function momentOf(raw, fallback) {
  if (typeof raw !== "string" || raw === "") return fallback;
  const ms = Date.parse(raw);
  return Number.isSafeInteger(ms) && ms >= 0 && ms <= MAX_CREATED ? ms : fallback;
}

/** @param {unknown} value @returns {string} a text with no lone surrogate, or "" */
const text = (value) => (typeof value === "string" ? scalar(value) : "");

/**
 * @typedef {{ input: PasskeyInput } | { skip: "not_discoverable" | "other_key" | "bad_site" | "unreadable" }} Read
 */

/**
 * Reads one `fido2Credentials` entry of a Bitwarden export.
 * @param {unknown} raw
 * @param {{ now: number }} context
 * @returns {Read}
 */
export function readBitwardenPasskey(raw, { now }) {
  const c = raw !== null && typeof raw === "object" && !Array.isArray(raw) ? /** @type {Record<string, unknown>} */ (raw) : null;
  if (c === null) return { skip: "unreadable" };
  // Ferret's passkeys are all discoverable, and a handle is needed to find one.
  if (scalar(c.discoverable).trim().toLowerCase() === "false") return { skip: "not_discoverable" };
  if (typeof c.userHandle !== "string" || c.userHandle === "") return { skip: "not_discoverable" };
  if (c.keyType !== "public-key" || c.keyAlgorithm !== "ECDSA" || c.keyCurve !== "P-256") return { skip: "other_key" };
  const rpId = text(c.rpId);
  if (rpId === "") return { skip: "bad_site" };

  const id = typeof c.credentialId === "string" ? c.credentialId : "";
  const credId = id.startsWith("b64.") ? decodeBase64(id.slice(4), true) : guidBytes(id);
  const handle = decodeBase64(c.userHandle, true);
  const key = decodeBase64(c.keyValue, true);
  const counter = counterOf(c.counter);
  if (credId === null || credId.length > MAX_CRED_ID || handle === null || handle.length > MAX_HANDLE || key === null || key.length > MAX_PKCS8 || counter === null) {
    key?.fill(0);
    return { skip: "unreadable" };
  }
  /** @type {PasskeyInput} */
  const input = {
    cred_id: credId, rp_id: rpId, user_handle: handle, user_name: text(c.userName), created: momentOf(c.creationDate, now), counter, key_pkcs8: key,
  };
  const rpName = text(c.rpName);
  if (rpName !== "") input.rp_name = rpName;
  const display = text(c.userDisplayName);
  if (display !== "") input.user_display_name = display;
  return { input };
}

/**
 * Reads one entry of `passkeys` of an AliasVault item (the members are named in lower case, as `members` of the reader gives them).
 * @param {Record<string, unknown>} c
 * @param {{ now: number, userName: string, created: number }} context `userName`: the user name of the item's login
 * @returns {Read & { prfDropped?: boolean }}
 */
export function readAliasVaultPasskey(c, { now, userName, created }) {
  if (typeof c.userhandle !== "string" || c.userhandle === "") return { skip: "not_discoverable" };
  const rpId = text(c.rpid);
  if (rpId === "") return { skip: "bad_site" };
  const privateKey = typeof c.privatekey === "string" ? c.privatekey : "";
  if (privateKey === "" || privateKey.length > MAX_JWK_TEXT) return { skip: "unreadable" };
  // Only to see what kind of key it is: the text itself goes on as it is, the core reads it.
  let kind = /** @type {{ kty?: unknown, crv?: unknown } | null} */ (null);
  try {
    const parsed = JSON.parse(privateKey);
    kind = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? { kty: parsed.kty, crv: parsed.crv } : null;
  } catch {
    kind = null;
  }
  if (kind === null) return { skip: "unreadable" };
  if ((kind.kty !== undefined && kind.kty !== "EC") || kind.crv !== "P-256") return { skip: "other_key" };

  const credId = typeof c.credentialid === "string" && c.credentialid !== "" ? decodeBase64(c.credentialid, false) : guidBytes(c.id);
  const handle = decodeBase64(c.userhandle, false);
  const counter = 0;
  if (credId === null || credId.length > MAX_CRED_ID || handle === null || handle.length > MAX_HANDLE) return { skip: "unreadable" };
  const display = text(c.displayname);
  /** @type {PasskeyInput} */
  const input = {
    cred_id: credId, rp_id: rpId, user_handle: handle, user_name: userName !== "" ? userName : display, created: created > 0 ? created : now, counter, key_jwk: privateKey,
  };
  if (display !== "") input.user_display_name = display;
  // AliasVault's one PRF secret answers for both (the same formula as Ferret's): a secret of any other length is no PRF key.
  let prfDropped = false;
  if (c.prfkey !== undefined && c.prfkey !== null && c.prfkey !== "") {
    const prf = typeof c.prfkey === "string" ? decodeBase64(c.prfkey, false) : null;
    if (prf !== null && prf.length === 32) {
      input.prf_seed_uv = prf;
      input.prf_seed_nouv = prf.slice();
    } else {
      prf?.fill(0);
      prfDropped = true;
    }
  }
  return { input, prfDropped };
}

/**
 * Counts a passkey that is left out.
 * @param {import("./map.mjs").ImportReport} report
 * @param {string} reason one of `PASSKEY_SKIP_REASONS`
 */
export function skipPasskey(report, reason) {
  report.skipped.passkeys++;
  report.passkeys.skipped[/** @type {keyof typeof report.passkeys.skipped} */ (reason)]++;
}

/**
 * Reads the passkeys of one login of a Bitwarden export into tasks, and counts what is left out.
 * @param {unknown[]} entries the `fido2Credentials` of the login
 * @param {{ report: import("./map.mjs").ImportReport, index: number, now: number }} context `index`: the position of the item in the file
 * @param {number} draftIndex the position of the login's draft in the list of drafts
 * @returns {PasskeyTask[]}
 */
export function bitwardenPasskeys(entries, { report, index, now }, draftIndex) {
  /** @type {PasskeyTask[]} */
  const tasks = [];
  for (const entry of entries) {
    const read = readBitwardenPasskey(entry, { now });
    if ("skip" in read) {
      skipPasskey(report, read.skip);
      continue;
    }
    addTask(tasks, read.input, draftIndex, true, { report, index });
  }
  return tasks;
}

/**
 * Reads the passkeys of one AliasVault item into tasks, and counts what is left out.
 * @param {Record<string, unknown>[]} entries
 * @param {{ report: import("./map.mjs").ImportReport, index: number, now: number, userName: string, created: number }} context
 * @param {number} draftIndex
 * @param {boolean} login whether the item's draft is a login (a passkey can only join a login)
 * @returns {PasskeyTask[]}
 */
export function aliasVaultPasskeys(entries, { report, index, now, userName, created }, draftIndex, login) {
  /** @type {PasskeyTask[]} */
  const tasks = [];
  for (const entry of entries) {
    const read = readAliasVaultPasskey(entry, { now, userName, created });
    if ("skip" in read) {
      skipPasskey(report, read.skip);
      continue;
    }
    if (read.prfDropped) {
      report.passkeys.prfDropped++;
      warn(report, "passkey_prf_dropped", index);
    }
    addTask(tasks, read.input, draftIndex, login, { report, index });
  }
  return tasks;
}

/**
 * @param {PasskeyTask[]} tasks
 * @param {PasskeyInput} input
 * @param {number} draftIndex
 * @param {boolean} login
 * @param {{ report: import("./map.mjs").ImportReport, index: number }} context
 */
function addTask(tasks, input, draftIndex, login, { report, index }) {
  // The first passkey of a login joins it; a second one, or one of an item that is no login, gets an item of its own.
  const extra = !login || tasks.length > 0;
  if (extra) {
    report.passkeys.extra++;
    warn(report, "passkey_extra_item", index);
  }
  tasks.push({ index: draftIndex, input, extra });
}

/**
 * Wipes what a task holds of the key.
 * @param {PasskeyInput} input
 */
export function wipeInput(input) {
  for (const key of /** @type {const} */ (["key_pkcs8", "prf_seed_uv", "prf_seed_nouv"])) input[key]?.fill(0);
}
