// The wire form of a page's WebAuthn options and of the answer (the `passkeys` feature): JSON with the bytes in
// unpadded base64url, inside the limits of PASSKEY_LIMITS (shared/contentProtocol.mjs). Plain ESM, no dependencies but the
// protocol, so it runs in the bridge script of a page, in the background and in a unit test alike.
//
//   optionsToWire(kind, plain)      the bridge: what the page's script (content/passkey.main.entry.mjs) copied out of the
//                                   page's options (WebAuthn names, ArrayBuffers) -> the wire options of PASSKEY_CREATE_OPTIONS
//                                   or PASSKEY_GET_OPTIONS, or null for anything outside the limits or of the wrong type
//                                   (the page's call then goes to the browser untouched, which gives its own answer)
//   responseToWire(kind, fields)    the background: the core's answer (bytes as Uint8Array) -> PASSKEY_RESPONSE
//   responseFromWire(kind, wire)    the bridge: PASSKEY_RESPONSE -> the same fields with ArrayBuffers, for the page's
//                                   script to build the credential from; null when the fields are not those of `kind`
//   toB64u(bytes), fromB64u(text)   the byte form
//
// Nothing here decides whether Ferret answers a call: that is the background's (design § 9.2). This module only refuses a
// shape it cannot carry. Bytes are copied, never shared with the caller's buffers.

import { PASSKEY_CREATE_OPTIONS, PASSKEY_GET_OPTIONS, PASSKEY_LIMITS, PASSKEY_RESPONSE, ProtocolError } from "./contentProtocol.mjs";
import { validate } from "./schema.mjs";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** @type {Record<string, number>} */
const INDEX = Object.fromEntries([...ALPHABET].map((c, i) => [c, i]));
const encoder = new TextEncoder();

class WireError extends Error {}
const bad = () => new WireError("wire");

/**
 * Unpadded base64url of `bytes`.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toB64u(bytes) {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += ALPHABET[n >> 18] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63];
  }
  if (i + 1 === bytes.length) {
    const n = bytes[i] << 16;
    out += ALPHABET[n >> 18] + ALPHABET[(n >> 12) & 63];
  } else if (i + 2 === bytes.length) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += ALPHABET[n >> 18] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63];
  }
  return out;
}

/**
 * The bytes of unpadded base64url text. Refuses padding, other characters, a length no encoding has, and spare bits
 * that are not zero (so every byte string has exactly one text).
 * @param {string} text
 * @returns {Uint8Array}
 */
export function fromB64u(text) {
  if (typeof text !== "string" || text.length % 4 === 1) throw new ProtocolError("bad_shape", "base64url");
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let at = 0;
  for (const c of text) {
    const v = INDEX[c];
    if (v === undefined || !Object.hasOwn(INDEX, c)) throw new ProtocolError("bad_shape", "base64url");
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (value >> bits) & 255;
    }
  }
  if ((value & ((1 << bits) - 1)) !== 0) throw new ProtocolError("bad_shape", "base64url");
  return out;
}

/** True for an ArrayBuffer of any realm (the page's script and the bridge are different worlds). @param {unknown} x */
const isBuffer = (x) => Object.prototype.toString.call(x) === "[object ArrayBuffer]";

/** @param {unknown} x @returns {x is Record<string, unknown>} */
const isRecord = (x) => typeof x === "object" && x !== null && !Array.isArray(x);

/**
 * An own property of a plain record, or undefined. (What the bridge gets is a structured clone: own data properties only.)
 * @param {unknown} o @param {string} key
 */
const own = (o, key) => (isRecord(o) && Object.hasOwn(o, key) ? o[key] : undefined);

/** @param {unknown} x @param {number} max @param {number} [min] */
function bytes(x, max, min = 1) {
  if (!isBuffer(x)) throw bad();
  const view = new Uint8Array(/** @type {ArrayBuffer} */ (x));
  if (view.length < min || view.length > max) throw bad();
  return toB64u(view);
}

/** @param {unknown} x */
function text(x) {
  if (typeof x !== "string" || x.length > PASSKEY_LIMITS.text || encoder.encode(x).length > PASSKEY_LIMITS.text) throw bad();
  return x;
}

/** @param {unknown} x */
function word(x) {
  if (typeof x !== "string" || x.length > 32) throw bad();
  return x;
}

/**
 * @template T
 * @param {unknown} x @param {number} max @param {(item: unknown) => T} each
 * @returns {T[]}
 */
function list(x, max, each) {
  if (!Array.isArray(x) || x.length > max) throw bad();
  /** @type {T[]} */
  const out = [];
  for (let i = 0; i < x.length; i += 1) out.push(each(x[i]));
  return out;
}

/** @param {unknown} x */
const words = (x) => list(x, PASSKEY_LIMITS.words, word);

/** @param {unknown} x */
function credential(x) {
  /** @type {Record<string, unknown>} */
  const out = { type: word(own(x, "type")), id: bytes(own(x, "id"), PASSKEY_LIMITS.credentialId) };
  if (own(x, "transports") !== undefined) out.transports = words(own(x, "transports"));
  return out;
}

/** @param {unknown} x */
function salts(x) {
  /** @type {Record<string, unknown>} */
  const out = { first: bytes(own(x, "first"), PASSKEY_LIMITS.prfSalt, 0) };
  if (own(x, "second") !== undefined) out.second = bytes(own(x, "second"), PASSKEY_LIMITS.prfSalt, 0);
  return out;
}

/** The extensions the wire carries by value; any other name goes in `others`. */
const KNOWN_EXTENSIONS = Object.freeze(["credProps", "prf", "appid", "appidExclude"]);

/** @param {unknown} x */
function extensions(x) {
  /** @type {Record<string, unknown>} */
  const out = {};
  if (x === undefined) return out;
  if (!isRecord(x)) throw bad();
  if (own(x, "credProps") !== undefined) {
    if (typeof own(x, "credProps") !== "boolean") throw bad();
    out.cred_props = own(x, "credProps");
  }
  const prf = own(x, "prf");
  if (prf !== undefined) {
    if (!isRecord(prf)) throw bad();
    /** @type {Record<string, unknown>} */
    const p = {};
    if (own(prf, "eval") !== undefined) p.eval = salts(own(prf, "eval"));
    const byCredential = own(prf, "evalByCredential");
    if (byCredential !== undefined) {
      if (!isRecord(byCredential)) throw bad();
      const keys = Object.keys(byCredential);
      if (keys.length > PASSKEY_LIMITS.list) throw bad();
      p.eval_by_credential = keys.map((id) => {
        // The key is the credential id in base64url, as WebAuthn has it; it must be one.
        const raw = id.length === 0 ? null : fromB64uOrNull(id);
        if (raw === null || raw.length === 0 || raw.length > PASSKEY_LIMITS.credentialId) throw bad();
        return { id, ...salts(byCredential[id]) };
      });
    }
    out.prf = p;
  }
  for (const [name, key] of /** @type {const} */ ([["appid", "appid"], ["appidExclude", "appid_exclude"]])) {
    if (own(x, name) !== undefined) out[key] = text(own(x, name));
  }
  const others = own(x, "others");
  if (others !== undefined) {
    const names = list(others, PASSKEY_LIMITS.otherExtensions, (n) => {
      if (typeof n !== "string" || n.length === 0 || n.length > 64 || KNOWN_EXTENSIONS.includes(n)) throw bad();
      return n;
    });
    if (names.length > 0) out.others = names;
  }
  return out;
}

/** @param {string} id */
function fromB64uOrNull(id) {
  try {
    return fromB64u(id);
  } catch {
    return null;
  }
}

/**
 * Copies `key` into `out` under `wireKey` when the page gave it.
 * @param {Record<string, unknown>} out @param {unknown} from @param {string} key @param {string} wireKey @param {(x: unknown) => unknown} read
 */
function optional(out, from, key, wireKey, read) {
  const value = own(from, key);
  if (value !== undefined) out[wireKey] = read(value);
}

/** @param {unknown} x */
function timeout(x) {
  if (typeof x !== "number" || !Number.isSafeInteger(x) || x < 0 || x > 4_294_967_295) throw bad();
  return x;
}

/** @param {unknown} o */
function createToWire(o) {
  const rp = own(o, "rp");
  const user = own(o, "user");
  /** @type {Record<string, unknown>} */
  const rpOut = { name: text(own(rp, "name")) };
  optional(rpOut, rp, "id", "id", text);
  /** @type {Record<string, unknown>} */
  const out = {
    challenge: bytes(own(o, "challenge"), PASSKEY_LIMITS.challenge),
    rp: rpOut,
    user: { id: bytes(own(user, "id"), PASSKEY_LIMITS.userId, 0), name: text(own(user, "name")), display_name: text(own(user, "displayName")) },
    pub_key_cred_params: list(own(o, "pubKeyCredParams"), PASSKEY_LIMITS.list, (p) => {
      const alg = own(p, "alg");
      if (typeof alg !== "number" || !Number.isSafeInteger(alg) || alg < -2_147_483_648 || alg > 2_147_483_647) throw bad();
      return { type: word(own(p, "type")), alg };
    }),
    exclude_credentials: list(own(o, "excludeCredentials") ?? [], PASSKEY_LIMITS.list, credential),
    hints: words(own(o, "hints") ?? []),
    extensions: extensions(own(o, "extensions")),
  };
  optional(out, o, "timeout", "timeout", timeout);
  const selection = own(o, "authenticatorSelection");
  if (selection !== undefined) {
    if (!isRecord(selection)) throw bad();
    /** @type {Record<string, unknown>} */
    const s = {};
    optional(s, selection, "authenticatorAttachment", "authenticator_attachment", word);
    optional(s, selection, "residentKey", "resident", word);
    optional(s, selection, "requireResidentKey", "require_resident", (v) => {
      if (typeof v !== "boolean") throw bad();
      return v;
    });
    optional(s, selection, "userVerification", "user_verification", word);
    out.authenticator_selection = s;
  }
  optional(out, o, "attestation", "attestation", word);
  optional(out, o, "attestationFormats", "attestation_formats", words);
  return out;
}

/** @param {unknown} o */
function getToWire(o) {
  /** @type {Record<string, unknown>} */
  const out = {
    challenge: bytes(own(o, "challenge"), PASSKEY_LIMITS.challenge),
    allow_credentials: list(own(o, "allowCredentials") ?? [], PASSKEY_LIMITS.list, credential),
    hints: words(own(o, "hints") ?? []),
    extensions: extensions(own(o, "extensions")),
  };
  optional(out, o, "timeout", "timeout", timeout);
  optional(out, o, "rpId", "rp_id", text);
  optional(out, o, "userVerification", "user_verification", word);
  optional(out, o, "attestation", "attestation", word);
  optional(out, o, "attestationFormats", "attestation_formats", words);
  return out;
}

/**
 * The wire options of a page's call, from the copy the page's script made (WebAuthn names, bytes as ArrayBuffer), or
 * null when a value is of the wrong type or over a limit. Unknown keys are not carried.
 * @param {"create" | "get"} kind
 * @param {unknown} plain
 * @returns {Record<string, unknown> | null}
 */
export function optionsToWire(kind, plain) {
  try {
    if (!isRecord(plain)) return null;
    const wire = kind === "create" ? createToWire(plain) : kind === "get" ? getToWire(plain) : null;
    if (wire === null) return null;
    // The schema the background decodes with, so a shape the bridge sends is one it takes.
    return validate(kind === "create" ? PASSKEY_CREATE_OPTIONS : PASSKEY_GET_OPTIONS, wire);
  } catch {
    return null;
  }
}

/** The fields of the answer that only one kind has. */
const CREATE_ONLY = Object.freeze(["attestation_object", "spki", "public_key_algorithm", "transports"]);
const GET_ONLY = Object.freeze(["signature", "user_handle"]);

/**
 * @typedef {{
 *   id: Uint8Array, client_data_json: Uint8Array, authenticator_data: Uint8Array, authenticator_attachment: string | null,
 *   attestation_object?: Uint8Array, spki?: Uint8Array | null, public_key_algorithm?: number, transports?: string[],
 *   signature?: Uint8Array, user_handle?: Uint8Array | null,
 *   client_extension_results?: { cred_props?: { rk: boolean }, prf?: { enabled?: boolean, results?: { first: Uint8Array, second?: Uint8Array } } },
 * }} ResponseFields
 */

/**
 * The answer for the page on the wire, from the core's fields (bytes as Uint8Array).
 * @param {"create" | "get"} kind @param {ResponseFields} fields
 * @returns {Record<string, unknown>} a body of PASSKEY_RESPONSE
 */
export function responseToWire(kind, fields) {
  const b = (/** @type {Uint8Array} */ x) => toB64u(x);
  /** @type {Record<string, unknown>} */
  const out = {
    id: b(fields.id),
    client_data_json: b(fields.client_data_json),
    authenticator_data: b(fields.authenticator_data),
    authenticator_attachment: fields.authenticator_attachment ?? null,
  };
  if (kind === "create") {
    out.attestation_object = b(/** @type {Uint8Array} */ (fields.attestation_object));
    out.spki = fields.spki ? b(fields.spki) : null;
    out.public_key_algorithm = fields.public_key_algorithm;
    out.transports = [...(fields.transports ?? [])];
  } else {
    out.signature = b(/** @type {Uint8Array} */ (fields.signature));
    out.user_handle = fields.user_handle ? b(fields.user_handle) : null;
  }
  /** @type {Record<string, unknown>} */
  const ext = {};
  const given = fields.client_extension_results ?? {};
  if (given.cred_props) ext.cred_props = { rk: given.cred_props.rk === true };
  if (given.prf) {
    /** @type {Record<string, unknown>} */
    const prf = {};
    if (typeof given.prf.enabled === "boolean") prf.enabled = given.prf.enabled;
    if (given.prf.results) {
      prf.results = { first: b(given.prf.results.first), ...(given.prf.results.second ? { second: b(given.prf.results.second) } : {}) };
    }
    ext.prf = prf;
  }
  out.client_extension_results = ext;
  return validate(PASSKEY_RESPONSE, out);
}

/** @param {string} text @returns {ArrayBuffer} */
const buffer = (text) => {
  const bytes = fromB64u(text);
  const out = new ArrayBuffer(bytes.length);
  new Uint8Array(out).set(bytes);
  return out;
};

/**
 * The answer with its bytes as ArrayBuffers (WebAuthn names), for the page's script; null when it is not an answer of
 * `kind` (a field of the other kind, or one of its own missing).
 * @param {"create" | "get"} kind @param {unknown} wire a decoded PASSKEY_RESPONSE
 * @returns {Record<string, unknown> | null}
 */
export function responseFromWire(kind, wire) {
  try {
    const r = validate(PASSKEY_RESPONSE, wire);
    const mine = kind === "create" ? CREATE_ONLY : GET_ONLY;
    const theirs = kind === "create" ? GET_ONLY : CREATE_ONLY;
    if (theirs.some((k) => Object.hasOwn(r, k))) return null;
    if (mine.some((k) => !Object.hasOwn(r, k))) return null;
    /** @type {Record<string, unknown>} */
    const out = {
      id: buffer(r.id),
      clientDataJSON: buffer(r.client_data_json),
      authenticatorData: buffer(r.authenticator_data),
      authenticatorAttachment: r.authenticator_attachment,
    };
    if (kind === "create") {
      out.attestationObject = buffer(r.attestation_object);
      out.publicKey = r.spki === null ? null : buffer(r.spki);
      out.publicKeyAlgorithm = r.public_key_algorithm;
      out.transports = [...r.transports];
    } else {
      out.signature = buffer(r.signature);
      out.userHandle = r.user_handle === null ? null : buffer(r.user_handle);
    }
    /** @type {Record<string, unknown>} */
    const ext = {};
    const given = r.client_extension_results;
    if (given.cred_props) ext.credProps = { rk: given.cred_props.rk };
    if (given.prf) {
      /** @type {Record<string, unknown>} */
      const prf = {};
      if (Object.hasOwn(given.prf, "enabled")) prf.enabled = given.prf.enabled;
      if (given.prf.results) {
        prf.results = { first: buffer(given.prf.results.first), ...(given.prf.results.second ? { second: buffer(given.prf.results.second) } : {}) };
      }
      ext.prf = prf;
    }
    out.clientExtensionResults = ext;
    return out;
  } catch {
    return null;
  }
}
