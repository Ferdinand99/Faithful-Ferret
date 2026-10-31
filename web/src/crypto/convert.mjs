// Conversions between the wire (base64url text, hex ids) and what the core's
// bindings take (byte arrays). Nothing here is cryptography.
import { b64u, hex16 } from "../b64.mjs";
import { AccountError } from "./errors.mjs";

const TYPE_NUMBER = Object.freeze({ password: 1, recovery: 2, prf: 3 });
const TYPE_NAME = Object.freeze(/** @type {Record<number, string>} */ ({ 1: "password", 2: "recovery", 3: "prf" }));

/** @param {unknown} value @returns {number} */
export function num(value) {
  return typeof value === "bigint" ? Number(value) : /** @type {number} */ (value);
}

/**
 * The master password as UTF-8 bytes in a fresh array the caller wipes. A
 * string with a lone surrogate is refused: encoding it would change it.
 * @param {unknown} text
 * @returns {Uint8Array}
 */
export function encodePassword(text) {
  if (typeof text !== "string" || text === "") throw new AccountError("password_required");
  const wellFormed = /** @type {any} */ (String.prototype).isWellFormed;
  if (typeof wellFormed === "function" && !wellFormed.call(text)) throw new AccountError("input_not_utf8");
  return new TextEncoder().encode(text);
}

/**
 * Runs `use` with a fresh byte array of the password and wipes the array after.
 * @template T
 * @param {string} password
 * @param {(bytes: Uint8Array) => Promise<T>} use
 * @returns {Promise<T>}
 */
export async function withPassword(password, use) {
  const bytes = encodePassword(password);
  try {
    return await use(bytes);
  } finally {
    bytes.fill(0);
  }
}

/**
 * A wrap as the core made it, for the wire.
 * @param {Record<string, any>} wrap
 */
export function wrapToWire(wrap) {
  const type = wrap?.method?.type;
  if (!Object.hasOwn(TYPE_NUMBER, type)) throw new AccountError("methods_invalid");
  /** @type {Record<string, any>} */
  const out = {
    method_id: hex16.encode(wrap.method_id),
    method_type: TYPE_NUMBER[/** @type {"password"} */ (type)],
    kek_generation: num(wrap.kek_generation),
    wrap: b64u.encode(wrap.wrap),
  };
  if (type === "prf") {
    out.credential_id = b64u.encode(wrap.method.credential_id);
    out.prf_salt = b64u.encode(wrap.method.prf_salt);
  }
  return out;
}

/**
 * A wrap from the server's list, for the core. The password wrap's key
 * stretching profile is the one the sign-in used.
 * @param {Record<string, any>} wrap
 * @param {number} ksfProfile
 */
export function wrapToCore(wrap, ksfProfile) {
  const type = TYPE_NAME[wrap.method_type];
  if (type === undefined) throw new AccountError("methods_invalid");
  /** @type {Record<string, any>} */
  const method = { type };
  if (type === "password") method.ksf_profile = ksfProfile;
  if (type === "prf") {
    method.credential_id = b64u.decode(wrap.credential_id);
    method.prf_salt = b64u.decode(wrap.prf_salt);
  }
  return {
    method_id: hex16.decode(wrap.method_id),
    kek_generation: wrap.kek_generation,
    method,
    wrap: b64u.decode(wrap.wrap),
  };
}

/** @param {Record<string, any>} row */
export function rowToWire(row) {
  return { rev: num(row.rev), envelope: b64u.encode(row.envelope), tag: b64u.encode(row.tag) };
}

/** @param {Record<string, any>} row */
export function rowToCore(row) {
  return { rev: row.rev, envelope: b64u.decode(row.envelope), tag: b64u.decode(row.tag) };
}

/** @param {Record<string, any>} checkpoint */
export function checkpointToWire(checkpoint) {
  return {
    seq: num(checkpoint.seq),
    digest: b64u.encode(checkpoint.digest),
    mac: b64u.encode(checkpoint.mac),
    entries: b64u.encode(checkpoint.entries),
  };
}

/**
 * The list the server gave, in the form `check_server_methods` takes.
 * @param {ReadonlyArray<Record<string, any>>} methods
 */
export function serverMethods(methods) {
  return methods.map((m) => ({
    method_type: m.method_type,
    method_id: hex16.decode(m.method_id),
    kek_generation: m.kek_generation,
  }));
}
