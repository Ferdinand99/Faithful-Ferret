// The wire contract, from the web side: a strict JSON reader and a
// field-by-field description of every request and answer shape of the vault
// API. crates/ferret-server/tests/fixtures/wire/ holds the examples that the
// Rust tests and test/unit/wire.test.mjs read; both sides accept the same valid
// ones and refuse the same invalid ones with the same code, so the server and
// the vault cannot drift apart.
//
// The reader is stricter than `JSON.parse`: a repeated field is refused, and so
// is every number that is not a whole number from 0 to 2^53 - 1 written
// without a sign, fraction or exponent (the wire has no other numbers).
// Fields are refused when they are not in the shape: an unknown field is as
// wrong as a missing one. The messages of a `WireError` can quote the input
// (the JSON parser's message, a token, a field name): show or log `error.code`
// only.
import { b64u, hex16, WireError } from "./b64.mjs";

export { WireError };

/** @type {(message: string, code?: string) => never} */
const refuse = (message, code = "bad_request") => {
  throw new WireError(message, code);
};

// ----------------------------------------------------------- JSON reader

const MAX_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const WHITE = new Set([" ", "\t", "\n", "\r"]);

/**
 * Reads JSON text strictly (see the top of this file).
 * @param {string} text
 * @returns {any}
 */
export function readJson(text) {
  if (typeof text !== "string") refuse("not text");
  try {
    JSON.parse(text); // the syntax
  } catch (error) {
    refuse(`not JSON: ${/** @type {Error} */ (error).message}`);
  }
  let at = 0;
  const skip = () => {
    while (WHITE.has(text[at])) at += 1;
  };
  const string = () => {
    const pattern = /"(?:[^"\\]|\\.)*"/y;
    pattern.lastIndex = at;
    const hit = /** @type {RegExpExecArray} */ (pattern.exec(text));
    at = pattern.lastIndex;
    return JSON.parse(hit[0]);
  };
  /** @returns {any} */
  const value = () => {
    skip();
    const c = text[at];
    if (c === "{") {
      at += 1;
      /** @type {Record<string, any>} */
      const out = Object.create(null);
      skip();
      if (text[at] === "}") {
        at += 1;
        return out;
      }
      for (;;) {
        skip();
        const key = string();
        if (Object.hasOwn(out, key)) refuse(`repeated field ${key}`);
        skip();
        at += 1; // ":"
        out[key] = value();
        skip();
        const next = text[at];
        at += 1;
        if (next === "}") return out;
      }
    }
    if (c === "[") {
      at += 1;
      /** @type {any[]} */
      const out = [];
      skip();
      if (text[at] === "]") {
        at += 1;
        return out;
      }
      for (;;) {
        out.push(value());
        skip();
        const next = text[at];
        at += 1;
        if (next === "]") return out;
      }
    }
    if (c === '"') return string();
    const pattern = /true|false|null|-?[0-9][0-9.eE+-]*/y;
    pattern.lastIndex = at;
    const token = /** @type {RegExpExecArray} */ (pattern.exec(text))[0];
    at = pattern.lastIndex;
    if (token === "true") return true;
    if (token === "false") return false;
    if (token === "null") return null;
    if (!/^(0|[1-9][0-9]*)$/.test(token) || Number(token) > MAX_INT) {
      refuse(`not a wire integer: ${token}`);
    }
    return Number(token);
  };
  return value();
}

// ----------------------------------------------------------------- rules

/** A field check refuses a value it does not accept. @typedef {(value: any) => void} Check */

/** `[field, check, optional]`, in the order the server writes them. @typedef {ReadonlyArray<readonly [string, Check, boolean?]>} Spec */

/** @type {Check} */
const b = (text) => void b64u.decode(text);
/**
 * @param {number} n
 * @param {string} [code]
 * @returns {Check}
 */
const bytes = (n, code = "bad_request") => (text) => {
  const got = b64u.decode(text, code).length;
  if (got !== n) refuse(`expected ${n} bytes, got ${got}`, code);
};
const b32 = bytes(32);
/** @type {Check} */
const id = (text) => void hex16.decode(text);
/** @param {number} [max] @returns {Check} */
const int = (max = MAX_INT) => (n) => {
  if (!Number.isSafeInteger(n) || n < 0 || n > max) refuse("not a wire integer");
};
/** @type {Check} */
const str = (s) => {
  if (typeof s !== "string") refuse("not a string");
};
/** @type {Check} */
const bool = (v) => {
  if (typeof v !== "boolean") refuse("not a boolean");
};
/** @param {...string} words @returns {Check} */
const oneOf = (...words) => (v) => {
  if (!words.includes(v)) refuse(`not one of ${words}`);
};
/** @param {Spec} spec @returns {Check} */
const list = (spec) => (v) => {
  if (!Array.isArray(v)) refuse("not a list");
  for (const item of v) shape(spec, item);
};
/** @param {Spec} spec @returns {Check} */
const nested = (spec) => (v) => shape(spec, v);
const FORBIDDEN_IN_NAME = /[\p{Cc}؜​‎‏‪-‮⁠⁦-⁩﻿]/u;
/** @type {Check} */
const deviceName = (v) => {
  str(v);
  if ([...v].length > 64) refuse("device_name is longer than 64 characters");
  if (FORBIDDEN_IN_NAME.test(v)) refuse("device_name has a control or invisible character");
};
/** @type {Check} */
const next = (v) => {
  str(v);
  const n = [...v].length;
  if (n < 1 || n > 512) refuse("next is empty or longer than 512 characters");
};
/** @type {Check} */
const methodType = (v) => {
  int(3)(v);
  if (v < 1) refuse("method_type is 1, 2 or 3");
};

/** @type {Spec} */
const wrap = [
  ["method_id", id],
  ["method_type", methodType],
  ["kek_generation", int()],
  ["wrap", b],
  ["credential_id", b, true],
  ["prf_salt", b32, true],
];
/** @type {Spec} */
const sealedRow = [["rev", int()], ["envelope", b], ["tag", b32]];
/** @type {Spec} */
const checkpoint = [["seq", int()], ["digest", b32], ["mac", b32], ["entries", b]];
/** @type {Spec} */
const head = [["seq", int()], ["digest", b32], ["mac", b32]];
/** @type {Spec} */
const change = [
  ["id", id], ["rev", int()], ["seq", int()], ["deleted", bool],
  ["blob", b, true], ["tag", b32, true], ["tomb", bytes(40, "tombstone_invalid"), true],
];

/** @type {Readonly<Record<string, Spec>>} */
export const SHAPES = Object.freeze({
  sealed_row: sealedRow,
  wrap,
  checkpoint,
  checkpoint_head: head,
  register_start_req: [
    ["setup_token", str, true], ["email", str], ["request", bytes(32, "malformed_registration_request")],
  ],
  register_start_res: [
    ["registration_id", id], ["account_id", id], ["vault_id", id],
    ["response", bytes(64)], ["ksf_profile", int(255)],
  ],
  register_finish_req: [
    ["registration_id", id], ["device_id", id], ["device_name", deviceName, true],
    ["record", bytes(192, "malformed_registration_record")], ["ksf_profile", int(2 ** 32 - 1)], ["sk_bit", bool],
    ["wraps", list(wrap)], ["manifest", nested(sealedRow)], ["checkpoint", nested(checkpoint)],
    ["pk_a", b32], ["pk_r", b32],
  ],
  register_finish_res: [["account_id", id], ["vault_id", id]],
  login_start_req: [
    ["email", str], ["ke1", bytes(96, "malformed_ke1")], ["purpose", oneOf("login", "reauth"), true],
  ],
  login_start_res: [["login_id", id], ["ke2", bytes(320)], ["ksf_profile", int(255)], ["sk_hint", bool]],
  login_finish_req: [
    ["login_id", id], ["ke3", bytes(64, "malformed_ke3")], ["device_id", id], ["device_name", deviceName, true],
    ["purpose", oneOf("login", "reauth"), true],
  ],
  login_finish_res: [["account_id", id], ["vault_id", id], ["vk_epoch", int()]],
  handoff_req: [["purpose", oneOf("login", "reauth")], ["next", next], ["challenge", b32]],
  handoff_res: [["code", bytes(32)], ["expires_in", int()]],
  redeem_req: [["code", str]],
  handoff_redeem_res: [["next", str]],
  session_res: [
    ["account_id", id, true], ["email", str], ["scope", str], ["origin", oneOf("vault", "admin")],
  ],
  methods_res: [["methods", list(wrap)], ["pk_a", b32], ["vk_epoch", int()], ["manifest", nested(sealedRow)]],
  change,
  changes_res: [
    ["changes", list(change)], ["latest_seq", int()], ["vk_epoch", int()], ["restore_epoch", int()],
    ["checkpoint", nested(head), true], ["has_more", bool],
  ],
  put_item_req: [
    ["base_rev", int()], ["blob", b, true], ["tag", b32, true], ["deleted", bool, true],
    ["tomb", bytes(40, "tombstone_invalid"), true], ["idem", id], ["resurrect", bool, true],
  ],
  put_item_res: [["rev", int()], ["seq", int()], ["replayed", bool]],
  conflict_res: [["current_rev", int()], ["blob", b, true], ["tag", b32, true], ["deleted", bool]],
  error_res: [["error", str]],
});

/**
 * Checks that `value` has only the fields of `spec` and that each is valid.
 * @param {Spec} spec
 * @param {any} value
 */
export function shape(spec, value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) refuse("not an object");
  const names = spec.map(([name]) => name);
  for (const key of Object.keys(value)) {
    if (!names.includes(key)) refuse(`unknown field ${key}`);
  }
  for (const [name, check, optional] of spec) {
    const present = name in value && !(optional && value[name] === null);
    if (!present) {
      if (!optional) refuse(`missing field ${name}`);
      continue;
    }
    check(value[name]);
  }
}

/** @param {string} kind @returns {Spec} */
function specOf(kind) {
  const spec = SHAPES[kind];
  if (!spec) throw new TypeError(`no wire shape named ${kind}`);
  return spec;
}

/**
 * Reads `text` as the shape `kind`: strict JSON, then the shape.
 * @param {string} kind a key of {@link SHAPES}
 * @param {string} text
 * @returns {any}
 */
export function readWire(kind, text) {
  const value = readJson(text);
  shape(specOf(kind), value);
  return value;
}

/**
 * A hand-over code: 43 characters of strict base64url that decode to 32 bytes.
 * @param {unknown} code
 */
export function handoffCode(code) {
  str(code);
  if (/** @type {string} */ (code).length !== 43) refuse("a hand-over code has 43 characters", "handoff_invalid");
  if (b64u.decode(code, "handoff_invalid").length !== 32) refuse("not 32 bytes", "handoff_invalid");
}

/**
 * The checks that come with a shape once it is read: a hand-over code, the two
 * forms of an item write (a live row, or a tombstone, never both) and the two
 * forms of a conflict answer.
 * @param {string} kind
 * @param {any} value
 */
export function checkStep(kind, value) {
  if (kind === "redeem_req") handoffCode(value.code);
  if (kind === "conflict_res") {
    // The current row of an item: a live row has its blob and tag, a deleted one neither.
    const has = (/** @type {string} */ key) => value[key] !== undefined && value[key] !== null;
    if (value.deleted ? has("blob") || has("tag") : !has("blob") || !has("tag")) {
      refuse("a conflict answer is a live row (blob and tag) or a deleted one (neither)");
    }
  }
  if (kind !== "put_item_req") return;
  const has = (/** @type {string} */ key) => value[key] !== undefined && value[key] !== null;
  if (value.resurrect === true) refuse("resurrect is not supported yet");
  const live = has("blob") && has("tag") && !has("tomb") && value.deleted !== true;
  const gone = !has("blob") && !has("tag") && has("tomb") && value.deleted === true;
  if (!live && !gone) refuse("a put request is a live row or a tombstone, never both");
}

/**
 * The same as {@link encodeWire}, as the bytes to send (and to keep in the
 * outbox, whose entries hold the exact bytes of the request).
 * @param {string} kind
 * @param {any} value
 * @returns {Uint8Array}
 */
export function encodeWireBytes(kind, value) {
  return new TextEncoder().encode(encodeWire(kind, value));
}

/**
 * The text of a request body: the shape and its extra checks are applied, and
 * the result is the exact string to send. Keep it for a retry: a write sent
 * again must carry the same bytes under the same `idem`.
 * @param {string} kind a key of {@link SHAPES}
 * @param {any} value fields as the wire has them (ids as hex, bytes as base64url)
 * @returns {string}
 */
export function encodeWire(kind, value) {
  shape(specOf(kind), value);
  checkStep(kind, value);
  return JSON.stringify(value);
}
