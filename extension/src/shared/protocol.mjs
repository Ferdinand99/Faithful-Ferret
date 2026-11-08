// The message protocol of the extension. Plain ESM, no dependencies.
//
// Three directions, three tables of types. A receiver decodes with the table of
// its own channel only, so a type from another channel is "unknown_type":
//
// - UI_TYPES: an extension page to the background, over the port named
//   UI_PORT. The background answers on the same port with the same id.
// - CONTENT_TYPES: a content script to the background, over
//   runtime.sendMessage. A content script can never ask for a value.
// - PUSH_TYPES: the background to one content script, over tabs.sendMessage,
//   as the answer to a pending action in the extension's own UI. Only here does
//   a secret travel to a page, and it is one value for one field of one frame.
//
// Envelope: { v, id, type, body }, at most MAX_MESSAGE_BYTES, sent as a JSON
// string. Every body has a schema that refuses unknown keys, and every string
// and array in a schema has an upper bound. The origin of a sender is never
// read from a message (see origin.mjs).

import {
  ProtocolError,
  array,
  boolean,
  integer,
  object,
  string,
  validate,
} from "./schema.mjs";

export { ProtocolError };

export const PROTOCOL_VERSION = 1;
export const MAX_MESSAGE_BYTES = 65_536;
export const UI_PORT = "ferret-ui";

/** Keys that no schema may carry, except where `SECRET_KEY_EXCEPTIONS` says so. */
export const FORBIDDEN_KEYS = Object.freeze([
  "password",
  "value",
  "secret",
  "totp_secret",
  "vk",
]);

/**
 * The only places a secret key name is allowed. `fill_field` carries the one
 * value that is filled into a page. `sign_in` and `unlock` carry what the user
 * typed into an extension page; they go to the background and never come back.
 */
export const SECRET_KEY_EXCEPTIONS = Object.freeze({
  fill_field: Object.freeze(["value"]),
});

/** What the user types in an extension page and sends to the background. */
export const TYPED_CREDENTIAL_KEYS = Object.freeze({
  sign_in: Object.freeze(["mp", "sk", "qr_text"]),
  unlock: Object.freeze(["mp"]),
});

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const REASON = /^[a-z][a-z0-9_]*$/;

const requestId = string({ min: 1, max: 64, pattern: ID });
const ref = string({ min: 1, max: 64, pattern: ID });
const reason = string({ min: 1, max: 64, pattern: REASON });
const field = string({ max: 16, oneOf: ["username", "password", "totp"] });
// A canonical origin is at most 300 bytes. "null" (an opaque origin) fits.
const origin = string({ min: 1, max: 300 });
const serverUrl = string({ min: 1, max: 300 });
const url = string({ min: 1, max: 8192 });
const tabId = integer({ min: 0, max: 2_147_483_647 });
const frameId = integer({ min: 0, max: 2_147_483_647 });

const okReply = object({ ok: boolean(), reason }, { optional: ["reason"] });
const handle = object(
  {
    ref,
    name: string({ max: 256 }),
    username: string({ max: 256 }),
    insecure: boolean(),
  },
  { optional: ["username", "insecure"] },
);
const handles = object({ handles: array(handle, { max: 100 }) });
const empty = object({});

/**
 * @template {Record<string, { request: import("./schema.mjs").Schema, reply?: import("./schema.mjs").Schema }>} T
 * @param {T} table
 * @returns {Readonly<T>}
 */
function defineTypes(table) {
  for (const def of Object.values(table)) Object.freeze(def);
  return Object.freeze(table);
}

/** Extension page to background. Each type has a request and a reply. */
export const UI_TYPES = defineTypes({
  state: {
    request: empty,
    reply: object(
      {
        state: string({ max: 16, oneOf: ["signed_out", "locked", "unlocked"] }),
        server: serverUrl,
        lock_at: integer({ min: 0, max: 8_640_000_000_000_000 }),
      },
      { optional: ["server", "lock_at"] },
    ),
  },
  lock: { request: empty, reply: okReply },
  sign_in: {
    request: object(
      {
        server: serverUrl,
        email: string({ min: 1, max: 254 }),
        mp: string({ min: 1, max: 1024 }),
        sk: string({ min: 1, max: 128 }),
        qr_text: string({ min: 1, max: 2048 }),
      },
      { optional: ["sk", "qr_text"] },
    ),
    reply: okReply,
  },
  unlock: {
    request: object({ mp: string({ min: 1, max: 1024 }) }),
    reply: okReply,
  },
  candidates: {
    request: object({ tab_id: tabId, frame_id: frameId }),
    reply: handles,
  },
  // A search finds anything in the vault. Its handles are for copying only.
  search: {
    request: object({ query: string({ max: 256 }) }),
    reply: handles,
  },
  fill: {
    request: object({ ref, tab_id: tabId, frame_id: frameId }),
    reply: okReply,
  },
  copy: {
    request: object({ ref, field }),
    reply: okReply,
  },
  settings: {
    request: object(
      { lock_minutes: integer({ min: 1, max: 480 }) },
      { optional: ["lock_minutes"] },
    ),
    reply: object({ lock_minutes: integer({ min: 1, max: 480 }) }),
  },
});

/** Content script to background. A content script only reports; it never asks. */
export const CONTENT_TYPES = defineTypes({
  // `self_origin` is the script's own `self.origin`. The background takes the
  // origin from the browser and uses `self_origin` only to narrow: "null" or a
  // different value refuses the frame.
  frame_report: {
    request: object({
      request_id: requestId,
      self_origin: origin,
      fields: array(
        object({
          kind: string({ max: 16, oneOf: ["username", "password", "totp"] }),
          id: string({ min: 1, max: 64, pattern: ID }),
        }),
        { max: 64 },
      ),
    }),
  },
  fill_result: {
    request: object(
      { request_id: requestId, ok: boolean(), reason },
      { optional: ["reason"] },
    ),
  },
});

/** Background to one content script. */
export const PUSH_TYPES = defineTypes({
  fill_field: {
    request: object({
      request_id: requestId,
      field,
      value: string({ max: 2048 }),
      expect: object({ origin, frameUrl: url }),
    }),
  },
});

const ALL_TYPES = [UI_TYPES, CONTENT_TYPES, PUSH_TYPES];

/** @param {string} type */
function lookup(type) {
  for (const table of ALL_TYPES) {
    if (Object.hasOwn(table, type)) return /** @type {any} */ (table)[type];
  }
  return null;
}

const ENVELOPE_KEYS = ["v", "id", "type", "body"];
const encoder = new TextEncoder();

function newId() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Build a message. The body is checked against its schema, so a bug on the
 * sending side fails at the sender.
 *
 * @param {string} type
 * @param {unknown} body
 * @param {{ id?: string, reply?: boolean }} [opts] `reply` builds the answer to a request; `id` is the request's id
 * @returns {string}
 */
export function encode(type, body, opts = {}) {
  const def = lookup(type);
  const schema = def && (opts.reply ? def.reply : def.request);
  if (!schema) throw new ProtocolError("unknown_type");
  const id = opts.id ?? newId();
  if (!ID.test(id)) throw new ProtocolError("bad_shape", "id");
  const clean = validate(schema, body);
  const raw = JSON.stringify({ v: PROTOCOL_VERSION, id, type, body: clean });
  if (encoder.encode(raw).length > MAX_MESSAGE_BYTES) {
    throw new ProtocolError("too_large");
  }
  return raw;
}

/**
 * Check a received message. `allowed` is the table of the channel the message
 * came in on (UI_TYPES, CONTENT_TYPES or PUSH_TYPES). Nothing from the message
 * is trusted until every check has passed.
 *
 * @param {unknown} raw
 * @param {Readonly<Record<string, { request: import("./schema.mjs").Schema, reply?: import("./schema.mjs").Schema }>>} allowed
 * @param {{ reply?: boolean }} [opts] `reply` decodes the answer to a request
 * @returns {{ id: string, type: string, body: any }}
 */
export function decode(raw, allowed, opts = {}) {
  if (typeof raw !== "string") throw new ProtocolError("bad_shape", "message");
  // A string is at least as many bytes as it has UTF-16 units, so a long one
  // is refused before it is encoded or parsed.
  if (raw.length > MAX_MESSAGE_BYTES) throw new ProtocolError("too_large");
  if (encoder.encode(raw).length > MAX_MESSAGE_BYTES) {
    throw new ProtocolError("too_large");
  }
  /** @type {unknown} */
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ProtocolError("bad_shape", "message");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    Object.getPrototypeOf(parsed) !== Object.prototype
  ) {
    throw new ProtocolError("bad_shape", "message");
  }
  const envelope = /** @type {Record<string, unknown>} */ (parsed);
  const keys = Object.keys(envelope);
  if (
    keys.length !== ENVELOPE_KEYS.length ||
    !ENVELOPE_KEYS.every((k) => Object.hasOwn(envelope, k))
  ) {
    throw new ProtocolError("bad_shape", "message");
  }
  const { v, id, type, body } = envelope;
  if (typeof v !== "number" || !Number.isSafeInteger(v)) {
    throw new ProtocolError("bad_shape", "v");
  }
  if (v !== PROTOCOL_VERSION) throw new ProtocolError("bad_version");
  if (typeof id !== "string" || !ID.test(id)) {
    throw new ProtocolError("bad_shape", "id");
  }
  if (typeof type !== "string" || type.length > 64) {
    throw new ProtocolError("bad_shape", "type");
  }
  if (!Object.hasOwn(allowed, type)) throw new ProtocolError("unknown_type");
  const def = allowed[type];
  const schema = opts.reply ? def.reply : def.request;
  if (!schema) throw new ProtocolError("unknown_type");
  return { id, type, body: validate(schema, body) };
}
