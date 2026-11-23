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
// One more type is not in any table: `refused`, the background's answer when it
// could not answer a request (see REFUSAL_REASONS). It is a reply only, valid
// for every UI request and for no other channel; as a request it is an unknown
// type. What an answer means for the user (a wrong password, say) stays in the
// reply of its own type.
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

/**
 * The choices of the setting "Lock after", in seconds: 15 seconds, 30 seconds,
 * 1 minute, 5 minutes, 15 minutes, 30 minutes, 1 hour, 4 hours, 8 hours and
 * 24 hours. There is no "never". The background keeps the setting and reads
 * anything else as DEFAULT_LOCK_SECONDS.
 */
export const LOCK_CHOICES = Object.freeze([15, 30, 60, 300, 900, 1800, 3600, 14_400, 28_800, 86_400]);
export const DEFAULT_LOCK_SECONDS = 900;

/** Keys that no schema may carry, except where `SECRET_KEY_EXCEPTIONS` says so. */
export const FORBIDDEN_KEYS = Object.freeze([
  "password",
  "value",
  "secret",
  "totp_secret",
  "vk",
]);

/**
 * The only place a forbidden key name is allowed: `fill_field` carries the one
 * value that is filled into a page.
 */
export const SECRET_KEY_EXCEPTIONS = Object.freeze({
  fill_field: Object.freeze(["value"]),
});

/**
 * What the user types in an extension page: `sign_in` and `unlock` carry it to
 * the background, one way. No reply, content type or push type carries it.
 * A new device answers the secret key question with `sk`, `sk_bit: false` or
 * the sheet's `qr_text`; a device that holds the account's record answers it
 * from there. An unlock needs `sk` only when this device does not keep the
 * secret key (the user chose not to remember it).
 */
export const TYPED_CREDENTIAL_KEYS = Object.freeze({
  sign_in: Object.freeze(["mp", "sk", "qr_text"]),
  unlock: Object.freeze(["mp", "sk"]),
});

/** The type of the background's refusal. No table may define it. */
export const REFUSED = "refused";

/**
 * Why the background could not answer. A short fixed list: a reason from
 * anywhere else (a handler's own code, a client's error) becomes
 * "internal_error".
 */
export const REFUSAL_REASONS = Object.freeze([
  "vault_locked",
  "not_available",
  "invalid_input",
  "internal_error",
]);

/**
 * The reason of a refused fill when the frame of the form lies below a frame
 * whose document Ferret may not ask whether the form is shown (a frame of
 * another origin than the page, without its host permission). It differs from
 * `frame_hidden` ("hidden or covered") so the popup can say that Ferret could
 * not check, not that the frame is hidden.
 */
export const FRAME_UNCHECKED = "frame_unchecked";

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
// Firefox numbers the frames below a tab from 17179869185 up (more than 2^32), so the bound is the largest safe integer.
const frameId = integer({ min: 0, max: Number.MAX_SAFE_INTEGER });

const okReply = object({ ok: boolean(), reason }, { optional: ["reason"] });
// A host name as the extension shows it (the core's `display_host`): the Unicode form, and the A-label next to it.
const host = string({ min: 1, max: 300 });
const displayHost = object({ a_label: host, unicode: host });
const email = string({ min: 1, max: 254 });
// The item types of the vault, as the core names them.
const itemType = string({ max: 16, oneOf: ["login", "note", "card", "identity", "other"] });
// One item as a page may see it: a name, a user name, marks, and a reference that is good only in the session of the
// page that got it. Never a password, a code or any other value of the item.
const handle = object(
  {
    ref,
    name: string({ max: 256 }),
    username: string({ max: 256 }),
    insecure: boolean(),
    favorite: boolean(),
    type: itemType,
    // The item has a web address that "Open the site" can open.
    site: boolean(),
    // A candidate of a page: the first frame it was matched in, and every frame it may be filled in (the top first).
    frame_id: frameId,
    frame_ids: array(frameId, { max: 4 }),
  },
  { optional: ["username", "insecure", "favorite", "type", "site", "frame_id", "frame_ids"] },
);
const empty = object({});
const count = integer({ min: 0, max: 1_000_000 });
// One version of an item in conflict, as a page may see it.
const conflictSide = object(
  {
    deleted: boolean(),
    name: string({ max: 256 }),
    username: string({ max: 256 }),
    // When it was last changed, in milliseconds since 1970.
    modified: integer({ min: 0, max: 8_640_000_000_000_000 }),
    device: string({ max: 256 }),
  },
  { optional: ["name", "username", "modified", "device"] },
);

/**
 * @template {Record<string, { request: import("./schema.mjs").Schema, reply?: import("./schema.mjs").Schema }>} T
 * @param {T} table
 * @returns {Readonly<T>}
 */
function defineTypes(table) {
  if (Object.hasOwn(table, REFUSED)) throw new TypeError("a table cannot define refused");
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
        host,
        host_a_label: host,
        account: email,
        lock_at: integer({ min: 0, max: 8_640_000_000_000_000 }),
      },
      { optional: ["server", "host", "host_a_label", "account", "lock_at"] },
    ),
  },
  // The address a user typed on the sign-in page, checked and shown before anything is sent to it.
  server_check: {
    request: object({ server: serverUrl }),
    reply: object(
      { ok: boolean(), reason, server: serverUrl, host, host_a_label: host },
      { optional: ["reason", "server", "host", "host_a_label"] },
    ),
  },
  lock: { request: empty, reply: okReply },
  sign_in: {
    request: object(
      {
        server: serverUrl,
        email,
        mp: string({ min: 1, max: 1024 }),
        sk: string({ min: 1, max: 128 }),
        // The answer to "does this account have a secret key?" when no code is typed: only false (it has none)
        // means anything; "yes" is answered by `sk`, and true without `sk` leaves the question open.
        sk_bit: boolean(),
        // Whether this device keeps the secret key (sealed) after the sign-in; left out: it does.
        remember_sk: boolean(),
        qr_text: string({ min: 1, max: 2048 }),
      },
      { optional: ["sk", "sk_bit", "remember_sk", "qr_text"] },
    ),
    // Only the account's e-mail and the server: never anything the user typed.
    reply: object(
      { ok: boolean(), reason, account_email: email, server: serverUrl },
      { optional: ["reason", "account_email", "server"] },
    ),
  },
  unlock: {
    request: object({ mp: string({ min: 1, max: 1024 }), sk: string({ min: 1, max: 128 }) }, { optional: ["sk"] }),
    reply: okReply,
  },
  // The items a tab is offered, each once, with a reference good for filling it in this popup session only (all of
  // the tab's fillable frames, or only the one `frame_id` names: the menu's frame). The host is the core's
  // `display_host` of the page, missing when the tab shows no web page; `insecure` marks a plain `http` page; `grant`
  // lists the frames of the same site that some item matches and that are offered nothing until their host
  // permission is granted. `automatic` (here and in `search`): a read the page made by itself (after the sync changed
  // something), not an action of the user, so it does not move the auto-lock's deadline. The lock is still checked.
  candidates: {
    request: object({ tab_id: tabId, frame_id: frameId, automatic: boolean() }, { optional: ["frame_id", "automatic"] }),
    reply: object(
      {
        handles: array(handle, { max: 100 }),
        host: displayHost,
        insecure: boolean(),
        grant: array(object({ origin, host: displayHost }), { max: 32 }),
      },
      { optional: ["host"] },
    ),
  },
  // The origin the grant tab was opened for, checked by the core: an `https` origin, its host and the permission.
  grant_check: {
    request: object({ origin }),
    reply: object(
      { ok: boolean(), reason, origin, host: displayHost, pattern: string({ min: 1, max: 320 }) },
      { optional: ["reason", "origin", "host", "pattern"] },
    ),
  },
  // A search finds anything in the vault. Its handles are for copying only: "Fill" takes a handle of `candidates`.
  // `favorites` keeps the favourites only and `type` one item type; `offset` pages through a long answer, and `total`
  // says how many items match in all.
  search: {
    request: object(
      { query: string({ max: 256 }), favorites: boolean(), type: itemType, offset: integer({ min: 0, max: 1_000_000 }), automatic: boolean() },
      { optional: ["favorites", "type", "offset", "automatic"] },
    ),
    reply: object({ handles: array(handle, { max: 100 }), total: integer({ min: 0, max: 1_000_000 }) }),
  },
  // "Fill" with a reference of `candidates`. Without `frame_id` the background fills the first of the reference's frames
  // that has a sign-in form; with it (the menu's frame) only that frame.
  fill: {
    request: object({ ref, tab_id: tabId, frame_id: frameId }, { optional: ["frame_id"] }),
    reply: okReply,
  },
  copy: {
    request: object({ ref, field }),
    reply: okReply,
  },
  // What the popup shows of one item: the name, the user name, the addresses and which values can be copied. A
  // password or a code is never part of it.
  item: {
    request: object({ ref }),
    reply: object(
      {
        ok: boolean(),
        reason,
        name: string({ max: 256 }),
        username: string({ max: 256 }),
        type: itemType,
        favorite: boolean(),
        urls: array(string({ max: 2048 }), { max: 16 }),
        copyable: array(field, { max: 3 }),
      },
      { optional: ["reason", "name", "username", "type", "favorite", "urls", "copyable"] },
    ),
  },
  // "Open the site": the background opens the item's first web address in a new tab.
  open_site: {
    request: object({ ref }),
    reply: okReply,
  },
  // What the sync shows in the popup: codes only (the state, a stop, the warnings, why the device's tokens ended), never
  // an item or a name.
  sync_state: {
    request: empty,
    reply: object(
      {
        running: boolean(),
        status: reason,
        live: string({ max: 16, oneOf: ["connecting", "live", "fallback", "offline", "unauthorized"] }),
        halted: reason,
        warnings: array(reason, { max: 16 }),
        ended: string({ max: 16, oneOf: ["token_reused"] }),
        // How many items have a change that waits to be sent, a change the server refused, or a conflict.
        pending: count,
        blocked: count,
        conflicts: count,
      },
      { optional: ["status", "halted", "ended", "pending", "blocked", "conflicts"] },
    ),
  },
  // "Try again" after a stop of the sync.
  sync_retry: { request: empty, reply: okReply },
  // What accepting the older state of a restored server would do: how many of this device's newer changes would be sent,
  // how many items would become conflicts, and whether the server's unlock methods are older. Nothing is done.
  sync_older_preview: {
    request: empty,
    reply: object(
      { ok: boolean(), reason, reupload: count, conflicts: count, manifest_older: boolean() },
      { optional: ["reason", "reupload", "conflicts", "manifest_older"] },
    ),
  },
  // "Accept the older state", once the user has typed the word (`confirmed`). The counts of what was done; the items
  // that could not be opened are counted, never named.
  sync_accept_older: {
    request: object({ confirmed: boolean() }),
    reply: object(
      { ok: boolean(), reason, reuploaded: count, conflicts: count, manifest_older: boolean(), unreadable: count },
      { optional: ["reason", "reuploaded", "conflicts", "manifest_older", "unreadable"] },
    ),
  },
  // What "Forget this server" would lose, for its question: the changes not yet sent, and whether another address of the
  // server keeps the same account (then they and the saved items stay, for that address).
  forget_preview: {
    request: object({ server: serverUrl }),
    reply: object({ ok: boolean(), reason, pending: count, shared: boolean() }, { optional: ["reason", "pending", "shared"] }),
  },
  // "Forget this server": `server` is the one the page showed; another stored one is not forgotten. `expect_pending` is
  // the count of unsent changes the page's question named: when more wait now, nothing is forgotten (`changed`).
  forget_server: { request: object({ server: serverUrl, expect_pending: count }, { optional: ["expect_pending"] }), reply: okReply },
  // The items whose change waits to be sent, was refused (`reason`: the server's code), or is in conflict, conflicts
  // first, each with a reference good only in this page's session. Names and user names only.
  sync_items: {
    request: empty,
    reply: object({
      items: array(
        object(
          { ref, name: string({ max: 256 }), username: string({ max: 256 }), state: string({ max: 16, oneOf: ["conflict", "blocked", "pending"] }), reason },
          { optional: ["username", "reason"] },
        ),
        { max: 40 },
      ),
      total: count,
    }),
  },
  // The two versions of an item in conflict: for each, its name, user name, when and on which device it was changed, or
  // that it is a deletion. Never a password or another value of the item.
  item_conflict: {
    request: object({ ref }),
    reply: object(
      { ok: boolean(), reason, mine: conflictSide, theirs: conflictSide },
      { optional: ["reason", "mine", "theirs"] },
    ),
  },
  // "Keep mine" or "Keep the server's", against the versions `item_conflict` showed this page last.
  item_resolve: {
    request: object({ ref, choice: string({ max: 8, oneOf: ["mine", "theirs"] }) }),
    reply: okReply,
  },
  // "Discard the draft" of an item whose change the server refused.
  item_discard: { request: object({ ref }), reply: okReply },
  settings: {
    // The bounds are those of LOCK_CHOICES; the background accepts only the listed values.
    request: object(
      { lock_seconds: integer({ min: LOCK_CHOICES[0], max: LOCK_CHOICES[LOCK_CHOICES.length - 1] }) },
      { optional: ["lock_seconds"] },
    ),
    reply: object({ lock_seconds: integer({ min: LOCK_CHOICES[0], max: LOCK_CHOICES[LOCK_CHOICES.length - 1] }) }),
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

const refusal = object({ reason: string({ max: 32, oneOf: REFUSAL_REASONS }) });

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
 * The refusal of the request `id`. A reason that is not in REFUSAL_REASONS is
 * sent as "internal_error".
 *
 * @param {string} id the request's id
 * @param {string} reason
 * @returns {string}
 */
export function encodeRefusal(id, reason) {
  if (!ID.test(id)) throw new ProtocolError("bad_shape", "id");
  const known = REFUSAL_REASONS.includes(reason) ? reason : "internal_error";
  return JSON.stringify({
    v: PROTOCOL_VERSION,
    id,
    type: REFUSED,
    body: validate(refusal, { reason: known }),
  });
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
  if (type === REFUSED) {
    // Only an answer, and only on the UI channel (the page that asked).
    if (!opts.reply || allowed !== UI_TYPES) throw new ProtocolError("unknown_type");
    return { id, type, body: validate(refusal, body) };
  }
  if (!Object.hasOwn(allowed, type)) throw new ProtocolError("unknown_type");
  const def = allowed[type];
  const schema = opts.reply ? def.reply : def.request;
  if (!schema) throw new ProtocolError("unknown_type");
  return { id, type, body: validate(schema, body) };
}
