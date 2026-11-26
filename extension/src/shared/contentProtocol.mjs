// The two channels of the protocol that a content script speaks: CONTENT_TYPES (a content script to the background) and
// PUSH_TYPES (the background to one content script), with the envelope, the limits and the wire form of a page's passkey
// call. Plain ESM, no dependencies but the schema checker.
//
// The content scripts that run in pages (the fill script and the passkey bridge) are joined from this module and not
// from protocol.mjs, so they carry neither the tables of the extension pages (UI_TYPES) nor their schemas. protocol.mjs
// imports these two tables and re-exports them: each is defined once, here. See protocol.mjs for the rules of the three
// channels and the envelope.

import {
  ProtocolError,
  array,
  boolean,
  integer,
  nullable,
  object,
  string,
  validate,
} from "./schema.mjs";

export { ProtocolError };

export const PROTOCOL_VERSION = 1;
export const MAX_MESSAGE_BYTES = 65_536;
/** A message of these types is smaller still: a capture is a user name and a password or two, never a page. */
export const MAX_BYTES_BY_TYPE = Object.freeze({ form_capture: 4096 });
/** @param {string} type */
const limitOf = (type) => /** @type {Record<string, number>} */ (MAX_BYTES_BY_TYPE)[type] ?? MAX_MESSAGE_BYTES;

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

/** The pattern of a message id and of a request id. */
export const ID = /^[A-Za-z0-9_-]{1,64}$/;
/** The pattern of a reason code. */
export const REASON = /^[a-z][a-z0-9_]*$/;

export const requestId = string({ min: 1, max: 64, pattern: ID });
export const reason = string({ min: 1, max: 64, pattern: REASON });
// What a frame can report and what can be pushed into it: the sign-in kinds, and, for a generated password, the new and
// the confirm field of a sign-up, change or reset form.
export const fillKind = string({ max: 16, oneOf: ["username", "password", "totp", "new_password", "confirm_password"] });
// A canonical origin is at most 300 bytes. "null" (an opaque origin) fits.
export const origin = string({ min: 1, max: 300 });
export const url = string({ min: 1, max: 8192 });
export const empty = object({});

// ---------------------------------------------------------------- passkeys (the `passkeys` feature)
//
// What the bridge script of a page (content/passkey.bridge.entry.mjs) and the background say about a page's WebAuthn
// call (`create` or `get` of the page's credentials container). The options and the answer travel as JSON with their bytes in unpadded
// base64url (shared/webauthnWire.mjs makes and reads that form). No message of a page carries an origin, a top, a frame or
// an address: the background takes those from the browser (`sender`, `webNavigation`), never from the page.

/**
 * The limits of a page's request and of the answer, in bytes (texts in UTF-8 bytes). The bridge, the background and the
 * core each check them. A whole message is at most MAX_MESSAGE_BYTES.
 */
export const PASSKEY_LIMITS = Object.freeze({
  challenge: 1024,
  // allowCredentials, excludeCredentials, pubKeyCredParams, evalByCredential
  list: 200,
  credentialId: 1023,
  // rp.id, rp.name, user.name, user.displayName, appid
  text: 1024,
  // user.id: WebAuthn allows 1 to 64 bytes; anything up to this bound is carried, so the answer to a wrong length is
  // the one the background gives (a TypeError), not a silent handover.
  userId: 1024,
  // a PRF salt (`first`, `second`)
  prfSalt: 1024,
  // hints, transports, attestationFormats
  words: 8,
  // the names of extensions the page asked for that the wire does not carry
  otherExtensions: 16,
});

/** The names of the errors the background can give a page's call (as the browser gives them, design § 9.3). */
export const PASSKEY_ERRORS = Object.freeze(["NotAllowedError", "AbortError", "InvalidStateError", "SecurityError", "TypeError", "NotSupportedError"]);

const B64U_ANY = /^[A-Za-z0-9_-]*$/;
/** The characters of the unpadded base64url form of `n` bytes. @param {number} n */
export const b64uLength = (n) => Math.ceil((n * 4) / 3);
/** @param {number} maxBytes @param {number} [minBytes] */
const pkBytes = (maxBytes, minBytes = 1) => string({ min: b64uLength(minBytes), max: b64uLength(maxBytes), pattern: B64U_ANY });
const pkText = string({ max: PASSKEY_LIMITS.text });
// A value of a WebAuthn enumeration or a type name, as the page gave it (an unknown value is the background's to judge).
const pkWord = string({ max: 32 });
const pkWords = array(pkWord, { max: PASSKEY_LIMITS.words });
const coseAlg = integer({ min: -2_147_483_648, max: 2_147_483_647 });
const pkCredential = object({ type: pkWord, id: pkBytes(PASSKEY_LIMITS.credentialId), transports: pkWords }, { optional: ["transports"] });
const pkCredentials = array(pkCredential, { max: PASSKEY_LIMITS.list });
const prfSalts = object({ first: pkBytes(PASSKEY_LIMITS.prfSalt, 0), second: pkBytes(PASSKEY_LIMITS.prfSalt, 0) }, { optional: ["second"] });
const pkExtensions = object(
  {
    cred_props: boolean(),
    prf: object(
      {
        eval: prfSalts,
        eval_by_credential: array(
          object({ id: pkBytes(PASSKEY_LIMITS.credentialId), first: pkBytes(PASSKEY_LIMITS.prfSalt, 0), second: pkBytes(PASSKEY_LIMITS.prfSalt, 0) }, { optional: ["second"] }),
          { max: PASSKEY_LIMITS.list },
        ),
      },
      { optional: ["eval", "eval_by_credential"] },
    ),
    appid: pkText,
    appid_exclude: pkText,
    // Extensions the page asked for that the wire does not carry, by name only.
    others: array(string({ min: 1, max: 64 }), { max: PASSKEY_LIMITS.otherExtensions }),
  },
  { optional: ["cred_props", "prf", "appid", "appid_exclude", "others"] },
);
/** The options of a page's `create` (PublicKeyCredentialCreationOptions), on the wire. */
export const PASSKEY_CREATE_OPTIONS = object(
  {
    challenge: pkBytes(PASSKEY_LIMITS.challenge),
    rp: object({ id: pkText, name: pkText }, { optional: ["id"] }),
    user: object({ id: pkBytes(PASSKEY_LIMITS.userId, 0), name: pkText, display_name: pkText }),
    pub_key_cred_params: array(object({ type: pkWord, alg: coseAlg }), { max: PASSKEY_LIMITS.list }),
    timeout: integer({ min: 0, max: 4_294_967_295 }),
    exclude_credentials: pkCredentials,
    authenticator_selection: object(
      { authenticator_attachment: pkWord, resident: pkWord, require_resident: boolean(), user_verification: pkWord },
      { optional: ["authenticator_attachment", "resident", "require_resident", "user_verification"] },
    ),
    hints: pkWords,
    attestation: pkWord,
    attestation_formats: pkWords,
    extensions: pkExtensions,
  },
  { optional: ["timeout", "authenticator_selection", "attestation", "attestation_formats"] },
);
/** The options of a page's `get` (PublicKeyCredentialRequestOptions), on the wire. */
export const PASSKEY_GET_OPTIONS = object(
  {
    challenge: pkBytes(PASSKEY_LIMITS.challenge),
    timeout: integer({ min: 0, max: 4_294_967_295 }),
    rp_id: pkText,
    allow_credentials: pkCredentials,
    user_verification: pkWord,
    hints: pkWords,
    attestation: pkWord,
    attestation_formats: pkWords,
    extensions: pkExtensions,
  },
  { optional: ["timeout", "rp_id", "user_verification", "attestation", "attestation_formats"] },
);
const prfResults = object({ first: pkBytes(32, 32), second: pkBytes(32, 32) }, { optional: ["second"] });
/**
 * The answer for the page, on the wire: the fields of a `create` (attestation_object, spki, public_key_algorithm,
 * transports) or of a `get` (signature, user_handle), never both; shared/webauthnWire.mjs checks which. The bytes are
 * what the core made; no key and no seed.
 */
export const PASSKEY_RESPONSE = object(
  {
    id: pkBytes(PASSKEY_LIMITS.credentialId),
    client_data_json: pkBytes(4096),
    authenticator_data: pkBytes(2048),
    authenticator_attachment: nullable(pkWord),
    attestation_object: pkBytes(8192),
    // The public key as SubjectPublicKeyInfo (getPublicKey()), or null.
    spki: nullable(pkBytes(1024)),
    public_key_algorithm: coseAlg,
    transports: pkWords,
    signature: pkBytes(1024),
    user_handle: nullable(pkBytes(64)),
    client_extension_results: object(
      {
        cred_props: object({ rk: boolean() }),
        prf: object({ enabled: boolean(), results: prfResults }, { optional: ["enabled", "results"] }),
      },
      { optional: ["cred_props", "prf"] },
    ),
  },
  { optional: ["attestation_object", "spki", "public_key_algorithm", "transports", "signature", "user_handle"] },
);

/**
 * @template {Record<string, { request: import("./schema.mjs").Schema, reply?: import("./schema.mjs").Schema }>} T
 * @param {T} table
 * @returns {Readonly<T>}
 */
export function defineTypes(table) {
  if (Object.hasOwn(table, REFUSED)) throw new TypeError("a table cannot define refused");
  for (const def of Object.values(table)) Object.freeze(def);
  return Object.freeze(table);
}

/** Content script to background. A content script only reports; it never asks (the passkey bridge only learns "taken"). */
export const CONTENT_TYPES = defineTypes({
  // `self_origin` is the script's own `self.origin`. The background takes the
  // origin from the browser and uses `self_origin` only to narrow: "null" or a
  // different value refuses the frame.
  frame_report: {
    request: object({
      request_id: requestId,
      self_origin: origin,
      fields: array(
        object(
          {
            kind: fillKind,
            id: string({ min: 1, max: 64, pattern: ID }),
            // The `maxlength` of a new or confirm field, for a generated fill; left out when the field has none.
            max: integer({ min: 0, max: 1_000_000 }),
            // The classes of characters the field refuses by its `passwordrules` or `pattern` (at most three of the four).
            forbid: array(string({ max: 8, oneOf: ["lower", "upper", "digit", "symbol"] }), { max: 3 }),
          },
          { optional: ["max", "forbid"] },
        ),
        { max: 64 },
      ),
      // The kind of the form a generated fill found (the fields are its new and confirm field); only in that mode.
      group: string({ max: 16, oneOf: ["signup", "change", "reset"] }),
    }, { optional: ["group"] }),
  },
  fill_result: {
    request: object(
      { request_id: requestId, ok: boolean(), reason },
      { optional: ["reason"] },
    ),
  },
  // The capture script (the `save` feature). A form was submitted: its kind, the user name (with where it came from:
  // typed by the person, or already in the field), and the password the person typed (the new one in a sign-up, change
  // or reset form; the one in use in a sign-in) and, in a change form, the one in use. A key is `null` when the form
  // has no such value or it did not come from the person's own typing. `identifier` is a step that asks for the user
  // name only: no password. `self_origin` only narrows, as in `frame_report`.
  form_capture: {
    request: object({
      capture_id: requestId,
      self_origin: origin,
      kind: string({ max: 16, oneOf: ["login", "signup", "change", "reset", "identifier"] }),
      username: nullable(string({ min: 1, max: 512 })),
      username_from: nullable(string({ max: 8, oneOf: ["typed", "page"] })),
      password: nullable(string({ min: 1, max: 1024 })),
      current_password: nullable(string({ min: 1, max: 1024 })),
    }),
  },
  // The password field of a capture went away (or was hidden) and no new one showed up within five seconds.
  form_gone: { request: object({ capture_id: requestId }) },
  // A password field the person can see is on the page: sent only when there is one.
  page_ready: { request: empty },
  // The passkey bridge (the `passkeys` feature). A page called `create` or `get`: the bridge's own id for the request (the
  // background answers it with a push of that id, and the bridge passes on answers to its own ids only), the kind, the
  // mediation, the options of that kind on the wire, and what the bridge read in the isolated world: whether the page
  // has transient user activation, and what `document.featurePolicy` says (null where the browser has none). No origin,
  // top, frame or address: the background takes them from the browser.
  passkey_request: {
    request: object(
      {
        request_id: requestId,
        kind: string({ max: 8, oneOf: ["create", "get"] }),
        mediation: string({ max: 16, oneOf: ["optional", "required", "conditional"] }),
        create: PASSKEY_CREATE_OPTIONS,
        get: PASSKEY_GET_OPTIONS,
        activation: boolean(),
        policy: nullable(boolean()),
      },
      { optional: ["create", "get"] },
    ),
    // The background took the request: it answers it later with a push. Anything else (no answer, a refused sender such as
    // a frame with an opaque origin, a build without the feature) and the bridge hands the page's call to the browser.
    reply: object({ accepted: boolean() }),
  },
  // The page's AbortSignal ended a request of this bridge (or a modal request replaced a conditional one).
  passkey_abort: { request: object({ request_id: requestId }) },
  // The page's create or get were not the browser's own when the page script started, or Ferret's were replaced later: by
  // another password manager or by the site itself (the script cannot tell). Text for Ferret's UI only, never routing.
  passkey_foreign: { request: empty },
  // Every 20 seconds while requests of this bridge wait, and never otherwise: a suspended event page must not lose them.
  passkey_ping: { request: object({ request_ids: array(requestId, { min: 1, max: 64 }) }) },
});

/** Background to one content script. */
export const PUSH_TYPES = defineTypes({
  fill_field: {
    request: object({
      request_id: requestId,
      field: fillKind,
      value: string({ max: 2048 }),
      expect: object({ origin, frameUrl: url }),
    }),
  },
  // The answers to a request of the passkey bridge, sent only to the frame and document that asked. The bridge drops an
  // answer to an id it did not issue.
  // Ferret answered: the bytes of the credential for the page.
  passkey_result: { request: object({ request_id: requestId, response: PASSKEY_RESPONSE }) },
  // The browser answers: `once: false` calls the browser's own function now, with the page's own options; `once: true`
  // ends this call with NotAllowedError and lets the next call of the same kind through (the user clicks again).
  passkey_handover: { request: object({ request_id: requestId, once: boolean() }) },
  // The request ends with this error.
  passkey_error: { request: object({ request_id: requestId, name: string({ max: 32, oneOf: PASSKEY_ERRORS }) }) },
});

/** The body of the background's refusal. */
export const REFUSAL_SCHEMA = object({ reason: string({ max: 32, oneOf: REFUSAL_REASONS }) });

const ENVELOPE_KEYS = ["v", "id", "type", "body"];
const encoder = new TextEncoder();

function newId() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** @typedef {Readonly<Record<string, { request: import("./schema.mjs").Schema, reply?: import("./schema.mjs").Schema }>>} TypeTable */

/**
 * The encoder and the decoder of a set of tables. `ui` is the table whose replies may be the background's refusal
 * (`refused`); null: no table of the set may receive one.
 *
 * @param {TypeTable[]} tables
 * @param {TypeTable | null} ui
 */
export function createCodec(tables, ui) {
  /** @param {string} type */
  const lookup = (type) => {
    for (const table of tables) {
      if (Object.hasOwn(table, type)) return /** @type {any} */ (table)[type];
    }
    return null;
  };

  /**
   * Build a message. The body is checked against its schema, so a bug on the
   * sending side fails at the sender.
   *
   * @param {string} type
   * @param {unknown} body
   * @param {{ id?: string, reply?: boolean }} [opts] `reply` builds the answer to a request; `id` is the request's id
   * @returns {string}
   */
  function encode(type, body, opts = {}) {
    const def = lookup(type);
    const schema = def && (opts.reply ? def.reply : def.request);
    if (!schema) throw new ProtocolError("unknown_type");
    const id = opts.id ?? newId();
    if (!ID.test(id)) throw new ProtocolError("bad_shape", "id");
    const clean = validate(schema, body);
    const raw = JSON.stringify({ v: PROTOCOL_VERSION, id, type, body: clean });
    if (encoder.encode(raw).length > limitOf(type)) {
      throw new ProtocolError("too_large");
    }
    return raw;
  }

  /**
   * Check a received message. `allowed` is the table of the channel the message
   * came in on. Nothing from the message is trusted until every check has passed.
   *
   * @param {unknown} raw
   * @param {TypeTable} allowed
   * @param {{ reply?: boolean }} [opts] `reply` decodes the answer to a request
   * @returns {{ id: string, type: string, body: any }}
   */
  function decode(raw, allowed, opts = {}) {
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
      if (!opts.reply || ui === null || allowed !== ui) throw new ProtocolError("unknown_type");
      return { id, type, body: validate(REFUSAL_SCHEMA, body) };
    }
    if (!Object.hasOwn(allowed, type)) throw new ProtocolError("unknown_type");
    if (limitOf(type) < MAX_MESSAGE_BYTES && encoder.encode(raw).length > limitOf(type)) throw new ProtocolError("too_large");
    const def = allowed[type];
    const schema = opts.reply ? def.reply : def.request;
    if (!schema) throw new ProtocolError("unknown_type");
    return { id, type, body: validate(schema, body) };
  }

  return { encode, decode };
}

const contentCodec = createCodec([CONTENT_TYPES, PUSH_TYPES], null);
/** Build a message of CONTENT_TYPES or PUSH_TYPES (see createCodec). */
export const encode = contentCodec.encode;
/** Check a received message of CONTENT_TYPES or PUSH_TYPES (see createCodec). */
export const decode = contentCodec.decode;
