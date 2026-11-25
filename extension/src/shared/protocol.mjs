// The message protocol of the extension. Plain ESM, no dependencies.
//
// Three directions, three tables of types. A receiver decodes with the table of
// its own channel only, so a type from another channel is "unknown_type":
//
// - UI_TYPES: an extension page to the background, over the port named
//   UI_PORT. The background answers on the same port with the same id.
// - CONTENT_TYPES: a content script to the background, over
//   runtime.sendMessage. A content script can never ask for a value. One type
//   carries a secret up: `form_capture`, what a person typed into a form they
//   submitted (SECRET_KEY_EXCEPTIONS).
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
  "current_password",
  "value",
  "secret",
  "totp_secret",
  "code",
  "vk",
  "pin",
  "prf_output",
]);

/**
 * The only places a forbidden key name is allowed: `fill_field` carries the one
 * value that is filled into a page; the reply of `generate` carries the password or passphrase the core has just made,
 * for the popup to show; `offer_reveal` answers with the password of one offer, to the popup session that was told of
 * it, on the click of "Show" (it is never in a list or a classification); and `form_capture` (content script to
 * background) carries what the person typed into the form they submitted, the password and, in a change form, the one
 * in use. Nothing is sent back. `item_code` answers with the current one-time code of one item, to the popup session
 * that holds the item's reference, for the popup to show it; the secret the code comes from never leaves the core.
 */
export const SECRET_KEY_EXCEPTIONS = Object.freeze({
  fill_field: Object.freeze(["value"]),
  generate: Object.freeze(["value"]),
  form_capture: Object.freeze(["password", "current_password"]),
  offer_reveal: Object.freeze(["value"]),
  item_code: Object.freeze(["code"]),
  // What the user types to open the vault with a PIN, and the PIN when one is set: a request from an extension page to
  // the background, never a reply. (The master password and the secret key of `pin_set` are `mp` and `sk`, as in `unlock`.)
  pin_set: Object.freeze(["pin"]),
  pin_unlock: Object.freeze(["pin"]),
  // The 32 bytes a passkey gave the unlock window, on their one way to the background (a request from the window, never a
  // reply). The window wipes its copy as soon as the message is sent.
  prf_unlock: Object.freeze(["prf_output"]),
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
  // `pin_set` asks for the master password again (`mp`) and, when this device does not keep it, the secret key (`sk`).
  // `pin` is a forbidden name, so SECRET_KEY_EXCEPTIONS names exactly these two types for it (and no reply carries it:
  // the rule and the state in the reply of `unlock_policy` are `pin_state`).
  pin_set: Object.freeze(["mp", "sk", "pin"]),
  pin_unlock: Object.freeze(["pin"]),
  // Not typed, but it travels the same way: from the unlock window to the background, one way, in this one type.
  prf_unlock: Object.freeze(["prf_output"]),
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
const B64U = /^[A-Za-z0-9_-]+$/;

const requestId = string({ min: 1, max: 64, pattern: ID });
const ref = string({ min: 1, max: 64, pattern: ID });
const reason = string({ min: 1, max: 64, pattern: REASON });
const field = string({ max: 16, oneOf: ["username", "password", "totp"] });
// What a frame can report and what can be pushed into it: the sign-in kinds, and, for a generated password, the new and
// the confirm field of a sign-up, change or reset form.
const fillKind = string({ max: 16, oneOf: ["username", "password", "totp", "new_password", "confirm_password"] });
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
    // The item holds a one-time code (a mark only: the row's copy menu offers the code; never the code itself).
    has_totp: boolean(),
    // The item has a one-time code and was filled in this tab a short while ago: the page may ask for the code next.
    next: boolean(),
    // A candidate of a page: the first frame it was matched in, and every frame it may be filled in (the top first).
    frame_id: frameId,
    frame_ids: array(frameId, { max: 4 }),
  },
  { optional: ["username", "insecure", "favorite", "type", "site", "has_totp", "next", "frame_id", "frame_ids"] },
);
const empty = object({});
// A generation: a random name for a value that the background keeps for a while.
const generationId = string({ min: 1, max: 64, pattern: ID });
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

// An offer to save or update a password, as the popup may see it: a reference good only in the popup's session, the
// kind of form it came from, the host as the core shows it, the user name (editable on the card) and whether Ferret
// made the password. Never the password.
const offerId = string({ min: 32, max: 32, pattern: /^[0-9a-f]{32}$/ });
const itemId = string({ min: 32, max: 32, pattern: /^[0-9a-f]{32}$/ });
const revision = integer({ min: 1, max: 1_000_000_000 });
const offerMeta = object(
  {
    offer_id: offerId,
    kind: string({ max: 16, oneOf: ["login", "signup", "change", "reset"] }),
    host: displayHost,
    username: string({ max: 512 }),
    generated: boolean(),
    // The offer came from a private window ("Never" is then kept for this browser session only).
    incognito: boolean(),
  },
  { optional: ["username"] },
);
// What an offer means for the vault, from the core: save as new, update one item, choose among several, or nothing.
// Item ids, names, user names and hosts only; never a value of an item.
const classificationShape = {
  action: string({ max: 8, oneOf: ["save", "update", "choose", "none"] }),
  targets: array(object({ id: itemId, rev: revision, name: string({ max: 256 }), username: string({ max: 256 }), how: string({ max: 24 }) }), { max: 32 }),
  domain_only: array(object({ id: itemId, rev: revision, name: string({ max: 256 }), host: nullable(displayHost) }), { max: 32 }),
  reused: array(object({ name: string({ max: 256 }), host: nullable(displayHost) }), { max: 3 }),
  username_from: nullable(string({ max: 16, oneOf: ["typed", "page", "identifier", "fill"] })),
};
const classification = object(classificationShape);
// Which parts of a conflicting item differ between the two versions (the item's own fields by their labels). Names of
// what differs, never a value; a password or another hidden field is named only as "hidden".
const conflictDiff = object(
  { what: string({ max: 16, oneOf: ["name", "username", "urls", "folders", "favorite", "notes", "totp", "hidden", "field"] }), label: string({ max: 256 }) },
  { optional: ["label"] },
);

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
  // "Never on this site", from Ferret's chooser window for a page's passkey request (the `passkeys` feature): the background keeps
  // the request's RP ID on the never list (in memory only for a private window) and hands the page's call to the browser. The
  // request is named by the id the window has in its address; the host is the background's, never the window's.
  passkey_never: {
    request: object({ request_id: string({ min: 32, max: 32, pattern: /^[0-9a-f]{32}$/ }) }),
    reply: okReply,
  },
  // The PIN (design document, sections 7.2 and 7.6). `unlock_policy`: the administrator's rule as this device last saw
  // it, and what this device has of a PIN (whether one is set, where it is kept, the attempts left, the wait, whether
  // it works without the server now). It needs no key and works while the vault is locked. Nothing in it tells the
  // length or the kind of the PIN. The object is `pin_state` and not `pin`: `pin` is a forbidden name, and the only
  // two places that may carry it are the requests of `pin_set` and `pin_unlock`.
  unlock_policy: {
    request: empty,
    reply: object({
      pin_state: object(
        {
          allowed: boolean(),
          after_restart: boolean(),
          min_length: integer({ min: 4, max: 64 }),
          set: boolean(),
          location: string({ max: 8, oneOf: ["disk", "session"] }),
          failures_left: integer({ min: 0, max: 5 }),
          wait_ms: integer({ min: 0, max: 3_600_000 }),
          offline_ok: boolean(),
        },
        { optional: ["location"] },
      ),
      prf: object({ enabled: boolean() }),
    }),
  },
  // Sets (or changes) the PIN: needs the open vault, the network and the master password again (and the secret key
  // when this device does not keep it): `mp` and `sk` as in `unlock`. `acknowledged`: the user ticked "I understand"
  // under the warning (required for `disk`). The PIN, the password and the secret key go to the background and nowhere else.
  pin_set: {
    request: object(
      {
        mp: string({ min: 1, max: 1024 }),
        sk: string({ min: 1, max: 128 }),
        pin: string({ min: 1, max: 256 }),
        location: string({ max: 8, oneOf: ["disk", "session"] }),
        acknowledged: boolean(),
      },
      { optional: ["sk"] },
    ),
    reply: okReply,
  },
  // Opens the vault with the PIN. A wrong PIN says how many attempts are left and how long to wait for the next.
  pin_unlock: {
    request: object({ pin: string({ min: 1, max: 256 }) }),
    reply: object(
      {
        ok: boolean(),
        reason,
        account_email: email,
        server: serverUrl,
        left: integer({ min: 0, max: 5 }),
        wait_ms: integer({ min: 0, max: 3_600_000 }),
      },
      { optional: ["reason", "account_email", "server", "left", "wait_ms"] },
    ),
  },
  // Turns the PIN off: the record is deleted. It needs no password.
  pin_off: { request: empty, reply: okReply },
  // Unlocking with a passkey (design document, sections 7.2 and 7.3), only from the extension's own unlock window.
  // `prf_options`: what the window needs for its one WebAuthn call, read from the server now (never kept): the host the
  // passkeys belong to (the vault's exact host) and, for each passkey, its credential id and salt (base64url). It needs the
  // network and live tokens. `prf_unlock`: the credential that answered and the 32 bytes it gave for its salt (base64url);
  // the background opens the vault with them or says why not. Neither answer carries a key or a text of the core.
  prf_options: {
    request: empty,
    reply: object(
      {
        ok: boolean(),
        reason,
        rp_id: string({ min: 1, max: 253 }),
        credentials: array(object({ id: string({ min: 1, max: 1024, pattern: B64U }), salt: string({ min: 43, max: 43, pattern: B64U }) }), { max: 16 }),
      },
      { optional: ["reason", "rp_id", "credentials"] },
    ),
  },
  // `prf_window`: opens the unlock window (or brings the open one to the front); the popup asks for it, because a popup that
  // makes the call itself closes when the system's dialog takes the focus. It carries nothing and the answer says only whether
  // the window could be opened.
  prf_window: { request: empty, reply: okReply },
  prf_unlock: {
    request: object({ credential_id: string({ min: 1, max: 1024, pattern: B64U }), prf_output: string({ min: 43, max: 43, pattern: B64U }) }),
    reply: object({ ok: boolean(), reason, account_email: email, server: serverUrl }, { optional: ["reason", "account_email", "server"] }),
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
  // `only: "totp"` fills the one-time code field alone (the frame is the first one that has such a field).
  fill: {
    request: object({ ref, tab_id: tabId, frame_id: frameId, only: string({ max: 16, oneOf: ["totp"] }) }, { optional: ["frame_id", "only"] }),
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
  // The current one-time code of an item and the seconds it still holds, made in the core from the device's clock, for the
  // popup to show. `automatic`: the open popup asks again at the end of a period, which is not the user's activity.
  item_code: {
    request: object({ ref, automatic: boolean() }, { optional: ["automatic"] }),
    reply: object(
      { ok: boolean(), reason, code: string({ min: 6, max: 10, pattern: /^[0-9]{6,10}$/ }), seconds_left: integer({ min: 0, max: 3600 }) },
      { optional: ["reason", "code", "seconds_left"] },
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
      { ok: boolean(), reason, mine: conflictSide, theirs: conflictSide, differs: array(conflictDiff, { max: 40 }) },
      { optional: ["reason", "mine", "theirs", "differs"] },
    ),
  },
  // "Keep mine" or "Keep the server's", against the versions `item_conflict` showed this page last.
  item_resolve: {
    request: object({ ref, choice: string({ max: 8, oneOf: ["mine", "theirs"] }) }),
    reply: okReply,
  },
  // "Discard the draft" of an item whose change the server refused.
  item_discard: { request: object({ ref }), reply: okReply },
  // The offers to save or update a password that wait for a tab (the popup's own list; `tab_id` is the page the popup
  // is about), and `notice`: the reason a shortcut or menu click of the tab was refused, shown once.
  offer_list: {
    request: object({ tab_id: tabId, automatic: boolean() }, { optional: ["automatic"] }),
    reply: object({ ok: boolean(), reason, offers: array(offerMeta, { max: 4 }), notice: reason }, { optional: ["reason", "offers", "notice"] }),
  },
  // What an offer means for the vault now (the core decides: save, update, choose, none).
  offer_classify: {
    request: object({ offer_id: offerId }),
    reply: object({ ok: boolean(), reason, ...classificationShape }, { optional: ["reason", ...Object.keys(classificationShape)] }),
  },
  // The folders of the vault the save card offers.
  folder_names: { request: empty, reply: object({ ok: boolean(), reason, folders: array(string({ max: 256 }), { max: 500 }) }, { optional: ["reason", "folders"] }) },
  // "Save": a new item from the offer, with the name, user name and folder the user chose on the card. The password is
  // the one the background holds; it is never in the message.
  offer_save: {
    request: object({ offer_id: offerId, name: string({ max: 512 }), username: string({ max: 512 }), folder: string({ max: 256 }) }, { optional: ["username", "folder"] }),
    reply: object({ ok: boolean(), reason, pending: boolean(), classification }, { optional: ["reason", "pending", "classification"] }),
  },
  // "Update": the new password into one item (`id` and `rev` are those of the classification; `picked`: the user chose
  // an item that matches by domain only, from the list that names its host).
  offer_update: {
    request: object({ offer_id: offerId, id: itemId, rev: revision, picked: boolean() }, { optional: ["picked"] }),
    reply: object({ ok: boolean(), reason, pending: boolean(), classification }, { optional: ["reason", "pending", "classification"] }),
  },
  // "Not now", and "Never for this site".
  offer_dismiss: { request: object({ offer_id: offerId }), reply: okReply },
  offer_never: { request: object({ offer_id: offerId }), reply: okReply },
  // "Show" on the card's password: the value of one offer, to the popup session that was told of it.
  offer_reveal: {
    request: object({ offer_id: offerId }),
    reply: object({ ok: boolean(), reason, value: string({ max: 1024 }) }, { optional: ["reason", "value"] }),
  },
  // The generator (design document, section 10.2). `generate` asks the core for a new password or passphrase with the
  // options the popup keeps in its own storage, and answers the value with a random `generation_id` under which the
  // background keeps it until the vault locks or 15 minutes have passed (`expires_at`, milliseconds since 1970). With
  // `current` it shows the value the background still holds (the popup was closed and opened again) and makes nothing
  // new. The reply of `generate` is the only reply that carries a value; the popup never sends it back: "Fill" and
  // "Copy" name the `generation_id`.
  generate: {
    request: object(
      {
        current: boolean(),
        kind: string({ max: 16, oneOf: ["password", "passphrase"] }),
        length: integer({ min: 4, max: 128 }),
        lower: boolean(),
        upper: boolean(),
        digits: boolean(),
        symbols: boolean(),
        min_each: integer({ min: 0, max: 8 }),
        avoid_ambiguous: boolean(),
        words: integer({ min: 3, max: 20 }),
        separator: string({ max: 1, oneOf: ["-", ".", "_", " "] }),
        capitalize: boolean(),
        number: boolean(),
      },
      {
        optional: ["current", "kind", "length", "lower", "upper", "digits", "symbols", "min_each", "avoid_ambiguous", "words", "separator", "capitalize", "number"],
      },
    ),
    reply: object(
      {
        ok: boolean(),
        reason,
        generation_id: generationId,
        value: string({ max: 1024 }),
        kind: string({ max: 16, oneOf: ["password", "passphrase"] }),
        // The core's entropy estimate, in whole bits, for the strength line.
        bits: integer({ min: 0, max: 100_000 }),
        expires_at: integer({ min: 0, max: 8_640_000_000_000_000 }),
      },
      { optional: ["reason", "generation_id", "value", "kind", "bits", "expires_at"] },
    ),
  },
  // "Fill" with a generated value: the `generation_id`, the tab and (the menu's) frame, never the value. The background
  // fills the new and the confirm field of a sign-up, change or reset form of that tab, and never a password in use.
  // `length` is the length that was filled (a field's `maxlength` can make it shorter than the value the popup shows:
  // the popup asks `generate { current: true }` again); `offer`: the background now holds an offer to save it.
  fill_generated: {
    request: object({ generation_id: generationId, tab_id: tabId, frame_id: frameId }, { optional: ["frame_id"] }),
    reply: object({ ok: boolean(), reason, length: integer({ min: 0, max: 1024 }), offer: boolean() }, { optional: ["reason", "length", "offer"] }),
  },
  // "Copy" of a generated value: the background writes the clipboard itself and clears it 30 seconds later.
  generate_copy: { request: object({ generation_id: generationId }), reply: okReply },
  settings: {
    // The bounds are those of LOCK_CHOICES; the background accepts only the listed values.
    request: object(
      { lock_seconds: integer({ min: LOCK_CHOICES[0], max: LOCK_CHOICES[LOCK_CHOICES.length - 1] }) },
      { optional: ["lock_seconds"] },
    ),
    reply: object({ lock_seconds: integer({ min: LOCK_CHOICES[0], max: LOCK_CHOICES[LOCK_CHOICES.length - 1] }) }),
  },
  // "Offer to save passwords" and the never list, from the settings page. `enable` follows the page's own request for
  // the permission for https pages (the background checks it again); `never_remove` takes one host off the list and
  // `never_clear` empties it. A request with none of them only reads. The reply is what is true now.
  capture_settings: {
    request: object(
      { enable: boolean(), never_remove: host, never_clear: boolean(), auto_open: boolean() },
      { optional: ["enable", "never_remove", "never_clear", "auto_open"] },
    ),
    reply: object(
      {
        ok: boolean(),
        reason,
        on: boolean(),
        permission: boolean(),
        never: array(host, { max: 500 }),
        // "Open the popup by itself" and what the browser has shown about it (`unknown` until it was tried).
        auto_open: boolean(),
        auto_open_state: string({ max: 8, oneOf: ["unknown", "works", "fails"] }),
      },
      { optional: ["reason", "auto_open", "auto_open_state"] },
    ),
  },
});

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
  if (encoder.encode(raw).length > limitOf(type)) {
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
  if (limitOf(type) < MAX_MESSAGE_BYTES && encoder.encode(raw).length > limitOf(type)) throw new ProtocolError("too_large");
  const def = allowed[type];
  const schema = opts.reply ? def.reply : def.request;
  if (!schema) throw new ProtocolError("unknown_type");
  return { id, type, body: validate(schema, body) };
}
