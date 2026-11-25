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
// CONTENT_TYPES and PUSH_TYPES, the envelope and the wire form of a page's passkey call live in contentProtocol.mjs, so
// the content scripts in pages are joined from that module alone and carry no table of the extension pages. This module
// re-exports them; extension pages and the background import everything from here.
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
  array,
  boolean,
  integer,
  nullable,
  object,
  string,
  validate,
} from "./schema.mjs";
import {
  CONTENT_TYPES,
  ID,
  MAX_BYTES_BY_TYPE,
  MAX_MESSAGE_BYTES,
  PASSKEY_CREATE_OPTIONS,
  PASSKEY_ERRORS,
  PASSKEY_GET_OPTIONS,
  PASSKEY_LIMITS,
  PASSKEY_RESPONSE,
  PROTOCOL_VERSION,
  PUSH_TYPES,
  ProtocolError,
  REFUSAL_REASONS,
  REFUSAL_SCHEMA,
  REFUSED,
  b64uLength,
  createCodec,
  defineTypes,
  empty,
  origin,
  reason,
} from "./contentProtocol.mjs";

export {
  CONTENT_TYPES,
  MAX_BYTES_BY_TYPE,
  MAX_MESSAGE_BYTES,
  PASSKEY_CREATE_OPTIONS,
  PASSKEY_ERRORS,
  PASSKEY_GET_OPTIONS,
  PASSKEY_LIMITS,
  PASSKEY_RESPONSE,
  PROTOCOL_VERSION,
  PUSH_TYPES,
  ProtocolError,
  REFUSAL_REASONS,
  REFUSED,
  b64uLength,
};

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
  // The passkey chooser's verification step: the PIN or a passkey's 32 bytes, one way (a request only).
  passkey_verify: Object.freeze(["pin", "prf_output"]),
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
  // The passkey chooser's verification step.
  passkey_verify: Object.freeze(["mp", "sk", "pin", "prf_output"]),
});

/**
 * The reason of a refused fill when the frame of the form lies below a frame
 * whose document Ferret may not ask whether the form is shown (a frame of
 * another origin than the page, without its host permission). It differs from
 * `frame_hidden` ("hidden or covered") so the popup can say that Ferret could
 * not check, not that the frame is hidden.
 */
export const FRAME_UNCHECKED = "frame_unchecked";

const B64U = /^[A-Za-z0-9_-]+$/;

const ref = string({ min: 1, max: 64, pattern: ID });
const field = string({ max: 16, oneOf: ["username", "password", "totp"] });
const serverUrl = string({ min: 1, max: 300 });
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

// ---------------------------------------------------------------- passkeys (the `passkeys` feature): what Ferret's own pages see

const pkText = string({ max: PASSKEY_LIMITS.text });

/**
 * The background's own name for a waiting request of a page: 16 random bytes as hex. It is what Ferret's chooser window has
 * in its address (`?r=`) and sends back; it is never the bridge's id, which the bridge of the page's frame chose and which
 * never leaves the background.
 */
const pkRequestRef = string({ min: 32, max: 32, pattern: /^[0-9a-f]{32}$/ });
/**
 * A waiting request as Ferret's chooser window may see it (the `passkeys` feature). `origin` is the calling frame's
 * origin as the browser gave it (never a value of the page); `rp_id` is the RP ID the page asked for, unchecked (null: the
 * origin's host): the checked one and the host to show come from the core (`passkey_site`). `rp_name`, `user_name` and
 * `user_display_name` are texts the page chose (create only; null for a get), raw: the window shows them only as the
 * site's, isolated and stripped of control characters. `credentials`: how many credentials the page listed
 * (`allowCredentials` of a get, `excludeCredentials` of a create). `expires_in`: milliseconds left (null: a conditional
 * request, which has no deadline). `foreign`: the page's top document found create or get changed by something else (text
 * only, never routing). `incognito`: the request comes from a private window.
 */
export const PASSKEY_REQUEST_VIEW = object({
  request_id: pkRequestRef,
  kind: string({ max: 8, oneOf: ["create", "get"] }),
  mediation: string({ max: 16, oneOf: ["optional", "required", "conditional"] }),
  origin: string({ min: 1, max: 300 }),
  rp_id: nullable(pkText),
  rp_name: nullable(pkText),
  user_name: nullable(pkText),
  user_display_name: nullable(pkText),
  user_verification: string({ max: 16, oneOf: ["required", "preferred", "discouraged"] }),
  credentials: integer({ min: 0, max: PASSKEY_LIMITS.list }),
  prf: boolean(),
  expires_in: nullable(integer({ min: 0, max: 600_000 })),
  foreign: boolean(),
  incognito: boolean(),
});
/** The site of a request as the core checked it (`passkey_site`): canonical forms (A-labels) and the forms for reading. */
/** The ways to verify for a passkey request, in the order the window offers them. */
const PK_WAYS = ["recent", "prf", "pin", "password"];
const pkWays = array(string({ max: 16, oneOf: PK_WAYS }), { max: 4 });
const pkSite = object({
  origin: string({ min: 1, max: 300 }),
  host_unicode: string({ min: 1, max: 300 }),
  rp_id: string({ min: 1, max: 300 }),
  rp_id_unicode: string({ min: 1, max: 300 }),
});

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
    request: object({ request_id: pkRequestRef }),
    reply: okReply,
  },
  // The passkey provider's settings, from the settings page (the `passkeys` feature): `enable` follows the page's own request for the
  // permission for https pages (the background checks it again), `pending` marks that the switch is about to ask for it, `never_remove`
  // takes one RP ID off the "never" list and `never_clear` empties it, `recent_unlock` is "Count an unlock in the last 5 minutes as
  // verification". A request with none of them only reads. The reply is what is true now.
  passkey_settings: {
    request: object(
      { enable: boolean(), pending: boolean(), never_remove: host, never_clear: boolean(), recent_unlock: boolean() },
      { optional: ["enable", "pending", "never_remove", "never_clear", "recent_unlock"] },
    ),
    reply: object(
      {
        ok: boolean(),
        reason,
        on: boolean(),
        permission: boolean(),
        signed_in: boolean(),
        never: array(host, { max: 500 }),
        recent_unlock: boolean(),
      },
      { optional: ["reason"] },
    ),
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
  // Ferret's chooser window for a page's passkey request (the `passkeys` feature), only from that window
  // (`pages/passkey.html?r=<request_id>`). The first window session that asks for a request owns it; any other gets
  // `gone`, as for a request that has ended. `passkey_pending`: the request as the window may show it (works while the vault
  // is locked). `passkey_site`: the site as the core checked it (needs the open vault); an RP ID the page may not use ends
  // the request with SecurityError (`reason: "security_error"`). `passkey_cancel`: the user cancelled (the page gets
  // NotAllowedError, the same as for no match). `passkey_browser`: the browser answers instead, with the page's own options.
  passkey_pending: {
    request: object({ request_id: pkRequestRef }),
    reply: object({ ok: boolean(), reason, request: PASSKEY_REQUEST_VIEW }, { optional: ["reason", "request"] }),
  },
  passkey_site: {
    request: object({ request_id: pkRequestRef }),
    reply: object({ ok: boolean(), reason, site: pkSite }, { optional: ["reason", "site"] }),
  },
  passkey_cancel: { request: object({ request_id: pkRequestRef }), reply: okReply },
  passkey_browser: { request: object({ request_id: pkRequestRef }), reply: okReply },
  // What the vault has for a create request (the window's choices; needs the open vault): the items a new passkey can be added
  // to (`same_user`: its user name is the page's), the item that already holds a passkey for the same RP ID and user handle, and
  // the folders, each named by a reference good for this request only. Names are the vault's, as stored: the window cleans them.
  passkey_create_options: {
    request: object({ request_id: pkRequestRef }),
    reply: object(
      {
        ok: boolean(),
        reason,
        targets: array(object({ item_id: pkRequestRef, name: string({ max: 4096 }), user_name: string({ max: 4096 }), same_user: boolean() }), { max: 200 }),
        existing: nullable(object({ item_id: pkRequestRef, name: string({ max: 4096 }) })),
        folders: array(object({ id: pkRequestRef, name: string({ max: 4096 }) }), { max: 500 }),
        recent: boolean(),
        methods: pkWays,
      },
      { optional: ["reason", "targets", "existing", "folders", "recent", "methods"] },
    ),
  },
  // The person's choice in the window: for a create request a new item (`name`, `folder_id` from passkey_create_options) or an
  // item to add to (`item_id`); for a get request a passkey of the vault (`item_id`). Nothing about presence or verification: the
  // click in this window is the background's evidence of presence, and verification is its own mark for the request.
  // From Ferret's popup (a get only), for the tab's conditional request: `tab_id` in place of `request_id` (the handler takes exactly
  // one of the two, and `tab_id` only from the popup page).
  passkey_choose: {
    request: object(
      {
        request_id: pkRequestRef,
        tab_id: tabId,
        kind: string({ max: 8, oneOf: ["create", "get"] }),
        mode: string({ max: 8, oneOf: ["new", "attach"] }),
        name: string({ min: 1, max: 800 }),
        folder_id: pkRequestRef,
        item_id: pkRequestRef,
      },
      { optional: ["request_id", "tab_id", "mode", "name", "folder_id", "item_id"] },
    ),
    reply: okReply,
  },
  // A get in the window: the passkeys the core says may answer, the ways to verify now (in order), whether the server answers.
  passkey_candidates: {
    request: object({ request_id: pkRequestRef }),
    reply: object(
      {
        ok: boolean(),
        reason,
        candidates: array(
          object({ item_id: pkRequestRef, name: string({ max: 1024 }), user_name: string({ max: 1024 }), created: nullable(integer({ min: 0, max: 8_640_000_000_000_000 })) }),
          { max: 200 },
        ),
        recent: boolean(),
        methods: pkWays,
        online: boolean(),
      },
      { optional: ["reason", "candidates", "recent", "methods", "online"] },
    ),
  },
  // The verification step (request only, never a reply): of the chooser window of the request, or of Ferret's popup for the tab's
  // conditional request (`tab_id` in place of `request_id`; the PIN or the master password only: a passkey needs the window).
  passkey_verify: {
    request: object(
      {
        request_id: pkRequestRef,
        tab_id: tabId,
        method: string({ max: 16, oneOf: PK_WAYS }),
        pin: string({ min: 1, max: 256 }),
        mp: string({ min: 1, max: 1024 }),
        sk: string({ min: 1, max: 128 }),
        credential_id: string({ min: 1, max: 1024, pattern: B64U }),
        prf_output: string({ min: 43, max: 43, pattern: B64U }),
      },
      { optional: ["request_id", "tab_id", "pin", "mp", "sk", "credential_id", "prf_output"] },
    ),
    reply: object(
      { ok: boolean(), reason, left: integer({ min: 0, max: 5 }), wait_ms: integer({ min: 0, max: 3_600_000 }) },
      { optional: ["reason", "left", "wait_ms"] },
    ),
  },
  // Ferret's popup for the tab it is about (the `passkeys` feature; from the popup page only). `passkey_tab` works locked: a modal
  // request that waits without a window (the card: the calling frame's origin from the browser, and the kind), whether a conditional
  // request waits for the popup's list, `again`: a one-time pass of "use the browser" that waits for a click on the page (its kind), and the
  // foreign mark (text only). `passkey_tab_list` (open vault): the passkeys for the tab, `pick` for a conditional request (a button
  // each), `info` without one (no button), `none` when Ferret does not answer there; `host` is the RP ID as the core reads it.
  // `passkey_tab_open`: the popup's click opens Ferret's window for the waiting request (`waiting`) or for the conditional one
  // (`conditional`: Windows Hello, which the popup cannot ask for). The list goes to the popup and nowhere else.
  passkey_tab: {
    request: object({ tab_id: tabId }),
    reply: object(
      {
        ok: boolean(),
        reason,
        waiting: nullable(object({ origin: string({ min: 1, max: 300 }), kind: string({ max: 8, oneOf: ["create", "get"] }) })),
        conditional: boolean(),
        again: nullable(string({ max: 8, oneOf: ["create", "get"] })),
        foreign: boolean(),
      },
      { optional: ["reason", "waiting", "conditional", "again", "foreign"] },
    ),
  },
  passkey_tab_list: {
    request: object({ tab_id: tabId }),
    reply: object(
      {
        ok: boolean(),
        reason,
        mode: string({ max: 8, oneOf: ["none", "pick", "info"] }),
        host: string({ max: 300 }),
        candidates: array(
          object({ item_id: pkRequestRef, name: string({ max: 1024 }), user_name: string({ max: 1024 }), created: nullable(integer({ min: 0, max: 8_640_000_000_000_000 })) }),
          { max: 200 },
        ),
        recent: boolean(),
        methods: pkWays,
        online: boolean(),
      },
      { optional: ["reason", "mode", "host", "candidates", "recent", "methods", "online"] },
    ),
  },
  passkey_tab_open: {
    request: object({ tab_id: tabId, which: string({ max: 16, oneOf: ["waiting", "conditional"] }) }),
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
  // `never_clear` empties it. `pending` marks that the switch is about to ask the browser for the permission (true) or that it
  // will not (false): only a grant that follows a mark switches the feature on (the permission is shared with the passkeys). A
  // request with none of them only reads. The reply is what is true now.
  capture_settings: {
    request: object(
      { enable: boolean(), never_remove: host, never_clear: boolean(), auto_open: boolean(), pending: boolean() },
      { optional: ["enable", "never_remove", "never_clear", "auto_open", "pending"] },
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

const codec = createCodec([UI_TYPES, CONTENT_TYPES, PUSH_TYPES], UI_TYPES);

/**
 * Build a message of any table. The body is checked against its schema, so a bug on the sending side fails at the sender.
 * @type {(type: string, body: unknown, opts?: { id?: string, reply?: boolean }) => string}
 */
export const encode = codec.encode;

/**
 * Check a received message. `allowed` is the table of the channel the message came in on (UI_TYPES, CONTENT_TYPES or
 * PUSH_TYPES). Nothing from the message is trusted until every check has passed. `refused` is a reply on UI_TYPES only.
 * @type {(raw: unknown, allowed: import("./contentProtocol.mjs").TypeTable, opts?: { reply?: boolean }) => { id: string, type: string, body: any }}
 */
export const decode = codec.decode;

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
    body: validate(REFUSAL_SCHEMA, { reason: known }),
  });
}
