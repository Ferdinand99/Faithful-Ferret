// The background's side of the passkey bridge: the request broker (the `passkeys` feature, design document § 9.2, § 9.3
// and § 10.8).
//
// The bridge script of a page reports a call of `create` or `get` (`passkey_request`), the page's abort
// (`passkey_abort`), a provider that was there before Ferret (`passkey_foreign`) and, while a request waits, a ping
// (`passkey_ping`). The router hands each over with the sender it checked (tab, frame, document, the browser's origin;
// never anything from the message) to the one core operation `passkey_event`, which ends here. The answer is a push of the
// bridge's id to that frame and that document only (`tabs.sendMessage` with `frameId` and `documentId`): `passkey_result`,
// `passkey_handover` or `passkey_error`. A sender without a `documentId` gets no answer, so an answer can never reach
// another document of the frame.
//
// Who may get Ferret instead of the browser (anything else is handed to the browser at once, with the page's own options):
//   - the setting is on and the permission for https pages is there, checked at every request and again before an answer;
//     every request that waits ends when the setting goes off or the permission is taken back (a tab that was open when
//     the feature went off, or when the device was signed out, keeps its scripts);
//   - the device is signed in at a server and its session is live (a device ended remotely keeps its server);
//   - the calling frame's origin is the browser's (`sender.origin`, the same as its address's), `https`, without a
//     trailing dot, and (in a release) not localhost or a loopback address;
//   - it is not the signed-in Ferret server's host (any port) and not on the "never" list;
//   - the frame chain from the calling frame up to the top, from `webNavigation`, is whole, and every frame in it has the
//     caller's origin with an `https` address (so no opaque frame, no about:blank, srcdoc, data: or blob: frame, and no
//     frame of the top's origin below a frame of another);
//   - `document.featurePolicy` (where the browser has it) allows the call;
//   - the request is not one only the browser can answer (a list of algorithms without ES256, `appid`, enterprise
//     attestation, a cross-platform create that hints only at a security key or a phone, a conditional create).
// The caller the core is given is built here and nowhere else (`callerOf`, `passkey_site`), from those facts only.
//
// What happens to a request Ferret takes:
//   - one modal request per tab: another one from the same tab ends at once with AbortError (it never replaces the one
//     that waits); a modal request from the same document ends a conditional one that waits (AbortError);
//   - a conditional request has no deadline and only marks the toolbar button (its list is the popup's); one per tab. The
//     popup acts on it by tab (`tabRef`), never by an id it was given. A window opened for it (Windows Hello from the popup)
//     gives it back when it closes or the person cancels there: it ends only on an answer, a hand-over (always straight to the
//     browser, no pass), the page's abort, a modal request of the same document, a navigation, a lock or the tab closing;
//   - a modal request has a deadline, the page's `timeout` clamped to PASSKEY_TIMEOUT_MS;
//   - at most one Ferret window: a modal request opens it only when the page had user activation, no window is open and
//     the tab is not in its calm period; otherwise the request waits with a mark on the button and a card in the popup,
//     whose click opens the window;
//   - the calm period: PASSKEY_QUIET.cancels modal requests of a tab that ended without an answer within windowMs give the
//     tab quietMs in which a new request only waits with the mark (it is kept, not refused);
//   - it ends on an answer, a hand-over, the user's cancel (or closing the window), the page's abort, its deadline, a new
//     document in its frame or above it, the tab closing, and a lock of the open vault. A frame that goes away (removed from
//     its page, which no browser event reports) ends it through the bridge's abort on `pagehide`, or, should that message be
//     lost, when its bridge has not pinged for SILENT_MS. A same-document navigation
//     (`pushState`) keeps it; its origin is checked again, and before an answer the frame chain is checked again.
// Cancelled, no match and expired all end with NotAllowedError, after the same small random delay, so a page cannot tell
// them apart by type or by time.
//
// A Manifest V3 event page that was unloaded lost its requests: the bridge's next ping names ids the background no longer
// knows, and each ends with NotAllowedError (fails closed). The ping (every 20 s while something waits) keeps the event
// page alive meanwhile.
//
// The chooser window (pages/passkey.html) is opened only in a build that has it (`windows` is null otherwise): without it
// every request is handed to the browser, as before the window existed.

import { encode } from "../shared/protocol.mjs";
import { PASSKEY_PASS_ONCE_MS, createPassOnce } from "./passkeyHandover.mjs";
import { PASSKEY_ORIGINS, PASSKEY_SETTING_KEY } from "./passkeyRegistry.mjs";

/** The core operation the router hands a message of the bridge to. */
export const PASSKEY_EVENT_OP = "passkey_event";
/**
 * The core operations of Ferret's chooser window (the UI types of the same names): the broker's, the choices of a create
 * (`passkey_create_options`: passkeyFlow.mjs) and those of a get and of verification (`passkey_candidates`, `passkey_choose`,
 * `passkey_verify`: passkeyGet.mjs; a create choice goes on to passkeyFlow.mjs).
 */
export const PASSKEY_WINDOW_OPS = Object.freeze([
  "passkey_pending",
  "passkey_site",
  "passkey_cancel",
  "passkey_browser",
  "passkey_never",
  "passkey_create_options",
  "passkey_candidates",
  "passkey_choose",
  "passkey_verify",
]);
/**
 * How long a request may go without a ping of its bridge (which pings every 20 s while it waits) before it ends: its frame is
 * gone. Two pings and a margin.
 */
export const PASSKEY_SILENT_MS = 45_000;
/** The bridge's ping while a request waits. */
const PING_MS = 20_000;
/** The deadline of a modal request: the page's `timeout`, clamped; the default when the page gave none. Conditional ones have none. */
export const PASSKEY_TIMEOUT_MS = Object.freeze({ min: 30_000, max: 600_000, default: 300_000 });
/** A click in Ferret's window counts only this long after the window got the focus or its content last changed. */
export const PASSKEY_GUARD_MS = 400;
export { PASSKEY_PASS_ONCE_MS };
/** The calm period: this many modal requests of a tab ended without an answer within `windowMs` give `quietMs` of marks only. */
export const PASSKEY_QUIET = Object.freeze({ cancels: 3, windowMs: 60_000, quietMs: 300_000 });
/**
 * The session name under which Ferret's popup acts on a tab's conditional request (`tabRef`): the popup names the tab, never a
 * request, and any popup of this extension may act for the tab it shows. A window opened for the request takes it over.
 */
export const POPUP_SESSION = "popup";
/** How long a mark of verification counts (the same five minutes as a recent unlock), on the monotonic clock and the wall clock. */
export const MARK_MS = 5 * 60_000;
/** The delay of every NotAllowedError (cancel, no match, deadline): `min` plus a random part below `spread`. */
export const PASSKEY_ERROR_DELAY_MS = Object.freeze({ min: 120, spread: 200 });

/** How long an abort that came before its request is remembered. */
const ABORT_KEPT_MS = 30_000;
/** Per tab: a frame that floods aborts with made-up ids evicts only its own tab's. */
const MAX_ABORTS_PER_TAB = 32;
/** The most requests that wait at once, over all tabs (one modal and one conditional per tab in practice). */
const MAX_PENDING = 256;
const MAX_TABS_KEPT = 256;
/** The most frames of a tab that are looked at; a tab with more is left to the browser. */
const MAX_FRAMES = 1024;
const MAX_URL = 8192;
const REF = /^[0-9a-f]{32}$/;
const UV = Object.freeze(["required", "preferred", "discouraged"]);
const PAGE_ERRORS = Object.freeze(["NotAllowedError", "SecurityError", "TypeError", "InvalidStateError", "AbortError", "NotSupportedError"]);
/** The core's codes that say the vault or its worker is gone: the op's caller (the core host) handles those. */
const VAULT_GONE = Object.freeze(["vault_locked", "locked", "worker_failed", "internal", "kdf_out_of_memory"]);
/** What the window is told when `passkey_site` ended the request, by the page's error. */
const SITE_REASONS = Object.freeze({
  SecurityError: "security_error",
  TypeError: "type_error",
  NotSupportedError: "type_error",
  InvalidStateError: "not_allowed",
  NotAllowedError: "not_allowed",
});
/** The algorithm Ferret signs with (ES256). */
const ES256 = -7;

/**
 * @typedef {{ tabId: number, frameId: number, documentId?: string, url: string, origin?: string, incognito?: boolean }} BridgeSender
 *   the sender the router checked (`contentSender`)
 * @typedef {{ type: string, sender: BridgeSender, body: any }} BridgeEvent
 * @typedef {{ tabId: number, frameId: number, documentId: string, url: string, origin: string | null, incognito: boolean }} Sender
 * @typedef {{
 *   id: string, bridgeId: string, key: string, sender: Sender, origin: string, kind: "create" | "get",
 *   mediation: "optional" | "required" | "conditional", options: any, top: string | null,
 *   deadline: number | null, timer: unknown, state: "window" | "waiting" | "conditional",
 *   windowId: number | null, session: string | null, held: boolean, lastPing: number, quiet: unknown,
 * }} Request
 * @typedef {{
 *   request_id: string, kind: "create" | "get", mediation: string, origin: string, rp_id: string | null,
 *   rp_name: string | null, user_name: string | null, user_display_name: string | null, user_verification: string,
 *   credentials: number, prf: boolean, expires_in: number | null, foreign: boolean, incognito: boolean,
 * }} RequestView what Ferret's window and popup may see of a request (PASSKEY_REQUEST_VIEW)
 * @typedef {{
 *   getAllFrames(details: { tabId: number }): Promise<Array<{ frameId: number, parentFrameId: number, url: string, documentId?: string, errorOccurred?: boolean }> | null | undefined>,
 * }} Frames the browser's frames of a tab (webNavigation)
 * @typedef {{ open(requestId: string): Promise<number | null>, close(windowId: number): Promise<void> }} Windows the chooser window
 * @typedef {{ current(): Promise<{ origin: string, live: boolean } | null> }} Servers the signed-in server and whether its session is live
 * @typedef {{ setTimeout(fn: () => void, ms: number): unknown, clearTimeout(id: any): void }} Timers
 */

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * The origin of an `https` address, or null (any other scheme, an address the parser refuses, an opaque origin).
 * @param {unknown} url @returns {string | null}
 */
export function httpsOrigin(url) {
  if (typeof url !== "string" || url.length > MAX_URL || !/^https:\/\//i.test(url)) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || parsed.hostname === "" || parsed.origin === "null") return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/** @param {string} origin @returns {string} */
const hostOf = (origin) => new URL(origin).hostname;

/**
 * localhost, its subdomains and the loopback addresses (127.0.0.0/8, ::1, and IPv4 loopback written as IPv6).
 * @param {string} host as the URL parser writes it @returns {boolean}
 */
export function isLoopbackHost(host) {
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  return host === "[::1]" || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(host);
}

/**
 * The bytes of an unpadded base64url text, or -1 when no text of that length is one.
 * @param {string} text @returns {number}
 */
const b64uBytes = (text) => (text.length % 4 === 1 ? -1 : Math.floor((text.length * 3) / 4));

/**
 * Why only the browser can answer a request, from the request's own properties (never the vault's content, so it tells the
 * page nothing it did not know), or null.
 * @param {"create" | "get"} kind @param {any} options @param {string} mediation
 * @returns {string | null}
 */
export function automaticHandover(kind, options, mediation) {
  // Conditional creation (WebAuthn L3) is not supported.
  if (kind === "create" && mediation === "conditional") return "conditional_create";
  const extensions = options?.extensions ?? {};
  if (extensions.appid !== undefined || extensions.appid_exclude !== undefined) return "appid";
  if (options?.attestation === "enterprise") return "enterprise";
  if (kind === "create") {
    // An empty list means ES256 and RS256 (WebAuthn): Ferret answers. A list of only other algorithms (or other types) does not.
    const params = Array.isArray(options?.pub_key_cred_params) ? options.pub_key_cred_params : [];
    if (params.length > 0 && !params.some((/** @type {any} */ p) => p?.type === "public-key" && p?.alg === ES256)) return "algorithms";
    const hints = Array.isArray(options?.hints) ? options.hints : [];
    if (
      options?.authenticator_selection?.authenticator_attachment === "cross-platform" &&
      hints.length > 0 &&
      hints.every((/** @type {unknown} */ h) => h === "security-key" || h === "hybrid")
    ) {
      return "security_key";
    }
  }
  return null;
}

/**
 * A request whose options the browser would refuse with a TypeError (WebAuthn): `user.id` of 0 or more than 64 bytes.
 * @param {"create" | "get"} kind @param {any} options @returns {boolean}
 */
export function malformedOptions(kind, options) {
  if (kind !== "create") return false;
  const bytes = typeof options?.user?.id === "string" ? b64uBytes(options.user.id) : -1;
  return bytes < 1 || bytes > 64;
}

/** An RP ID already in canonical form: lower-case ASCII LDH labels (A-labels allowed), no trailing dot. */
const CANONICAL_RP_ID = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * An RP ID the page asked for that the browser refuses with a SecurityError before any UI: one that is not already in
 * canonical form (a trailing dot, upper case, a port, full-width or other characters that IDNA would map or drop), or one
 * that is neither the page's host nor a dot-delimited suffix of it. The browser compares the string as the page gave it with
 * the origin's host; the core would canonicalize such a string first and answer for one the page did not pass. (That a suffix
 * is not a public suffix is still the core's check, in the window.)
 * @param {"create" | "get"} kind @param {any} options @param {string} host the page's host, as the URL parser writes it
 * @returns {boolean}
 */
export function refusedRpId(kind, options, host) {
  const asked = kind === "create" ? options?.rp?.id : options?.rp_id;
  if (asked === undefined) return false;
  if (typeof asked !== "string" || !CANONICAL_RP_ID.test(asked)) return true;
  return asked !== host && !host.endsWith(`.${asked}`);
}

/**
 * Options the browser ends with a NotSupportedError in its client extension processing, before any authenticator (WebAuthn
 * L3 § 10.1.4, prf): `evalByCredential` at registration, and a non-empty `evalByCredential` with an empty `allowCredentials`.
 * @param {"create" | "get"} kind @param {any} options @returns {boolean}
 */
export function unsupportedOptions(kind, options) {
  const byCredential = options?.extensions?.prf?.eval_by_credential;
  if (kind === "create") return byCredential !== undefined;
  const allow = Array.isArray(options?.allow_credentials) ? options.allow_credentials : [];
  return Array.isArray(byCredential) && byCredential.length > 0 && allow.length === 0;
}

/**
 * The deadline of a modal request, from the page's `timeout` (milliseconds, a hint): clamped, the default when not given.
 * @param {unknown} timeout @returns {number}
 */
export function modalTimeout(timeout) {
  if (typeof timeout !== "number" || !Number.isFinite(timeout)) return PASSKEY_TIMEOUT_MS.default;
  return Math.min(PASSKEY_TIMEOUT_MS.max, Math.max(PASSKEY_TIMEOUT_MS.min, Math.floor(timeout)));
}

/**
 * The error a page gets for a code of the core: an RP ID the origin may not use is a SecurityError, malformed options a
 * TypeError, a credential the page excluded an InvalidStateError, an extension input the browser does not process (prf
 * `evalByCredential` without an allow list) a NotSupportedError; everything else (a refused caller, no match, a failed
 * verification) is the one NotAllowedError, as the browser gives it.
 * @param {unknown} code @returns {"NotAllowedError" | "SecurityError" | "TypeError" | "InvalidStateError" | "NotSupportedError"}
 */
export function pageErrorOf(code) {
  if (code === "malformed_rp_id") return "SecurityError";
  if (code === "unsupported") return "NotSupportedError";
  if (code === "invalid_input" || code === "too_large") return "TypeError";
  if (code === "invalid_state") return "InvalidStateError";
  return "NotAllowedError";
}

/**
 * The chooser window: `page?r=<request id>` in a window of its own (type popup), and its closing.
 * @param {{ windows: { create(o: { type: "popup", url: string, width: number, height: number }): Promise<{ id?: number } | undefined>, remove(id: number): Promise<void> }, getURL: (path: string) => string, page: string }} deps
 * @returns {Windows}
 */
export function chooserWindows({ windows, getURL, page }) {
  return {
    async open(requestId) {
      if (!REF.test(requestId)) return null;
      const made = await windows.create({ type: "popup", url: getURL(`${page}?r=${requestId}`), width: 460, height: 640 });
      return isIndex(made?.id) ? made.id : null;
    },
    async close(windowId) {
      await windows.remove(windowId);
    },
  };
}

/**
 * @param {{
 *   tabs: { sendMessage(tabId: number, message: unknown, options: { frameId: number, documentId: string }): Promise<unknown>, update?(tabId: number, props: { active: true }): Promise<unknown>, query?(q: { active: true, lastFocusedWindow: true }): Promise<Array<{ id?: number }>> },
 *   frames?: Frames | null,
 *   windows?: Windows | null,
 *   badge?: { passkey(tabId: number, on: boolean): void } | null,
 *   servers?: Servers | null,
 *   storageLocal?: { get(key: string): Promise<Record<string, unknown>> } | null,
 *   permissions?: { contains(wanted: { origins: string[] }): Promise<boolean> } | null,
 *   never?: { has(host: string): Promise<boolean>, add?(rpId: string, options: { incognito?: boolean }): Promise<unknown> } | null,
 *   passStorage?: { get(key: string): Promise<Record<string, unknown>>, set(items: Record<string, unknown>): Promise<void> } | null,
 *   listen?: { start(): void, stop(): void } | null,
 *   release?: boolean,
 *   now?: () => number,
 *   monotonic?: () => number,
 *   random?: (bytes: Uint8Array) => Uint8Array,
 *   timers?: Timers,
 * }} deps
 *   `frames`: webNavigation; `windows`: the chooser window, null in a build without it (every request then goes to the
 *   browser); `badge`: the toolbar button's passkey mark; `servers`: the signed-in server; `storageLocal` and `permissions`:
 *   the setting and the permission, read at every request; `never`: the "never on this site" list; `passStorage`: where the one-time passes of "use the browser" are also kept (the session storage); `listen`: starts the
 *   navigation, tab and window listeners while a request waits and stops them when none does (so they never wake an event
 *   page); `release`: a release leaves localhost and the loopback addresses to the browser. `now` (the wall clock) and `monotonic`
 *   measure the age of a mark of verification.
 */
export function createPasskeyRequests({
  tabs,
  frames = null,
  windows = null,
  badge = null,
  servers = null,
  storageLocal = null,
  permissions = null,
  never = null,
  passStorage = null,
  listen = null,
  release = true,
  now = () => Date.now(),
  monotonic = () => globalThis.performance.now(),
  random = (bytes) => globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)),
  timers = { setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms), clearTimeout: (id) => globalThis.clearTimeout(id) },
}) {
  /**
   * The tabs whose top document's script found create or get changed by something else: another password manager or the site
   * itself (the script cannot tell which). Memory only, cleared when the top frame moves to a new document. It is for the
   * text of Ferret's UI only and never changes where a call goes: any page can set it.
   * By tab: the documentId of the top document that reported it (a later top document of the tab is not marked by it).
   * @type {Map<number, string>}
   */
  const foreign = new Map();
  /** The requests that wait, by the background's own id. @type {Map<string, Request>} */
  const requests = new Map();
  /** The background's id of a request, by its sender and the bridge's id. @type {Map<string, string>} */
  const byBridge = new Map();
  /** Aborts that came before their request, per tab, by sender and bridge id: until when they are kept. @type {Map<number, Map<string, number>>} */
  const aborts = new Map();
  /** The requests whose NotAllowedError waits for its delay (a ping must not answer them early), by sender and bridge id. */
  const ending = new Set();
  /** "Use the browser" once: the next call of that kind from that document goes to the browser (passkeyHandover.mjs). */
  const passes = createPassOnce({ now, storage: passStorage });
  /** The timers that take a pass's mark off the toolbar button when the pass ends, by tab. @type {Map<number, unknown>} */
  const passTimers = new Map();
  /** Per tab: the moments its modal requests ended without an answer, and the end of its calm period. @type {Map<number, { ended: number[], until: number }>} */
  const calm = new Map();
  /**
   * The one-time marks that the user was verified for a request (UV), by request id, with when they were made on both clocks. Gone
   * with the request, at every lock, and after MARK_MS on either clock (a conditional request has no deadline, so a mark could
   * otherwise wait for hours).
   * @type {Map<string, { mono: number, wall: number }>}
   */
  const verified = new Map();
  /** The request whose window is open (or being opened). @type {string | null} */
  let windowHolder = null;
  /** The requests whose window the browser is making now. @type {Set<string>} */
  const making = new Set();
  let listening = false;

  /** @param {Sender} s @param {string} bridgeId */
  const keyOf = (s, bridgeId) => `${s.tabId}\u0000${s.frameId}\u0000${s.documentId}\u0000${bridgeId}`;

  /** A new id of the background's own: 16 random bytes as hex. */
  const newId = () => {
    for (;;) {
      const id = Array.from(random(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
      if (!requests.has(id)) return id;
    }
  };

  /** @param {() => void} fn @param {number} ms */
  const later = (fn, ms) => {
    try {
      const timer = timers.setTimeout(fn, ms);
      /** @type {any} */ (timer)?.unref?.();
      return timer;
    } catch {
      fn();
      return null;
    }
  };

  /** The delay of a NotAllowedError: the same for every cause. */
  const errorDelay = () => {
    const [a, b] = random(new Uint8Array(2));
    return PASSKEY_ERROR_DELAY_MS.min + Math.floor((((a << 8) | b) / 65536) * PASSKEY_ERROR_DELAY_MS.spread);
  };

  /**
   * The sender as the broker uses it: the router's checks plus the browser's origin, which must be the origin of the
   * frame's address (`sender.origin` and `sender.url` both come from the browser). Null without a document id.
   * @param {BridgeSender | undefined} sender @returns {Sender | null}
   */
  const senderOf = (sender) => {
    if (typeof sender !== "object" || sender === null) return null;
    if (!isIndex(sender.tabId) || !isIndex(sender.frameId) || typeof sender.url !== "string") return null;
    if (typeof sender.documentId !== "string" || sender.documentId === "" || sender.documentId.length > 128) return null;
    const fromUrl = httpsOrigin(sender.url);
    const origin = typeof sender.origin === "string" && fromUrl !== null && sender.origin === fromUrl ? fromUrl : null;
    return Object.freeze({ tabId: sender.tabId, frameId: sender.frameId, documentId: sender.documentId, url: sender.url, origin, incognito: sender.incognito === true });
  };

  /**
   * An answer to one request, to the frame and document that asked and nowhere else.
   * @param {{ tabId: number, frameId: number, documentId?: string }} sender @param {"passkey_result" | "passkey_handover" | "passkey_error"} type @param {Record<string, unknown>} body
   */
  const push = async (sender, type, body) => {
    if (typeof sender?.documentId !== "string" || sender.documentId === "") return false;
    try {
      await tabs.sendMessage(sender.tabId, encode(type, body), { frameId: sender.frameId, documentId: sender.documentId });
      return true;
    } catch {
      // The document is gone (or the answer did not fit the schema): there is no one to answer.
      return false;
    }
  };

  /**
   * Ends a page's call with an error. Every NotAllowedError comes after the same random delay, whatever its cause.
   * @param {Sender} s @param {string} bridgeId @param {string} name @returns {Promise<boolean>}
   */
  const pushError = (s, bridgeId, name) => {
    if (name !== "NotAllowedError") return push(s, "passkey_error", { request_id: bridgeId, name });
    const key = keyOf(s, bridgeId);
    ending.add(key);
    return new Promise((resolve) => {
      later(() => {
        ending.delete(key);
        void push(s, "passkey_error", { request_id: bridgeId, name }).then(resolve);
      }, errorDelay());
    });
  };

  /** The browser answers the page's call, with the page's own options. @param {Sender} s @param {string} bridgeId @param {boolean} once */
  const pushHandover = (s, bridgeId, once) => push(s, "passkey_handover", { request_id: bridgeId, once });

  /** The mark on the toolbar button: a request of the tab waits for the user outside a window. @param {number} tabId */
  const mark = (tabId) => {
    if (badge === null) return;
    let on = false;
    for (const r of requests.values()) if (r.sender.tabId === tabId && r.state !== "window") on = true;
    // A pass waits for the person's next click on the page ("click the page again"): the mark stays until it is used or ends.
    if (passes.pendingIn(tabId) !== null) on = true;
    try {
      badge.passkey(tabId, on);
    } catch {
      // A tab that is gone has no badge.
    }
  };

  const startListening = () => {
    if (listening || listen === null) return;
    listening = true;
    try {
      listen.start();
    } catch {
      // Without the listeners a request still ends by its deadline, its abort or the check before an answer.
    }
  };
  const stopListening = () => {
    if (!listening || listen === null || requests.size > 0) return;
    listening = false;
    try {
      listen.stop();
    } catch {
      // Nothing to stop.
    }
  };

  /** @param {number} tabId */
  const inCalm = (tabId) => {
    const entry = calm.get(tabId);
    if (entry === undefined) return false;
    const at = now();
    // A clock that went backwards must not keep a tab calm for longer than the period.
    return at < entry.until && entry.until - at <= PASSKEY_QUIET.quietMs;
  };

  /** A modal request of the tab ended without an answer. @param {number} tabId */
  const countEnded = (tabId) => {
    const at = now();
    const entry = calm.get(tabId) ?? { ended: [], until: 0 };
    entry.ended = entry.ended.filter((t) => t <= at && at - t < PASSKEY_QUIET.windowMs);
    entry.ended.push(at);
    if (entry.ended.length >= PASSKEY_QUIET.cancels) {
      entry.until = at + PASSKEY_QUIET.quietMs;
      entry.ended = [];
    }
    calm.delete(tabId);
    calm.set(tabId, entry);
    if (calm.size > MAX_TABS_KEPT) calm.delete(/** @type {number} */ (calm.keys().next().value));
  };

  /**
   * Removes a request. `unanswered`: it ended without an answer or a hand-over (it counts toward the tab's calm period when
   * it was modal). The window it had is closed.
   * @param {Request} req @param {boolean} unanswered @returns {boolean} false when it had ended already
   */
  const end = (req, unanswered) => {
    if (requests.get(req.id) !== req) return false;
    requests.delete(req.id);
    byBridge.delete(req.key);
    verified.delete(req.id);
    for (const timer of [req.timer, req.quiet]) {
      if (timer === null) continue;
      try {
        timers.clearTimeout(timer);
      } catch {
        // Nothing to clear.
      }
    }
    // A window still being made keeps the one window place until `showWindow` has closed it again, so a second window never
    // opens beside one that is about to appear and close.
    if (windowHolder === req.id && !making.has(req.id)) {
      windowHolder = null;
      if (req.windowId !== null && windows !== null) windows.close(req.windowId).catch(() => {});
    }
    if (unanswered && req.mediation !== "conditional") countEnded(req.sender.tabId);
    mark(req.sender.tabId);
    stopListening();
    return true;
  };

  /** @param {Request} req @param {string} name @param {boolean} unanswered @returns {Promise<boolean>} */
  const endWithError = async (req, name, unanswered) => {
    if (!end(req, unanswered)) return false;
    return pushError(req.sender, req.bridgeId, name);
  };

  /**
   * Ends a request whose bridge has gone silent (its frame went away without a navigation the browser reports, and the
   * bridge's abort was lost): nothing can be delivered there, and the window closes. Measured on the monotonic clock. A check
   * that comes more than a ping late (the machine slept) waits once more for the next ping before it ends anything.
   * @param {Request} req @param {boolean} [grace] this is the one extra wait after a late check
   */
  const watchPings = (req, grace = false) => {
    const ms = grace ? PING_MS + 5_000 : Math.max(1, req.lastPing + PASSKEY_SILENT_MS - monotonic());
    const due = monotonic() + ms;
    const check = () => {
      if (requests.get(req.id) !== req) return;
      const at = monotonic();
      if (at - req.lastPing < PASSKEY_SILENT_MS) watchPings(req);
      else if (!grace && at - due > PING_MS) watchPings(req, true);
      else end(req, false);
    };
    try {
      req.quiet = timers.setTimeout(check, ms);
      /** @type {any} */ (req.quiet)?.unref?.();
    } catch {
      // Without a timer the request still ends by its deadline, its abort or the check before an answer.
      req.quiet = null;
    }
  };

  /** A modal request reached its deadline. @param {Request} req */
  const expire = (req) => {
    // An upload that has started holds the deadline: it waits for the outcome (`holdDeadline`).
    if (requests.get(req.id) !== req || req.deadline === null || req.held) return;
    void endWithError(req, "NotAllowedError", true);
  };

  /** The request by id, after its deadline was checked by the clock (a timer may come late). @param {unknown} id */
  const live = (id) => {
    if (typeof id !== "string" || !REF.test(id)) return null;
    const req = requests.get(id);
    if (req === undefined) return null;
    if (req.deadline !== null && !req.held && now() >= req.deadline) {
      expire(req);
      return null;
    }
    return req;
  };

  /**
   * The request when `session` (a page's port) may act on it: the first session that names it owns it. When the request
   * has Ferret's window and the caller names the browser window it is in (`windowId`), that must be the request's window.
   * @param {unknown} id @param {unknown} session @param {unknown} [windowId]
   */
  const owned = (id, session, windowId) => {
    const req = live(id);
    if (req === null || typeof session !== "string" || session === "") return null;
    if (windowId !== undefined && req.windowId !== null && windowId !== req.windowId) return null;
    if (req.session === null) req.session = session;
    return req.session === session ? req : null;
  };

  /** @param {Request} req @returns {RequestView} */
  const viewOf = (req) => {
    const o = req.options;
    const create = req.kind === "create";
    const uv = create ? o.authenticator_selection?.user_verification : o.user_verification;
    const listed = create ? o.exclude_credentials : o.allow_credentials;
    return {
      request_id: req.id,
      kind: req.kind,
      mediation: req.mediation,
      origin: req.origin,
      rp_id: (create ? o.rp?.id : o.rp_id) ?? null,
      rp_name: create ? (o.rp?.name ?? null) : null,
      user_name: create ? (o.user?.name ?? null) : null,
      user_display_name: create ? (o.user?.display_name ?? null) : null,
      user_verification: UV.includes(uv) ? uv : "preferred",
      credentials: Array.isArray(listed) ? listed.length : 0,
      prf: o.extensions?.prf !== undefined,
      expires_in: req.deadline === null ? null : Math.max(0, Math.min(PASSKEY_TIMEOUT_MS.max, req.deadline - now())),
      foreign: req.top !== null && foreign.get(req.sender.tabId) === req.top,
      incognito: req.sender.incognito,
    };
  };

  /** Whether the setting is on and the permission for https pages is there (both read now). */
  const enabled = async () => {
    if (storageLocal === null || permissions === null) return false;
    try {
      const items = await storageLocal.get(PASSKEY_SETTING_KEY);
      if (items?.[PASSKEY_SETTING_KEY] !== true) return false;
      return (await permissions.contains({ origins: [...PASSKEY_ORIGINS] })) === true;
    } catch {
      return false;
    }
  };

  /** The host of the signed-in server when its session is live, else null. @returns {Promise<string | null>} */
  const liveServerHost = async () => {
    if (servers === null) return null;
    try {
      const current = await servers.current();
      if (current === null || current.live !== true) return null;
      const origin = httpsOrigin(current.origin);
      return origin === null ? null : hostOf(origin);
    } catch {
      return null;
    }
  };

  /**
   * The frame chain of a sender, from the browser: the calling frame (with its document) up to the top, every frame with
   * the caller's origin and an `https` address. The top document's id when it holds, null otherwise.
   * @param {Sender} s @returns {Promise<{ top: string | null } | null>}
   */
  const chainOf = async (s) => {
    if (frames === null || s.origin === null) return null;
    /** @type {unknown} */
    let listed;
    try {
      listed = await frames.getAllFrames({ tabId: s.tabId });
    } catch {
      return null;
    }
    if (!Array.isArray(listed) || listed.length === 0 || listed.length > MAX_FRAMES) return null;
    /** @type {Map<number, any>} */
    const byId = new Map();
    for (const f of listed) {
      if (typeof f !== "object" || f === null || !isIndex(f.frameId) || !Number.isSafeInteger(f.parentFrameId)) continue;
      // A frame the browser lists twice is not one anyone can trust.
      if (byId.has(f.frameId)) return null;
      byId.set(f.frameId, f);
    }
    let frame = byId.get(s.frameId);
    if (frame === undefined) return null;
    // The browser names each frame's document (Firefox gives `documentId` here); a frame without one is not trusted.
    if (frame.documentId !== s.documentId) return null;
    for (let steps = 0; ; steps += 1) {
      if (steps > byId.size || frame.errorOccurred === true) return null;
      if (httpsOrigin(frame.url) !== s.origin) return null;
      if (frame.frameId === 0) {
        if (frame.parentFrameId !== -1) return null;
        return { top: typeof frame.documentId === "string" && frame.documentId !== "" ? frame.documentId : null };
      }
      frame = byId.get(frame.parentFrameId);
      if (frame === undefined) return null;
    }
  };

  /**
   * Whether Ferret may take this request; the reason it goes to the browser otherwise.
   * @param {Sender} s @param {any} body @returns {Promise<{ refuse: string } | { top: string | null }>}
   */
  const checkPage = async (s, body) => {
    if (s.origin === null) return { refuse: "origin" };
    const host = hostOf(s.origin);
    if (host.endsWith(".")) return { refuse: "trailing_dot" };
    if (release && isLoopbackHost(host)) return { refuse: "loopback" };
    if (body.policy === false) return { refuse: "policy" };
    const automatic = automaticHandover(body.kind, body[body.kind], body.mediation);
    if (automatic !== null) return { refuse: automatic };
    if (!(await enabled())) return { refuse: "off" };
    const serverHost = await liveServerHost();
    if (serverHost === null) return { refuse: "signed_out" };
    if (host === serverHost) return { refuse: "ferret_server" };
    if (never !== null) {
      const options = body[body.kind];
      const asked = body.kind === "create" ? options.rp?.id : options.rp_id;
      const named = typeof asked === "string" && asked !== "" ? asked.toLowerCase() : host;
      try {
        if ((await never.has(named)) || (named !== host && (await never.has(host)))) return { refuse: "never" };
      } catch {
        return { refuse: "never" };
      }
    }
    const chain = await chainOf(s);
    if (chain === null) return { refuse: "frames" };
    return chain;
  };

  /** Takes the "use the browser once" of a sender, if one is there for this kind. @param {Sender} s @param {string} kind */
  const takePass = (s, kind) => {
    if (s.origin === null || !passes.take({ tabId: s.tabId, frameId: s.frameId, documentId: s.documentId, origin: s.origin, kind })) return false;
    mark(s.tabId);
    return true;
  };

  /** Whether the page aborted this request before it arrived (then it is forgotten). @param {number} tabId @param {string} key */
  const takeAbort = (tabId, key) => {
    const forTab = aborts.get(tabId);
    const until = forTab?.get(key);
    if (forTab === undefined || until === undefined) return false;
    forTab.delete(key);
    return until > now();
  };

  /** Opens the window for a request, if it can. @param {Request} req */
  const showWindow = async (req) => {
    if (windows === null || windowHolder !== null) return false;
    windowHolder = req.id;
    req.state = "window";
    mark(req.sender.tabId);
    /** @type {number | null} */
    let windowId = null;
    making.add(req.id);
    try {
      const made = await windows.open(req.id);
      windowId = isIndex(made) ? made : null;
    } catch {
      windowId = null;
    } finally {
      making.delete(req.id);
    }
    if (requests.get(req.id) !== req) {
      // It ended while the window opened.
      if (windowId !== null) windows.close(windowId).catch(() => {});
      if (windowHolder === req.id) windowHolder = null;
      return false;
    }
    if (windowId === null) {
      windowHolder = null;
      req.state = req.mediation === "conditional" ? "conditional" : "waiting";
      mark(req.sender.tabId);
      return false;
    }
    req.windowId = windowId;
    return true;
  };

  /** Opens the window for the tab's modal request that waits without one (the popup's card). @param {unknown} tabId */
  const showWaiting = async (tabId) => {
    if (!isIndex(tabId)) return false;
    for (const req of [...requests.values()]) {
      if (req.sender.tabId === tabId && req.state === "waiting" && live(req.id) !== null) return showWindow(req);
    }
    return false;
  };

  /**
   * Whether the tab a popup op names is the popup's own: the tab of its address (`?tab=N`, a popped-out popup) when it has one
   * (`popup_tab`, from the handler), else the active tab of the last focused window (the toolbar panel). Fails closed.
   * @param {any} args @returns {Promise<boolean>}
   */
  const popupTabOk = async (args) => {
    const tabId = args?.tab_id;
    if (!isIndex(tabId)) return false;
    if (isIndex(args?.popup_tab)) return tabId === args.popup_tab;
    if (typeof tabs.query !== "function") return false;
    try {
      const [active] = await tabs.query({ active: true, lastFocusedWindow: true });
      return active?.id === tabId;
    } catch {
      return false;
    }
  };

  /**
   * A page's request. The answer goes as a push to the frame and document that asked: at once a hand-over or an error, or
   * later from the window. What it returns is for the tests.
   * @param {BridgeSender} sender @param {any} body
   * @returns {Promise<{ request_id: string } | { handover: true, reason: string } | { error: string }>}
   */
  const open = async (sender, body) => {
    const s = senderOf(sender);
    if (s === null) return { error: "no_document" };
    const bridgeId = body?.request_id;
    if (typeof bridgeId !== "string") return { error: "invalid" };
    /** @param {string} reason */
    const handOver = async (reason) => {
      await pushHandover(s, bridgeId, false);
      return /** @type {{ handover: true, reason: string }} */ ({ handover: true, reason });
    };
    const kind = body.kind;
    // (The handler lets nothing else through; anything unexpected is the browser's.)
    if ((kind !== "create" && kind !== "get") || typeof body[kind] !== "object" || body[kind] === null) return handOver("invalid");
    const key = keyOf(s, bridgeId);
    if (byBridge.has(key)) return { error: "duplicate" };
    await passes.ready();
    // A conditional get (a site's autofill UI, started again after a failed modal call) never takes the pass: it is meant for the
    // modal call the person makes by clicking the page's button.
    if (body.mediation !== "conditional" && takePass(s, kind)) return handOver("pass_once");
    const checked = await checkPage(s, body);
    if ("refuse" in checked) return handOver(checked.refuse);
    if (malformedOptions(kind, body[kind])) {
      await pushError(s, bridgeId, "TypeError");
      return { error: "TypeError" };
    }
    // What the browser refuses before any UI is refused here the same way, before any window: never more than the browser.
    if (refusedRpId(kind, body[kind], hostOf(/** @type {string} */ (s.origin)))) {
      await pushError(s, bridgeId, "SecurityError");
      return { error: "SecurityError" };
    }
    if (unsupportedOptions(kind, body[kind])) {
      await pushError(s, bridgeId, "NotSupportedError");
      return { error: "NotSupportedError" };
    }
    // Without the chooser window in this build, the browser answers (as before the window existed).
    if (windows === null) return handOver("no_window");

    // From here on nothing awaits until the request is in place.
    if (takeAbort(s.tabId, key) || byBridge.has(key)) return { error: "AbortError" };
    if (requests.size >= MAX_PENDING) return handOver("busy");
    const conditional = body.mediation === "conditional";
    const tabId = s.tabId;
    if (!conditional) {
      for (const r of requests.values()) {
        if (r.sender.tabId === tabId && r.mediation !== "conditional") {
          // One modal request per tab: the one that waits stays, the new one ends.
          countEnded(tabId);
          await pushError(s, bridgeId, "AbortError");
          return { error: "AbortError" };
        }
      }
    }
    for (const r of [...requests.values()]) {
      if (r.sender.tabId !== tabId || r.mediation !== "conditional") continue;
      // A new conditional request replaces the older one; a modal one of the same document ends it.
      const same = r.sender.frameId === s.frameId && r.sender.documentId === s.documentId;
      if (conditional || same) void endWithError(r, "AbortError", false);
    }
    const deadline = conditional ? null : now() + modalTimeout(body[kind].timeout);
    /** @type {Request} */
    const req = {
      id: newId(),
      bridgeId,
      key,
      sender: s,
      origin: /** @type {string} */ (s.origin),
      kind,
      mediation: body.mediation,
      options: body[kind],
      top: checked.top,
      deadline,
      timer: null,
      state: conditional ? "conditional" : "waiting",
      windowId: null,
      session: null,
      held: false,
      lastPing: monotonic(),
      quiet: null,
    };
    requests.set(req.id, req);
    byBridge.set(key, req.id);
    startListening();
    if (deadline !== null) req.timer = later(() => expire(req), deadline - now());
    watchPings(req);
    if (conditional || body.activation !== true || inCalm(tabId) || windowHolder !== null) {
      // No window without user activation, during the calm period, or while another request has it: a mark and a card.
      mark(tabId);
      return { request_id: req.id };
    }
    await showWindow(req);
    return { request_id: req.id };
  };

  /** @param {Sender} s @param {unknown} bridgeId */
  const abort = (s, bridgeId) => {
    if (typeof bridgeId !== "string") return;
    const key = keyOf(s, bridgeId);
    const id = byBridge.get(key);
    const req = id === undefined ? undefined : requests.get(id);
    if (req !== undefined) {
      // The page has rejected its call itself (with its signal's reason); the window closes.
      void endWithError(req, "AbortError", true);
      return;
    }
    // The abort came first (the router does not keep the order of two messages): the request is dropped when it comes.
    const at = now();
    const forTab = aborts.get(s.tabId) ?? new Map();
    for (const [k, until] of forTab) if (until <= at) forTab.delete(k);
    forTab.set(key, at + ABORT_KEPT_MS);
    if (forTab.size > MAX_ABORTS_PER_TAB) forTab.delete(/** @type {string} */ (forTab.keys().next().value));
    aborts.delete(s.tabId);
    aborts.set(s.tabId, forTab);
    if (aborts.size > MAX_TABS_KEPT) aborts.delete(/** @type {number} */ (aborts.keys().next().value));
  };

  /** @param {Sender} s @param {unknown} ids */
  const ping = (s, ids) => {
    if (!Array.isArray(ids)) return;
    for (const bridgeId of ids) {
      if (typeof bridgeId !== "string") continue;
      const key = keyOf(s, bridgeId);
      const id = byBridge.get(key);
      const req = id === undefined ? null : live(id);
      if (req !== null) {
        req.lastPing = monotonic();
        continue;
      }
      // An abort that came first, or an error that waits for its delay (it must not come early).
      if (aborts.get(s.tabId)?.has(key) || ending.has(key)) continue;
      // Not a request of this sender that waits here (the event page was unloaded, or it ended): it fails closed.
      void push(s, "passkey_error", { request_id: bridgeId, name: "NotAllowedError" });
    }
  };

  /** @param {BridgeEvent} event */
  const onEvent = async ({ type, sender, body }) => {
    if (type === "passkey_request") {
      // The checks and the window's opening only: the user's choice comes later, as a push (the bridge said "taken" already).
      await open(sender, body).catch(async () => {
        // Something unexpected: the browser answers.
        const s = senderOf(sender);
        if (s !== null && typeof body?.request_id === "string") {
          const id = byBridge.get(keyOf(s, body.request_id));
          const req = id === undefined ? undefined : requests.get(id);
          if (req !== undefined) end(req, false);
          await pushHandover(s, body.request_id, false);
        }
      });
      return;
    }
    if (type === "passkey_foreign") {
      // Only the top document's report counts (a frame of another site must not mark the page).
      if (sender.frameId === 0 && typeof sender.documentId === "string") {
        foreign.delete(sender.tabId);
        foreign.set(sender.tabId, sender.documentId);
        if (foreign.size > MAX_TABS_KEPT) foreign.delete(/** @type {number} */ (foreign.keys().next().value));
      }
      return;
    }
    const s = senderOf(sender);
    if (s === null) return;
    if (type === "passkey_abort") abort(s, body?.request_id);
    else if (type === "passkey_ping") ping(s, body?.request_ids);
  };

  /**
   * The browser answers instead. With `once` (the person chose "the browser" or "never on this site" in the window) the page's
   * call that is open ends as the browser ends a call the person left, and the tab is brought to the front. With `pass` (the
   * default with `once`: "the browser") the next call of the same kind from the same document goes to the browser untouched,
   * once, within a minute, and the toolbar button is marked until it does. "Never on this site" has no pass: the site is on the
   * list now, so the next call goes to the browser by the list.
   * @param {Request} req @param {{ once: boolean, pass?: boolean }} how
   */
  const handoverReq = (req, how) => {
    // A conditional request goes to the browser at once, with no pass: the original's own list needs no click of the person.
    const once = req.mediation === "conditional" ? false : how.once;
    const pass = req.mediation === "conditional" ? false : (how.pass ?? how.once);
    if (!end(req, false)) return false;
    if (once === true) {
      const tabId = req.sender.tabId;
      if (pass === true) {
        const until = passes.grant({ tabId, frameId: req.sender.frameId, documentId: req.sender.documentId, origin: req.origin, kind: req.kind });
        mark(tabId);
        const old = passTimers.get(tabId);
        if (old !== undefined) {
          try {
            timers.clearTimeout(old);
          } catch {
            // Nothing to clear.
          }
        }
        // When the pass ends, the mark goes (a pass nobody used leaves nothing on the button).
        const timer = later(() => {
          passTimers.delete(tabId);
          mark(tabId);
        }, Math.max(0, until - now()) + 1);
        if (timer !== null) passTimers.set(tabId, timer);
      }
      try {
        void Promise.resolve(tabs.update?.(tabId, { active: true })).catch(() => {});
      } catch {
        // A tab that is gone needs no focus.
      }
    }
    void pushHandover(req.sender, req.bridgeId, once === true);
    return true;
  };

  /**
   * A conditional request whose window closed (the person cancelled there, or closed it): it waits again for the popup, as the
   * browser's own list stays when its dialog is dismissed. The window goes; the request is nobody's until the popup or another
   * window acts on it.
   * @param {Request} req @param {boolean} closeWindow
   */
  const giveBack = (req, closeWindow) => {
    if (requests.get(req.id) !== req) return false;
    if (windowHolder === req.id) windowHolder = null;
    if (closeWindow && req.windowId !== null && windows !== null) windows.close(req.windowId).catch(() => {});
    req.windowId = null;
    req.session = null;
    req.state = "conditional";
    mark(req.sender.tabId);
    return true;
  };

  /** The user cancelled (or closed the window, or had no match): NotAllowedError. A conditional request waits again. @param {Request} req */
  const cancelReq = (req) => {
    if (requests.get(req.id) !== req) return false;
    if (req.mediation === "conditional") return giveBack(req, true);
    void endWithError(req, "NotAllowedError", true);
    return true;
  };

  /** Ends a request with an error (a core code through pageErrorOf). @param {Request} req @param {string} name */
  const failReq = (req, name) => {
    if (requests.get(req.id) !== req) return false;
    const error = PAGE_ERRORS.includes(name) ? name : "NotAllowedError";
    void endWithError(req, error, error === "NotAllowedError");
    return true;
  };

  /**
   * Whether a request may still be answered by Ferret: the setting is still on and the permission still there, and the device
   * is still signed in with a live session at a server whose host is not the page's (the person may have turned the setting
   * off, taken the permission back, signed out or changed the server while it waited).
   * @param {Request} req
   */
  const stillAllowed = async (req) => {
    if (!(await enabled())) return false;
    const serverHost = await liveServerHost();
    return serverHost !== null && serverHost !== hostOf(req.origin);
  };

  /**
   * Ferret's answer (PASSKEY_RESPONSE on the wire). The frame chain is checked again first: an answer goes only to the
   * document that asked, while it still has the origin and the chain it had.
   * @param {Request} req @param {Record<string, unknown>} response @returns {Promise<boolean>}
   */
  const answerReq = async (req, response) => {
    if (requests.get(req.id) !== req) return false;
    const chain = await chainOf(req.sender);
    const allowed = chain !== null && (await stillAllowed(req));
    if (requests.get(req.id) !== req) return false;
    if (!allowed) {
      void endWithError(req, "NotAllowedError", false);
      return false;
    }
    end(req, false);
    if (await push(req.sender, "passkey_result", { request_id: req.bridgeId, response })) return true;
    // An answer that could not be sent (the document went, or it did not fit the schema) ends the call all the same.
    await push(req.sender, "passkey_error", { request_id: req.bridgeId, name: "NotAllowedError" });
    return false;
  };

  /** A new document in a frame of a tab (`webNavigation.onCommitted`). @param {{ tabId?: unknown, frameId?: unknown, documentId?: unknown }} details */
  const onNavigation = (details) => {
    if (!isIndex(details?.tabId) || !isIndex(details?.frameId)) return;
    for (const req of [...requests.values()]) {
      if (req.sender.tabId !== details.tabId) continue;
      if (details.documentId === req.sender.documentId) continue;
      if (details.frameId === 0 || details.frameId === req.sender.frameId) {
        // Its document is gone: nobody to answer.
        end(req, false);
        continue;
      }
      // Another frame of the tab has a new document: the chain of this request is looked at again.
      void chainOf(req.sender).then((chain) => {
        if (chain === null) end(req, false);
      });
    }
    if (details.frameId === 0) foreign.delete(details.tabId);
  };

  /**
   * A navigation within the same document (`pushState`, a fragment): the request stays, but its frame's origin must
   * still be the one it was made for.
   * @param {{ tabId?: unknown, frameId?: unknown, url?: unknown }} details
   */
  const onSameDocument = (details) => {
    if (!isIndex(details?.tabId) || !isIndex(details?.frameId)) return;
    for (const req of [...requests.values()]) {
      if (req.sender.tabId !== details.tabId || req.sender.frameId !== details.frameId) continue;
      if (httpsOrigin(details.url) !== req.origin) void endWithError(req, "NotAllowedError", false);
    }
  };

  /** @param {unknown} tabId */
  const onTabRemoved = (tabId) => {
    if (!isIndex(tabId)) return;
    for (const req of [...requests.values()]) if (req.sender.tabId === tabId) end(req, false);
    foreign.delete(tabId);
    calm.delete(tabId);
    passes.forgetTab(tabId);
    passTimers.delete(tabId);
  };

  /** The user closed Ferret's window. @param {unknown} windowId */
  const onWindowRemoved = (windowId) => {
    for (const req of [...requests.values()]) {
      if (req.windowId !== null && req.windowId === windowId) {
        req.windowId = null;
        if (req.mediation === "conditional") giveBack(req, false);
        else void endWithError(req, "NotAllowedError", true);
      }
    }
  };

  /** A page's port ended: the window that owned a request is gone. @param {string} session */
  const endSession = (session) => {
    for (const req of [...requests.values()]) {
      if (req.session !== session || req.state !== "window") continue;
      if (req.mediation === "conditional") giveBack(req, true);
      else void endWithError(req, "NotAllowedError", true);
    }
  };

  /**
   * A lock. The marks of verification go at every lock; with `wasOpen` (the vault was open until now) every request that
   * waits ends with NotAllowedError, the conditional ones too. A lock of a vault that was locked already (a wrong PIN in
   * the window) ends nothing: the request came while it was locked.
   * @param {boolean} [wasOpen]
   */
  const onLock = (wasOpen = true) => {
    verified.clear();
    if (wasOpen) endAll();
  };

  /**
   * Ends every request that waits with NotAllowedError, the conditional ones too: a lock of the open vault, a sign-out, a
   * sign-in or "forget this server" (the server a request was checked against may be another one now).
   */
  const endAll = () => {
    verified.clear();
    const marked = [...passTimers.keys()];
    passes.clear();
    for (const req of [...requests.values()]) void endWithError(req, "NotAllowedError", false);
    for (const tabId of marked) mark(tabId);
  };

  /** The view of the tab's request of the given kind of waiting. @param {unknown} tabId @param {(r: Request) => boolean} which */
  const viewIn = (tabId, which) => {
    if (!isIndex(tabId)) return null;
    for (const req of [...requests.values()]) {
      if (req.sender.tabId === tabId && which(req) && live(req.id) !== null) return viewOf(req);
    }
    return null;
  };

  /**
   * The caller the core is given for a request: built here only, from the browser's origin of the frame and its frame
   * chain (every frame up to the top has that origin, so the top's origin is the same). Never from the page.
   * @param {Request} req @returns {Readonly<{ origin: string, top_origin_is_same: boolean }>}
   */
  const callerFor = (req) => Object.freeze({ origin: req.origin, top_origin_is_same: true });

  /** @param {Request} req @returns {string | null} the RP ID the page asked for, unchecked */
  const askedRpId = (req) => {
    const asked = req.kind === "create" ? req.options.rp?.id : req.options.rp_id;
    return typeof asked === "string" ? asked : null;
  };

  /** @param {any} args */
  const windowArgs = (args) => ({ id: args?.request_id, session: args?.session, windowId: args?.window_id });
  /** The request a window's op names, for that window's session (and browser window, when the handler knows it). @param {any} args */
  const ownedBy = (args) => {
    const { id, session, windowId } = windowArgs(args);
    return owned(id, session, isIndex(windowId) ? windowId : undefined);
  };

  return {
    push,
    open,
    /** What the window of `session` may see of a request, or null (ended, unknown, another window's). @param {string} id @param {string} session */
    forUi: (id, session) => {
      const req = owned(id, session);
      return req === null ? null : viewOf(req);
    },
    /**
     * What the page asked, for the session that owns the request: the kind and the page's options as the bridge carried them
     * (PASSKEY_CREATE_OPTIONS or PASSKEY_GET_OPTIONS), or null. Read only: the options are the request's own.
     * @param {string} id @param {string} session
     * @returns {{ kind: "create" | "get", options: any } | null}
     */
    requestOf: (id, session) => {
      const req = owned(id, session);
      return req === null ? null : Object.freeze({ kind: req.kind, options: req.options });
    },
    /** The caller for the core, for the session that owns the request (see callerFor). @param {string} id @param {string} session */
    callerOf: (id, session) => {
      const req = owned(id, session);
      return req === null ? null : callerFor(req);
    },
    // Every way to end a request names the session (the page's port) that owns it: a page can act only on a request it
    // came to own (the first session that named it), never on any id it can name.
    /** Ferret's answer. @param {string} id @param {string} session @param {Record<string, unknown>} response */
    answer: async (id, session, response) => {
      const req = owned(id, session);
      return req === null ? false : answerReq(req, response);
    },
    /** The browser answers instead. @param {string} id @param {string} session @param {{ once: boolean }} how */
    handover: (id, session, how) => {
      const req = owned(id, session);
      return req === null ? false : handoverReq(req, how);
    },
    /** @param {string} id @param {string} session */
    cancel: (id, session) => {
      const req = owned(id, session);
      return req === null ? false : cancelReq(req);
    },
    /** @param {string} id @param {string} session @param {string} name */
    fail: (id, session, name) => {
      const req = owned(id, session);
      return req === null ? false : failReq(req, name);
    },
    /**
     * The popup's card opens the window for the request that waits in the tab the popup shows (the click is the user's
     * activation). It takes the tab, not an id: the popup never needs one for it.
     * @param {number} tabId
     */
    show: (tabId) => showWaiting(tabId),
    /**
     * What the window's create op needs of a create request it owns (the same gate as the window's ops: `{ request_id, session,
     * window_id? }`): the page's options, the frame's address, the caller (built here) and the RP ID the page asked for. Null for
     * a request that has ended, is another session's, or is a get.
     * @param {any} args
     */
    createOf: (args) => {
      const req = ownedBy(args);
      if (req === null || req.kind !== "create") return null;
      return Object.freeze({ id: req.id, session: req.session, options: req.options, url: req.sender.url, caller: callerFor(req), askedRpId: askedRpId(req) });
    },
    /**
     * Holds the deadline of a request while an upload for it runs: it does not end by its deadline until the returned function
     * is called (then a deadline that has passed ends it). Null for a request the session does not own.
     * @param {string} id @param {string} session @returns {(() => void) | null}
     */
    holdDeadline: (id, session) => {
      const req = owned(id, session);
      if (req === null) return null;
      req.held = true;
      return () => {
        if (!req.held) return;
        req.held = false;
        if (requests.get(req.id) === req && req.deadline !== null && now() >= req.deadline) expire(req);
      };
    },
    /** Whether the request still waits and the session owns it. @param {string} id @param {string} session */
    waiting: (id, session) => owned(id, session) !== null,
    /**
     * Checks again, before anything is written for it, that the request may still be answered: the frame chain is whole and the
     * device is still signed in at a server that is not the page's. A request that may not ends with NotAllowedError.
     * @param {string} id @param {string} session @returns {Promise<boolean>}
     */
    recheck: async (id, session) => {
      const req = owned(id, session);
      if (req === null) return false;
      const chain = await chainOf(req.sender);
      const allowed = chain !== null && (await stillAllowed(req));
      if (requests.get(req.id) !== req) return false;
      if (!allowed) {
        void endWithError(req, "NotAllowedError", false);
        return false;
      }
      return true;
    },
    /** The user was verified for this request (one time, gone with the request and at every lock). @param {string} id @param {string} session */
    markVerified: (id, session) => {
      const req = owned(id, session);
      if (req === null) return false;
      verified.set(req.id, { mono: monotonic(), wall: now() });
      return true;
    },
    /** Takes the mark of verification of a request, for the session that owns it: true once. @param {string} id @param {string} session */
    takeVerified: (id, session) => {
      const req = owned(id, session);
      if (req === null) return false;
      const made = verified.get(req.id);
      if (made === undefined) return false;
      verified.delete(req.id);
      // Older than MARK_MS on either clock, or a clock that went back: no mark (the person verifies again).
      const mono = monotonic() - made.mono;
      const wall = now() - made.wall;
      return mono >= 0 && wall >= 0 && mono < MARK_MS && wall < MARK_MS;
    },
    onEvent,
    onNavigation,
    onSameDocument,
    onTabRemoved,
    onWindowRemoved,
    endSession,
    onLock,
    endAll,
    /** The tab's conditional request (the popup's passkey part), or null. @param {number} tabId */
    conditionalFor: (tabId) => viewIn(tabId, (r) => r.mediation === "conditional"),
    /** The tab's modal request that waits without a window (the popup's card), or null. @param {number} tabId */
    waitingFor: (tabId) => viewIn(tabId, (r) => r.state === "waiting"),
    /**
     * What waits for the person's next click on the page after "use the browser" (the one-time pass): the kind of call and when
     * the pass ends, or null. For the popup's line "click the button on the page again".
     * @param {number} tabId
     */
    passPendingFor: (tabId) => (isIndex(tabId) ? passes.pendingIn(tabId) : null),
    /**
     * The tab's conditional request for Ferret's popup: the request and the popup's session name, while it waits for the popup (no
     * window has it), or null. With `expect` (the id and origin the popup listed), only that request: a new request in the tab is
     * not it. The id is good for nothing outside the popup's ops (the window's ops take it only from the window's own address).
     * @param {unknown} tabId @param {{ request_id: unknown, origin: unknown } | null} [expect]
     * @returns {{ request_id: string, session: string, origin: string } | null}
     */
    tabRef: (tabId, expect = null) => {
      if (!isIndex(tabId)) return null;
      for (const req of [...requests.values()]) {
        if (req.sender.tabId !== tabId || req.mediation !== "conditional" || req.state !== "conditional") continue;
        // The request the popup listed, and no other: a new request in the tab (another site, after a navigation) is not it.
        if (expect !== null && (expect.request_id !== req.id || expect.origin !== req.origin)) return null;
        return owned(req.id, POPUP_SESSION) === null ? null : Object.freeze({ request_id: req.id, session: POPUP_SESSION, origin: req.origin });
      }
      return null;
    },
    popupTabOk,
    /**
     * The page of a tab when Ferret would answer it and no request waits (the popup then lists the passkeys for information only,
     * with no button): its top frame's `https` origin, under the same rules as a request (the setting, a live server that is not the
     * page's host, not localhost in a release, not on the never list). The caller is built here, as for a request. Null otherwise.
     * @param {unknown} tabId @returns {Promise<{ caller: Readonly<{ origin: string, top_origin_is_same: boolean }> } | null>}
     */
    tabSite: async (tabId) => {
      if (!isIndex(tabId) || frames === null) return null;
      /** @type {unknown} */
      let listed;
      try {
        listed = await frames.getAllFrames({ tabId });
      } catch {
        return null;
      }
      const top = Array.isArray(listed) ? listed.find((f) => f?.frameId === 0 && f?.parentFrameId === -1) : undefined;
      const origin = httpsOrigin(top?.url);
      if (origin === null) return null;
      const host = hostOf(origin);
      if (host.endsWith(".") || (release && isLoopbackHost(host))) return null;
      if (!(await enabled())) return null;
      const serverHost = await liveServerHost();
      if (serverHost === null || serverHost === host) return null;
      try {
        if (never !== null && (await never.has(host))) return null;
      } catch {
        return null;
      }
      return Object.freeze({ caller: Object.freeze({ origin, top_origin_is_same: true }) });
    },
    /** How many requests wait. */
    size: () => requests.size,
    /**
     * Whether the tab's top document (`documentId`, from `webNavigation.getFrame` of frame 0 when the UI asks) found create or
     * get changed by something else. Text only. A new top document has no mark: the id differs.
     * @param {number} tabId @param {string} documentId
     */
    foreignIn: (tabId, documentId) => foreign.get(tabId) === documentId,
    ops: Object.freeze({
      [PASSKEY_EVENT_OP]: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {BridgeEvent} */ args) => {
          await onEvent(args);
        },
      },
      // What Ferret's popup shows for the tab it is about (works locked, and it is not a use of the vault): a modal request that waits
      // without a window (the card: the calling frame's origin from the browser and the kind), whether a conditional request waits for
      // the popup's list, a one-time pass of "use the browser" that waits for the person's next click on the page, and the foreign
      // mark (text only).
      passkey_tab: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const tabId = args?.tab_id;
          if (!isIndex(tabId)) return { ok: false, reason: "invalid_input" };
          if (!(await popupTabOk(args))) return { ok: false, reason: "gone" };
          const waiting = viewIn(tabId, (r) => r.state === "waiting");
          const conditional = viewIn(tabId, (r) => r.mediation === "conditional" && r.state === "conditional");
          // A stopped event page reads its passes back first.
          await passes.ready();
          const pass = passes.pendingIn(tabId);
          return {
            ok: true,
            waiting: waiting === null ? null : { origin: waiting.origin, kind: waiting.kind },
            conditional: conditional !== null,
            request: conditional === null ? null : { request_id: conditional.request_id, origin: conditional.origin },
            again: pass === null ? null : pass.kind,
            foreign: (waiting ?? conditional)?.foreign === true,
          };
        },
      },
      // The popup's click opens Ferret's window: for the tab's modal request that waits (the card; the click is the activation the page
      // did not have), or for its conditional request (Windows Hello, which only the window can ask for).
      passkey_tab_open: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const tabId = args?.tab_id;
          if (!isIndex(tabId)) return { ok: false, reason: "invalid_input" };
          if (!(await popupTabOk(args))) return { ok: false, reason: "gone" };
          if (windowHolder !== null) return { ok: false, reason: "busy" };
          if (args?.which === "waiting") return (await showWaiting(tabId)) ? { ok: true } : { ok: false, reason: "gone" };
          for (const req of [...requests.values()]) {
            if (req.sender.tabId !== tabId || live(req.id) === null) continue;
            if (args?.which === "conditional" && req.mediation === "conditional" && req.state === "conditional") {
              if (req.session !== null && req.session !== POPUP_SESSION) return { ok: false, reason: "busy" };
              req.session = null;
              return (await showWindow(req)) ? { ok: true } : { ok: false, reason: "busy" };
            }
          }
          return { ok: false, reason: "gone" };
        },
      },
      passkey_pending: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const req = ownedBy(args);
          return req === null ? { ok: false, reason: "gone" } : { ok: true, request: viewOf(req) };
        },
      },
      passkey_cancel: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const req = ownedBy(args);
          return req !== null && cancelReq(req) ? { ok: true } : { ok: false, reason: "gone" };
        },
      },
      passkey_browser: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const req = ownedBy(args);
          return req !== null && handoverReq(req, { once: true }) ? { ok: true } : { ok: false, reason: "gone" };
        },
      },
      // "Never on this site", from the window: the RP ID the core checked (never the page's unchecked one) goes on the never list, in
      // memory only for a private window, and the page's call goes to the browser. It needs the open vault, like `passkey_site`
      // (refused `vault_locked` otherwise), because only then is there an RP ID the core has checked.
      passkey_never: {
        vault: true,
        worker: /** @type {const} */ ("vault"),
        run: async (/** @type {{ vault: any }} */ client, /** @type {any} */ args) => {
          const req = ownedBy(args);
          if (req === null) return { ok: false, reason: "gone" };
          if (never === null || typeof never.add !== "function") return { ok: false, reason: "not_available" };
          /** @type {any} */
          let site;
          try {
            site = await client.vault.passkey_site(callerFor(req), askedRpId(req));
          } catch (error) {
            const code = /** @type {{ code?: unknown }} */ (error)?.code;
            if (typeof code === "string" && VAULT_GONE.includes(code)) throw error;
            const name = pageErrorOf(code);
            failReq(req, name);
            return { ok: false, reason: SITE_REASONS[name] };
          }
          if (requests.get(req.id) !== req) return { ok: false, reason: "gone" };
          try {
            await never.add(site.rp_id, { incognito: req.sender.incognito });
          } catch {
            return { ok: false, reason: "internal_error" };
          }
          // The site is on the list now, so the page's next call goes to the browser at once, by the list; this one ends like the
          // browser's own ends when the window closed (no pass is needed).
          return handoverReq(req, { once: true, pass: false }) ? { ok: true } : { ok: false, reason: "gone" };
        },
      },
      passkey_site: {
        vault: true,
        worker: /** @type {const} */ ("vault"),
        run: async (/** @type {{ vault: any }} */ client, /** @type {any} */ args) => {
          const req = ownedBy(args);
          if (req === null) return { ok: false, reason: "gone" };
          /** @type {any} */
          let site;
          try {
            site = await client.vault.passkey_site(callerFor(req), askedRpId(req));
          } catch (error) {
            const code = /** @type {{ code?: unknown }} */ (error)?.code;
            // The vault or its worker went: the core host handles that (the request waits for the unlock in the window).
            if (typeof code === "string" && VAULT_GONE.includes(code)) throw error;
            // Anything else the core refuses ends the call as the browser would end it: an RP ID the origin may not use
            // (SecurityError), options it cannot take (TypeError), a refused caller (NotAllowedError).
            const name = pageErrorOf(code);
            failReq(req, name);
            return { ok: false, reason: SITE_REASONS[name] };
          }
          if (requests.get(req.id) !== req) return { ok: false, reason: "gone" };
          return {
            ok: true,
            site: { origin: site.origin, host_unicode: site.host_unicode, rp_id: site.rp_id, rp_id_unicode: site.rp_id_unicode },
          };
        },
      },
    }),
  };
}
