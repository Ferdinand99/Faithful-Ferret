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
//   - the setting is on and the permission for https pages is there, checked at every request (a tab that was open when
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
//   - a conditional request has no deadline and only marks the toolbar button (its list is the popup's); one per tab;
//   - a modal request has a deadline, the page's `timeout` clamped to PASSKEY_TIMEOUT_MS;
//   - at most one Ferret window: a modal request opens it only when the page had user activation, no window is open and
//     the tab is not in its calm period; otherwise the request waits with a mark on the button and a card in the popup,
//     whose click opens the window;
//   - the calm period: PASSKEY_QUIET.cancels modal requests of a tab that ended without an answer within windowMs give the
//     tab quietMs in which a new request only waits with the mark (it is kept, not refused);
//   - it ends on an answer, a hand-over, the user's cancel (or closing the window), the page's abort, its deadline, a new
//     document in its frame or above it, the tab closing, and a lock of the open vault. A same-document navigation
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
import { PASSKEY_ORIGINS, PASSKEY_SETTING_KEY } from "./passkeyRegistry.mjs";

/** The core operation the router hands a message of the bridge to. */
export const PASSKEY_EVENT_OP = "passkey_event";
/** The core operations of Ferret's chooser window (the UI types of the same names). */
export const PASSKEY_WINDOW_OPS = Object.freeze(["passkey_pending", "passkey_site", "passkey_cancel", "passkey_browser"]);
/** The deadline of a modal request: the page's `timeout`, clamped; the default when the page gave none. Conditional ones have none. */
export const PASSKEY_TIMEOUT_MS = Object.freeze({ min: 30_000, max: 600_000, default: 300_000 });
/** A click in Ferret's window counts only this long after the window got the focus or its content last changed. */
export const PASSKEY_GUARD_MS = 400;
/** After "use the browser" with `once`, the next call of the same kind from the same document goes through within this. */
export const PASSKEY_PASS_ONCE_MS = 60_000;
/** The calm period: this many modal requests of a tab ended without an answer within `windowMs` give `quietMs` of marks only. */
export const PASSKEY_QUIET = Object.freeze({ cancels: 3, windowMs: 60_000, quietMs: 300_000 });
/** The delay of every NotAllowedError (cancel, no match, deadline): `min` plus a random part below `spread`. */
export const PASSKEY_ERROR_DELAY_MS = Object.freeze({ min: 120, spread: 200 });

/** How long an abort that came before its request is remembered. */
const ABORT_KEPT_MS = 30_000;
const MAX_ABORTS = 256;
/** The most requests that wait at once, over all tabs (one modal and one conditional per tab in practice). */
const MAX_PENDING = 256;
const MAX_TABS_KEPT = 256;
const MAX_PASSES = 64;
/** The most frames of a tab that are looked at; a tab with more is left to the browser. */
const MAX_FRAMES = 1024;
const MAX_URL = 8192;
const REF = /^[0-9a-f]{32}$/;
const UV = Object.freeze(["required", "preferred", "discouraged"]);
const PAGE_ERRORS = Object.freeze(["NotAllowedError", "SecurityError", "TypeError", "InvalidStateError", "AbortError"]);
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
 *   windowId: number | null, session: string | null,
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
 * TypeError, a credential the page excluded an InvalidStateError; everything else (a refused caller, no match, a failed
 * verification) is the one NotAllowedError, as the browser gives it.
 * @param {unknown} code @returns {"NotAllowedError" | "SecurityError" | "TypeError" | "InvalidStateError"}
 */
export function pageErrorOf(code) {
  if (code === "malformed_rp_id") return "SecurityError";
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
 *   tabs: { sendMessage(tabId: number, message: unknown, options: { frameId: number, documentId: string }): Promise<unknown> },
 *   frames?: Frames | null,
 *   windows?: Windows | null,
 *   badge?: { passkey(tabId: number, on: boolean): void } | null,
 *   servers?: Servers | null,
 *   storageLocal?: { get(key: string): Promise<Record<string, unknown>> } | null,
 *   permissions?: { contains(wanted: { origins: string[] }): Promise<boolean> } | null,
 *   never?: { has(host: string): Promise<boolean> } | null,
 *   listen?: { start(): void, stop(): void } | null,
 *   release?: boolean,
 *   now?: () => number,
 *   random?: (bytes: Uint8Array) => Uint8Array,
 *   timers?: Timers,
 * }} deps
 *   `frames`: webNavigation; `windows`: the chooser window, null in a build without it (every request then goes to the
 *   browser); `badge`: the toolbar button's passkey mark; `servers`: the signed-in server; `storageLocal` and `permissions`:
 *   the setting and the permission, read at every request; `never`: the "never on this site" list; `listen`: starts the
 *   navigation, tab and window listeners while a request waits and stops them when none does (so they never wake an event
 *   page); `release`: a release leaves localhost and the loopback addresses to the browser.
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
  listen = null,
  release = true,
  now = () => Date.now(),
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
  /** Aborts that came before their request, by sender and bridge id: until when they are kept. @type {Map<string, number>} */
  const aborts = new Map();
  /** "Use the browser" once: the next call of that kind from that document. @type {Array<{ tabId: number, frameId: number, documentId: string, origin: string, kind: string, until: number }>} */
  let passes = [];
  /** Per tab: the moments its modal requests ended without an answer, and the end of its calm period. @type {Map<number, { ended: number[], until: number }>} */
  const calm = new Map();
  /** The one-time marks that the user was verified for a request (UV), by request id. Gone with the request and at every lock. */
  const verified = new Set();
  /** The request whose window is open (or being opened). @type {string | null} */
  let windowHolder = null;
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
    return new Promise((resolve) => {
      later(() => void push(s, "passkey_error", { request_id: bridgeId, name }).then(resolve), errorDelay());
    });
  };

  /** The browser answers the page's call, with the page's own options. @param {Sender} s @param {string} bridgeId @param {boolean} once */
  const pushHandover = (s, bridgeId, once) => push(s, "passkey_handover", { request_id: bridgeId, once });

  /** The mark on the toolbar button: a request of the tab waits for the user outside a window. @param {number} tabId */
  const mark = (tabId) => {
    if (badge === null) return;
    let on = false;
    for (const r of requests.values()) if (r.sender.tabId === tabId && r.state !== "window") on = true;
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
    if (req.timer !== null) {
      try {
        timers.clearTimeout(req.timer);
      } catch {
        // Nothing to clear.
      }
    }
    if (windowHolder === req.id) {
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

  /** A modal request reached its deadline. @param {Request} req */
  const expire = (req) => {
    if (requests.get(req.id) !== req || req.deadline === null) return;
    void endWithError(req, "NotAllowedError", true);
  };

  /** The request by id, after its deadline was checked by the clock (a timer may come late). @param {unknown} id */
  const live = (id) => {
    if (typeof id !== "string" || !REF.test(id)) return null;
    const req = requests.get(id);
    if (req === undefined) return null;
    if (req.deadline !== null && now() >= req.deadline) {
      expire(req);
      return null;
    }
    return req;
  };

  /**
   * The request when `session` (a page's port) may act on it: the first session that names it owns it.
   * @param {unknown} id @param {unknown} session
   */
  const owned = (id, session) => {
    const req = live(id);
    if (req === null || typeof session !== "string" || session === "") return null;
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
    if (typeof frame.documentId === "string" && frame.documentId !== s.documentId) return null;
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
    const at = now();
    passes = passes.filter((p) => p.until > at && p.until - at <= PASSKEY_PASS_ONCE_MS);
    const i = passes.findIndex((p) => p.tabId === s.tabId && p.frameId === s.frameId && p.documentId === s.documentId && p.origin === s.origin && p.kind === kind);
    if (i < 0) return false;
    passes.splice(i, 1);
    return true;
  };

  /** Whether the page aborted this request before it arrived (then it is forgotten). @param {string} key */
  const takeAbort = (key) => {
    const until = aborts.get(key);
    if (until === undefined) return false;
    aborts.delete(key);
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
    try {
      const made = await windows.open(req.id);
      windowId = isIndex(made) ? made : null;
    } catch {
      windowId = null;
    }
    if (requests.get(req.id) !== req) {
      // It ended while the window opened.
      if (windowId !== null) windows.close(windowId).catch(() => {});
      if (windowHolder === req.id) windowHolder = null;
      return false;
    }
    if (windowId === null) {
      windowHolder = null;
      req.state = "waiting";
      mark(req.sender.tabId);
      return false;
    }
    req.windowId = windowId;
    return true;
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
    if (s.origin !== null && takePass(s, kind)) return handOver("pass_once");
    const checked = await checkPage(s, body);
    if ("refuse" in checked) return handOver(checked.refuse);
    if (malformedOptions(kind, body[kind])) {
      await pushError(s, bridgeId, "TypeError");
      return { error: "TypeError" };
    }
    // Without the chooser window in this build, the browser answers (as before the window existed).
    if (windows === null) return handOver("no_window");

    // From here on nothing awaits until the request is in place.
    if (takeAbort(key) || byBridge.has(key)) return { error: "AbortError" };
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
    };
    requests.set(req.id, req);
    byBridge.set(key, req.id);
    startListening();
    if (deadline !== null) req.timer = later(() => expire(req), deadline - now());
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
    for (const [k, until] of aborts) if (until <= at) aborts.delete(k);
    aborts.set(key, at + ABORT_KEPT_MS);
    if (aborts.size > MAX_ABORTS) aborts.delete(/** @type {string} */ (aborts.keys().next().value));
  };

  /** @param {Sender} s @param {unknown} ids */
  const ping = (s, ids) => {
    if (!Array.isArray(ids)) return;
    for (const bridgeId of ids) {
      if (typeof bridgeId !== "string") continue;
      const key = keyOf(s, bridgeId);
      const id = byBridge.get(key);
      if (id !== undefined && live(id) !== null) continue;
      if (aborts.has(key)) continue;
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

  /** @param {string} id @param {{ once: boolean }} how */
  const handover = (id, { once }) => {
    const req = live(id);
    if (req === null || !end(req, false)) return false;
    if (once === true) {
      passes.push({ tabId: req.sender.tabId, frameId: req.sender.frameId, documentId: req.sender.documentId, origin: req.origin, kind: req.kind, until: now() + PASSKEY_PASS_ONCE_MS });
      if (passes.length > MAX_PASSES) passes.shift();
    }
    void pushHandover(req.sender, req.bridgeId, once === true);
    return true;
  };

  /** The user cancelled (or closed the window, or had no match): NotAllowedError. @param {string} id */
  const cancel = (id) => {
    const req = live(id);
    if (req === null) return false;
    void endWithError(req, "NotAllowedError", true);
    return true;
  };

  /** Ends a request with an error (a core code through pageErrorOf). @param {string} id @param {string} name */
  const fail = (id, name) => {
    const req = live(id);
    if (req === null) return false;
    const error = PAGE_ERRORS.includes(name) ? name : "NotAllowedError";
    void endWithError(req, error, error === "NotAllowedError");
    return true;
  };

  /**
   * Ferret's answer (PASSKEY_RESPONSE on the wire). The frame chain is checked again first: an answer goes only to the
   * document that asked, while it still has the origin and the chain it had.
   * @param {string} id @param {Record<string, unknown>} response @returns {Promise<boolean>}
   */
  const answer = async (id, response) => {
    const req = live(id);
    if (req === null) return false;
    const chain = await chainOf(req.sender);
    if (requests.get(id) !== req) return false;
    if (chain === null) {
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
    passes = passes.filter((p) => p.tabId !== tabId);
  };

  /** The user closed Ferret's window. @param {unknown} windowId */
  const onWindowRemoved = (windowId) => {
    for (const req of [...requests.values()]) {
      if (req.windowId !== null && req.windowId === windowId) {
        req.windowId = null;
        void endWithError(req, "NotAllowedError", true);
      }
    }
  };

  /** A page's port ended: the window that owned a request is gone. @param {string} session */
  const endSession = (session) => {
    for (const req of [...requests.values()]) {
      if (req.session === session && req.state === "window") void endWithError(req, "NotAllowedError", true);
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
    if (!wasOpen) return;
    passes = [];
    for (const req of [...requests.values()]) void endWithError(req, "NotAllowedError", false);
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
  const windowArgs = (args) => ({ id: args?.request_id, session: args?.session });

  return {
    push,
    open,
    /** What the window of `session` may see of a request, or null (ended, unknown, another window's). @param {string} id @param {string} session */
    forUi: (id, session) => {
      const req = owned(id, session);
      return req === null ? null : viewOf(req);
    },
    /** The caller for the core, for the session that owns the request (see callerFor). @param {string} id @param {string} session */
    callerOf: (id, session) => {
      const req = owned(id, session);
      return req === null ? null : callerFor(req);
    },
    answer,
    handover,
    cancel,
    fail,
    /** The card in the popup opens the window for a request that waits (the click is the user's activation). @param {string} id */
    show: async (id) => {
      const req = live(id);
      if (req === null || req.state !== "waiting") return false;
      return showWindow(req);
    },
    /** The user was verified for this request (one time, gone with the request and at every lock). @param {string} id @param {string} session */
    markVerified: (id, session) => {
      const req = owned(id, session);
      if (req === null) return false;
      verified.add(req.id);
      return true;
    },
    /** Takes the mark of verification of a request: true once. @param {string} id */
    takeVerified: (id) => verified.delete(id),
    onEvent,
    onNavigation,
    onSameDocument,
    onTabRemoved,
    onWindowRemoved,
    endSession,
    onLock,
    /** The tab's conditional request (the popup's passkey part), or null. @param {number} tabId */
    conditionalFor: (tabId) => viewIn(tabId, (r) => r.mediation === "conditional"),
    /** The tab's modal request that waits without a window (the popup's card), or null. @param {number} tabId */
    waitingFor: (tabId) => viewIn(tabId, (r) => r.state === "waiting"),
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
      passkey_pending: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const { id, session } = windowArgs(args);
          const req = owned(id, session);
          return req === null ? { ok: false, reason: "gone" } : { ok: true, request: viewOf(req) };
        },
      },
      passkey_cancel: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const { id, session } = windowArgs(args);
          const req = owned(id, session);
          return req !== null && cancel(req.id) ? { ok: true } : { ok: false, reason: "gone" };
        },
      },
      passkey_browser: {
        vault: false,
        worker: /** @type {const} */ ("none"),
        run: async (/** @type {unknown} */ _client, /** @type {any} */ args) => {
          const { id, session } = windowArgs(args);
          const req = owned(id, session);
          return req !== null && handover(req.id, { once: false }) ? { ok: true } : { ok: false, reason: "gone" };
        },
      },
      passkey_site: {
        vault: true,
        worker: /** @type {const} */ ("vault"),
        run: async (/** @type {{ vault: any }} */ client, /** @type {any} */ args) => {
          const { id, session } = windowArgs(args);
          const req = owned(id, session);
          if (req === null) return { ok: false, reason: "gone" };
          /** @type {any} */
          let site;
          try {
            site = await client.vault.passkey_site(callerFor(req), askedRpId(req));
          } catch (error) {
            const code = /** @type {{ code?: unknown }} */ (error)?.code;
            // An RP ID the origin may not use, or a refused caller: the page learns it as the browser would tell it.
            if (code === "malformed_rp_id" || code === "not_allowed") {
              fail(req.id, pageErrorOf(code));
              return { ok: false, reason: code === "malformed_rp_id" ? "security_error" : "not_allowed" };
            }
            throw error;
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
