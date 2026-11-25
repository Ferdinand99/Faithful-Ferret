// The steps of the chooser window for passkey requests (the `passkeys` feature; design document § 9.4 and § 10.3.3), with no
// DOM: what the background says the window shows, the cleaning of what a website wrote, the order of the passkeys, the
// guard that keeps a click from counting too early, and the one place that names the messages of the window.
//
// The window is a top-level page of the extension (`pages/passkey.html?r=<request id>`), opened by the background for one
// request of a page. It shows what the core says about the site and what the vault has; it decides nothing. A choice goes to
// the background as the request's id and the choice (an item, or a name); the background signs, answers the page and closes the
// window. The window never claims "user present" or "user verified": the click is the background's evidence for the first,
// and a recent unlock or the verification step (U4-8) for the second.
//
// Everything a website chose (the name it calls itself, the user name, the display name) is text of the website: it is cleaned
// of control and direction characters, shortened, shown apart under a label that says whose it is, and isolated from the text
// around it. The identity of the site is the canonical origin and RP ID from the core, never a name the site chose.
//
// The messages, as the broker's contract names them (the background's handler of the window):
//
//   passkey_pending { request_id }  -> { ok, request }   what the page asked (works while the vault is locked)
//   passkey_site    { request_id }  -> { ok, site }      the site as the core checked it (needs the open vault)
//   passkey_cancel / passkey_browser { request_id }       the person gave up / the browser answers instead
//   passkey_never   { request_id }                        "Never on this site", then the browser (this window's own type)
//   passkey_candidates { request_id } -> { ok, candidates, recent, methods, online }   the passkeys of the vault for a get
//   passkey_choose  { request_id, kind, item_id | mode, name, folder_id }   the person's choice
//   passkey_verify  { request_id, method, pin | mp, sk | credential_id, prf_output }   the verification step (passkeyVerify.mjs)
//
// Each message is sent only when the build's UI table has it (passkey_create_options belongs to the create side of the
// background); without it the window shows no passkeys of Ferret and the browser as the way on, and a choice is refused as
// not_available.

import { UI_TYPES } from "../shared/protocol.mjs";
import { VERIFY_WAYS } from "./passkeyVerify.mjs";

/** How long a click is ignored after the window got the focus or its content changed (milliseconds; design § 10.3.3). */
export const GUARD_MS = 400;

/** How often the window asks whether the request is still there and the vault still open (milliseconds). */
export const POLL_MS = 2000;

/** The most characters of a text of a website that the window shows. */
export const SITE_TEXT_MAX = 128;

/** The reasons the window has a text for (`passkeys.error.<reason>`); any other reason is `unknown`. */
export const CHOOSER_ERRORS = Object.freeze([
  "request_gone",
  "security_error",
  "type_error",
  "site_refused",
  "vault_locked",
  "network",
  "not_found",
  "invalid_input",
  "not_verified",
  "verification_needed",
  "verification_unavailable",
  "busy",
  "already_exists",
  "excluded",
  "not_allowed",
  "worker_failed",
  "internal_error",
  "disconnected",
  "not_available",
  "signed_out",
]);

/** The reasons that mean the request is over: the window says so and closes. */
export const GONE_REASONS = Object.freeze(["request_gone", "security_error", "type_error", "site_refused", "signed_out", "disconnected"]);

/** The reasons of the broker's contract, by the names the window uses (`gone`: ended, unknown, or owned by another window). */
const REASON_OF = Object.freeze({ gone: "request_gone", not_allowed: "site_refused" });
/** @param {unknown} reason @returns {string} */
const named = (reason) => (typeof reason === "string" ? (Object.hasOwn(REASON_OF, reason) ? /** @type {Record<string, string>} */ (REASON_OF)[reason] : reason) : "internal_error");

/** @param {unknown} reason */
export const chooserErrorKey = (reason) => `passkeys.error.${typeof reason === "string" && CHOOSER_ERRORS.includes(reason) ? reason : "unknown"}`;

/** @param {unknown} reason */
export const isGone = (reason) => typeof reason === "string" && GONE_REASONS.includes(reason);

// ---------------------------------------------------------------- what a website wrote

/**
 * Characters that never belong in a name shown to the person: the control characters, the line and paragraph separators, the
 * characters that set or isolate the direction of text, the invisible ones that hide a spoofed name (zero width, joiners, the
 * word joiner, the byte order mark, the object and annotation characters), the tag characters and the private use area.
 */
const REFUSED_RANGES = Object.freeze([
  [0x0000, 0x001f], [0x007f, 0x009f], [0x00ad, 0x00ad], [0x034f, 0x034f], [0x061c, 0x061c], [0x115f, 0x1160], [0x17b4, 0x17b5],
  [0x180b, 0x180f], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f], [0x3164, 0x3164], [0xfe00, 0xfe0f], [0xfeff, 0xfeff],
  [0xffa0, 0xffa0], [0xfff9, 0xfffc], [0xd800, 0xdfff], [0xe000, 0xf8ff], [0xe0000, 0xe0fff], [0xf0000, 0x10ffff],
]);

/** @param {number} cp */
const refused = (cp) => REFUSED_RANGES.some(([low, high]) => cp >= low && cp <= high);

/**
 * The text of a website, made safe to show: no control or direction characters, runs of white space made one space, trimmed,
 * and at most `max` characters (a longer one ends with an ellipsis). Empty when nothing is left. Never an identity: the caller
 * shows it labelled as the website's and isolated.
 * @param {unknown} value @param {number} [max]
 * @returns {string}
 */
export function siteText(value, max = SITE_TEXT_MAX) {
  if (typeof value !== "string") return "";
  const cleaned = [...value].map((ch) => (refused(/** @type {number} */ (ch.codePointAt(0))) ? " " : ch)).join("").replace(/\s+/gu, " ").trim();
  const chars = [...cleaned];
  return chars.length > max ? `${chars.slice(0, max - 1).join("").trimEnd()}…` : cleaned;
}

/**
 * The name a new item gets: the website's host without a leading `www.` (the core's Unicode host, which the person can change).
 * @param {unknown} host
 */
export function defaultItemName(host) {
  const text = siteText(host, 253);
  return text.replace(/^www\./iu, "");
}

// ---------------------------------------------------------------- the view

/**
 * @typedef {{ origin: string, hostUnicode: string, rpId: string, rpIdUnicode: string }} Site what the core says (public text)
 * @typedef {{ itemId: string, name: string, userName: string, created: number | null }} Candidate a passkey of Ferret that can answer
 * @typedef {{ itemId: string, name: string, userName: string, sameUser: boolean }} Target an item a new passkey can be added to
 * @typedef {{
 *   kind: "create" | "get",
 *   state: "ready" | "locked",
 *   origin: string,
 *   site: Site | null,
 *   rpName: string,
 *   userName: string,
 *   displayName: string,
 *   online: boolean,
 *   foreign: boolean,
 *   candidates: Candidate[],
 *   targets: Target[],
 *   existing: { itemId: string, name: string } | null,
 *   folders: Array<{ id: string, name: string }>,
 *   recent: boolean,
 *   methods: string[],
 * }} View
 */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** @param {unknown} value */
const text = (value) => (typeof value === "string" ? value : "");
/** @param {unknown} value */
const itemId = (value) => (typeof value === "string" && /^[0-9a-f]{32}$/.test(value) ? value : null);
/** @param {unknown} value */
const stamp = (value) => (typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null);

/**
 * The order of the passkeys of a get request: by when each was created (oldest first), the item id breaking a tie, so two
 * windows of the same request show the same list. A passkey without a date comes last.
 * @param {Candidate[]} list
 * @returns {Candidate[]}
 */
export function sortCandidates(list) {
  return [...list].sort((a, b) => {
    if (a.created !== b.created) {
      if (a.created === null) return 1;
      if (b.created === null) return -1;
      return a.created - b.created;
    }
    return a.itemId < b.itemId ? -1 : a.itemId > b.itemId ? 1 : 0;
  });
}

/**
 * The items a new passkey can be added to: those with the same user name as the new account first, then by name, then by id.
 * @param {Target[]} list
 * @returns {Target[]}
 */
export function sortTargets(list) {
  return [...list].sort((a, b) => {
    if (a.sameUser !== b.sameUser) return a.sameUser ? -1 : 1;
    const byName = a.name.localeCompare(b.name, "en");
    if (byName !== 0) return byName;
    return a.itemId < b.itemId ? -1 : a.itemId > b.itemId ? 1 : 0;
  });
}

/**
 * The answer of `passkey_view` in the shape the window uses, or null for one of another shape (it is not shown). Every text a
 * website chose is cleaned here, once; the site's host and RP ID are the core's public text and only checked to be text.
 * @param {unknown} reply
 * @returns {View | null}
 */
export function viewOf(reply) {
  if (!isRecord(reply) || reply.ok !== true) return null;
  const kind = reply.kind === "create" || reply.kind === "get" ? reply.kind : null;
  if (kind === null) return null;
  const state = reply.state === "locked" ? "locked" : reply.state === "ready" ? "ready" : null;
  if (state === null) return null;
  // The calling frame's origin as the browser gave it (an https origin, an A-label): shown while the core cannot say the site.
  if (typeof reply.origin !== "string" || !/^https:\/\/[^\s/]+$/.test(reply.origin)) return null;
  /** @type {Site | null} */
  let site = null;
  if (isRecord(reply.site)) {
    const s = reply.site;
    if (typeof s.origin !== "string" || typeof s.rp_id !== "string" || s.origin === "" || s.rp_id === "") return null;
    site = {
      origin: s.origin,
      hostUnicode: text(s.host_unicode) !== "" ? text(s.host_unicode) : s.origin,
      rpId: s.rp_id,
      rpIdUnicode: text(s.rp_id_unicode) !== "" ? text(s.rp_id_unicode) : s.rp_id,
    };
  }
  // A ready window knows its site (the core says it); a locked one may not (the core needs an open vault to say it).
  if (state === "ready" && site === null) return null;
  const user = isRecord(reply.user) ? reply.user : {};
  /** @type {Candidate[]} */
  const candidates = [];
  for (const raw of Array.isArray(reply.candidates) ? reply.candidates.slice(0, 200) : []) {
    const id = isRecord(raw) ? itemId(raw.item_id) : null;
    if (id === null || !isRecord(raw)) continue;
    candidates.push({ itemId: id, name: siteText(raw.name), userName: siteText(raw.user_name), created: stamp(raw.created) });
  }
  /** @type {Target[]} */
  const targets = [];
  for (const raw of Array.isArray(reply.targets) ? reply.targets.slice(0, 200) : []) {
    const id = isRecord(raw) ? itemId(raw.item_id) : null;
    if (id === null || !isRecord(raw)) continue;
    targets.push({ itemId: id, name: siteText(raw.name), userName: siteText(raw.user_name), sameUser: raw.same_user === true });
  }
  const existingId = isRecord(reply.existing) ? itemId(reply.existing.item_id) : null;
  /** @type {Array<{ id: string, name: string }>} */
  const folders = [];
  for (const raw of Array.isArray(reply.folders) ? reply.folders.slice(0, 500) : []) {
    if (isRecord(raw) && typeof raw.id === "string" && /^[0-9a-f]{32}$/.test(raw.id)) folders.push({ id: raw.id, name: siteText(raw.name, 64) });
  }
  return {
    kind,
    state,
    origin: reply.origin,
    site,
    rpName: siteText(reply.rp_name),
    userName: siteText(user.name),
    displayName: siteText(user.display_name),
    online: reply.online !== false,
    foreign: reply.foreign === true,
    candidates: sortCandidates(candidates),
    targets: sortTargets(targets),
    existing: existingId !== null && isRecord(reply.existing) ? { itemId: existingId, name: siteText(reply.existing.name) } : null,
    folders,
    recent: reply.recent === true,
    // The ways to verify the background offers, in its order (the recent unlock is the background's own: it needs no step).
    methods: (Array.isArray(reply.methods) ? reply.methods : []).filter((m) => typeof m === "string" && VERIFY_WAYS.includes(m)),
  };
}

// ---------------------------------------------------------------- the background

/** The statuses of the sync that mean the server cannot be reached now. */
const OFFLINE_STATUSES = Object.freeze(["offline", "retrying", "failed", "unauthorized"]);

/**
 * The window's side of the messages. Each takes the request's id from here and never from the page's address a second time.
 * @param {import("./ui.mjs").Request} request
 * @param {string} requestId
 * @param {{ has?: (type: string) => boolean }} [options] `has`: whether the build's UI table has a message type (the default
 *   reads it); a type that is not there is not sent, and the reason is `not_available`
 */
export function createChooserBackend(request, requestId, { has = (type) => Object.hasOwn(UI_TYPES, type) } = {}) {
  /**
   * @param {string} type @param {Record<string, unknown>} [body]
   * @returns {Promise<any>}
   */
  const ask = async (type, body = {}) => {
    if (!has(type)) return { ok: false, reason: "not_available" };
    try {
      return await request(type, type === "sync_state" ? body : { request_id: requestId, ...body });
    } catch (error) {
      const code = /** @type {{ code?: unknown }} */ (error)?.code;
      return { ok: false, reason: typeof code === "string" ? code : "internal_error" };
    }
  };
  /** @param {any} reply @returns {{ ok: true } | { ok: false, reason: string }} */
  const outcome = (reply) => (reply?.ok === true ? { ok: true } : { ok: false, reason: named(reply?.reason) });
  return Object.freeze({
    /**
     * Whether the request is still there: `passkey_pending` alone. It works while the vault is locked and does not count as a use
     * of the vault, so the window can ask it on a timer without keeping the vault from locking.
     * @returns {Promise<{ ok: true } | { ok: false, reason: string }>}
     */
    async alive() {
      const pending = await ask("passkey_pending");
      return pending?.ok === true ? { ok: true } : { ok: false, reason: named(pending?.reason) };
    },
    /**
     * What the window shows now: the request (works locked), the site the core checked (needs the open vault: without it the
     * window asks for the unlock), and for an open vault what Ferret has for the request.
     * @returns {Promise<{ ok: true, view: View } | { ok: false, reason: string }>}
     */
    async view() {
      const pending = await ask("passkey_pending");
      if (pending?.ok !== true || !isRecord(pending.request)) return { ok: false, reason: named(pending?.reason) };
      const req = pending.request;
      const site = await ask("passkey_site");
      /** @type {Record<string, unknown>} */
      const raw = {
        ok: true,
        kind: req.kind,
        origin: req.origin,
        rp_name: req.rp_name,
        user: { name: req.user_name, display_name: req.user_display_name },
        foreign: req.foreign === true,
        online: true,
        candidates: [],
        targets: [],
        existing: null,
        folders: [],
        recent: false,
        methods: [],
      };
      if (site?.ok === true && isRecord(site.site)) {
        raw.state = "ready";
        raw.site = site.site;
      } else if (site?.reason === "vault_locked") {
        raw.state = "locked";
        raw.site = null;
        const viewed = viewOf(raw);
        return viewed === null ? { ok: false, reason: "internal_error" } : { ok: true, view: viewed };
      } else {
        return { ok: false, reason: named(site?.reason) };
      }
      if (req.kind === "get") {
        const found = await ask("passkey_candidates");
        if (found?.ok === true && Array.isArray(found.candidates)) {
          raw.candidates = found.candidates;
          raw.recent = found.recent === true;
          raw.methods = Array.isArray(found.methods) ? found.methods : [];
          raw.online = found.online !== false;
        }
      } else {
        // A new passkey is saved only with the server (design UK111): the window finds out before it offers anything.
        const sync = await ask("sync_state");
        raw.online = !(typeof sync?.status === "string" && OFFLINE_STATUSES.includes(sync.status));
        const options = await ask("passkey_create_options");
        if (options?.ok === true) {
          raw.targets = Array.isArray(options.targets) ? options.targets : [];
          raw.existing = isRecord(options.existing) ? options.existing : null;
          raw.folders = Array.isArray(options.folders) ? options.folders : [];
          raw.recent = options.recent === true;
        }
      }
      const view = viewOf(raw);
      return view === null ? { ok: false, reason: "internal_error" } : { ok: true, view };
    },
    /**
     * The choice of the person: an item of Ferret for a get request; for a create request a new item (`name`, `folderId`)
     * or an item to add to. Nothing but the id of the request, the kind of choice and these values goes.
     * @param {{ kind: "get", itemId: string } | { kind: "create", mode: "new", name: string, folderId: string | null } | { kind: "create", mode: "attach", itemId: string }} choice
     */
    async choose(choice) {
      /** @type {Record<string, unknown>} */
      const body = { kind: choice.kind };
      if (choice.kind === "get") body.item_id = choice.itemId;
      else if (choice.mode === "new") Object.assign(body, { mode: "new", name: choice.name, ...(choice.folderId !== null ? { folder_id: choice.folderId } : {}) });
      else Object.assign(body, { mode: "attach", item_id: choice.itemId });
      return outcome(await ask("passkey_choose", body));
    },
    /**
     * One try of the verification step: the way and what the person gave for it (the PIN, the master password and the secret key,
     * or a passkey's credential id and 32 bytes). The background checks it and issues the request's one-time mark; the window
     * never says "verified" itself.
     * @param {"prf" | "pin" | "password"} method @param {Record<string, string>} input
     * @returns {Promise<{ ok: true } | { ok: false, reason: string, left?: number, wait_ms?: number }>}
     */
    async verify(method, input) {
      const reply = await ask("passkey_verify", { method, ...input });
      if (reply?.ok === true) return { ok: true };
      return {
        ok: false,
        reason: named(reply?.reason),
        ...(Number.isSafeInteger(reply?.left) ? { left: reply.left } : {}),
        ...(Number.isSafeInteger(reply?.wait_ms) ? { wait_ms: reply.wait_ms } : {}),
      };
    },
    browser: async () => outcome(await ask("passkey_browser")),
    never: async () => outcome(await ask("passkey_never")),
    cancel: async () => outcome(await ask("passkey_cancel")),
  });
}

// ---------------------------------------------------------------- the guard

/**
 * The guard of the window (design § 10.3.3, as the offer card's): a click counts only when it comes from the person
 * (`isTrusted`) and only 400 ms after the window got the focus or its content last changed (a new list, a new step), not just
 * after it was made.
 * @param {{ now?: () => number, ms?: number }} [deps]
 */
export function createGuard({ now = () => Date.now(), ms = GUARD_MS } = {}) {
  let since = now();
  return Object.freeze({
    /** The focus came to the window, or its content changed: the 400 ms start again. */
    touch() {
      since = now();
    },
    /** Whether 400 ms have passed since the last `touch`. */
    open: () => now() - since >= ms,
    /**
     * Whether a click counts: an event the person made, after the guard.
     * @param {{ isTrusted?: unknown } | null | undefined} event
     */
    accepts(event) {
      return event?.isTrusted === true && now() - since >= ms;
    },
  });
}

/**
 * The id of the request from the window's address (`?r=<32 hex>`), or null for any other address: a window that was not made
 * for a request shows nothing to answer.
 * @param {string} search
 * @returns {string | null}
 */
export function requestIdOf(search) {
  const match = /^\?r=([0-9a-f]{32})$/.exec(typeof search === "string" ? search : "");
  return match === null ? null : match[1];
}
