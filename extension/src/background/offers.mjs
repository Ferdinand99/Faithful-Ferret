// The offers to save or update a password (design document, section 10.9): what
// the background holds of the forms people submitted, until the user answers
// in Ferret's own UI or the time runs out.
//
// A form that was submitted arrives as a capture from a content script. Nothing
// of it is believed before the browser has said where it came from:
//
//   - the origin is the browser's: the core's `page_origin` of `sender.url`,
//     never anything in the message; the script's own `self.origin` can only
//     narrow it (a different value or "null" drops the capture);
//   - the frame is the top of the tab, or a frame whose every ancestor is on
//     the same site as the top, secure and not opaque, and which is shown in
//     every document above it (the same rules as a fill); never `http`, not
//     even a loopback address;
//   - the frame, as the browser lists it now, shows the same origin as the
//     sender (a frame that has moved to another origin since is dropped, never
//     re-attributed);
//   - the host is not on the "never" list.
//
// An offer is not shown at once. A login is offered only when it worked: the
// page has to leave the form within ten seconds (a new document in the tab, a
// change of the history, or the script saying that the form is gone within six),
// has to finish loading, and then three and a half quiet seconds have to pass with no
// password form shown again by a page of the same site; a landing page the
// script cannot report from (another site, `http`) counts as unknown and gives
// no offer. A sign-up, a change or a reset is offered three seconds after the
// last capture of its group. A newer capture from the same tab, origin and kind
// replaces the older one. The user name of a separate identifier step is kept
// for five minutes for the same tab and site and joined to the password step.
//
// What is held is held here and nowhere else: in this module's memory, with
// `expiresAt` set on arrival (five minutes; a password Ferret generated lives
// fifteen) and checked on EVERY access (a timer is only a nudge: it stands
// still while the machine sleeps). Every lock, sign-out, forgotten server, closed
// tab, restart, switched-off capture and removed permission clears it. Nothing of
// it goes to storage, a log, a page or a popup: a reply carries an offer's id, its
// kind, the host and the user name, never a password. An offer is given to the
// popup sessions that asked for it, and only a session that was given an offer can
// read or take it; `take` gives it out once.
//
// No randomness source is imported here: the ids are made by `random`, which the
// caller passes in, and a password is never made in this module.

import { narrowOrigin } from "../shared/origin.mjs";

/** How long a captured form is kept. */
export const OFFER_TTL_MS = 300_000;
/** How long a password Ferret generated is kept (it is also dropped at every lock). */
export const GENERATED_TTL_MS = 900_000;
export const MAX_OFFERS_PER_TAB = 4;
export const MAX_OFFERS = 16;

/** After a login capture: how long the page has to give a sign that it left the form. */
export const LOGIN_OUTCOME_MS = 10_000;
/** After a login capture: how long the script has to say that the form is gone (its last check is at 4.9 s; the window tolerates a late timer and the message on its way). */
export const FORM_GONE_MS = 6_000;
/**
 * After the new page has loaded (or the history changed): how long no password form may show again.
 * Deviation: 3.5 s, not 2 s. The capture script's last look for a password form is 3 s after the page is idle, so a
 * failed sign-in whose form is drawn late must still be seen before the offer is made.
 */
export const SETTLE_MS = 3_500;
/** After the last capture of a sign-up, change or reset form. */
export const QUIET_MS = 3_000;
/** A login whose new page has not finished loading by then is dropped. */
export const LOGIN_GIVE_UP_MS = 30_000;
/** At most one capture per frame in this time. */
export const FRAME_GAP_MS = 2_000;
/** At most this many captures per tab in TAB_WINDOW_MS. */
export const TAB_MAX = 20;
export const TAB_WINDOW_MS = 60_000;
/** How long the user name of an identifier step is kept. */
export const IDENTIFIER_MS = 300_000;
/**
 * How far back a navigation reported just before a capture still counts for it.
 * Deviation: an outcome is a navigation after the submit; the capture is sent one task after the trigger, so a route change
 * of the same turn is reported within tens of milliseconds, and half a second is the most that is taken as the same turn.
 */
export const LOOKBACK_MS = 500;
const MAX_RECENT = 16;
/** The most password-form reports one login keeps (a decided one already ends the login). */
const MAX_READIES = 32;
/** The longest the page's own timer waits before it reads the wall clock again. */
export const RECHECK_MS = 15_000;

export const MAX_USERNAME = 512;
export const MAX_PASSWORD = 1024;
/** The largest capture message, in bytes of its JSON. */
export const MAX_MESSAGE = 4096;
const MAX_URL = 8192;
const MAX_SESSIONS = 8;
const MAX_IDENTIFIERS = 16;

/** The reasons for clearing, as the module names them. */
export const CLEAR_REASONS = Object.freeze(["lock", "sign_out", "forget", "tab_closed", "restart", "capture_off", "permission_removed"]);

const KINDS = Object.freeze(["login", "signup", "change", "reset"]);
const CAPTURE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const encoder = new TextEncoder();

/**
 * @typedef {{ a_label: string, unicode: string }} Host
 * @typedef {{
 *   tabId: number, frameId: number, documentId?: string, frameUrl: string, origin: string,
 *   kind: "login" | "signup" | "change" | "reset",
 *   username: string | null, usernameFrom: "typed" | "page" | "identifier" | "fill" | null,
 *   password: string, currentPassword: string | null, generated: boolean,
 * }} Capture a submitted form, held in memory only (the shape the write path reads)
 * @typedef {{ offer_id: string, kind: string, host: Host, username: string | null, generated: boolean }} OfferMeta
 *   what an answer carries of an offer: never a password
 * @typedef {{ tabId: number, frameId: number, documentId?: string, url: string }} Sender
 *   a content script's sender, as the router checked it
 * @typedef {{ frameId: number, documentId?: string }} FrameRef
 * @typedef {{
 *   frameId: number, documentId?: string, url: string, origin: string, ancestors: FrameRef[], chainSecure: boolean,
 * }} FrameFact a frame as the browser lists it now (`chainSecure`: it and every frame above it is `https`)
 * @typedef {{
 *   origin(url: string): Promise<string | null>,
 *   sameSite(a: string, b: string): Promise<boolean>,
 *   host(url: string): Promise<Host>,
 *   frame(tabId: number, frameId: number): Promise<FrameFact | null>,
 *   shown(tabId: number, frame: FrameFact): Promise<boolean>,
 *   incognito(tabId: number): Promise<boolean>,
 * }} Frames the browser's and the core's facts about a tab (never a page's or a message's)
 * @typedef {{
 *   has(aLabel: string): Promise<boolean>,
 *   add(aLabel: string, options: { incognito: boolean }): Promise<unknown>,
 * }} Never the hosts the user does not want offers for
 * @typedef {{ classify(capture: Capture): Promise<{ action: string } | null> }} Writer
 * @typedef {{ set(tabId: number, count: number): unknown }} Badge
 * @typedef {{ setTimeout(fn: () => void, ms: number): unknown, clearTimeout(id: any): void }} Timers
 * @typedef {
 *   | { type: "committed", frameId: number, url: string, documentId?: string }
 *   | { type: "completed", frameId: number, url: string, documentId?: string }
 *   | { type: "history", frameId: number, url?: string }
 *   | { type: "form_gone", frameId: number, captureId: string }
 *   | { type: "page_ready", frameId: number, url: string, documentId?: string }
 * } Signal what happened in a tab (the browser's navigation events, and two reports of the capture script)
 */

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** @param {unknown} s @param {number} max @returns {s is string} */
const isText = (s, max) => typeof s === "string" && s !== "" && s.length <= max;

/** @param {unknown} v @param {number} max @returns {string | null | undefined} undefined: not a usable value */
function optionalText(v, max) {
  if (v === undefined || v === null) return null;
  return typeof v === "string" && v.length <= max ? v : undefined;
}

/**
 * @typedef {{
 *   id: string,
 *   state: "verifying" | "waiting" | "ready",
 *   tabId: number, frameId: number, documentId?: string, captureId: string,
 *   capture: Capture | null,
 *   host: Host | null,
 *   incognito: boolean,
 *   createdAt: number, receivedAt: number, expiresAt: number,
 *   readyAt: number | null,
 *   generated: boolean,
 *   sessions: Set<string>,
 *   login: LoginState | null,
 *   removed: boolean,
 *   originP: Promise<string | null>,
 * }} Entry
 * @typedef {{
 *   via: "commit" | "history" | "gone" | null,
 *   start: number,
 *   landing: { frameId: number, url: string, documentId?: string, unknown: boolean | null } | null,
 *   completedAt: number | null,
 *   settleAt: number | null,
 *   readies: Array<{ at: number, same: boolean | null }>,
 * }} LoginState
 */

/**
 * @param {{
 *   now: () => number,
 *   frames: Frames,
 *   random: (bytes: Uint8Array) => Uint8Array,
 *   never?: Never | null,
 *   writer?: Writer | null,
 *   badge?: Badge | null,
 *   timers?: Timers,
 * }} deps `random` fills the bytes of an offer's id; `writer` is the write path's classification, which says when a login
 *   is saved already (then there is nothing to offer); `badge` is the toolbar button's per-tab count
 */
export function createOffers({
  now,
  frames,
  random,
  never = null,
  writer = null,
  badge = null,
  timers = { setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms), clearTimeout: (id) => globalThis.clearTimeout(id) },
}) {
  /** The offers, pending and ready, by id. @type {Map<string, Entry>} */
  const entries = new Map();
  /** The user names of identifier steps, kept in memory for a few minutes. @type {Array<{ tabId: number, origin: string, username: string, at: number }>} */
  let identifiers = [];
  /** When each frame last sent a capture, and each tab's recent ones, for the limits. @type {Map<string, number>} */
  const frameLast = new Map();
  /** @type {Map<number, number[]>} */
  const tabRecent = new Map();
  /** The tabs whose badge needs a new count. @type {Set<number>} */
  const dirty = new Set();
  /** @type {unknown} */
  let timer = null;
  /** Counts the clears: a capture that is being judged when one comes is dropped. @type {number} */
  let epoch = 0;
  /** @type {Map<number, number>} */
  const tabEpoch = new Map();
  /** The last navigations of the tabs, for a login that arrives just after one. @type {Array<{ tabId: number, at: number, signal: Signal }>} */
  let recentSignals = [];
  /** @param {number} tabId */
  const epochOf = (tabId) => epoch * 1_000_000 + (tabEpoch.get(tabId) ?? 0);

  const newId = () => Array.from(random(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

  /** @param {number} tabId */
  const readyIn = (tabId) => [...entries.values()].filter((e) => e.tabId === tabId && e.state === "ready").length;

  const refreshBadges = () => {
    for (const tabId of [...dirty]) {
      dirty.delete(tabId);
      try {
        const result = /** @type {any} */ (badge?.set(tabId, readyIn(tabId)));
        result?.catch?.(() => {});
      } catch {
        // The button keeps what it showed; the offer is still there.
      }
    }
  };

  /** Forgets one offer: its values go with the entry. @param {Entry} entry */
  function drop(entry) {
    if (entry.removed) return;
    entry.removed = true;
    entry.capture = null;
    entry.sessions.clear();
    entries.delete(entry.id);
    dirty.add(entry.tabId);
  }

  /** The offers a tab holds, the oldest first. @param {number} tabId */
  const inTab = (tabId) => [...entries.values()].filter((e) => e.tabId === tabId).sort((a, b) => a.createdAt - b.createdAt);

  /** The most offers per tab and in all: the oldest go. */
  function enforceCaps() {
    for (const tabId of new Set([...entries.values()].map((e) => e.tabId))) {
      const own = inTab(tabId);
      for (const old of own.slice(0, Math.max(0, own.length - MAX_OFFERS_PER_TAB))) drop(old);
    }
    const all = [...entries.values()].sort((a, b) => a.createdAt - b.createdAt);
    for (const old of all.slice(0, Math.max(0, all.length - MAX_OFFERS))) drop(old);
  }

  /** The page's own timer, for the earliest moment something changes (at most RECHECK_MS: it then reads the clock). */
  function schedule() {
    if (timer !== null) {
      try {
        timers.clearTimeout(timer);
      } catch {
        // Nothing to clear.
      }
      timer = null;
    }
    if (entries.size === 0 && identifiers.length === 0) return;
    const at = now();
    let next = at + RECHECK_MS;
    for (const entry of entries.values()) {
      const times = [entry.expiresAt, entry.readyAt, entry.login?.settleAt, entry.state === "waiting" && entry.login !== null && entry.login.via === null ? entry.receivedAt + LOGIN_OUTCOME_MS : null];
      for (const t of times) if (typeof t === "number" && t > at && t < next) next = t;
    }
    try {
      timer = timers.setTimeout(() => {
        timer = null;
        sweep();
        refreshBadges();
        schedule();
      }, Math.max(0, next - at));
      // A node test run must not wait for it; a browser's handle is a number.
      /** @type {any} */ (timer)?.unref?.();
    } catch {
      // No timer: every access still reads the clock.
    }
  }

  /**
   * What the clock says: offers that ran out go, a login that never left its form or never finished loading goes, and
   * an offer whose waiting is over becomes ready. Every access calls this first.
   */
  function sweep() {
    const at = now();
    // A clock that went backwards (the system time was set) drops everything that was held for longer than it can be
    // held: nothing may outlive its wall-clock time.
    identifiers = identifiers.filter((i) => at - i.at >= 0 && at - i.at <= IDENTIFIER_MS);
    for (const [key, last] of [...frameLast]) if (at - last > FRAME_GAP_MS || at < last) frameLast.delete(key);
    for (const [tab, list] of [...tabRecent]) {
      const kept = list.filter((t) => at - t <= TAB_WINDOW_MS && at >= t);
      if (kept.length === 0) tabRecent.delete(tab);
      else tabRecent.set(tab, kept);
    }
    for (const entry of [...entries.values()]) {
      if (at >= entry.expiresAt || at < entry.createdAt) {
        drop(entry);
        continue;
      }
      if (entry.state !== "waiting") continue;
      const login = entry.login;
      if (login === null) {
        // Sign-up, change, reset: quiet for three seconds.
        if (entry.readyAt !== null && at >= entry.readyAt) makeReady(entry);
        continue;
      }
      if (login.via === null) {
        if (at - entry.receivedAt > LOGIN_OUTCOME_MS) drop(entry);
        continue;
      }
      if (login.via === "commit" && login.completedAt === null && at - entry.receivedAt > LOGIN_GIVE_UP_MS) {
        drop(entry);
        continue;
      }
      if (login.settleAt === null || at < login.settleAt) continue;
      // The landing page and the pages that said "a password form is shown" are judged by the core; one that is not
      // known yet waits for the next look.
      if (login.landing !== null && login.landing.unknown === null) continue;
      if (login.readies.some((r) => r.at <= /** @type {number} */ (login.settleAt) && r.same === null)) continue;
      if (login.landing !== null && login.landing.unknown === true) {
        drop(entry);
        continue;
      }
      // A form shown again by a page of the same site: the login did not work.
      if (login.readies.some((r) => r.at <= /** @type {number} */ (login.settleAt) && r.same === true)) {
        drop(entry);
        continue;
      }
      makeReady(entry);
    }
  }

  /** @param {Entry} entry */
  function makeReady(entry) {
    entry.state = "ready";
    entry.readyAt = entry.readyAt ?? now();
    entry.login = null;
    dirty.add(entry.tabId);
    // The write path can say that the vault holds this login already: then there is nothing to offer.
    const capture = entry.capture;
    if (writer !== null && capture !== null && !entry.generated) {
      Promise.resolve()
        .then(() => writer.classify({ ...capture }))
        .then(
          (outcome) => {
            if (outcome?.action === "none" && !entry.removed) {
              drop(entry);
              refreshBadges();
            }
          },
          () => {},
        );
    }
  }

  /** The kinds of a login's evidence get this tab's pending logins. @param {number} tabId @returns {Entry[]} */
  const pendingLogins = (tabId) =>
    [...entries.values()].filter((e) => e.tabId === tabId && e.login !== null && (e.state === "waiting" || e.state === "verifying"));

  /**
   * Whether a page at `url` is of the same site as the page the capture came from and is a page the script reports
   * from (`https`). The origin of the capture is the browser's, which may still be on its way: it is waited for.
   * @param {Entry} entry @param {string} url @returns {Promise<boolean>}
   */
  async function landedSameSite(entry, url) {
    try {
      const origin = await entry.originP;
      if (origin === null) return false;
      const there = await frames.origin(url);
      if (there === null || !there.startsWith("https://")) return false;
      return (await frames.sameSite(there, origin)) === true;
    } catch {
      return false;
    }
  }

  /**
   * One thing that happened in a tab, for the logins that wait for it. The browser's own events and the capture
   * script's two reports come here; each is judged by the clock of this module, not by anything in it.
   *
   * @param {number} tabId
   * @param {Signal} signal
   * @returns {Promise<void>} resolves when the checks it started are done (the timer does not wait for it)
   */
  async function onSignal(tabId, signal) {
    try {
      if (!isIndex(tabId) || typeof signal !== "object" || signal === null) return;
      sweep();
      const at = now();
      // The navigation of a page that was just submitted may be reported before the capture that caused it arrives:
      // the last few are kept for a moment, and a login that arrives sees them (see `onCapture`).
      if (signal.type === "committed" || signal.type === "completed" || signal.type === "history") {
        recentSignals = [...recentSignals.filter((r) => at - r.at <= LOOKBACK_MS && at >= r.at), { tabId, at, signal }].slice(-MAX_RECENT);
      }
      /** @type {Array<Promise<unknown>>} */
      const checks = [];
      for (const entry of pendingLogins(tabId)) {
        const age = at - entry.receivedAt;
        if (age < 0) continue;
        applySignal(entry, signal, at, age, checks);
      }
      await Promise.all(checks);
      sweep();
      refreshBadges();
      schedule();
    } catch {
      // A signal that cannot be judged changes nothing.
    }
  }

  /**
   * What one signal means for one login that waits for it. `age` is how long ago the capture arrived, at the time of the
   * signal (0 for a signal that was reported a moment before the capture).
   * @param {Entry} entry @param {Signal} signal @param {number} at @param {number} age @param {Array<Promise<unknown>>} checks
   */
  function applySignal(entry, signal, at, age, checks) {
    {
      {
        const login = /** @type {LoginState} */ (entry.login);
        const ownFrame = signal.frameId === entry.frameId;
        switch (signal.type) {
          case "form_gone":
            if (ownFrame && signal.captureId === entry.captureId && login.via === null && age <= FORM_GONE_MS) {
              login.via = "gone";
              login.start = at;
              login.settleAt = at + SETTLE_MS;
            }
            break;
          case "history":
            if ((signal.frameId === 0 || ownFrame) && (login.via === null || login.via === "gone") && age <= LOGIN_OUTCOME_MS) {
              login.via = "history";
              login.start = at;
              login.settleAt = at + SETTLE_MS;
            }
            break;
          case "committed":
            // The document that sent the capture is not a new one (its own load, reported late, is no outcome).
            if (signal.documentId !== undefined && signal.documentId === entry.documentId) break;
            // A new document in the tab (or in the frame of the form). Later ones within the give-up time replace the
            // earlier: a login may pass through several redirects; the last page is where it landed.
            if ((signal.frameId === 0 || ownFrame) && typeof signal.url === "string" && (login.via === null ? age <= LOGIN_OUTCOME_MS : age <= LOGIN_GIVE_UP_MS && login.via === "commit")) {
              login.via = "commit";
              if (login.start === 0) login.start = at;
              login.completedAt = null;
              login.settleAt = null;
              const landing = { frameId: signal.frameId, url: signal.url, ...(typeof signal.documentId === "string" ? { documentId: signal.documentId } : {}), unknown: /** @type {boolean | null} */ (null) };
              login.landing = landing;
              checks.push(
                landedSameSite(entry, signal.url).then((same) => {
                  landing.unknown = !same;
                }),
              );
            }
            break;
          case "completed":
            if (login.via === "commit" && login.landing !== null && login.completedAt === null && signal.frameId === login.landing.frameId) {
              const sameDocument = login.landing.documentId !== undefined && signal.documentId !== undefined ? login.landing.documentId === signal.documentId : login.landing.url === signal.url;
              if (sameDocument) {
                login.completedAt = at;
                login.settleAt = at + SETTLE_MS;
              }
            }
            break;
          case "page_ready":
            // A password form shown after the outcome, by a page of the same site: not by the document that was left.
            if (login.via !== null && at >= login.start && !(login.via === "commit" && signal.documentId !== undefined && signal.documentId === entry.documentId)) {
              if (login.readies.length >= MAX_READIES) break;
              const reading = { at, same: /** @type {boolean | null} */ (null) };
              login.readies.push(reading);
              checks.push(
                landedSameSite(entry, signal.url).then((same) => {
                  reading.same = same;
                }),
              );
            }
            break;
          default:
            break;
        }
      }
    }
  }

  /**
   * A capture from a content script. Nothing is thrown: anything that does not pass is dropped.
   *
   * @param {Sender} sender
   * @param {any} body the body of a `form_capture` message
   * @returns {Promise<void>} resolves when the capture is judged
   */
  async function onCapture(sender, body) {
    /** @type {Entry | null} */
    let entry = null;
    try {
      sweep();
      const at = now();
      // The sender is the router's, the body the protocol's; both are checked again here, cheaply, because the
      // limits below protect the memory this module holds.
      if (typeof sender !== "object" || sender === null || !isIndex(sender.tabId) || !isIndex(sender.frameId) || !isText(sender.url, MAX_URL)) return;
      if (typeof body !== "object" || body === null || !CAPTURE_ID.test(String(body.capture_id)) || !isText(body.self_origin, 300)) return;
      const kind = body.kind;
      const identifierStep = kind === "identifier";
      if (!identifierStep && !KINDS.includes(kind)) return;
      const username = optionalText(body.username, MAX_USERNAME);
      const password = optionalText(body.password, MAX_PASSWORD);
      const current = optionalText(body.current_password, MAX_PASSWORD);
      if (username === undefined || password === undefined || current === undefined) return;
      const sourceOf = body.username_from;
      if (sourceOf !== undefined && sourceOf !== null && sourceOf !== "typed" && sourceOf !== "page") return;
      if (encoder.encode(JSON.stringify(body)).length > MAX_MESSAGE) return;

      // The shapes the script sends, and only those: a message of another shape is refused, never filled in.
      //   identifier    the user name that was typed, and no password
      //   login         the password that was typed; no current password
      //   signup, reset the new password that was typed; no current password. With no password at all it is a join
      //                 request: the new password was not typed (Ferret filled the one it generated)
      //   change        the new password that was typed, and the current one if that was typed too; or a join request
      // A source with no user name is refused; a user name with no source is the page's, never the person's.
      if (username === null && sourceOf !== undefined && sourceOf !== null) return;
      /** @type {Capture["usernameFrom"]} */
      const usernameFrom = username === null ? null : sourceOf === "typed" ? "typed" : "page";
      const joinRequest = !identifierStep && password === null && current === null;
      if (identifierStep) {
        if (password !== null || current !== null || username === null || usernameFrom !== "typed") return;
      } else if (kind === "login") {
        if (password === null || current !== null) return;
      } else if (kind === "change") {
        if (password === null && current !== null) return;
      } else if (current !== null) {
        return;
      }
      if (password === "" || current === "" || username === "") return;

      // The limits: one per frame in two seconds, twenty per tab a minute. A flood is dropped, not queued.
      // Deviation: one capture per frame document, not per frame, so that the password step of a two-page sign-in (a new
      // document of the same frame a moment after the identifier step) is not dropped; the per-tab limit still holds. An identifier
      // step has a gap of its own for the same reason: the password step that follows it on the same page is not dropped.
      const frameKey = `${sender.tabId}:${sender.frameId}:${typeof sender.documentId === "string" ? sender.documentId : ""}:${identifierStep ? "identifier" : "form"}`;
      const last = frameLast.get(frameKey);
      if (last !== undefined && at >= last && at - last < FRAME_GAP_MS) return;
      const recent = (tabRecent.get(sender.tabId) ?? []).filter((t) => at - t <= TAB_WINDOW_MS);
      if (recent.length >= TAB_MAX) return;
      frameLast.set(frameKey, at);
      tabRecent.set(sender.tabId, [...recent, at]);

      const savedPassword = password ?? "";
      entry = {
        id: newId(),
        state: "verifying",
        tabId: sender.tabId,
        frameId: sender.frameId,
        ...(typeof sender.documentId === "string" && sender.documentId !== "" ? { documentId: sender.documentId } : {}),
        captureId: String(body.capture_id),
        capture: null,
        host: null,
        incognito: false,
        createdAt: at,
        receivedAt: at,
        expiresAt: at + OFFER_TTL_MS,
        readyAt: null,
        generated: false,
        sessions: new Set(),
        login: kind === "login" ? { via: null, start: 0, landing: null, completedAt: null, settleAt: null, readies: [] } : null,
        removed: false,
        originP: Promise.resolve().then(() => frames.origin(sender.url)).catch(() => null),
      };
      const mine = entry;
      const started = epochOf(sender.tabId);
      // A clear (a lock, a closed tab) while the capture is judged ends it, and nothing of it is kept.
      const stale = () => mine.removed || epochOf(sender.tabId) !== started;
      if (!identifierStep) {
        entries.set(mine.id, mine);
        // A navigation the browser reported a moment before this capture arrived belongs to it (the page can move on
        // in the same turn as the submit).
        if (mine.login !== null) {
          /** @type {Array<Promise<unknown>>} */
          const early = [];
          for (const r of recentSignals) {
            if (r.tabId !== sender.tabId || at - r.at > LOOKBACK_MS || at < r.at) continue;
            // The load of the capturing document itself, reported late, is no outcome (not every browser gives a document id).
            if (r.signal.type !== "history" && r.signal.frameId === sender.frameId && "url" in r.signal && r.signal.url === sender.url && !(typeof r.signal.documentId === "string" && r.signal.documentId !== sender.documentId)) continue;
            applySignal(mine, r.signal, r.at, 0, early);
          }
        }
      }

      // 1. The origin is the browser's.
      const origin = await mine.originP;
      if (stale()) return;
      if (origin === null || !origin.startsWith("https://") || narrowOrigin(origin, String(body.self_origin)) === null) return void drop(mine);
      // 2. The frame is allowed to be captured from, and shows the same origin now.
      const frame = await frames.frame(sender.tabId, sender.frameId);
      if (stale()) return;
      if (frame === null || frame.origin !== origin || frame.chainSecure !== true) return void drop(mine);
      if (sender.frameId !== 0 && !(await frames.shown(sender.tabId, frame))) return void drop(mine);
      if (stale()) return;
      const host = await frames.host(sender.url);
      if (stale()) return;
      if (never !== null && (await never.has(host.a_label))) return void drop(mine);
      if (stale()) return;
      const incognito = await frames.incognito(sender.tabId);
      if (stale()) return;

      if (identifierStep) {
        // Kept for the same tab and site; replaced when the same tab sends another.
        identifiers = identifiers.filter((i) => !(i.tabId === sender.tabId && i.origin === origin));
        identifiers.push({ tabId: sender.tabId, origin, username: /** @type {string} */ (username), at: now() });
        if (identifiers.length > MAX_IDENTIFIERS) identifiers = identifiers.slice(-MAX_IDENTIFIERS);
        schedule();
        return;
      }

      // 3. The user name: typed or from the page as it came, else the one from an identifier step of this tab and site.
      /** @type {Capture["usernameFrom"]} */
      let from = usernameFrom;
      let name = username;
      if (name === null) {
        for (const ident of [...identifiers].reverse()) {
          if (ident.tabId !== sender.tabId || now() - ident.at > IDENTIFIER_MS) continue;
          if (ident.origin === origin || (await frames.sameSite(ident.origin, origin)) === true) {
            name = ident.username;
            from = "identifier";
            break;
          }
        }
        if (stale()) return;
      }

      // 4a. A join request (the form was submitted with the password Ferret generated, which the script is not allowed to
      // send) is never an offer of its own: it gives its user name to the generated offer of this very frame and
      // document, found by identity and never by comparing values; with no such offer it is dropped.
      if (joinRequest) {
        const target = [...entries.values()].find(
          (e) =>
            e.generated &&
            e.state === "ready" &&
            e.capture !== null &&
            e.tabId === sender.tabId &&
            e.frameId === sender.frameId &&
            e.documentId !== undefined &&
            e.documentId === mine.documentId &&
            e.capture.origin === origin,
        );
        drop(mine);
        if (target?.capture && name !== null) target.capture = { ...target.capture, username: name, usernameFrom: from };
        dirty.add(sender.tabId);
        refreshBadges();
        return;
      }

      // 4b. A capture whose password is the one Ferret generated for this tab and origin joins that offer (the person
      // pasted it, which is typing: the value is compared in this memory only).
      const generated = [...entries.values()].find(
        (e) => e.generated && e.state === "ready" && e.capture !== null && e.tabId === sender.tabId && e.capture.origin === origin && e.capture.password === savedPassword,
      );
      if (generated?.capture) {
        generated.capture = { ...generated.capture, username: name, usernameFrom: from, currentPassword: current };
        drop(mine);
        dirty.add(sender.tabId);
        refreshBadges();
        return;
      }

      // 5. A newer capture from the same tab, origin and kind replaces the older offer (not a generated one).
      for (const old of [...entries.values()]) {
        if (old !== mine && !old.generated && old.tabId === sender.tabId && old.capture !== null && old.capture.origin === origin && old.capture.kind === kind) drop(old);
      }

      mine.host = host;
      mine.incognito = incognito;
      mine.capture = {
        tabId: sender.tabId,
        frameId: sender.frameId,
        ...(mine.documentId !== undefined ? { documentId: mine.documentId } : {}),
        frameUrl: sender.url,
        origin,
        kind: /** @type {Capture["kind"]} */ (kind),
        username: name,
        usernameFrom: from,
        password: savedPassword,
        currentPassword: kind === "change" ? current : null,
        generated: false,
      };
      mine.state = "waiting";
      if (mine.login === null) mine.readyAt = mine.receivedAt + QUIET_MS;
      enforceCaps();
      sweep();
    } catch {
      if (entry !== null) drop(entry);
    } finally {
      refreshBadges();
      schedule();
    }
  }

  /**
   * A password Ferret generated and filled into a form: an offer to save it, ready at once, kept for fifteen minutes (or
   * until a lock). It names the frame the fill went to; the origin is the core's. The "never" list does not stop it.
   *
   * @param {{
   *   tabId: number, frameId: number, documentId?: string, frameUrl: string,
   *   kind: "signup" | "change" | "reset", password: string, username?: string | null, expiresAt?: number,
   * }} meta `expiresAt`: when the generator stops holding the value; the offer never outlives it
   * @returns {Promise<string | null>} the offer's id, or null when no offer was made
   */
  async function onGenerated(meta) {
    try {
      sweep();
      if (!isIndex(meta?.tabId) || !isIndex(meta.frameId) || !isText(meta.frameUrl, MAX_URL) || !["signup", "change", "reset"].includes(meta.kind)) return null;
      if (!isText(meta.password, MAX_PASSWORD)) return null;
      // A lock or a closed tab while this is judged ends it: no generated password outlives a lock.
      const started = epochOf(meta.tabId);
      const stale = () => epochOf(meta.tabId) !== started;
      const origin = await frames.origin(meta.frameUrl);
      if (stale() || origin === null || !origin.startsWith("https://")) return null;
      // The never list does not stop this: the password was made on the person's own click, and without an offer it
      // could be lost with the account made from it. ("Never" on an offer does drop the generated ones that exist.)
      const host = await frames.host(meta.frameUrl);
      if (stale()) return null;
      const incognito = await frames.incognito(meta.tabId);
      if (stale()) return null;
      const at = now();
      // The offer ends when the generator stops holding the value, never later: a fill at minute 14 does not make 29.
      const until = typeof meta.expiresAt === "number" && Number.isFinite(meta.expiresAt) ? Math.min(at + GENERATED_TTL_MS, meta.expiresAt) : at + GENERATED_TTL_MS;
      if (until <= at) return null;
      // The newest generated password of a tab and origin is the one that is offered.
      for (const old of [...entries.values()]) if (old.generated && old.tabId === meta.tabId && old.capture?.origin === origin) drop(old);
      const username = typeof meta.username === "string" && meta.username !== "" && meta.username.length <= MAX_USERNAME ? meta.username : null;
      /** @type {Entry} */
      const entry = {
        id: newId(),
        state: "ready",
        tabId: meta.tabId,
        frameId: meta.frameId,
        ...(typeof meta.documentId === "string" && meta.documentId !== "" ? { documentId: meta.documentId } : {}),
        captureId: "",
        capture: {
          tabId: meta.tabId,
          frameId: meta.frameId,
          ...(typeof meta.documentId === "string" && meta.documentId !== "" ? { documentId: meta.documentId } : {}),
          frameUrl: meta.frameUrl,
          origin,
          kind: meta.kind,
          username,
          usernameFrom: username === null ? null : "typed",
          password: meta.password,
          currentPassword: null,
          generated: true,
        },
        host,
        incognito,
        createdAt: at,
        receivedAt: at,
        expiresAt: until,
        readyAt: at,
        generated: true,
        sessions: new Set(),
        login: null,
        removed: false,
        originP: Promise.resolve(origin),
      };
      entries.set(entry.id, entry);
      dirty.add(entry.tabId);
      enforceCaps();
      refreshBadges();
      schedule();
      return entries.has(entry.id) ? entry.id : null;
    } catch {
      return null;
    }
  }

  /**
   * The offers of a tab that are ready, newest first. `uiSession` is the popup page that asks: the offers it is told of
   * are the ones it may read and take afterwards.
   *
   * @param {number} tabId
   * @param {string} [uiSession]
   * @returns {OfferMeta[]}
   */
  function forTab(tabId, uiSession) {
    sweep();
    const found = [...entries.values()]
      .filter((e) => e.tabId === tabId && e.state === "ready" && e.capture !== null && e.host !== null)
      .sort((a, b) => b.createdAt - a.createdAt);
    for (const entry of found) {
      if (typeof uiSession === "string" && uiSession !== "" && (entry.sessions.has(uiSession) || entry.sessions.size < MAX_SESSIONS)) entry.sessions.add(uiSession);
    }
    refreshBadges();
    return found.map((e) => ({
      offer_id: e.id,
      kind: /** @type {Capture} */ (e.capture).kind,
      host: { a_label: /** @type {Host} */ (e.host).a_label, unicode: /** @type {Host} */ (e.host).unicode },
      username: /** @type {Capture} */ (e.capture).username,
      generated: e.generated,
    }));
  }

  /** @param {string} offerId @param {string} uiSession @returns {Entry | null} */
  function readable(offerId, uiSession) {
    sweep();
    if (typeof offerId !== "string" || !HEX32.test(offerId) || typeof uiSession !== "string" || uiSession === "") return null;
    const entry = entries.get(offerId);
    if (entry === undefined || entry.state !== "ready" || entry.capture === null || !entry.sessions.has(uiSession)) return null;
    return entry;
  }

  return {
    onCapture,
    onSignal,
    onGenerated,
    forTab,

    /**
     * The captured form of an offer this popup session was told of, left where it is (a copy): the write path reads it
     * before it writes. Null when the offer is gone, ran out, or belongs to another session.
     * @param {string} offerId @param {string} uiSession @returns {Capture | null}
     */
    peek(offerId, uiSession) {
      const entry = readable(offerId, uiSession);
      refreshBadges();
      return entry?.capture ? { ...entry.capture } : null;
    },

    /**
     * The captured form, once: the offer is gone after this. Null when it is gone already, ran out, or belongs to
     * another session.
     * @param {string} offerId @param {string} uiSession @returns {Capture | null}
     */
    take(offerId, uiSession) {
      const entry = readable(offerId, uiSession);
      if (entry === null || entry.capture === null) {
        refreshBadges();
        return null;
      }
      const capture = { ...entry.capture };
      drop(entry);
      refreshBadges();
      schedule();
      return capture;
    },

    /**
     * "Not now" (the offer goes) or "Never for this site" (it goes, so does every offer of that host, and the host joins
     * the list; a private window's choice is kept in memory only). Takes only an offer's id, which no page knows.
     * @param {string} offerId @param {{ never?: boolean }} [options]
     */
    dismiss(offerId, { never: forever = false } = {}) {
      sweep();
      const entry = typeof offerId === "string" ? entries.get(offerId) : undefined;
      if (entry === undefined) return;
      const host = entry.host;
      const incognito = entry.incognito;
      drop(entry);
      if (forever && host !== null) {
        for (const other of [...entries.values()]) if (other.host?.a_label === host.a_label) drop(other);
        Promise.resolve(never?.add(host.a_label, { incognito })).catch(() => {});
      }
      refreshBadges();
      schedule();
    },

    /**
     * Drops every offer, pending capture and kept identifier (or those of one tab), at a lock, a sign-out, a forgotten
     * server, a closed tab, a restart, a switched-off capture or a removed permission.
     * @param {string} reason one of CLEAR_REASONS @param {{ tabId?: number }} [options]
     */
    clear(reason, { tabId } = {}) {
      if (!CLEAR_REASONS.includes(reason)) throw new RangeError("offers: unknown reason");
      if (tabId === undefined) epoch += 1;
      else tabEpoch.set(tabId, (tabEpoch.get(tabId) ?? 0) + 1);
      for (const entry of [...entries.values()]) if (tabId === undefined || entry.tabId === tabId) drop(entry);
      identifiers = tabId === undefined ? [] : identifiers.filter((i) => i.tabId !== tabId);
      recentSignals = tabId === undefined ? [] : recentSignals.filter((r) => r.tabId !== tabId);
      if (tabId === undefined) {
        frameLast.clear();
        tabRecent.clear();
      } else {
        tabRecent.delete(tabId);
        for (const key of [...frameLast.keys()]) if (key.startsWith(`${tabId}:`)) frameLast.delete(key);
        dirty.add(tabId);
      }
      refreshBadges();
      schedule();
    },

    /** The popup page `uiSession` has gone: it can no longer read or take an offer. @param {string} uiSession */
    endSession(uiSession) {
      for (const entry of entries.values()) entry.sessions.delete(uiSession);
    },

    /** How many offers (ready or not) are held, for the tests. */
    size: () => entries.size,
  };
}
