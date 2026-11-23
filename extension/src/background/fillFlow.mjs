// The items of the open vault as the popup uses them: the list and its search,
// one item's view, copying a value, opening an item's site, and "Fill" on the
// page (design document, sections 10.2, 10.3 and 10.6).
//
// This module is part of the core host: only the entry (main.mjs) imports it,
// and it hands the core host its operations (`ops`). A page never gets an item
// id, a handle or a value from it. It gets references (`ref`): random names
// that are good only in the session of the page that got them (one UI port, see
// router.mjs), and only until the vault locks. Each reference is marked with
// what it was made for:
//
//   "fill"   made by `offer` from the page matching (frames.mjs) for one item
//            of one tab, with the frames it may be filled in: those that tie on
//            the item's closest match, the top first, at most 4. Only such a
//            reference can fill, and only in those frames.
//   "copy"   made by a search of the whole vault. It can copy, show the item
//            and open its site, never fill: an item found by searching is not
//            an item that matches the page, and filling it there is the step a
//            phishing page needs.
//
// "Fill" (`fill`): the reference must be a "fill" reference of this session for
// this tab; the frames are fetched again and each must still be there with the
// same origin and document and still match the item (the page matching, which
// uses the core's rule). For each frame left a pending request `(request_id,
// tabId, frameId, documentId)` is made and the fill script is put into that
// frame; each report is paired with its request by id, frame and document, and
// its own origin (`self_origin`) can only narrow what the browser says: a frame
// whose report narrows to nothing is dropped. The first frame, the top first,
// whose report has sign-in fields and that is shown on the page is filled, and
// no other (one fill action fills one group); when none has fields, the answer
// is `no_fields`. A request that names a frame (the menu's) looks at that frame
// only. Then the item is opened and each value goes, one at a time, in a
// `fill_field` to that one frame, and the handle is closed. A value never passes
// through the popup: the popup's answer is `{ ok }` or a reason.
//
// Which frame: the first one, the top first, whose report has a sign-in field
// (a user name or a password). A frame whose report has only a one-time code is
// filled only when no frame has a sign-in field: a code field on its own is not
// a sign-in form.
//
// "Shown on the page": the fill script checks a field only inside its own
// frame. For a frame below the top, the field must also be shown in every
// document above it: the frame's script gives the field's points, and in the
// parent the element that holds the frame must pass the ancestor chain and
// each point, moved into the parent, must be in its viewport and reach that
// element; and so on up to the top (inject.mjs `frameChainShown`; the chain of
// documents comes from the browser). A frame that fails is not filled
// (`frame_hidden`). The check runs when the frame is chosen and again right
// before each value is sent, so a frame that is hidden or covered after its
// report gets nothing more. A frame below a middle frame whose document Ferret
// may not ask (another origin than the top, without that origin's host
// permission; see frames.mjs) cannot be checked, and is not filled either
// (`frame_unchecked`). Each step has a time limit: a page that never
// answers cannot keep the fill flow busy.
//
// A report or a fill result that names no pending request, or comes from
// another frame or document, does nothing.
//
// Each value that lands is noted in the fill context (fillContext.mjs, when the
// background has one): which item's value of which kind went into which
// document. The write path reads it when a change form is submitted there. It
// holds item ids only, in memory, and every lock clears it.
//
// A generated password (`fill_generated`, with the feature `save` on) goes the
// same way with no item: the popup names a `generation_id` of the generator
// (generator.mjs), the frames of the tab that may take a fill are asked for
// their fields in the mode "generated", and only the new and the confirm field
// of a sign-up, change or reset form are reported; a sign-in form and a password
// in use are not. The same frame rules apply (the check that the frame is
// shown, now and again before each value, and the origin and address the
// extension expects). The shortest `maxlength` of the two fields decides the
// length: a password is made again by the core at that length, never shorter
// than 8 (`field_too_short`), and a passphrase is never cut. After the fill the
// background holds an offer to save the value, marked as generated.

import { FRAME_UNCHECKED, encode } from "../shared/protocol.mjs";
import { confirmFrame } from "./frames.mjs";
import { frameChainShown, injectFill } from "./inject.mjs";

/** What a reference was made for. */
export const PURPOSES = Object.freeze(["fill", "copy"]);

/** The most references one page session may hold. */
export const MAX_REFS = 4096;

/** The most page sessions whose references are kept; the oldest goes first. */
export const MAX_SESSIONS = 8;

/** The most frames one "fill" reference names. */
export const MAX_REF_FRAMES = 4;

/** The most handles one answer carries (a reply stays well under the message limit). */
export const PAGE_SIZE = 40;

/** How long the frame has to report its fields, and to answer each value. */
export const REPORT_TIMEOUT_MS = 5000;
export const RESULT_TIMEOUT_MS = 3000;

/** The kinds of value one fill puts in, in this order. */
const FILL_ORDER = Object.freeze(["username", "password", "totp"]);

/** The kinds of value a generated fill puts in, in this order: the new password, then its confirmation. */
const GENERATED_ORDER = Object.freeze(["new_password", "confirm_password"]);

/** The shortest generated password Ferret fills into a page (the same floor as the one a field's `maxlength` meets). */
export const MIN_GENERATED_FILL = 8;

/** The most frames one generated fill asks. */
const MAX_GENERATED_FRAMES = 8;

/** The item types the popup names; any other type is "other". */
const ITEM_TYPES = Object.freeze(["login", "note", "card", "identity"]);

/** The most characters of a name or user name in a list. */
const LIST_TEXT = 128;

const SESSION = /^[0-9a-f]{32}$/;
const ITEM_ID = /^[0-9a-f]{32}$/;

/** The error of this module: a short code. */
export class FillError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "FillError";
    this.code = code;
  }
}

/**
 * The page matching (frames.mjs): for one tab, each item whose saved addresses match by the core's rule, with the
 * frames it may be filled in (the browser's view of each frame), the page's host, whether it is plain `http`, and the
 * frames that wait for their host permission.
 *
 * @typedef {import("./frames.mjs").CandidateSource} CandidateSource
 * @typedef {{ frameId: number, documentId?: string, origin: string }} RefFrame
 * @typedef {import("./frames.mjs").FrameRef} FrameRef
 * @typedef {{ purpose: "fill" | "copy", itemId: string, tabId?: number, frames?: RefFrame[] }} RefEntry
 */

/** @param {Uint8Array} bytes */
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * The references of the page sessions. A reference is stable within one
 * session (the same item, purpose and frame give the same name), random across
 * sessions, and gone when the session ends or the vault locks.
 *
 * @param {{ random: (bytes: Uint8Array) => Uint8Array, max?: number }} options
 */
export function createRefs({ random, max = MAX_REFS }) {
  /** @type {Map<string, { byKey: Map<string, string>, entries: Map<string, RefEntry> }>} */
  const sessions = new Map();

  return {
    /**
     * @param {string} session
     * @param {"fill" | "copy"} purpose
     * @param {RefEntry} entry
     * @returns {string}
     */
    issue(session, purpose, entry) {
      if (!SESSION.test(session) || !PURPOSES.includes(purpose)) throw new FillError("invalid_input");
      let own = sessions.get(session);
      if (!own) {
        own = { byKey: new Map(), entries: new Map() };
        sessions.set(session, own);
        // The oldest session goes when there are too many (a page that is still open asks again).
        while (sessions.size > MAX_SESSIONS) sessions.delete(/** @type {string} */ (sessions.keys().next().value));
      }
      const key = JSON.stringify([purpose, entry.itemId, entry.tabId ?? null, entry.frames ?? null]);
      const known = own.byKey.get(key);
      if (known !== undefined) return known;
      if (own.entries.size >= max) {
        // Full: the oldest "copy" reference goes (a search makes it again when it is needed). A "fill" reference is
        // never dropped to make room.
        const oldest = [...own.entries].find(([, e]) => e.purpose === "copy");
        if (oldest === undefined) throw new FillError("busy");
        own.entries.delete(oldest[0]);
        for (const [k, r] of own.byKey) {
          if (r === oldest[0]) {
            own.byKey.delete(k);
            break;
          }
        }
      }
      const ref = hex(random(new Uint8Array(16)));
      own.byKey.set(key, ref);
      own.entries.set(ref, Object.freeze({ ...entry, purpose }));
      return ref;
    },

    /**
     * What `ref` names in `session`, or null.
     * @param {unknown} session @param {unknown} ref
     * @returns {RefEntry | null}
     */
    get(session, ref) {
      if (typeof session !== "string" || typeof ref !== "string") return null;
      return sessions.get(session)?.entries.get(ref) ?? null;
    },

    /** @param {string} session */
    drop(session) {
      sessions.delete(session);
    },

    clear() {
      sessions.clear();
    },

    /** The number of sessions that hold references (for the tests). */
    size: () => sessions.size,
  };
}

/** A promise with its settle functions. @returns {Deferred} */
function deferred() {
  /** @type {(value: any) => void} */
  let resolve = () => {};
  /** @type {(error: Error) => void} */
  let reject = () => {};
  /** @type {Promise<any>} */
  const promise = new Promise((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  promise.catch(() => {});
  return { promise, resolve, reject };
}

/** @param {unknown} text */
const listText = (text) => {
  const chars = [...(typeof text === "string" ? text : "")];
  return chars.length > LIST_TEXT ? `${chars.slice(0, LIST_TEXT - 1).join("")}…` : chars.join("");
};

/** @param {unknown} type */
const typeOf = (type) => (ITEM_TYPES.includes(/** @type {string} */ (type)) ? /** @type {string} */ (type) : "other");

/** An address that "Open the site" can open (the core checks it again before it is opened). @param {unknown} url */
const isWebAddress = (url) => typeof url === "string" && url.length <= 2048 && /^https?:\/\/[^\s]/i.test(url);

/**
 * @typedef {{
 *   id: string, name: string, username: string, favorite: boolean, type: string, urls: string[],
 * }} Summary the part of the engine's item summary this module reads
 * @typedef {{
 *   list(): Summary[],
 *   open(id: string): Promise<{ handle: number, view: any, close(): Promise<void> }>,
 * }} Engine the part of the sync engine this module reads
 * @typedef {{ promise: Promise<any>, resolve: (value: any) => void, reject: (error: Error) => void }} Deferred
 * @typedef {{
 *   requestId: string, tabId: number, frameId: number, documentId?: string, origin: string,
 *   ancestors: FrameRef[], unchecked?: boolean, mode?: "generated",
 *   report: Deferred,
 *   result: Deferred | null,
 * }} Pending one frame of a fill
 *   `report` settles with `{ kinds: Set<string>, url: string, limits: Map<string, number> }` (`limits`: the `maxlength` of
 *   the fields of a generated fill that have one), `result` with `{ ok: boolean, reason?: string }`
 */

/**
 * The item operations of the core host. Call `attach` once the core host exists.
 *
 * @param {{
 *   syncHost: { engine(): Engine | null },
 *   clipboard: { copy(text: string): Promise<void> },
 *   scripting: { executeScript: (injection: any) => Promise<any[]> },
 *   tabs: { sendMessage: (tabId: number, message: string, options: Record<string, unknown>) => Promise<unknown>, create: (info: { url: string }) => Promise<unknown> },
 *   source?: CandidateSource | null,
 *   fillContext?: { record(entry: { tabId: number, frameId: number, documentId?: string, url: string, fieldKind: string, itemId: string }): void, clear(): void } | null,
 *   generator?: { get(id: unknown): { value: string, kind: string, expiresAt: number } | null, fit(id: string, limit: number): Promise<{ ok: boolean }> } | null,
 *   offers?: { onGenerated(meta: GeneratedMeta): unknown } | null,
 *   now?: () => number,
 *   random?: (bytes: Uint8Array) => Uint8Array,
 *   timers?: { setTimeout: (fn: () => void, ms: number) => unknown, clearTimeout: (id: unknown) => void },
 *   reportTimeoutMs?: number,
 *   resultTimeoutMs?: number,
 * }} options `source` is the page matching (null: no page has candidates, so nothing can be filled); `fillContext`
 *   notes what was filled where (null: nothing is noted); `generator` holds the generated values (null: no generated
 *   fill); `offers` is given what was filled so it can hold an offer to save it (null: no offer is made)
 * @typedef {{
 *   tabId: number, frameId: number, documentId?: string, url: string, origin: string, generationId: string,
 *   value: string, expiresAt: number,
 * }} GeneratedMeta what the store of offers is told after a generated fill: the frame and the value, in memory only
 */
export function createFillHost({
  syncHost,
  clipboard,
  scripting,
  tabs,
  source = null,
  fillContext = null,
  generator = null,
  offers = null,
  now = Date.now,
  random = (bytes) => {
    globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes));
    return bytes;
  },
  timers = {
    setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id) => globalThis.clearTimeout(/** @type {any} */ (id)),
  },
  reportTimeoutMs = REPORT_TIMEOUT_MS,
  resultTimeoutMs = RESULT_TIMEOUT_MS,
}) {
  const refs = createRefs({ random });
  /** The frames of the fill that runs now, by request id. @type {Map<string, Pending>} */
  const pending = new Map();
  /** One fill at a time. */
  let filling = false;
  /** The core host, set by `attach`. @type {any} */
  let host = null;

  /** @returns {Engine} */
  const engine = () => {
    const running = syncHost.engine();
    // An open vault whose sync did not start has no list: that is not a lock, and must not look like a failed worker.
    if (running === null) throw new FillError("sync_not_running");
    return running;
  };

  /** A client of the vault that is open now: after any lock, every call of it is refused. */
  const client = () => {
    if (host === null) throw new FillError("vault_locked");
    return host.liveClient({ open: true });
  };

  /** @param {unknown} session */
  const sessionOf = (session) => {
    if (typeof session !== "string" || !SESSION.test(session)) throw new FillError("invalid_input");
    return session;
  };

  /**
   * Waits for `promise`, or fails with `code` after `ms`.
   * @template T @param {Promise<T>} promise @param {number} ms @param {string} code
   * @returns {Promise<T>}
   */
  const within = (promise, ms, code) => {
    /** @type {unknown} */
    let timer = null;
    const late = new Promise((_, reject) => {
      timer = timers.setTimeout(() => reject(new FillError(code)), ms);
    });
    return /** @type {Promise<T>} */ (Promise.race([promise, late])).finally(() => timers.clearTimeout(timer));
  };

  /**
   * One value of an opened item, made in the core. `null` when the item has none of that kind.
   * @param {any} vault @param {{ handle: number, view: any }} opened @param {string} kind
   * @returns {Promise<string | null>}
   */
  async function valueOf(vault, opened, kind) {
    if (kind === "totp") {
      if (opened.view?.has_totp !== true) return null;
      // The code comes from the core, for the device's clock, in seconds.
      const made = await vault.totp_code(opened.handle, Math.floor(now() / 1000));
      return typeof made?.code === "string" && made.code !== "" ? made.code : null;
    }
    /** @type {any[]} */
    const fields = Array.isArray(opened.view?.fields) ? opened.view.fields : [];
    const index = fields.findIndex((f) => f?.id === kind);
    if (index < 0) return null;
    const shown = fields[index]?.value;
    if (kind === "username" && typeof shown === "string") return shown === "" ? null : shown;
    const value = await vault.reveal_item_field(opened.handle, index);
    return typeof value === "string" && value !== "" ? value : null;
  }

  /**
   * Opens an item for one call and closes it again, whatever happens.
   * @template T @param {string} itemId @param {(opened: { handle: number, view: any }) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async function withItem(itemId, fn) {
    if (!ITEM_ID.test(itemId)) throw new FillError("not_found");
    const opened = await engine().open(itemId);
    try {
      return await fn(opened);
    } finally {
      await opened.close().catch(() => {});
    }
  }

  /** @param {Summary} s @param {string} ref @param {Record<string, unknown>} [extra] */
  const handleOf = (s, ref, extra = {}) => {
    const username = listText(s.username);
    return {
      ref,
      name: listText(s.name),
      ...(username !== "" ? { username } : {}),
      favorite: s.favorite === true,
      type: typeOf(s.type),
      site: Array.isArray(s.urls) && s.urls.some(isWebAddress),
      ...extra,
    };
  };

  /**
   * The reference of `ref` in `session`, if it may be used for `purposes`.
   * @param {string} session @param {unknown} ref @param {readonly string[]} purposes
   */
  const entryOf = (session, ref, purposes) => {
    const entry = refs.get(session, ref);
    return entry !== null && purposes.includes(entry.purpose) ? entry : null;
  };

  // ------------------------------------------------------------ the list

  /**
   * A search of the whole vault. Its references are for copying only.
   * @param {{ session: string, query: string, favorites?: boolean, type?: string, offset?: number }} args
   */
  function search({ session, query, favorites = false, type, offset = 0 }) {
    const own = sessionOf(session);
    const words = String(query ?? "").trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    const found = engine().list().filter((s) => {
      if (favorites && s.favorite !== true) return false;
      if (type !== undefined && typeOf(s.type) !== type) return false;
      if (words.length === 0) return true;
      const text = [s.name, s.username, ...(Array.isArray(s.urls) ? s.urls : [])].join("\n").toLocaleLowerCase();
      return words.every((word) => text.includes(word));
    });
    const start = Number.isSafeInteger(offset) && offset > 0 ? offset : 0;
    const handles = found.slice(start, start + PAGE_SIZE).map((s) => handleOf(s, refs.issue(own, "copy", { purpose: "copy", itemId: s.id })));
    return { handles, total: found.length };
  }

  /**
   * The candidates of one tab for the popup: each item once, with a "fill" reference for it and the frames it may be
   * filled in. Without page matching there are none.
   * @param {{ session: string, tab_id: number, frame_id?: number }} args `frame_id` keeps that frame only (the menu's)
   */
  async function offer({ session, tab_id: tabId, frame_id: frameId }) {
    const own = sessionOf(session);
    if (source === null) return { handles: [], insecure: false, grant: [] };
    // An open vault whose sync did not start has no items: the page still gets its host and its marks, and no row.
    const running = syncHost.engine();
    const byId = new Map((running?.list() ?? []).map((s) => [s.id, s]));
    const found = await source.candidates(tabId, frameId !== undefined ? { frameId } : {});
    const insecure = found?.insecure === true;
    /** @type {any[]} */
    const handles = [];
    for (const item of Array.isArray(found?.items) ? found.items : []) {
      if (handles.length >= PAGE_SIZE) break;
      /** @type {RefFrame[]} */
      const frames = (Array.isArray(item.frames) ? item.frames : []).slice(0, MAX_REF_FRAMES).map((f) => ({
        frameId: f.frameId,
        ...(typeof f.documentId === "string" ? { documentId: f.documentId } : {}),
        origin: f.origin,
      }));
      if (running === null || frames.length === 0 || !ITEM_ID.test(item.itemId)) continue;
      const known = byId.get(item.itemId);
      /** @type {Summary} */
      const summary = known ?? { id: item.itemId, name: item.name, username: item.username ?? "", favorite: false, type: "other", urls: [] };
      const ref = refs.issue(own, "fill", { purpose: "fill", itemId: item.itemId, tabId, frames });
      handles.push(handleOf(summary, ref, { insecure, frame_id: frames[0].frameId, frame_ids: frames.map((f) => f.frameId) }));
    }
    /** @param {any} h */
    const hostOf = (h) => ({ a_label: String(h?.a_label ?? ""), unicode: String(h?.unicode ?? "") });
    const grant = (Array.isArray(found?.grant) ? found.grant : []).slice(0, 32).map((g) => ({ origin: g.origin, host: hostOf(g.host) }));
    return {
      handles,
      insecure,
      grant,
      ...(found?.host ? { host: hostOf(found.host) } : {}),
    };
  }

  // ------------------------------------------------------------ one item

  /** @param {{ session: string, ref: string }} args */
  async function item({ session, ref }) {
    const entry = entryOf(sessionOf(session), ref, PURPOSES);
    if (entry === null) return { ok: false, reason: "not_offered" };
    return withItem(entry.itemId, async ({ view }) => {
      /** @type {any[]} */
      const fields = Array.isArray(view?.fields) ? view.fields : [];
      const user = fields.find((f) => f?.id === "username");
      /** @type {string[]} */
      const copyable = [];
      if (user) copyable.push("username");
      if (fields.some((f) => f?.id === "password")) copyable.push("password");
      if (view?.has_totp === true) copyable.push("totp");
      /** @type {string[]} */
      const urls = (Array.isArray(view?.urls) ? view.urls : []).map((/** @type {any} */ u) => String(u?.url ?? "")).filter((/** @type {string} */ u) => u !== "" && u.length <= 2048).slice(0, 16);
      const username = typeof user?.value === "string" ? listText(user.value) : "";
      return {
        ok: true,
        name: listText(view?.name),
        ...(username !== "" ? { username } : {}),
        type: typeOf(view?.item_type),
        favorite: view?.favorite === true,
        urls,
        copyable,
      };
    });
  }

  /** @param {{ session: string, ref: string, field: string }} args */
  async function copy({ session, ref, field }) {
    const entry = entryOf(sessionOf(session), ref, PURPOSES);
    if (entry === null) return { ok: false, reason: "not_offered" };
    if (!FILL_ORDER.includes(field)) return { ok: false, reason: "no_value" };
    const core = client();
    const value = await withItem(entry.itemId, (opened) => valueOf(core.vault, opened, field));
    if (value === null) return { ok: false, reason: "no_value" };
    await clipboard.copy(value);
    return { ok: true };
  }

  /** @param {{ session: string, ref: string }} args */
  async function openSite({ session, ref }) {
    const entry = entryOf(sessionOf(session), ref, PURPOSES);
    if (entry === null) return { ok: false, reason: "not_offered" };
    const core = client();
    const url = await withItem(entry.itemId, async ({ view }) => {
      for (const u of Array.isArray(view?.urls) ? view.urls : []) {
        const text = u?.url;
        if (!isWebAddress(text)) continue;
        // The core reads the address as the browser would; an address it cannot read is skipped.
        const origin = await core.vault.page_origin(text).catch(() => null);
        if (typeof origin === "string" && /^https?:\/\//.test(origin)) return /** @type {string} */ (text);
      }
      return null;
    });
    if (url === null) return { ok: false, reason: "no_site" };
    await tabs.create({ url });
    return { ok: true };
  }

  // ------------------------------------------------------------ fill

  /** Ends the fill that runs now, if any, with `code`. @param {string} code */
  function cancelAll(code) {
    for (const request of pending.values()) {
      request.report.reject(new FillError(code));
      request.result?.reject(new FillError(code));
    }
    pending.clear();
  }

  /**
   * Sends one value to the frame of `request` and waits for its answer.
   * @param {Pending} request @param {string} kind @param {string} value @param {string} frameUrl
   * @returns {Promise<{ ok: boolean, reason?: string }>}
   */
  async function push(request, kind, value, frameUrl) {
    /** @type {string} */
    let raw;
    try {
      raw = encode("fill_field", { request_id: request.requestId, field: kind, value, expect: { origin: request.origin, frameUrl } });
    } catch {
      return { ok: false, reason: "value_too_long" };
    }
    const answer = deferred();
    request.result = answer;
    // One document of one frame: the document when the browser names it, else the frame.
    const target = request.documentId !== undefined ? { documentId: request.documentId } : { frameId: request.frameId };
    await tabs.sendMessage(request.tabId, raw, target).catch(() => {});
    try {
      return await within(/** @type {Promise<{ ok: boolean, reason?: string }>} */ (answer.promise), resultTimeoutMs, "no_answer");
    } finally {
      request.result = null;
    }
  }

  /**
   * Puts the fill script into one frame of a fill and waits for its report.
   * @param {Pending} request
   * @returns {Promise<{ kinds: Set<string>, url: string }>}
   */
  async function reportOf(request) {
    const injected = injectFill({
      scripting,
      tabId: request.tabId,
      frameId: request.frameId,
      documentId: request.documentId,
      requestId: request.requestId,
      ...(request.mode !== undefined ? { mode: request.mode } : {}),
    }).catch(() => {
      throw new FillError("frame_gone");
    });
    // A page that never lets the script in (a blocked main thread) is a frame that did not report.
    await within(injected, reportTimeoutMs, "no_report");
    return within(request.report.promise, reportTimeoutMs, "no_report");
  }

  /**
   * Whether the field of `kind` in the frame of `request` is shown in every document above the frame: null, or the
   * refusal (`frame_hidden`, or the frame's own problem with the field). The top has nothing above it. A check that
   * does not end in time refuses.
   * @param {Pending} request @param {string} kind
   * @returns {Promise<null | string>}
   */
  function shownOnPage(request, kind) {
    const frame = {
      frameId: request.frameId,
      ...(request.documentId !== undefined ? { documentId: request.documentId } : {}),
      ancestors: request.ancestors,
    };
    return within(frameChainShown({ scripting, tabId: request.tabId, frame, requestId: request.requestId, kind }), reportTimeoutMs, "frame_hidden").catch(
      () => "frame_hidden",
    );
  }

  /** @param {{ session: string, ref: string, tab_id: number, frame_id?: number }} args */
  async function fill({ session, ref, tab_id: tabId, frame_id: frameId }) {
    const entry = entryOf(sessionOf(session), ref, ["fill"]);
    // Only a reference the page matching made, in this session, for this tab; and a frame named must be one of its.
    if (entry === null || entry.tabId !== tabId || !Array.isArray(entry.frames)) return { ok: false, reason: "not_offered" };
    const wanted = frameId === undefined ? entry.frames : entry.frames.filter((f) => f.frameId === frameId);
    if (wanted.length === 0) return { ok: false, reason: "not_offered" };
    if (source === null) return { ok: false, reason: "not_offered" };
    if (filling) return { ok: false, reason: "busy" };
    if (host?.state() !== "unlocked") return { ok: false, reason: "vault_locked" };
    // No running sync, no item to fill: said before anything is put into the page.
    engine();

    filling = true;
    /** @type {Pending[]} */
    let requests = [];
    try {
      // The frames now, as the browser and the core see them: each must still be one the reference was made for.
      const now = await source.candidates(tabId, frameId !== undefined ? { frameId } : {});
      // A lock (and a new unlock) while the frames were asked for dropped every reference: this one is gone too.
      if (refs.get(session, ref) !== entry) return { ok: false, reason: "not_offered" };
      const fresh = (Array.isArray(now?.items) ? now.items : []).find((i) => i.itemId === entry.itemId);
      /** @type {Array<RefFrame & { ancestors: FrameRef[], unchecked: boolean }>} */
      const frames = [];
      for (const want of wanted) {
        const seen = (Array.isArray(fresh?.frames) ? fresh.frames : []).find(
          (f) => f.frameId === want.frameId && f.origin === want.origin && (want.documentId === undefined || f.documentId === want.documentId),
        );
        // The documents above the frame, as the browser gives them now.
        if (seen !== undefined) frames.push({ ...want, ancestors: Array.isArray(seen.ancestors) ? seen.ancestors : [], unchecked: seen.unchecked === true });
      }
      if (frames.length === 0) return { ok: false, reason: "origin_changed" };
      const core = client();

      requests = frames.map((f) => ({
        requestId: hex(random(new Uint8Array(16))),
        tabId,
        frameId: f.frameId,
        ...(f.documentId !== undefined ? { documentId: f.documentId } : {}),
        origin: f.origin,
        ancestors: f.ancestors,
        unchecked: f.unchecked,
        report: deferred(),
        result: null,
      }));
      for (const request of requests) pending.set(request.requestId, request);
      const reports = await Promise.allSettled(requests.map((request) => reportOf(request)));

      // The first frame, the top first, whose report has sign-in fields and which is shown in every document above it;
      // a frame whose report has only a code comes after every frame with a sign-in field. A frame that narrowed to
      // nothing is dropped.
      /** @param {number} i @param {(kinds: Set<string>) => boolean} test */
      const reportHas = (i, test) => reports[i].status === "fulfilled" && test(/** @type {PromiseFulfilledResult<{ kinds: Set<string> }>} */ (reports[i]).value.kinds);
      const signIn = (/** @type {Set<string>} */ kinds) => kinds.has("username") || kinds.has("password");
      const order = [...reports.keys()].filter((i) => reportHas(i, signIn)).concat([...reports.keys()].filter((i) => reportHas(i, (kinds) => !signIn(kinds) && kinds.has("totp"))));
      let chosen = -1;
      /** Why a frame with sign-in fields was passed over, the first such reason (a frame reason before any other). @type {string | null} */
      let passed = null;
      for (const i of order) {
        if (chosen >= 0) break;
        const r = /** @type {PromiseFulfilledResult<{ kinds: Set<string> }>} */ (reports[i]);
        const first = /** @type {string} */ (FILL_ORDER.find((kind) => r.value.kinds.has(kind)));
        const problem = requests[i].unchecked === true ? FRAME_UNCHECKED : await shownOnPage(requests[i], first);
        if (problem === null) chosen = i;
        else if (passed === null || problem === "frame_hidden" || (problem === FRAME_UNCHECKED && passed !== "frame_hidden")) passed = problem;
      }
      if (chosen < 0) {
        if (passed !== null) return { ok: false, reason: passed };
        if (reports.some((r) => r.status === "fulfilled")) return { ok: false, reason: "no_fields" };
        const first = /** @type {PromiseRejectedResult} */ (reports[0]);
        const code = /** @type {any} */ (first.reason)?.code;
        return { ok: false, reason: typeof code === "string" ? code : "not_filled" };
      }
      const request = requests[chosen];
      // The other frames' requests end here: a later report or result of theirs does nothing.
      for (const other of requests) if (other !== request) pending.delete(other.requestId);
      const report = /** @type {PromiseFulfilledResult<{ kinds: Set<string>, url: string }>} */ (reports[chosen]).value;
      const kinds = FILL_ORDER.filter((kind) => report.kinds.has(kind));
      return await withItem(entry.itemId, async (opened) => {
        let filled = 0;
        for (const kind of kinds) {
          if (pending.get(request.requestId) !== request) throw new FillError("vault_locked");
          const value = await valueOf(core.vault, opened, kind);
          if (value === null) continue;
          // Right before the value goes: the frame must still be shown in every document above it.
          const hiddenNow = await shownOnPage(request, kind);
          if (hiddenNow !== null) return { ok: false, reason: hiddenNow };
          if (pending.get(request.requestId) !== request) throw new FillError("vault_locked");
          const result = await push(request, kind, value, report.url);
          if (!result.ok) return { ok: false, reason: typeof result.reason === "string" ? result.reason : "not_filled" };
          filled += 1;
          fillContext?.record({
            tabId, frameId: request.frameId, ...(request.documentId !== undefined ? { documentId: request.documentId } : {}), url: report.url, fieldKind: kind, itemId: entry.itemId,
          });
        }
        return filled > 0 ? { ok: true } : { ok: false, reason: "no_value" };
      });
    } catch (error) {
      const code = /** @type {any} */ (error)?.code;
      return { ok: false, reason: typeof code === "string" ? code : "not_filled" };
    } finally {
      for (const request of requests) pending.delete(request.requestId);
      filling = false;
    }
  }

  /**
   * "Fill" with a generated value: the new and the confirm field of a sign-up, change or reset form of the tab (see the
   * top of this file). Nothing but the `generation_id` comes from the popup; the value comes from the generator.
   * @param {{ session: string, generation_id: string, tab_id: number, frame_id?: number }} args
   */
  async function fillGenerated({ session, generation_id: generationId, tab_id: tabId, frame_id: frameId }) {
    sessionOf(session);
    // Without the generator (a build without the feature) there is no such operation.
    if (generator === null) throw new FillError("not_available");
    if (source === null || typeof source.frames !== "function") return { ok: false, reason: "not_offered" };
    // A value that expired, or that a lock took, is gone: nothing is asked of the page for it.
    if (generator.get(generationId) === null) return { ok: false, reason: "not_offered" };
    if (filling) return { ok: false, reason: "busy" };
    if (host?.state() !== "unlocked") return { ok: false, reason: "vault_locked" };

    filling = true;
    /** @type {Pending[]} */
    let requests = [];
    try {
      const found = await source.frames(tabId, frameId !== undefined ? { frameId } : {});
      if (host?.state() !== "unlocked") return { ok: false, reason: "vault_locked" };
      if (found.host === null || found.frames.length === 0) return { ok: false, reason: "no_fields" };
      // Not on a plain `http` page: a password made here would be sent in the clear.
      if (found.insecure) return { ok: false, reason: "insecure_page" };

      requests = found.frames.slice(0, MAX_GENERATED_FRAMES).map((f) => ({
        requestId: hex(random(new Uint8Array(16))),
        tabId,
        frameId: f.frameId,
        ...(f.documentId !== undefined ? { documentId: f.documentId } : {}),
        origin: f.origin,
        ancestors: f.ancestors,
        unchecked: f.unchecked === true,
        mode: /** @type {const} */ ("generated"),
        report: deferred(),
        result: null,
      }));
      for (const request of requests) pending.set(request.requestId, request);
      const reports = await Promise.allSettled(requests.map((request) => reportOf(request)));

      // The first frame, the top first, that reports a new-password field and shows it on the page.
      /** @param {number} i */
      const hasNew = (i) => reports[i].status === "fulfilled" && /** @type {PromiseFulfilledResult<{ kinds: Set<string> }>} */ (reports[i]).value.kinds.has("new_password");
      let chosen = -1;
      /** @type {string | null} */
      let passed = null;
      for (const i of [...reports.keys()].filter(hasNew)) {
        if (chosen >= 0) break;
        const problem = requests[i].unchecked === true ? FRAME_UNCHECKED : await shownOnPage(requests[i], "new_password");
        if (problem === null) chosen = i;
        else if (passed === null || problem === "frame_hidden" || (problem === FRAME_UNCHECKED && passed !== "frame_hidden")) passed = problem;
      }
      if (chosen < 0) {
        if (passed !== null) return { ok: false, reason: passed };
        if (reports.some((r) => r.status === "fulfilled")) return { ok: false, reason: "no_fields" };
        const code = /** @type {any} */ (/** @type {PromiseRejectedResult} */ (reports[0]).reason)?.code;
        return { ok: false, reason: typeof code === "string" ? code : "not_filled" };
      }
      const request = requests[chosen];
      for (const other of requests) if (other !== request) pending.delete(other.requestId);
      const report = /** @type {PromiseFulfilledResult<{ kinds: Set<string>, url: string, limits: Map<string, number> }>} */ (reports[chosen]).value;
      const kinds = GENERATED_ORDER.filter((kind) => report.kinds.has(kind));

      // The shortest `maxlength` of the fields decides the length; below the shortest password Ferret makes, nothing is filled.
      const limits = kinds.map((kind) => report.limits.get(kind)).filter((n) => n !== undefined);
      const limit = limits.length > 0 ? Math.min(.../** @type {number[]} */ (limits)) : null;
      const before = generator.get(generationId);
      if (before === null) return { ok: false, reason: "not_offered" };
      if (limit !== null && before.value.length > limit) {
        // `fit` refuses a limit below 8, and a passphrase, which is never cut.
        if (!(await generator.fit(generationId, limit)).ok) return { ok: false, reason: "field_too_short" };
      }
      // Read after the fit, and after every await: a lock in between has taken it.
      const generated = generator.get(generationId);
      if (generated === null || host?.state() !== "unlocked") return { ok: false, reason: "not_offered" };
      const value = generated.value;
      // Ferret fills no generated password shorter than 8 characters, whatever the field says (the popup can make one of 4).
      if (value.length < MIN_GENERATED_FILL) return { ok: false, reason: "field_too_short" };

      /** Tells the store of offers what went into the page. True when an offer is held for it. */
      const announce = async () => {
        if (offers === null) return false;
        try {
          await offers.onGenerated({
            tabId,
            frameId: request.frameId,
            ...(request.documentId !== undefined ? { documentId: request.documentId } : {}),
            url: report.url,
            origin: request.origin,
            generationId,
            value,
            expiresAt: generated.expiresAt,
          });
          return true;
        } catch {
          // The value is in the page; the offer to save it is what failed.
          return false;
        }
      };
      // A value that landed in one field and was refused by the next is in the page all the same: the offer is made then too.
      let landed = false;
      /** @param {string} reason */
      const stopped = async (reason) => (landed ? { ok: false, reason, offer: await announce() } : { ok: false, reason });
      for (const kind of kinds) {
        if (pending.get(request.requestId) !== request) throw new FillError("vault_locked");
        // Right before the value goes: the frame must still be shown in every document above it.
        const hiddenNow = await shownOnPage(request, kind);
        if (hiddenNow !== null) return await stopped(hiddenNow);
        if (pending.get(request.requestId) !== request || generator.get(generationId) === null) throw new FillError("vault_locked");
        const result = await push(request, kind, value, report.url);
        if (!result.ok) return await stopped(typeof result.reason === "string" ? result.reason : "not_filled");
        landed = true;
      }
      return { ok: true, length: value.length, offer: await announce() };
    } catch (error) {
      const code = /** @type {any} */ (error)?.code;
      return { ok: false, reason: typeof code === "string" ? code : "not_filled" };
    } finally {
      for (const request of requests) pending.delete(request.requestId);
      filling = false;
    }
  }

  /**
   * A report of a content script (`frame_report` or `fill_result`). It counts only for the pending request it
   * names, from that request's frame and document; anything else does nothing.
   * @param {{ kind: string, body: any, sender: { tabId: number, frameId: number, documentId?: string, url: string } }} args
   */
  async function onReport({ kind, body, sender }) {
    const request = pending.get(body?.request_id);
    if (!request || typeof sender !== "object" || sender === null) return undefined;
    if (sender.tabId !== request.tabId || sender.frameId !== request.frameId) return undefined;
    if (request.documentId !== undefined && sender.documentId !== request.documentId) return undefined;
    if (kind === "fill_result") {
      request.result?.resolve(body.ok === true ? { ok: true } : { ok: false, reason: typeof body.reason === "string" ? body.reason : "not_filled" });
      return undefined;
    }
    if (kind !== "frame_report") return undefined;
    // The frame's origin comes from the browser (the sender's address, read by the core). The script's own
    // `self.origin` can only narrow it (`confirmFrame`): an opaque or a different one drops the frame.
    const fromBrowser = await client().vault.page_origin(sender.url).catch(() => null);
    if (pending.get(request.requestId) !== request) return undefined;
    if (fromBrowser !== request.origin || !confirmFrame(request, body.self_origin)) {
      request.report.reject(new FillError("origin_changed"));
      return undefined;
    }
    // A generated fill takes the new and the confirm field only, a sign-in fill never those.
    const wanted = request.mode === "generated" ? GENERATED_ORDER : FILL_ORDER;
    /** @type {any[]} */
    const fields = (Array.isArray(body.fields) ? body.fields : []).filter((/** @type {any} */ f) => wanted.includes(f?.kind));
    /** @type {Set<string>} */
    const kinds = new Set(fields.map((f) => f.kind));
    /** @type {Map<string, number>} */
    const limits = new Map();
    for (const f of fields) if (Number.isSafeInteger(f.max) && f.max >= 0) limits.set(f.kind, f.max);
    request.report.resolve({ kinds, url: sender.url, limits });
    return undefined;
  }

  /**
   * @param {(args: any) => unknown} run
   * @returns {import("./coreHost.mjs").CoreOp}
   */
  const op = (run) => ({ vault: true, worker: "vault", run: async (_client, args) => run(args ?? {}) });

  const ops = Object.freeze({
    fill_offer: op(offer),
    fill: op(fill),
    fill_generated: op(fillGenerated),
    fill_report: op(onReport),
    search: op(search),
    item: op(item),
    copy: op(copy),
    open_site: op(openSite),
  });

  return {
    ops,
    refs,

    /**
     * Joins the core host: every lock drops the references, ends a fill that runs and clears the fill context.
     * @param {{ state(): string, liveClient(options?: { open?: boolean }): any, onLocked(listener: () => void): unknown }} coreHost
     */
    attach(coreHost) {
      host = coreHost;
      coreHost.onLocked(() => {
        refs.clear();
        cancelAll("vault_locked");
        fillContext?.clear();
      });
    },

    /** The page session `session` has ended (its port is gone). @param {string} session */
    endSession(session) {
      refs.drop(session);
    },
  };
}
