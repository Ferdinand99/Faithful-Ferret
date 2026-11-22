// What the popup shows, with no DOM (the tests run it as it is). In this
// version the popup has three views:
//
//   signed_out   no device is signed in: a button opens the sign-in tab
//   locked       the server and the account, and the unlock with the master
//                password (and the secret key when this device does not keep it)
//   unlocked     the lock button in the header, what the sync shows (its
//                state, a stop and the warnings), and the list of the vault:
//                the candidates of the page ("Suggestions for this page", with
//                "Fill"), the favourites and all items, a search and a filter
//                by type, and one item's view
//
// A stop of the sync offers exactly two ways on, "Try again" and "Forget this
// server", and nothing else (accepting an older state of the server comes in
// a later version). A warning is a text and has no button. Every text comes
// from a code the background sent, through a fixed list here; a code the list
// does not know gets the general text, never the code itself.
//
// "Forget this server" is also offered on a locked or signed-out device that
// still names a server, so a device that cannot unlock any more, or that is to
// be signed in at another server, has a way out.
//
// The list holds names, user names and marks, and a reference per item that is
// good only in this popup's session. A password or a code never reaches the
// popup: "Copy" asks the background, which writes the clipboard itself, and
// "Fill" asks the background, which fills the frame itself. Only a candidate of
// the page can be filled; an item found by a search can be copied, shown and
// its site opened, never filled.

import { shownHost } from "./ui.mjs";
import { unlockWith } from "./signinFlow.mjs";

/** The ways on from a stop of the sync, in the order the popup shows them. */
export const STOP_ACTIONS = Object.freeze(["try_again", "forget"]);

/** The stops the popup has a text of its own for (`sync.stop.<code>`); any other stop gets `sync.stop.generic`. */
export const STOP_TEXTS = Object.freeze(["rollback_suspected", "server_restored", "restore_epoch_lowered", "sync_memory_full", "unsupported"]);

/** The warnings the popup has a text for (`sync.warning.<code>`); any other gets `sync.warning.unknown`. */
export const WARNING_TEXTS = Object.freeze([
  // They stand until a later check of the server's checkpoint clears them.
  "server_shows_older_state",
  "checkpoint_rolled_back",
  "checkpoint_forged",
  "bad_feed",
  "server_hid_item",
  "verify_deferred",
  // What one read of the feed found.
  "cached_row_dropped",
  "missing_on_server",
  "rev_lower_than_local",
  "rev_below_remembered",
  "restore_epoch_raised",
  "rev_same_row_changed",
  "row_damaged",
  "tombstone_unverified",
  "trash_copy_skipped",
  "unexpected_rev",
  // An error the engine reports until it is fixed.
  "checkpoint_upload_failed",
]);

/** The states of the engine the popup has a text for (`sync.status.<state>`); before the first, `sync.status.starting`. */
export const STATUS_TEXTS = Object.freeze(["syncing", "idle", "offline", "retrying", "failed", "unauthorized"]);

/** @param {unknown} code @returns {code is string} */
const isCode = (code) => typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code);

/** The i18n key of the text of a stop. @param {string} code */
export const stopKey = (code) => `sync.stop.${STOP_TEXTS.includes(code) ? code : "generic"}`;

/** The i18n key of the text of a warning. @param {string} code */
export const warningKey = (code) => `sync.warning.${WARNING_TEXTS.includes(code) ? code : "unknown"}`;

/** The i18n key of the text of the engine's state. @param {string | null} status */
export const statusKey = (status) => `sync.status.${status !== null && STATUS_TEXTS.includes(status) ? status : "starting"}`;

/**
 * @typedef {{ running: boolean, status: string | null, live: string, halted: string | null, actions: string[], warnings: string[] }} SyncView
 * @typedef {{ view: "signed_out" | "locked" | "unlocked", host: string, account: string, server: string, sync: SyncView | null }} PopupView
 */

/**
 * What the sync shows, from the answer of `sync_state`.
 * @param {Record<string, any> | null | undefined} reply
 * @returns {SyncView}
 */
export function syncViewOf(reply) {
  const running = reply?.running === true;
  const halted = running && isCode(reply?.halted) ? reply.halted : null;
  return {
    running,
    status: running && isCode(reply?.status) ? reply.status : null,
    // Whether the server's event stream is open (only a hint for the tests and the eye: the feed is read in any case).
    live: running && isCode(reply?.live) ? reply.live : "offline",
    halted,
    // A stop has exactly these ways on, whatever its code; nothing else is offered.
    actions: halted !== null ? [...STOP_ACTIONS] : [],
    warnings: running && Array.isArray(reply?.warnings) ? [...new Set(reply.warnings.filter(isCode))] : [],
  };
}

/**
 * @param {Record<string, any>} state the answer of `state`
 * @param {Record<string, any> | null} [sync] the answer of `sync_state` (an open vault only)
 * @returns {PopupView}
 */
export function viewOf(state, sync = null) {
  const view = state?.state === "unlocked" ? "unlocked" : state?.state === "locked" ? "locked" : "signed_out";
  return {
    view,
    host: shownHost(state ?? {}),
    account: typeof state?.account === "string" ? state.account : "",
    server: typeof state?.server === "string" ? state.server : "",
    sync: view === "unlocked" ? syncViewOf(sync) : null,
  };
}

/** @param {import("./ui.mjs").Request} request */
export function createPopupFlow(request) {
  const load = async () => {
    const state = await request("state", {});
    if (state?.state !== "unlocked") return viewOf(state);
    return viewOf(state, await request("sync_state", {}).catch(() => null));
  };
  return {
    /** The view for the state the background reports. */
    load,

    /** The lock button: the background locks, and the popup shows the unlock view. */
    async lock() {
      await request("lock", {});
      return load();
    },

    /**
     * @param {{ password: string, secretKey?: string }} fields
     * @returns {Promise<{ result: { ok: boolean, reason?: string }, view: PopupView }>}
     */
    async unlock(fields) {
      const result = await unlockWith(request, fields);
      return { result, view: await load() };
    },

    /**
     * "Try again" after a stop of the sync.
     * @returns {Promise<{ result: { ok: boolean, reason?: string }, view: PopupView }>}
     */
    async retry() {
      const result = await request("sync_retry", {});
      return { result, view: await load() };
    },

    /**
     * "Forget this server", after the user confirmed it in the popup.
     * @param {string} server the server the popup showed
     * @returns {Promise<{ result: { ok: boolean, reason?: string }, view: PopupView }>}
     */
    async forget(server) {
      const result = await request("forget_server", { server });
      return { result, view: await load() };
    },
  };
}

// ------------------------------------------------------------------ the list

/** The values an item may offer to copy, in the order the popup shows them. */
export const COPY_FIELDS = Object.freeze(["username", "password", "totp"]);

/** The item types of the filter, in the order the popup shows them. */
export const FILTER_TYPES = Object.freeze(["login", "note", "card", "identity"]);

/** The reasons of a refused action that the popup has a text for (`popup.error.<reason>`); any other gets `popup.error.unknown`. */
export const ACTION_ERRORS = Object.freeze([
  "not_offered",
  "origin_changed",
  "busy",
  "frame_gone",
  "no_report",
  "no_fields",
  "no_value",
  "no_answer",
  "value_too_long",
  "wrong_kind",
  "covered",
  "frame_hidden",
  "vault_locked",
  "not_filled",
  "no_site",
  "clipboard",
  "not_found",
  "sync_not_running",
]);

/** The i18n key of the text of a refused action. @param {unknown} reason */
export const actionErrorKey = (reason) => `popup.error.${typeof reason === "string" && ACTION_ERRORS.includes(reason) ? reason : "unknown"}`;

/**
 * @typedef {{
 *   ref: string, name: string, username: string, favorite: boolean, type: string, site: boolean, insecure: boolean,
 *   frameId: number | null,
 * }} Row
 * @typedef {{ rows: Row[], total: number }} Section
 * @typedef {{ origin: string, host: string }} Grant a frame of the page's site that waits for its host permission
 * @typedef {{ host: string, insecure: boolean, rows: Row[], grant: Grant[] }} PageSection `host` is "" when the tab shows no web page
 */

/**
 * The rows of an answer: what the popup shows of each item, and nothing else.
 * @param {any} reply
 * @returns {Row[]}
 */
export function rowsOf(reply) {
  const handles = Array.isArray(reply?.handles) ? reply.handles : [];
  return handles
    .filter((/** @type {any} */ h) => typeof h?.ref === "string")
    .map((/** @type {any} */ h) => ({
      ref: h.ref,
      name: typeof h.name === "string" ? h.name : "",
      username: typeof h.username === "string" ? h.username : "",
      favorite: h.favorite === true,
      type: typeof h.type === "string" ? h.type : "other",
      site: h.site === true,
      insecure: h.insecure === true,
      frameId: Number.isSafeInteger(h.frame_id) && h.frame_id >= 0 ? h.frame_id : null,
    }));
}

/**
 * The popup's part of the list of the vault.
 * @param {import("./ui.mjs").Request} request
 */
export function createListFlow(request) {
  /**
   * @param {{ query?: string, favorites?: boolean, type?: string | null, offset?: number, automatic?: boolean }} o
   *   `automatic`: the popup reads again by itself (not the user), so the auto-lock's deadline does not move
   * @returns {Promise<Section>}
   */
  const search = async ({ query = "", favorites = false, type = null, offset = 0, automatic = false }) => {
    const reply = await request("search", {
      query: query.slice(0, 256),
      ...(favorites ? { favorites: true } : {}),
      ...(type !== null ? { type } : {}),
      ...(offset > 0 ? { offset } : {}),
      ...(automatic ? { automatic: true } : {}),
    });
    return { rows: rowsOf(reply), total: Number.isSafeInteger(reply?.total) ? reply.total : 0 };
  };

  return {
    search,

    /**
     * The candidates of the page in the tab `tabId`: the items that may be filled there. Null when the background
     * offers none for this page (no page, no matching yet, or a refusal).
     * @param {number | null} tabId
     * @param {{ automatic?: boolean }} [o] see `search`
     * @returns {Promise<PageSection | null>}
     */
    async page(tabId, { automatic = false } = {}) {
      if (tabId === null) return null;
      try {
        const reply = await request("candidates", { tab_id: tabId, ...(automatic ? { automatic: true } : {}) });
        /** @param {any} h */
        const shown = (h) => (typeof h?.unicode === "string" ? shownHost({ host: h.unicode, host_a_label: h.a_label }) : "");
        return {
          host: shown(reply?.host),
          insecure: reply?.insecure === true,
          rows: rowsOf(reply).filter((row) => row.frameId !== null),
          grant: (Array.isArray(reply?.grant) ? reply.grant : [])
            .filter((/** @type {any} */ g) => typeof g?.origin === "string")
            .map((/** @type {any} */ g) => ({ origin: g.origin, host: shown(g.host) || g.origin })),
        };
      } catch {
        return null;
      }
    },

    /**
     * What the list shows: with no query, the favourites and all items; with a query, what it found.
     * @param {{ query?: string, type?: string | null, automatic?: boolean }} o `automatic`: see `search`
     * @returns {Promise<{ favorites: Section | null, all: Section, count: number }>}
     */
    async list({ query = "", type = null, automatic = false }) {
      const searching = query.trim() !== "";
      const [favorites, all, everything] = await Promise.all([
        searching ? Promise.resolve(null) : search({ favorites: true, type, automatic }),
        search({ query, type, automatic }),
        searching || type !== null ? search({ query: "", automatic }) : Promise.resolve(null),
      ]);
      return { favorites, all, count: (everything ?? all).total };
    },

    /**
     * "Fill" on a candidate of the page.
     * @param {Row} row @param {number} tabId
     * @returns {Promise<{ ok: boolean, reason?: string }>}
     */
    fill(row, tabId) {
      if (row.frameId === null) return Promise.resolve({ ok: false, reason: "not_offered" });
      // No frame named: the background fills the first of the item's frames that has a sign-in form.
      return request("fill", { ref: row.ref, tab_id: tabId });
    },

    /** @param {string} ref @param {string} field @returns {Promise<{ ok: boolean, reason?: string }>} */
    copy: (ref, field) => request("copy", { ref, field }),

    /** @param {string} ref @returns {Promise<{ ok: boolean, reason?: string }>} */
    openSite: (ref) => request("open_site", { ref }),

    /** @param {string} ref */
    item: (ref) => request("item", { ref }),
  };
}
