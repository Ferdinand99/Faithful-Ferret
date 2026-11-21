// What the popup shows, with no DOM (the tests run it as it is). In this
// version the popup has three views:
//
//   signed_out   no device is signed in: a button opens the sign-in tab
//   locked       the server and the account, and the unlock with the master
//                password (and the secret key when this device does not keep it)
//   unlocked     the server and the account, the lock button in the header,
//                and what the sync shows: its state, a stop and the warnings
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
// The list of the vault comes in a later version and builds on `unlocked`.

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
