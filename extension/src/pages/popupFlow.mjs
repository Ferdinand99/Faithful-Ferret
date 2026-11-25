// What the popup shows, with no DOM (the tests run it as it is). In this
// version the popup has three views:
//
//   signed_out   no device is signed in: a button opens the sign-in tab
//   locked       the server and the account, and the unlock with the master
//                password (and the secret key when this device does not keep it);
//                in a build with unlock on, with a PIN too when one is set
//                and allowed (`pinPolicy`, `pinUnlock`, `pinResultOf`)
//   unlocked     the lock button in the header, what the sync shows (its
//                state, a stop and the warnings), and the list of the vault:
//                the candidates of the page ("Suggestions for this page", with
//                "Fill"), the favourites and all items, a search and a filter
//                by type, and one item's view
//
// A stop of the sync offers "Try again" and "Forget this server"; a stop
// because the server was restored to an earlier state offers "Accept the older
// state" before them (design document, section 8.6): the popup shows what
// accepting would do (counts only), and accepts only after the user typed the
// word, as the web vault does. A warning is a text and has no button. Every
// text comes from a code the background sent, through a fixed list here; a code
// the list does not know gets the general text, never the code itself.
//
// "Forget this server" is also offered on a locked or signed-out device that
// still names a server, so a device that cannot unlock any more, or that is to
// be signed in at another server, has a way out. Its question names the
// changes that were never sent and an account that another address of the
// server keeps, with the web vault's words.
//
// In a build with saving from the extension on, the sync's part also counts
// the items whose change waits to be sent, was refused or is in conflict, and
// lists them (`createSyncItemsFlow`): a conflict is settled with "Keep mine" or
// "Keep the server's", a refused change is dropped with "Discard the draft".
//
// The list holds names, user names and marks, and a reference per item that is
// good only in this popup's session. A password or a code never reaches the
// popup: "Copy" asks the background, which writes the clipboard itself, and
// "Fill" asks the background, which fills the frame itself. Only a candidate of
// the page can be filled; an item found by a search can be copied, shown and
// its site opened, never filled.

import { FRAME_UNCHECKED } from "../shared/protocol.mjs";
import { reasonKey, shownHost } from "./ui.mjs";
import { unlockWith } from "./signinFlow.mjs";
import { readUnlockState } from "./unlockFlow.mjs";

/** The ways on from a stop of the sync, in the order the popup shows them. */
export const STOP_ACTIONS = Object.freeze(["try_again", "forget"]);

/** The ways on from the stop of a server that was restored to an earlier state: accepting that state comes first. */
export const RESTORED_ACTIONS = Object.freeze(["accept_older", "try_again", "forget"]);

/** The ways on from a stop. @param {string} code */
export const actionsOf = (code) => [...(code === "server_restored" ? RESTORED_ACTIONS : STOP_ACTIONS)];

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
 * @typedef {{
 *   running: boolean, status: string | null, live: string, halted: string | null, actions: string[], warnings: string[],
 *   pending: number, blocked: number, conflicts: number,
 * }} SyncView `pending`, `blocked`, `conflicts`: how many items have a change that waits, a refused change, a conflict
 * @typedef {{ view: "signed_out" | "locked" | "unlocked", host: string, account: string, server: string, sync: SyncView | null, ended?: string }} PopupView
 *   `ended`: why the server ended the device's tokens, when the background knows it (signed out only; one of ENDED_TEXTS)
 */

/** The reasons for a sign-out that the popup has a text for (`sync.ended.<code>`); any other shows nothing more. */
export const ENDED_TEXTS = Object.freeze(["token_reused"]);

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
    // A stop has exactly these ways on: "Try again" and "Forget this server", with "Accept the older state" first for a
    // restored server. Nothing else is offered.
    actions: halted !== null ? actionsOf(halted) : [],
    warnings: running && Array.isArray(reply?.warnings) ? [...new Set(reply.warnings.filter(isCode))] : [],
    pending: running ? countOf(reply?.pending) : 0,
    blocked: running ? countOf(reply?.blocked) : 0,
    conflicts: running ? countOf(reply?.conflicts) : 0,
  };
}

/** A count from the background, or 0. @param {unknown} n */
const countOf = (n) => (typeof n === "number" && Number.isSafeInteger(n) && n >= 0 ? n : 0);

/** The form of a typed word for comparing: composed, trimmed and in lower case (as the web vault compares it). @param {string} word */
export const plainWord = (word) => word.normalize("NFC").trim().toLocaleLowerCase();

/**
 * The i18n key of the question of "Forget this server", from what it would lose (`forget_preview`): the web vault's
 * four cases. Unsent changes are lost, unless another address of the server keeps the same account; then they stay,
 * with the saved items, for that address. Without an answer the question says that unsent changes, if there are any,
 * are lost.
 * @param {{ pending: number, shared: boolean } | null} preview
 */
export function forgetBodyKey(preview) {
  if (preview === null) return "sync.forget.body_unknown";
  const pending = preview.pending > 0;
  if (preview.shared) return pending ? "sync.forget.body_shared_pending" : "sync.forget.body_shared";
  return pending ? "sync.forget.body_pending" : "sync.forget.body";
}

/** The reasons of the older state's answers that the popup has a text for (`sync.older.error.<reason>`). */
export const OLDER_ERRORS = Object.freeze(["not_verified", "not_verified_no_checkpoint", "invalid_state", "busy", "bad_feed", "vault_locked", "word_wrong", "not_confirmed"]);

/** The i18n key of the text of a refused preview or accept. @param {unknown} reason @param {"preview" | "accept"} phase */
export const olderErrorKey = (reason, phase) =>
  typeof reason === "string" && OLDER_ERRORS.includes(reason) ? `sync.older.error.${reason}` : `sync.older.error.${phase === "preview" ? "preview_failed" : "failed"}`;

/**
 * "Accept the older state" of a restored server, for its panel: what accepting would do, then the accept, which is
 * sent only when the typed word is the word the panel asks for.
 * @param {import("./ui.mjs").Request} request
 */
export function createOlderFlow(request) {
  return {
    /**
     * What accepting would do: counts only.
     * @returns {Promise<{ ok: true, reupload: number, conflicts: number, manifestOlder: boolean } | { ok: false, reason: string }>}
     */
    async preview() {
      try {
        const reply = await request("sync_older_preview", {});
        if (reply?.ok !== true) return { ok: false, reason: String(reply?.reason ?? "unknown") };
        return { ok: true, reupload: countOf(reply.reupload), conflicts: countOf(reply.conflicts), manifestOlder: reply.manifest_older === true };
      } catch {
        return { ok: false, reason: "unknown" };
      }
    },

    /**
     * The accept. Nothing is sent unless `typed` is `word` (compared as the web vault compares it).
     * @param {string} typed what the user typed @param {string} word the word the panel asked for
     * @returns {Promise<{ ok: true, reuploaded: number, conflicts: number, manifestOlder: boolean, unreadable: number } | { ok: false, reason: string }>}
     */
    async accept(typed, word) {
      if (typeof typed !== "string" || plainWord(typed) === "" || plainWord(typed) !== plainWord(word)) return { ok: false, reason: "word_wrong" };
      try {
        const reply = await request("sync_accept_older", { confirmed: true });
        if (reply?.ok !== true) return { ok: false, reason: String(reply?.reason ?? "unknown") };
        return {
          ok: true,
          reuploaded: countOf(reply.reuploaded),
          conflicts: countOf(reply.conflicts),
          manifestOlder: reply.manifest_older === true,
          unreadable: countOf(reply.unreadable),
        };
      } catch {
        return { ok: false, reason: "unknown" };
      }
    },
  };
}

/** The refused changes that the popup has a text of their own for (`sync.blocked.<code>`); any other gets `sync.blocked.generic`. */
export const BLOCKED_TEXTS = Object.freeze(["quota_exceeded", "too_large", "reupload_refused", "restore_epoch_refused", "forbidden", "read_only", "storage"]);

/** The i18n key of why a change was refused. @param {unknown} code */
export const blockedKey = (code) => `sync.blocked.${typeof code === "string" && BLOCKED_TEXTS.includes(code) ? code : "generic"}`;

/** The reasons of the item answers that the popup has a text for (`sync.item.error.<reason>`); any other gets `unknown`. */
export const ITEM_ERRORS = Object.freeze([
  "not_offered", "not_shown", "not_found", "in_conflict", "conflict_changed", "conflict_unsettled", "busy", "invalid_state",
  "sync_not_running", "vault_locked", "worker_failed",
]);

/** The i18n key of a refused item answer. @param {unknown} reason */
export const itemErrorKey = (reason) => `sync.item.error.${typeof reason === "string" && ITEM_ERRORS.includes(reason) ? reason : "unknown"}`;

/**
 * @typedef {{ ref: string, name: string, username: string, state: "conflict" | "blocked" | "pending", reason: string | null }} SyncItem
 * @typedef {{ deleted: boolean, name: string | null, username: string, modified: number | null, device: string }} ConflictSideView
 */

/**
 * What differs between the two versions, as the background names it: a part of the item, and for an item's own field its
 * label. Never a value.
 * @typedef {{ what: string, label: string }} ConflictDifference
 */

/** The parts of an item that the card names when they differ (`sync.conflict.differs.<what>`); anything else is left out. */
export const DIFFERENCE_KINDS = Object.freeze(["name", "username", "urls", "folders", "favorite", "notes", "totp", "hidden", "field"]);

/** @param {unknown} list @returns {ConflictDifference[]} */
export function differencesOf(list) {
  if (!Array.isArray(list)) return [];
  /** @type {ConflictDifference[]} */
  const out = [];
  for (const d of list.slice(0, 40)) {
    if (typeof d?.what !== "string" || !DIFFERENCE_KINDS.includes(d.what)) continue;
    out.push({ what: d.what, label: typeof d.label === "string" ? d.label : "" });
  }
  return out;
}

/** @param {any} side @returns {ConflictSideView} */
const sideViewOf = (side) => ({
  deleted: side?.deleted === true,
  name: typeof side?.name === "string" ? side.name : null,
  username: typeof side?.username === "string" ? side.username : "",
  modified: Number.isSafeInteger(side?.modified) && side.modified > 0 ? side.modified : null,
  device: typeof side?.device === "string" ? side.device : "",
});

/**
 * The items whose change waits, was refused or is in conflict, as the popup works with them (a build with saving from
 * the extension on). Names, user names, states and references only.
 * @param {import("./ui.mjs").Request} request
 */
export function createSyncItemsFlow(request) {
  /** @param {string} type @param {Record<string, unknown>} body @returns {Promise<{ ok: boolean, reason?: string }>} */
  const act = async (type, body) => {
    try {
      const reply = await request(type, body);
      return reply?.ok === true ? { ok: true } : { ok: false, reason: String(reply?.reason ?? "unknown") };
    } catch {
      return { ok: false, reason: "unknown" };
    }
  };
  return {
    /** @returns {Promise<{ items: SyncItem[], total: number }>} */
    async items() {
      const reply = await request("sync_items", {});
      const items = (Array.isArray(reply?.items) ? reply.items : [])
        .filter((/** @type {any} */ i) => typeof i?.ref === "string" && ["conflict", "blocked", "pending"].includes(i.state))
        .map((/** @type {any} */ i) => ({
          ref: i.ref,
          name: typeof i.name === "string" ? i.name : "",
          username: typeof i.username === "string" ? i.username : "",
          state: i.state,
          reason: typeof i.reason === "string" ? i.reason : null,
        }));
      return { items, total: countOf(reply?.total) };
    },

    /**
     * The two versions of an item in conflict.
     * @param {string} ref
     * @returns {Promise<{ ok: true, mine: ConflictSideView, theirs: ConflictSideView, differs: ConflictDifference[] } | { ok: false, reason: string }>}
     */
    async conflict(ref) {
      try {
        const reply = await request("item_conflict", { ref });
        if (reply?.ok !== true) return { ok: false, reason: String(reply?.reason ?? "unknown") };
        return { ok: true, mine: sideViewOf(reply.mine), theirs: sideViewOf(reply.theirs), differs: differencesOf(reply.differs) };
      } catch {
        return { ok: false, reason: "unknown" };
      }
    },

    /** "Keep mine" or "Keep the server's". @param {string} ref @param {"mine" | "theirs"} choice */
    resolve: (ref, choice) => act("item_resolve", { ref, choice }),

    /** "Discard the draft". @param {string} ref */
    discard: (ref) => act("item_discard", { ref }),
  };
}

/**
 * @param {Record<string, any>} state the answer of `state`
 * @param {Record<string, any> | null} [sync] the answer of `sync_state` (an open vault, or a device that is signed out)
 * @returns {PopupView}
 */
export function viewOf(state, sync = null) {
  const view = state?.state === "unlocked" ? "unlocked" : state?.state === "locked" ? "locked" : "signed_out";
  const ended = view === "signed_out" && ENDED_TEXTS.includes(sync?.ended) ? { ended: /** @type {string} */ (sync?.ended) } : {};
  return {
    view,
    host: shownHost(state ?? {}),
    account: typeof state?.account === "string" ? state.account : "",
    server: typeof state?.server === "string" ? state.server : "",
    sync: view === "unlocked" ? syncViewOf(sync) : null,
    ...ended,
  };
}

/**
 * What the open popup does with the view the background reports now, while it shows the unlocked view `shown`:
 * "rebuild" when the vault is no longer open there (a lock, a sign-out, another account or server), which ends an
 * open question of "Forget this server" as well, so the list never stays on screen after a lock; "same" when nothing
 * changed, nothing was read, or the user is answering that question (the sync's part, where it is asked, stays as it
 * is); "sync" when only the sync's part changed.
 * @param {PopupView} shown
 * @param {PopupView | null} next null when the background could not be read
 * @param {boolean} asking whether the question of "Forget this server" is open
 * @returns {"rebuild" | "same" | "sync"}
 */
export function followStep(shown, next, asking) {
  if (next === null) return "same";
  if (next.view !== "unlocked" || next.account !== shown.account || next.server !== shown.server) return "rebuild";
  if (asking || JSON.stringify(next) === JSON.stringify(shown)) return "same";
  return "sync";
}

// ---------------------------------------------------------------- unlocking with a PIN

/**
 * The refusals of `pin_unlock` that the popup has a text of its own for (`unlock.pin.error.<reason>`). Any other reason
 * is one of the master-password unlock's (a network failure, a sign-out, the attack warning) and has its text there.
 */
export const PIN_REASONS = Object.freeze([
  "wrong_pin", "pin_wait", "pin_wiped", "pin_stale", "pin_offline_expired", "out_of_memory", "pin_unavailable", "pin_rule",
]);

/** The texts that the settings' PIN code owns and the popup reuses, by reason (the other reasons have `unlock.pin.error.<reason>`). */
const SHARED_TEXTS = Object.freeze({ pin_stale: "pin.error.pin_stale" });

/**
 * The refusals after which the PIN cannot be tried again in this popup (it is gone, or this device cannot check it): the
 * popup shows the master password and says why. `pin_offline_expired` is not one of them: the PIN is kept, and works again
 * once the server has been reached.
 */
export const PIN_ENDED_REASONS = Object.freeze(["pin_wiped", "pin_stale", "pin_unavailable", "attack_warning"]);

/** The longest wait the popup believes (milliseconds). */
const MAX_WAIT_MS = 3_600_000;

/**
 * @typedef {{ allowed: boolean, afterRestart: boolean, minLength: number, set: boolean, location: "disk" | "session" | null,
 *   failuresLeft: number, waitMs: number, offlineOk: boolean, lastContactAt: number | null }} PinOffer
 *   what the background says of the PIN while the vault is locked
 * @typedef {{ ok: true } | { ok: false, reason: string, keys: string[], left: number | null, waitMs: number, ended: boolean }} PinResult
 *   `keys`: the i18n keys of the text to show, in order; `left`: the tries left (when the background said); `waitMs`: how
 *   long until the next try; `ended`: the popup shows the master password now
 */

/**
 * The answer of `pin_unlock`, as the popup shows it. Nothing the background sent is shown as it is: a reason that is not
 * in a fixed list gets the text of the master-password unlock for it, and an odd one the general text.
 * @param {any} reply
 * @returns {PinResult}
 */
export function pinResultOf(reply) {
  if (reply?.ok === true) return { ok: true };
  const reason = isCode(reply?.reason) ? reply.reason : "unknown";
  const left = Number.isInteger(reply?.left) && reply.left >= 0 && reply.left <= 5 ? reply.left : null;
  const waitMs = Number.isInteger(reply?.wait_ms) && reply.wait_ms > 0 && reply.wait_ms <= MAX_WAIT_MS ? reply.wait_ms : 0;
  const ended = PIN_ENDED_REASONS.includes(reason);
  /** @type {string[]} */
  let keys;
  if (reason === "wrong_pin") keys = [left === null || left < 1 ? "unlock.pin.error.wrong_pin_plain" : left === 1 ? "unlock.pin.error.wrong_pin_last" : "unlock.pin.error.wrong_pin"];
  else if (reason === "attack_warning") keys = ["session.error.attack_warning", "unlock.pin.error.removed_note"];
  else if (reason === "pin_stale") keys = [SHARED_TEXTS.pin_stale];
  else if (PIN_REASONS.includes(reason)) keys = [`unlock.pin.error.${reason}`];
  else keys = [reasonKey(reason)];
  return { ok: false, reason, keys, left, waitMs, ended };
}

/** @param {import("./ui.mjs").Request} request */
export function createPopupFlow(request) {
  const load = async () => {
    const state = await request("state", {});
    // A locked vault shows nothing of the sync; a device that is signed out may show why (`ended`).
    if (state?.state === "locked") return viewOf(state);
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
     * Whether the locked popup offers a PIN, and what is true of it. Null when it does not: no PIN, the administrator does
     * not allow one, or the background has no answer (also a server or a build without the feature).
     * @returns {Promise<PinOffer | null>}
     */
    async pinPolicy() {
      try {
        const state = readUnlockState(await request("unlock_policy", {}));
        return state !== null && state.pin.set && state.pin.allowed ? state.pin : null;
      } catch {
        return null;
      }
    },

    /**
     * Opens the vault with the PIN. The PIN goes into this one request and is kept nowhere; the answer is read as
     * `pinResultOf` does, and the view is the one the background reports after it.
     * @param {string} pin
     * @returns {Promise<{ result: PinResult, view: PopupView }>}
     */
    async pinUnlock(pin) {
      /** @type {any} */
      let reply;
      try {
        reply = await request("pin_unlock", { pin });
      } catch (error) {
        reply = { ok: false, reason: /** @type {{ code?: unknown }} */ (error)?.code };
      }
      return { result: pinResultOf(reply), view: await load() };
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
     * What "Forget this server" would lose, for its question: null when the background could not say.
     * @param {string} server the server the popup shows
     * @returns {Promise<{ pending: number, shared: boolean } | null>}
     */
    async forgetPreview(server) {
      try {
        const reply = await request("forget_preview", { server });
        return reply?.ok === true ? { pending: countOf(reply.pending), shared: reply.shared === true } : null;
      } catch {
        return null;
      }
    },

    /**
     * "Forget this server", after the user confirmed it in the popup.
     * @param {string} server the server the popup showed
     * @param {number | null} [expectPending] the count of unsent changes the question named (null: it named none)
     * @returns {Promise<{ result: { ok: boolean, reason?: string }, view: PopupView }>}
     */
    async forget(server, expectPending = null) {
      const result = await request("forget_server", { server, ...(expectPending !== null ? { expect_pending: expectPending } : {}) });
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
  "insecure_page",
  "vault_locked",
  "not_filled",
  "no_site",
  "clipboard",
  "not_cleared",
  "not_found",
  "sync_not_running",
]);

/** The i18n key of the text of a refused action (a frame that could not be checked has its text in the frames catalog). @param {unknown} reason */
export const actionErrorKey = (reason) =>
  reason === FRAME_UNCHECKED ? "frames.error.frame_unchecked" : `popup.error.${typeof reason === "string" && ACTION_ERRORS.includes(reason) ? reason : "unknown"}`;

/**
 * @typedef {{
 *   ref: string, name: string, username: string, favorite: boolean, type: string, site: boolean, insecure: boolean,
 *   frameId: number | null, next?: true,
 * }} Row `next`: the item was filled in this tab a short while ago and holds a one-time code, so the page may ask for it next
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
      ...(h.next === true ? { next: /** @type {const} */ (true) } : {}),
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
     * "Fill" on a candidate of the page. `only: "totp"` fills the one-time code field alone.
     * @param {Row} row @param {number} tabId @param {{ only?: "totp" }} [o]
     * @returns {Promise<{ ok: boolean, reason?: string }>}
     */
    fill(row, tabId, { only } = {}) {
      if (row.frameId === null) return Promise.resolve({ ok: false, reason: "not_offered" });
      // No frame named: the background fills the first of the item's frames that has a sign-in form (or, for the code, a code field).
      return request("fill", { ref: row.ref, tab_id: tabId, ...(only !== undefined ? { only } : {}) });
    },

    /**
     * The current one-time code of an item and the seconds it still holds.
     * @param {string} ref @param {boolean} [automatic] the open popup asks again by itself at the end of a period (not the user)
     * @returns {Promise<{ ok: boolean, reason?: string, code?: string, seconds_left?: number }>}
     */
    itemCode: (ref, automatic = false) => request("item_code", { ref, ...(automatic ? { automatic: true } : {}) }),

    /** @param {string} ref @param {string} field @returns {Promise<{ ok: boolean, reason?: string }>} */
    copy: (ref, field) => request("copy", { ref, field }),

    /** @param {string} ref @returns {Promise<{ ok: boolean, reason?: string }>} */
    openSite: (ref) => request("open_site", { ref }),

    /** @param {string} ref */
    item: (ref) => request("item", { ref }),
  };
}
