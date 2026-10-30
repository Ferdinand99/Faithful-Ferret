// The sync engine of the web vault: it keeps the local copy of the vault in step
// with the server, and it is the only place that turns rows into items and
// items into rows.
//
// * Local state is of two kinds. The cache (IndexedDB) holds ciphertext only:
//   sealed items, their tags and tombstones. The item index (the list a screen
//   shows: name, type, urls, ...) is decrypted, lives in memory and is dropped
//   by `stop()`, which the lock calls. No decrypted field is ever written to a
//   store.
// * A row from the server is accepted only when the core opens it
//   (`open_item` checks the tag against item id and revision), and a tombstone
//   only when `verify_tombstone` accepts it. A row that does not open marks the
//   item `damaged` and the last good local version stays. A tombstone that does
//   not verify puts the item in quarantine: the server says deleted, nobody
//   could check it, the local copy stays. A row with a lower revision than the
//   local one is refused with a warning (the server is behind); the pinned
//   state of the account is never touched here.
// * The feed is read from the `seq` of the last row of the last page, never
//   from `latest_seq`: a server that lies about `latest_seq` must not be able
//   to make the client skip rows. A 410 (the cursor is below the floor of the
//   feed) is answered once per cycle with a full listing from 0; if that is
//   answered with 410 as well, the cycle ends with the error `gone`. A listing
//   never deletes anything here: items it does not show are kept, marked
//   `missing_on_server` and uploaded again; only the user can discard them.
// * A write that the server refuses for good (409 or a final code) blocks its
//   item: the draft stays in the outbox, the screen shows the server's version,
//   edits are refused until `discard(id)` drops the draft.
// * Writes go through the outbox (see outbox.mjs): stored before the request,
//   resent byte for byte under the same key.
import { b64u, hex16 } from "../b64.mjs";
import { rowOfChange } from "../store/cache.mjs";
import { encodeWireBytes } from "../wire.mjs";
import { createOutboxRunner } from "./outbox.mjs";

/**
 * @typedef {object} ItemSummary
 * @property {string} id 32 hex characters
 * @property {number} rev
 * @property {string} type
 * @property {string} name
 * @property {boolean} favorite
 * @property {string[]} urls
 * @property {number} modified
 * @property {boolean} pending a write of this item is waiting for the server
 * @property {boolean} damaged the server's newest row could not be opened (the last good version is shown)
 * @property {boolean} quarantined the server says deleted but the tombstone did not verify (the local copy is kept)
 * @property {boolean} missingOnServer a full listing did not show this item: it is kept, and being uploaded again until the user discards it
 * @property {boolean} blocked a write of this item was refused for good (conflict or a final answer): the server's version is shown; `discard` drops the draft
 * @property {string | null} blockedReason the code of the answer that blocked it (`conflict`, `quota_exceeded`, ...)
 * @property {boolean} readOnly
 *
 * @typedef {import("../store/cache.mjs").Scope} Scope
 * @typedef {import("../store/cache.mjs").CachedRow} CachedRow
 * @typedef {{ set(fn: () => void, ms: number): unknown, clear(handle: unknown): void }} Timers
 */

/** The all-zero id of the unlock-method manifest: a row, never an item. */
export const MANIFEST_ID = "00000000000000000000000000000000";

/** Rows asked for in one page of the feed (the server's maximum). */
const PAGE_LIMIT = 500;

/** Codes of the core and the client that mean "the vault is not usable now", not "this row is bad". */
const FATAL_CODES = new Set(["locked", "vault_locked", "worker_failed", "internal"]);

/** An error of the engine. `code` is a word for the caller to switch on. */
export class SyncError extends Error {
  /** @param {string} code @param {string} [message] @param {string | null} [reason] why (for `blocked`: the code that blocked the item) */
  constructor(code, message = code, reason = null) {
    super(message);
    this.name = "SyncError";
    /** @type {string} */
    this.code = code;
    /** @type {string | null} */
    this.reason = reason;
  }
}

/** @param {unknown} error */
const codeOf = (error) => {
  const code = /** @type {any} */ (error)?.code;
  return typeof code === "string" ? code : "internal";
};

/** @param {unknown} error */
const isFatal = (error) => FATAL_CODES.has(codeOf(error));

/**
 * @param {Uint8Array | null} a
 * @param {Uint8Array | null} b
 */
const sameBytes = (a, b) => a === b || (a !== null && b !== null && a.length === b.length && a.every((n, i) => n === b[i]));

/** @param {CachedRow} a @param {CachedRow} b */
const sameRow = (a, b) =>
  a.deleted === b.deleted && sameBytes(a.envelope, b.envelope) && sameBytes(a.tag, b.tag) && sameBytes(a.tomb, b.tomb);

const realTimers = /** @type {Timers} */ ({
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (handle) => clearTimeout(/** @type {any} */ (handle)),
});

/**
 * @param {{
 *   api: import("../api.mjs").Api,
 *   client: any,
 *   store: any,
 *   scope: Scope,
 *   now?: () => number,
 *   pollMs?: number,
 *   rand?: (bytes: Uint8Array) => Uint8Array,
 *   timers?: Timers,
 *   win?: any,
 * }} options
 *   `store` is the store service (`open()`, `cache`, `outbox`, `getSetting`, ...);
 *   `client` the worker client (`client.vault.open_item(...)`); `timers` and `win`
 *   are for tests (a fake clock; a target for the `focus` event).
 */
export function createSyncEngine({
  api,
  client,
  store,
  scope,
  now = Date.now,
  pollMs = 5_000,
  rand = crypto.getRandomValues.bind(crypto),
  timers = realTimers,
  win = globalThis,
}) {
  const flagsKey = `sync.flags.${scope.accountId}.${scope.vaultId}.${scope.vkEpoch}`;

  let started = false;
  let stopped = false;
  let paused = false; // the server said 401: wait for a manual `syncNow`
  /** The `seq` of the last row of the last page that was read. */
  let cursor = 0;
  /** @type {number | null} */
  let restoreEpoch = null;
  /** @type {unknown} */
  let pollTimer = null;
  /** @type {string} */
  let lastStatus = "";
  /** The last "server is behind" warning, so a poll every few seconds does not repeat it. */
  let behind = "";
  /** @type {Promise<void> | null} */
  let inflight = null;
  let again = false;
  /** The ids a full listing has shown so far, while one is going on. @type {Set<string> | null} */
  let listing = null;

  /** The server-accepted rows, ciphertext only (what the cache holds). @type {Map<string, CachedRow>} */
  const rows = new Map();
  /**
   * The newest local write of an item that the feed has not yet confirmed.
   * @type {Map<string, { rev: number, deleted: boolean, envelope: Uint8Array | null, tag: Uint8Array | null }>}
   */
  const overlay = new Map();
  /** The decrypted item index, in memory only. @type {Map<string, Omit<ItemSummary, "id" | "pending" | "damaged" | "quarantined" | "missingOnServer" | "blocked" | "blockedReason">>} */
  const index = new Map();
  /**
   * Marks on items (saved, ids, numbers and digests only). `damaged` and
   * `quarantined`: the server's newest row is not usable. `missing_on_server`: a
   * full listing did not show the item; `rev` is the revision of the local copy
   * and stays the floor of the item. `reuploaded`: the copy was uploaded again
   * (the server numbers it from 1) and the old floor is kept. `sent` lists the
   * writes of this device made since (`<rev>:<r|t>:<digest>`): they are the only
   * rows below the floor that are accepted, byte for byte.
   * @type {Map<string, { kind: "damaged" | "quarantined" | "missing_on_server" | "reuploaded", rev: number, sent?: string[] }>}
   */
  const flags = new Map();
  /** Items whose upload has been answered by the server in this session. @type {Set<string>} */
  const acked = new Set();
  /** Items being sealed for another upload right now. @type {Set<string>} */
  const sealing = new Set();
  /** Idempotency keys of writes that were dropped from the outbox in this session: their answers are ignored. @type {Set<string>} */
  const droppedIdems = new Set();
  /** Items the user gave up on in this session: nothing about them is applied any more. @type {Set<string>} */
  const abandoned = new Set();
  /** Items with a write that was refused for good; the code that blocked them (saved). @type {Map<string, string>} */
  const blocked = new Map();
  let flagsDirty = false;
  /** Handles the engine has opened for a screen. @type {Set<number>} */
  const handles = new Set();
  /** @type {Map<string, Promise<unknown>>} */
  const itemQueues = new Map();
  /** @type {Record<string, Set<(payload: any) => void>>} */
  const listeners = { changed: new Set(), error: new Set(), state: new Set() };

  // --------------------------------------------------------------- events

  /** @param {"changed" | "error" | "state"} event @param {any} payload */
  function emit(event, payload) {
    if (stopped) return;
    for (const fn of [...listeners[event]]) {
      try {
        fn(payload);
      } catch {
        // A listener must not break the engine.
      }
    }
  }

  /** @param {string} kind @param {Record<string, any>} [extra] */
  function setStatus(kind, extra = {}) {
    if (kind === lastStatus && kind !== "warning" && kind !== "idle") return;
    lastStatus = kind;
    emit("state", { kind, ...extra });
  }

  /** @param {string} code @param {Record<string, any>} [extra] */
  function warn(code, extra = {}) {
    emit("state", { kind: "warning", code, ...extra });
  }

  /** @param {Iterable<string>} ids */
  function changed(ids) {
    const list = [...ids];
    if (list.length > 0) emit("changed", { ids: list });
  }

  /** After an `await`: nothing may be stored once the engine is stopped. */
  function alive() {
    if (stopped) throw new SyncError("stopped");
  }

  // ------------------------------------------------------------ the core

  /**
   * Opens a row, reads the item's summary, closes the handle again. `open_item`
   * checks the tag, so a row that does not open is not accepted.
   * @param {string} id @param {number} rev @param {Uint8Array} envelope @param {Uint8Array} tag
   */
  async function summarize(id, rev, envelope, tag) {
    const handle = await client.vault.open_item(hex16.decode(id), rev, envelope, tag);
    try {
      return summaryOf(await client.vault.item_view(handle), rev);
    } finally {
      await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
    }
  }

  /** @param {any} view @param {number} rev */
  function summaryOf(view, rev) {
    return {
      rev,
      type: String(view.item_type ?? ""),
      name: String(view.name ?? ""),
      favorite: view.favorite === true,
      urls: Array.isArray(view.urls) ? view.urls.map((/** @type {any} */ u) => String(u?.url ?? "")) : [],
      modified: Number.isSafeInteger(view.modified) ? view.modified : 0,
      readOnly: view.read_only === true,
    };
  }

  // -------------------------------------------------------- the outbox

  const runner = createOutboxRunner({
    api,
    store,
    scope,
    timers,
    hooks: {
      onDone: (entry, answer) => {
        if (abandoned.has(entry.itemId) || droppedIdems.has(entry.idem)) return; // given up or dropped while it was being sent
        if (flags.get(entry.itemId)?.kind === "missing_on_server") acked.add(entry.itemId);
        if (answer.rev !== entry.baseRev + 1) {
          warn("unexpected_rev", { id: entry.itemId, rev: answer.rev, expected: entry.baseRev + 1 });
        }
        changed([entry.itemId]); // `pending` may have turned false
        void syncNow(); // bring our own row back with its `seq`
      },
      onRetry: (entry, delayMs, error) => setStatus("retrying", { id: entry.itemId, inMs: delayMs, code: error.code }),
      onBlocked: (entry, error, kind) => {
        if (kind === "unauthorized") {
          paused = true;
          setStatus("unauthorized");
          return;
        }
        if (abandoned.has(entry.itemId) || droppedIdems.has(entry.idem)) return;
        /** @type {Record<string, any>} */
        const detail = { code: kind === "conflict" ? "conflict" : error.code, id: entry.itemId };
        if (kind === "conflict") {
          const current = error.body?.current_rev;
          if (Number.isSafeInteger(current)) detail.currentRev = current;
          detail.deleted = error.body?.deleted === true;
        }
        // The item is blocked: the draft stays in the outbox, the screen goes
        // back to the server's version, and nothing more is queued behind it.
        blocked.set(entry.itemId, detail.code);
        flagsDirty = true;
        overlay.delete(entry.itemId);
        void persistFlags();
        void showServerVersion(entry.itemId).then(persistFlags);
        emit("error", detail);
        // A 409 on a deleted item carries no tombstone, and a live one carries a
        // row without a `seq`: both come through the feed, where they are checked.
        if (kind === "conflict") void syncNow();
      },
      onStorageError: () => emit("error", { code: "storage" }),
    },
  });

  // ----------------------------------------------------------- the feed

  /** Reads the feed from the cursor to its end. */
  async function cycle() {
    const db = await store.open();
    let since = cursor;
    let restarted = false;
    for (;;) {
      /** @type {any} */
      let page;
      try {
        page = await api.get(`/api/sync/changes?since=${since}&limit=${PAGE_LIMIT}`, { shape: "changes_res" });
      } catch (error) {
        if (/** @type {any} */ (error)?.code === "gone" && !restarted) {
          restarted = true; // the cursor is below the floor: list the vault again
          since = 0;
          cursor = 0;
          listing = new Set();
          continue;
        }
        throw error;
      }
      if (stopped) return;
      checkPage(page, since);
      await applyPage(db, page.changes);
      if (stopped) return;
      if (page.changes.length > 0) {
        since = page.changes[page.changes.length - 1].seq; // the last row, not latest_seq
        cursor = since;
      }
      if (!page.has_more) break;
    }
    if (listing !== null) await finishListing(db);
  }

  /**
   * What a page must look like for the engine to go on.
   * @param {any} page @param {number} since
   */
  function checkPage(page, since) {
    if (page.vk_epoch !== scope.vkEpoch) throw new SyncError("epoch_mismatch");
    let last = since;
    for (const change of page.changes) {
      if (change.seq <= last) throw new SyncError("bad_feed"); // not strictly rising: the loop could never end
      last = change.seq;
    }
    if (page.has_more && page.changes.length === 0) throw new SyncError("bad_feed");
    // The server shows fewer changes than this device has seen: a restore, or a
    // rollback. Say so; nothing is lowered.
    if (restoreEpoch !== null && restoreEpoch !== page.restore_epoch) {
      warn("server_restored", { from: restoreEpoch, to: page.restore_epoch });
    } else if (page.latest_seq < cursor && behind !== `${page.latest_seq}/${cursor}`) {
      behind = `${page.latest_seq}/${cursor}`;
      warn("server_behind", { latestSeq: page.latest_seq, cursor });
    }
    restoreEpoch = page.restore_epoch;
  }

  /** @param {any} db @param {any[]} changes */
  async function applyPage(db, changes) {
    /** @type {CachedRow[]} */
    const accepted = [];
    /** @type {Set<string>} */
    const touched = new Set();
    /** Marks that end with this page; they go only after the rows are in the cache. @type {Map<string, "clear" | "drop">} */
    const ending = new Map();
    /** The rows this page replaced, to put back when the cache write fails. @type {Map<string, CachedRow | undefined>} */
    const replaced = new Map();
    /** @param {string} itemId @param {CachedRow} next */
    const setRow = (itemId, next) => {
      if (!replaced.has(itemId)) replaced.set(itemId, rows.get(itemId));
      rows.set(itemId, next);
    };
    for (const change of changes) {
      if (stopped) return;
      const id = /** @type {string} */ (change.id);
      listing?.add(id);
      if (abandoned.has(id)) continue;
      /** @type {CachedRow} */
      let row;
      try {
        row = rowOfChange(change);
      } catch (error) {
        // A row that is not even a well-formed live row or tombstone: the item is damaged, the pass goes on.
        if (!hex16.is(id) || !Number.isSafeInteger(change.rev)) throw error;
        const floor = floorOf(id);
        if (floor !== null && change.rev <= floor) {
          warn("rev_lower_than_local", { id, rev: change.rev, localRev: floor });
          continue;
        }
        markDamaged(id, change.rev, "malformed");
        touched.add(id);
        continue;
      }
      let local = rows.get(id);
      const mark = flags.get(id);
      let ours = false;
      if ((mark?.kind === "missing_on_server" || mark?.kind === "reuploaded") && row.rev <= mark.rev) {
        // At or below the floor of an item that was uploaded again: only a row this device wrote is accepted.
        const key = await ownKeyOf(row);
        alive();
        if (mark.sent?.includes(key)) {
          ours = true;
          // Only the row that replaces the old one skips the check against the local row; a replay of an own
          // earlier version still has to be above what this device has now.
          if (mark.kind === "missing_on_server" && local && local.rev === mark.rev) local = undefined;
        } else if (row.rev < mark.rev) {
          warn("rev_lower_than_local", { id, rev: row.rev, localRev: mark.rev });
          continue;
        } else if (mark.kind === "missing_on_server" && !row.deleted && local && sameRow(row, local)) {
          // The server shows the item again with the row this device has: it was only left out.
          ending.set(id, "clear");
          accepted.push(row);
          touched.add(id);
          continue;
        } else {
          // Exactly the old floor, and not a row this device wrote: no honest path leads here.
          warn("rev_same_row_changed", { id, rev: row.rev });
          continue;
        }
      }
      if (local) {
        if (row.rev < local.rev) {
          warn("rev_lower_than_local", { id, rev: row.rev, localRev: local.rev });
          continue;
        }
        if (row.rev === local.rev) {
          if (sameRow(row, local)) accepted.push(row); // already known: only make sure it is cached
          else warn("rev_same_row_changed", { id, rev: row.rev });
          continue;
        }
      }
      if (id === MANIFEST_ID) {
        setRow(id, row); // kept in the cache, never an item
        accepted.push(row);
        continue;
      }
      if (row.deleted) {
        try {
          await client.vault.verify_tombstone(hex16.decode(id), row.rev, /** @type {Uint8Array} */ (row.tomb));
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
          // A mark that keeps a floor is not replaced: the floor would go with it.
          if (!keepsFloor(id)) {
            flags.set(id, { kind: "quarantined", rev: row.rev });
            flagsDirty = true;
          }
          touched.add(id);
          warn("tombstone_unverified", { id, rev: row.rev });
          continue;
        }
        alive();
        settleMark(id, row.rev, ours, ending);
        setRow(id, row);
        accepted.push(row);
        index.delete(id);
        overlay.delete(id);
        touched.add(id);
        continue;
      }
      try {
        const summary = await summarize(id, row.rev, /** @type {Uint8Array} */ (row.envelope), /** @type {Uint8Array} */ (row.tag));
        alive();
        settleMark(id, row.rev, ours, ending);
        setRow(id, row);
        accepted.push(row);
        const mine = overlay.get(id);
        if (mine && mine.rev > row.rev) {
          // A local write is ahead of this row: it stays on screen.
        } else {
          overlay.delete(id);
          index.set(id, summary);
        }
      } catch (error) {
        if (stopped || isFatal(error)) throw error;
        markDamaged(id, row.rev, codeOf(error));
      }
      touched.add(id);
    }
    if (accepted.length > 0) {
      try {
        await store.cache.putRows(db, scope, accepted);
      } catch (error) {
        // Not cached: the rows go back to what they were, and the marks stay, so the next pass does it all again.
        for (const [itemId, previous] of replaced) {
          if (previous) rows.set(itemId, previous);
          else rows.delete(itemId);
        }
        throw error;
      }
    }
    // A mark that keeps a floor ends only now that the row that ends it is stored.
    for (const [itemId, how] of ending) {
      if (how === "clear") await clearMissing(itemId);
      else flags.delete(itemId);
      flagsDirty = true;
    }
    await saveFlags(db);
    changed(touched);
  }

  /** @param {string} id @param {number} rev @param {string} reason */
  function markDamaged(id, rev, reason) {
    // A mark that keeps a floor or says "deleted, not verified" is not replaced by "damaged".
    if (!flags.has(id) || flags.get(id)?.kind === "damaged") {
      flags.set(id, { kind: "damaged", rev });
      flagsDirty = true;
      if (!index.has(id)) index.set(id, summaryOf({}, rev)); // nothing good to show
    }
    warn("row_damaged", { id, rev, reason });
  }

  /** Whether the item has a mark that holds the floor of an item uploaded again. @param {string} id */
  function keepsFloor(id) {
    const kind = flags.get(id)?.kind;
    return kind === "missing_on_server" || kind === "reuploaded";
  }

  /**
   * The highest revision this device holds for an item, or null when it holds none.
   * @param {string} id
   */
  function floorOf(id) {
    const mark = flags.get(id);
    const kept = mark?.kind === "missing_on_server" || mark?.kind === "reuploaded" ? mark.rev : -1;
    const known = rows.get(id)?.rev ?? -1;
    const floor = Math.max(kept, known);
    return floor < 0 ? null : floor;
  }

  /**
   * An accepted row settles the mark of its item. A row this device wrote
   * itself, below the old floor, leaves the item `reuploaded` with the old
   * floor; a row at or above the floor ends the mark (rows then hold the floor),
   * and, if the item was only left out of a listing, the upload queued for it.
   * A mark that holds a floor is not removed here but listed in `ending`: the
   * caller removes it after the row has been written to the cache.
   * @param {string} id @param {number} rev @param {boolean} ours @param {Map<string, "clear" | "drop">} ending
   */
  function settleMark(id, rev, ours, ending) {
    const mark = flags.get(id);
    if (!mark) return;
    if (ours && (mark.kind === "missing_on_server" || mark.kind === "reuploaded") && rev < mark.rev) {
      flags.set(id, { kind: "reuploaded", rev: mark.rev, sent: mark.sent });
    } else if (mark.kind === "missing_on_server") {
      ending.set(id, "clear");
    } else if (mark.kind === "reuploaded") {
      ending.set(id, "drop");
    } else {
      flags.delete(id);
    }
    flagsDirty = true;
  }

  /**
   * The server shows the item (again): the mark goes, and so does the upload
   * that was queued for it, which nobody asked for.
   * @param {string} id
   */
  async function clearMissing(id) {
    if (flags.get(id)?.kind === "missing_on_server") flags.delete(id);
    flagsDirty = true;
    acked.delete(id);
    try {
      for (const idem of await runner.discard(id)) droppedIdems.add(idem);
      blocked.delete(id);
    } catch {
      emit("error", { code: "storage" });
    }
  }

  /**
   * After a full listing from 0: nothing is deleted. Items the listing did not
   * show stay (rows, cache and revision floors), are marked, and are queued for
   * upload again; only `discardMissing` removes one, on the user's word. A
   * server can hide items to make the user throw away the only copy.
   * @param {any} db
   */
  async function finishListing(db) {
    const seen = /** @type {Set<string>} */ (listing);
    listing = null;
    /** @type {string[]} */
    const missing = [];
    for (const [id, row] of rows) {
      if (seen.has(id) || id === MANIFEST_ID || row.deleted || flags.has(id)) continue;
      flags.set(id, { kind: "missing_on_server", rev: row.rev });
      flagsDirty = true;
      missing.push(id);
    }
    if (missing.length === 0) return;
    await saveFlags(db);
    warn("missing_on_server", { count: missing.length });
    changed(missing);
  }

  /**
   * Queues the local copy of a missing item as a new write (revision 1 against
   * nothing), unless one is queued, was answered, or is being made. The digest
   * of what is sent is saved with the mark before the write is stored, so the
   * row that comes back is recognised as ours. The floor of the old revision
   * stays in the mark.
   * @param {string} id
   */
  async function uploadAgain(id) {
    const row = rows.get(id);
    const mark = flags.get(id);
    if (
      !row || row.deleted || mark?.kind !== "missing_on_server" || runner.entriesOf(id).length > 0 ||
      blocked.has(id) || acked.has(id) || sealing.has(id) || abandoned.has(id)
    ) return;
    sealing.add(id);
    try {
      if (row.rev <= mark.rev && mark.sent?.includes(await ownKeyOf(row))) {
        // The cache holds the copy this device uploaded (a restart came between caching it and saving the mark): finish the change.
        alive();
        if (row.rev === mark.rev) {
          flags.delete(id); // the copy is at the old floor itself: the rows hold it now
          acked.delete(id);
        } else {
          flags.set(id, { kind: "reuploaded", rev: mark.rev, sent: mark.sent });
        }
        flagsDirty = true;
        await persistFlags();
        return;
      }
      const handle = await client.vault.open_item(hex16.decode(id), row.rev, row.envelope, row.tag);
      /** @type {{ envelope: Uint8Array, tag: Uint8Array }} */
      let sealed;
      try {
        sealed = await client.vault.encrypt_item(hex16.decode(id), 1, {}, handle, now());
      } finally {
        await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
      }
      alive();
      if (flags.get(id)?.kind !== "missing_on_server" || abandoned.has(id)) return;
      await queue(id, 0, { blob: sealed.envelope, tag: sealed.tag }, null, null);
    } catch (error) {
      if (stopped || isFatal(error)) return;
      emit("error", { code: "upload_again_failed", id });
    } finally {
      sealing.delete(id);
    }
  }

  /**
   * @param {Uint8Array} first @param {Uint8Array} second @param {number} [domain] 1 for a sealed row, 2 for a tombstone
   */
  async function digestOf(first, second, domain = 1) {
    const all = new Uint8Array(1 + first.length + second.length);
    all[0] = domain;
    all.set(first, 1);
    all.set(second, 1 + first.length);
    return b64u.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", all)));
  }

  /** The name of a write in the `sent` list of a mark. @param {number} rev @param {{ blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }} body */
  async function ownKeyOfBody(rev, body) {
    return "tomb" in body
      ? `${rev}:t:${await digestOf(body.tomb, new Uint8Array(0), 2)}`
      : `${rev}:r:${await digestOf(body.blob, body.tag)}`;
  }

  /** @param {CachedRow} row */
  function ownKeyOf(row) {
    return row.deleted
      ? ownKeyOfBody(row.rev, { tomb: /** @type {Uint8Array} */ (row.tomb) })
      : ownKeyOfBody(row.rev, { blob: /** @type {Uint8Array} */ (row.envelope), tag: /** @type {Uint8Array} */ (row.tag) });
  }

  /** What the screen shows for an item whose write was refused: the server's version. @param {string} id */
  async function showServerVersion(id) {
    const row = rows.get(id);
    try {
      if (row && !row.deleted) {
        const summary = await summarize(id, row.rev, /** @type {Uint8Array} */ (row.envelope), /** @type {Uint8Array} */ (row.tag));
        alive();
        if (rows.get(id) === row) index.set(id, summary); // the feed may have moved on meanwhile
      } else if (row?.deleted) {
        index.delete(id);
      }
      // No server row at all: a draft the server never took. Its summary stays, marked blocked.
    } catch {
      // The marks still say what is wrong; the list keeps what it has.
    }
    changed([id]);
  }

  async function persistFlags() {
    if (stopped) return;
    try {
      await saveFlags(await store.open());
    } catch (error) {
      if (!stopped) emit("error", { code: "storage" });
    }
  }

  /** Saves run one after the other, so a save that finds nothing dirty knows that the one before it has finished. @type {Promise<void>} */
  let saveChain = Promise.resolve();

  /** @param {any} db @returns {Promise<void>} */
  function saveFlags(db) {
    const run = saveChain.then(() => writeFlags(db));
    saveChain = run.catch(() => {});
    return run;
  }

  /** @param {any} db */
  async function writeFlags(db) {
    // After a lock the maps are empty: saving them would wipe the marks that are stored.
    if (!flagsDirty || stopped) return;
    flagsDirty = false;
    try {
      if (flags.size === 0 && blocked.size === 0) {
        await store.deleteSetting(db, flagsKey);
        return;
      }
      await store.setSetting(db, flagsKey, { v: 1, marks: Object.fromEntries(flags), blocked: Object.fromEntries(blocked) });
    } catch (error) {
      flagsDirty = true; // not saved: the next save writes it
      throw error;
    }
  }

  /** One pass: the feed. Failures become events; they never reject. */
  async function runCycle() {
    setStatus("syncing");
    try {
      await cycle();
      if (stopped) return;
      // Only after a pass that read the whole feed: an item that is still missing and has no upload under way is uploaded.
      for (const [id, mark] of [...flags]) if (mark.kind === "missing_on_server") await uploadAgain(id);
      if (stopped) return;
      if (paused) {
        paused = false;
        runner.resume();
        schedule();
      }
      setStatus("idle", { at: now() });
    } catch (error) {
      if (stopped) return;
      const code = codeOf(error);
      const status = /** @type {any} */ (error)?.status;
      if (status === 401) {
        paused = true;
        setStatus("unauthorized");
      } else if (error instanceof SyncError || isFatal(error) || code === "gone" || code === "bad_request" || code.startsWith("malformed") || (code === "bad_response" && status >= 200 && status < 300)) {
        setStatus("failed", { code });
        emit("error", { code });
      } else if (typeof status === "number") {
        setStatus("offline", { code });
      } else {
        // A failure of the local store, or a bug: say so, do not look offline.
        setStatus("failed", { code });
        emit("error", { code });
      }
    }
  }

  /** Reads the feed now. Calls that arrive while a pass runs make it run once more. @returns {Promise<void>} */
  function syncNow() {
    if (stopped) return Promise.resolve();
    if (inflight) {
      again = true;
      return inflight;
    }
    inflight = (async () => {
      try {
        do {
          again = false;
          await runCycle();
        } while (again && !stopped);
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  function schedule() {
    if (stopped || paused || pollTimer !== null) return;
    pollTimer = timers.set(async () => {
      pollTimer = null;
      await syncNow();
      schedule();
    }, pollMs);
  }

  const onFocus = () => {
    void syncNow();
  };
  const FOCUS_EVENTS = ["focus", "online"];

  // --------------------------------------------------------------- writes

  /**
   * Runs `work` after every earlier write of the same item has composed its
   * entry: revisions of one item are handed out in order. Other items are not
   * held up.
   * @template T
   * @param {string} id @param {() => Promise<T>} work @returns {Promise<T>}
   */
  function withItem(id, work) {
    const before = itemQueues.get(id) ?? Promise.resolve();
    const run = before.then(work, work);
    const tail = run.catch(() => {});
    itemQueues.set(id, tail);
    void tail.then(() => {
      if (itemQueues.get(id) === tail) itemQueues.delete(id);
    });
    return run;
  }

  /**
   * The newest version of an item that this device knows: a local write that
   * the feed has not confirmed, else the server's row.
   * @param {string} id
   * @returns {{ rev: number, deleted: boolean, envelope: Uint8Array | null, tag: Uint8Array | null } | null}
   */
  function newest(id) {
    const mine = overlay.get(id);
    const row = rows.get(id);
    if (mine && (!row || mine.rev > row.rev)) return mine;
    return row ?? null;
  }

  /**
   * A live item that may be edited, with its newest version.
   * @param {string} id
   */
  function editable(id) {
    if (typeof id !== "string" || !hex16.is(id) || id === MANIFEST_ID) throw new SyncError("not_found");
    const why = blocked.get(id);
    // A refused write is still in the outbox: a new one would only queue behind it.
    if (why !== undefined) throw new SyncError("blocked", "blocked", why);
    const flag = flags.get(id);
    if (flag && flag.kind !== "reuploaded") throw new SyncError(flag.kind);
    const version = newest(id);
    if (!version || version.deleted || !index.has(id)) throw new SyncError("not_found");
    if (index.get(id)?.readOnly) throw new SyncError("read_only");
    return /** @type {{ rev: number, deleted: boolean, envelope: Uint8Array, tag: Uint8Array }} */ (version);
  }

  /** @returns {string} 32 hex characters from the random source */
  const randomId = () => hex16.encode(rand(new Uint8Array(16)));

  /**
   * Queues a write whose entry is ready: the outbox first, then the screen.
   * @param {string} id @param {number} baseRev
   * @param {{ blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }} body
   * @param {{ rev: number, deleted: boolean, envelope: Uint8Array | null, tag: Uint8Array | null } | null} next what the item is after the write; null leaves the screen as it is (an upload of a missing item)
   * @param {ReturnType<typeof summaryOf> | null} summary null for a deletion
   */
  async function queue(id, baseRev, body, next, summary) {
    const idem = randomId();
    const request =
      "tomb" in body
        ? { base_rev: baseRev, deleted: true, tomb: b64u.encode(body.tomb), idem }
        : { base_rev: baseRev, blob: b64u.encode(body.blob), tag: b64u.encode(body.tag), idem };
    const bytes = encodeWireBytes("put_item_req", request);
    const kept = flags.get(id)?.kind;
    const key = kept === "missing_on_server" || kept === "reuploaded" ? await ownKeyOfBody(baseRev + 1, body) : null;
    alive();
    const why = blocked.get(id);
    if (why !== undefined) throw new SyncError("blocked", "blocked", why); // a refusal came in while this write was being made
    const mark = flags.get(id);
    if (key !== null && mark && (mark.kind === "missing_on_server" || mark.kind === "reuploaded")) {
      const previousSent = mark.sent;
      mark.sent = [...(previousSent ?? []), key].slice(-256);
      flagsDirty = true;
      try {
        // Saved before the write is stored, and a failed save stops the write: without its key the row would be
        // refused when it comes back. A crash in between leaves a key nobody used, which is harmless.
        await saveFlags(await store.open());
      } catch (error) {
        mark.sent = previousSent;
        throw error;
      }
      alive();
    }
    const before = { overlay: overlay.get(id), index: index.get(id) };
    if (next) {
      overlay.set(id, next);
      if (summary) index.set(id, summary);
      else index.delete(id);
    }
    try {
      await runner.enqueue({ idem, itemId: id, baseRev, body, bytes });
    } catch (error) {
      // Not stored, so not sent: the screen goes back to what it showed.
      if (next) {
        if (before.overlay) overlay.set(id, before.overlay);
        else overlay.delete(id);
        if (before.index) index.set(id, before.index);
        else index.delete(id);
      }
      throw error;
    }
    changed([id]);
  }

  /** The seal of a draft at `rev`. @param {string} id @param {number} rev @param {object} draft @param {number | undefined} handle */
  async function seal(id, rev, draft, handle) {
    const sealed = await client.vault.encrypt_item(hex16.decode(id), rev, draft, handle, now());
    const summary = await summarize(id, rev, sealed.envelope, sealed.tag);
    return { sealed, summary };
  }

  // -------------------------------------------------------------- the API

  const engine = {
    async start() {
      if (started || stopped) throw new SyncError("invalid_state");
      started = true;
      const db = await store.open();
      const cached = /** @type {CachedRow[]} */ (await store.cache.getRows(db, scope));
      const saved = await store.getSetting(db, flagsKey);
      alive();
      for (const row of cached) {
        rows.set(row.itemId, row);
        cursor = Math.max(cursor, row.seq);
      }
      const savedMarks = saved?.v === 1 && saved.marks && typeof saved.marks === "object" ? saved.marks : {};
      for (const [id, flag] of Object.entries(savedMarks)) {
        const kinds = ["damaged", "quarantined", "missing_on_server", "reuploaded"];
        if (hex16.is(id) && kinds.includes(flag?.kind) && Number.isSafeInteger(flag.rev)) {
          const sent = Array.isArray(flag.sent) ? flag.sent.filter((/** @type {unknown} */ k) => typeof k === "string").slice(-256) : [];
          flags.set(id, { kind: flag.kind, rev: flag.rev, ...(sent.length > 0 ? { sent } : {}) });
        }
      }
      const savedBlocked = saved?.v === 1 && saved.blocked && typeof saved.blocked === "object" ? saved.blocked : {};
      for (const [id, code] of Object.entries(savedBlocked)) {
        if (hex16.is(id) && typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code)) blocked.set(id, code);
      }
      for (const row of cached) {
        if (row.deleted || row.itemId === MANIFEST_ID) continue;
        try {
          const summary = await summarize(row.itemId, row.rev, /** @type {Uint8Array} */ (row.envelope), /** @type {Uint8Array} */ (row.tag));
          alive();
          index.set(row.itemId, summary);
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
          if (!flags.has(row.itemId)) {
            flags.set(row.itemId, { kind: "damaged", rev: row.rev });
            flagsDirty = true;
          }
          index.set(row.itemId, summaryOf({}, row.rev));
        }
      }
      for (const [id, flag] of [...flags]) {
        // A flag needs its item: a damaged one may have no good version, but a quarantine keeps one.
        if (!rows.has(id) && flag.kind === "quarantined") flags.delete(id);
        else if (!index.has(id) && !rows.get(id)?.deleted) index.set(id, summaryOf({}, flag.rev)); // an own delete below the floor shows nothing
      }
      await saveFlags(db);
      if (stopped) return;

      // Writes that were queued before the restart show as pending, newest last.
      const queued = await runner.load();
      alive();
      for (const id of [...blocked.keys()]) {
        // A block needs its draft: when the outbox no longer has one, the block is over.
        if (queued.some((entry) => entry.itemId === id)) runner.block(id);
        else {
          blocked.delete(id);
          flagsDirty = true;
        }
      }
      for (const entry of queued) {
        const rev = entry.baseRev + 1;
        if (rev <= (rows.get(entry.itemId)?.rev ?? 0)) continue; // the feed already has this item beyond the draft
        if (blocked.has(entry.itemId)) {
          // Refused for good before the restart: the server's version stays on screen; a draft of an item the server never took is shown.
          if (!rows.has(entry.itemId) && !("tomb" in entry.body)) {
            try {
              index.set(entry.itemId, await summarize(entry.itemId, rev, entry.body.blob, entry.body.tag));
            } catch (error) {
              if (stopped || isFatal(error)) throw error;
            }
          }
          continue;
        }
        try {
          if ("tomb" in entry.body) {
            overlay.set(entry.itemId, { rev, deleted: true, envelope: null, tag: null });
            index.delete(entry.itemId);
          } else {
            const { blob, tag } = entry.body;
            const summary = await summarize(entry.itemId, rev, blob, tag);
            alive();
            index.set(entry.itemId, summary);
            overlay.set(entry.itemId, { rev, deleted: false, envelope: blob, tag });
          }
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
          emit("error", { code: "draft_unreadable", id: entry.itemId });
        }
      }
      if (stopped) return;
      await saveFlags(db);
      changed(index.keys());
      runner.start();
      await syncNow();
      if (stopped) return;
      for (const name of FOCUS_EVENTS) win?.addEventListener?.(name, onFocus);
      schedule();
    },

    stop() {
      if (stopped) return;
      stopped = true;
      if (pollTimer !== null) timers.clear(pollTimer);
      pollTimer = null;
      for (const name of FOCUS_EVENTS) win?.removeEventListener?.(name, onFocus);
      runner.stop();
      for (const handle of handles) {
        try {
          Promise.resolve(client.vault.close_item(handle)).catch(() => {});
        } catch {
          // The worker is gone already: nothing is left to close.
        }
      }
      handles.clear();
      index.clear();
      overlay.clear();
      rows.clear();
      flags.clear();
      blocked.clear();
      acked.clear();
      sealing.clear();
      abandoned.clear();
      droppedIdems.clear();
      flagsDirty = false;
      itemQueues.clear();
      listing = null;
      for (const set of Object.values(listeners)) set.clear();
    },

    syncNow,

    /** @returns {ItemSummary[]} */
    list() {
      if (stopped) return [];
      /** @type {ItemSummary[]} */
      const out = [];
      for (const [id, s] of index) {
        const flag = flags.get(id);
        out.push({
          id,
          rev: s.rev,
          type: s.type,
          name: s.name,
          favorite: s.favorite,
          urls: [...s.urls],
          modified: s.modified,
          pending: runner.entriesOf(id).length > 0,
          damaged: flag?.kind === "damaged",
          quarantined: flag?.kind === "quarantined",
          missingOnServer: flag?.kind === "missing_on_server",
          blocked: blocked.has(id),
          blockedReason: blocked.get(id) ?? null,
          readOnly: s.readOnly,
        });
      }
      return out.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || (a.id < b.id ? -1 : 1));
    },

    /**
     * Opens an item for a screen. The view has no secret; the secrets are read
     * with `client.vault.reveal_*(handle, ...)`. Close the handle when done.
     * @param {string} id
     * @returns {Promise<{ handle: number, view: object, close(): Promise<void> }>}
     */
    async open(id) {
      if (stopped) throw new SyncError("stopped");
      const valid = typeof id === "string" && hex16.is(id) && id !== MANIFEST_ID;
      const version = valid ? newest(id) : null;
      if (!version) throw new SyncError(valid && flags.get(id)?.kind === "damaged" ? "damaged" : "not_found");
      if (version.deleted) throw new SyncError("not_found");
      const { envelope, tag } = version;
      if (!envelope || !tag) throw new SyncError("not_found");
      const handle = await client.vault.open_item(hex16.decode(id), version.rev, envelope, tag);
      if (stopped) {
        await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
        throw new SyncError("stopped");
      }
      handles.add(handle);
      const close = async () => {
        if (!handles.delete(handle)) return;
        await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
      };
      try {
        const view = await client.vault.item_view(handle);
        return { handle, view, close };
      } catch (error) {
        await close();
        throw error;
      }
    },

    /**
     * A new item from a draft (`item_type` and `name` are needed).
     * @param {object} draft
     * @returns {Promise<string>} the item id
     */
    async create(draft) {
      if (stopped) throw new SyncError("stopped");
      const id = randomId();
      await withItem(id, async () => {
        const { sealed, summary } = await seal(id, 1, draft, undefined);
        await queue(id, 0, { blob: sealed.envelope, tag: sealed.tag }, { rev: 1, deleted: false, envelope: sealed.envelope, tag: sealed.tag }, summary);
      });
      return id;
    },

    /**
     * Changes an item: the draft is applied to the newest version this device
     * has, inside the core. The write goes out as revision base + 1.
     * @param {string} id @param {object} draft
     */
    async update(id, draft) {
      if (stopped) throw new SyncError("stopped");
      await withItem(id, async () => {
        const version = editable(id);
        const rev = version.rev + 1;
        const handle = await client.vault.open_item(hex16.decode(id), version.rev, version.envelope, version.tag);
        try {
          const { sealed, summary } = await seal(id, rev, draft, handle);
          await queue(id, version.rev, { blob: sealed.envelope, tag: sealed.tag }, { rev, deleted: false, envelope: sealed.envelope, tag: sealed.tag }, summary);
        } finally {
          await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
        }
      });
    },

    /** Deletes an item: a tombstone at revision base + 1. @param {string} id */
    async remove(id) {
      if (stopped) throw new SyncError("stopped");
      await withItem(id, async () => {
        const version = editable(id);
        const rev = version.rev + 1;
        const made = await client.vault.make_tombstone(hex16.decode(id), rev);
        await queue(id, version.rev, { tomb: made.tomb }, { rev, deleted: true, envelope: null, tag: null }, null);
      });
    },

    /**
     * Drops the refused write of a blocked item and everything queued behind it,
     * and lets the item be edited again. The screen already shows the server's
     * version (or, for a draft the server never took, nothing is left).
     * @param {string} id
     */
    async discard(id) {
      if (stopped) throw new SyncError("stopped");
      if (typeof id !== "string" || !blocked.has(id)) throw new SyncError("not_found");
      await withItem(id, async () => {
        // The stored entries go first; the block stays until that has worked, so a failed store leaves the item blocked.
        for (const idem of await runner.discard(id)) droppedIdems.add(idem);
        alive();
        blocked.delete(id);
        flagsDirty = true;
        overlay.delete(id);
        if (!rows.has(id)) index.delete(id);
        await showServerVersion(id);
        await persistFlags();
      });
    },

    /**
     * Gives up an item that a full listing did not show, on the user's word:
     * the local copy, its row and its revision floor are removed, and so is
     * the upload that was queued for it (or is under way: its result is dropped).
     * @param {string} id
     */
    async discardMissing(id) {
      if (stopped) throw new SyncError("stopped");
      if (typeof id !== "string" || flags.get(id)?.kind !== "missing_on_server") throw new SyncError("not_found");
      abandoned.add(id);
      await withItem(id, async () => {
        for (const idem of await runner.discard(id)) droppedIdems.add(idem);
        alive();
        const db = await store.open();
        await store.cache.removeRows(db, scope, [id]);
        alive();
        rows.delete(id);
        index.delete(id);
        overlay.delete(id);
        flags.delete(id);
        blocked.delete(id);
        flagsDirty = true;
        await persistFlags();
        changed([id]);
      }).catch((error) => {
        abandoned.delete(id); // nothing was given up
        throw error;
      });
    },

    /**
     * @param {"changed" | "error" | "state"} event
     * @param {(payload: any) => void} fn
     * @returns {() => void} removes the listener
     */
    on(event, fn) {
      const set = listeners[event];
      if (!set) throw new TypeError(`no event named ${event}`);
      if (!stopped) set.add(fn);
      return () => {
        set.delete(fn);
      };
    },
  };

  return Object.freeze(engine);
}
