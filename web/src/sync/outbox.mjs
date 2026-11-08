// The sender of the outbox: it takes the writes that the engine has queued and
// sends them to the server until the server has answered each one.
//
// * An entry is stored in IndexedDB (with its exact request bytes and its
//   idempotency key) before the first request is made. A retry sends those same
//   bytes under the same key, so a write whose answer was lost comes back as a
//   replay (`replayed: true`) and counts as done.
// * Writes to the same item go out one at a time, oldest first, because each
//   builds on the revision of the one before. Writes to different items are
//   independent: a retry wait or a conflict on one item never holds up another.
// * What the server answers decides what happens (the code is read, not the
//   status, because two codes can share a status):
//     200                           done: the entry leaves the outbox
//     network, 5xx, 408, 429, a      sent again with the same bytes after a wait
//       garbled answer               of 1, 2, 4, ... seconds (at most 60)
//     409 `restore_epoch_changed`  not a conflict, and the write was NOT stored: every
//                                   lane is held, the write stays at the head of its
//                                   lane unchanged, and the engine hears of it
//     409 (`conflict`)              done when it only shows our own write (see
//                                   `alreadyDone`); otherwise not done and not
//                                   sent again: the draft stays in the outbox and
//                                   the engine hears of it
//     400, 403, 413, 422            refused for good: same, with the server's code
//     401                           sign in again: every lane waits for `resume()`
//     404 and any other answer      not sent again; the draft stays
// Nothing here reads or writes a decrypted field: an entry is ciphertext and
// public numbers.
import { b64u } from "../b64.mjs";

/**
 * @typedef {import("../store/outbox.mjs").OutboxEntry} OutboxEntry
 * @typedef {import("../store/cache.mjs").Scope} Scope
 * @typedef {{ set(fn: () => void, ms: number): unknown, clear(handle: unknown): void }} Timers
 *
 * @typedef {object} Lane
 * @property {OutboxEntry[]} entries oldest first
 * @property {boolean} running a request is in flight
 * @property {unknown} timer the retry wait, when there is one
 * @property {number} attempt failed tries of the entry at the head
 * @property {string | null} blocked why the lane is not sent: `conflict`, `terminal`, `unauthorized`, `other`
 *
 * @typedef {object} Hooks
 * @property {(entry: OutboxEntry, answer: { rev: number, seq: number, replayed: boolean }) => void} [onDone] the server has the write
 * @property {(entry: OutboxEntry, error: import("../api.mjs").ApiError, kind: string) => void} [onBlocked] the write will not be sent again
 * @property {(entry: OutboxEntry, delayMs: number, error: import("../api.mjs").ApiError) => void} [onRetry] the write is sent again after the wait
 * @property {(error: unknown) => void} [onStorageError] the local store failed (the write is not lost: it goes out again after a restart)
 * @property {(entry: OutboxEntry, error: import("../api.mjs").ApiError) => void} [onRestoreEpochChanged] the server was restored
 *   (its restore epoch is not the one the write names): nothing is sent from any lane until `release()`, and the write has not been stored
 */

/** The longest wait between two tries of one write. */
export const MAX_BACKOFF_MS = 60_000;

/**
 * The wait before try number `attempt` + 1: 1, 2, 4, ... seconds, at most 60. A
 * `Retry-After` from the server can make it longer, still at most 60.
 * @param {number} attempt failed tries so far, from 0
 * @param {number | null} [retryAfter] seconds, from the server
 */
export function backoffMs(attempt, retryAfter = null) {
  const own = 1000 * 2 ** Math.min(attempt, 16);
  const asked = retryAfter === null ? 0 : retryAfter * 1000;
  return Math.min(MAX_BACKOFF_MS, Math.max(own, asked));
}

/**
 * Whether an answer says the write was refused because the restore epoch of the vault is not the one the write names: a 409
 * with the code `restore_epoch_changed` (an error of a single write) or a result of a batch in that form
 * (`{ status: 409, error: "restore_epoch_changed", restore_epoch }`). It is no conflict. The server checks the epoch after the
 * idempotency key and before anything is stored, so such a write was certainly not stored.
 * @param {unknown} answer
 */
export function isRestoreEpochChanged(answer) {
  const one = /** @type {any} */ (answer);
  if (one === null || typeof one !== "object") return false;
  return one.code === "restore_epoch_changed" || one.error === "restore_epoch_changed";
}

/**
 * What to do with a write that failed.
 *   retry         the server may not have seen it, or is busy: send it again
 *   epoch_changed 409 `restore_epoch_changed`: the server was restored; hold everything
 *   conflict      409: another write got there first; keep the draft
 *   unauthorized  401: sign in again, then resume
 *   terminal      400, 403, 413, 422: sending it again cannot help
 *   other         404 and anything else not understood: do not send it again
 * @param {import("../api.mjs").ApiError} error
 * @returns {"retry" | "epoch_changed" | "conflict" | "unauthorized" | "terminal" | "other"}
 */
export function classify(error) {
  if (!error || typeof error.status !== "number") return "retry";
  if (isRestoreEpochChanged(error)) return "epoch_changed"; // before the status: it is a 409, and no conflict
  if (error.code === "conflict" || error.status === 409) return "conflict";
  if (error.status === 401) return "unauthorized";
  if (error.terminal) return "terminal";
  if (error.status === 0 || error.status >= 500 || error.status === 408 || error.status === 429) return "retry";
  // A 200 that did not read as a write answer is a proxy page or a broken server: the write may have gone through.
  if (error.code === "bad_response" && error.status >= 200 && error.status < 300) return "retry";
  return "other";
}

/**
 * Whether a 409 only shows that the write is already on the server. The server keeps an idempotency key for 30 days; a
 * write that is sent again after that (the answer was lost) is judged against the row as it is now, and the row may be
 * the very one this write made. Two cases count as done:
 * - a live write, when the row in the 409 has the blob and the tag this write sent, byte for byte, at the revision it would have made;
 * - a tombstone, when the 409 says deleted at the revision this tombstone would have made (the tombstone itself is not in
 *   the 409, so nothing is compared here; the engine removes nothing locally until the feed brings a tombstone that verifies).
 * Anything else is a conflict.
 * Spec: Fase 1 section 8.3 ("Idempotency").
 * @param {OutboxEntry} entry @param {import("../api.mjs").ApiError} error
 * @returns {{ rev: number, seq: number, replayed: boolean } | null} the answer to report as done, or null
 */
export function alreadyDone(entry, error) {
  const body = /** @type {any} */ (error?.body);
  if (body === null || typeof body !== "object" || !Number.isSafeInteger(body.current_rev)) return null;
  const done = { rev: /** @type {number} */ (body.current_rev), seq: 0, replayed: true };
  if ("tomb" in entry.body) return body.deleted === true && body.current_rev === entry.baseRev + 1 ? done : null;
  if (body.deleted === true || typeof body.blob !== "string" || typeof body.tag !== "string") return null;
  if (body.current_rev !== entry.baseRev + 1) return null; // our write made that revision, and no other
  return body.blob === b64u.encode(entry.body.blob) && body.tag === b64u.encode(entry.body.tag) ? done : null;
}

/** The path of an item write. */
export const itemPath = (/** @type {string} */ itemId) => `/api/sync/items/${itemId}`;

/**
 * @param {{
 *   api: import("../api.mjs").Api,
 *   store: { open(): Promise<any>, outbox: typeof import("../store/outbox.mjs").outbox },
 *   scope: Scope,
 *   timers: Timers,
 *   hooks?: Hooks,
 * }} options
 */
export function createOutboxRunner({ api, store, scope, timers, hooks = {} }) {
  /** @type {Map<string, Lane>} */
  const lanes = new Map();
  let stopped = false;
  /** While held, entries are stored and queued but nothing is sent. */
  let held = false;
  /** Callers waiting for every request in flight to end. @type {Array<() => void>} */
  let idleWaiters = [];

  /** Wakes the callers of `whenIdle` once no lane has a request in flight. */
  function wakeIdle() {
    if ([...lanes.values()].some((lane) => lane.running)) return;
    const waiting = idleWaiters;
    idleWaiters = [];
    for (const wake of waiting) wake();
  }

  /** @param {string} itemId @returns {Lane} */
  function laneOf(itemId) {
    let lane = lanes.get(itemId);
    if (!lane) {
      lane = { entries: [], running: false, timer: null, attempt: 0, blocked: null };
      lanes.set(itemId, lane);
    }
    return lane;
  }

  /** @param {Lane} lane */
  function cancelWait(lane) {
    if (lane.timer !== null) timers.clear(lane.timer);
    lane.timer = null;
  }

  /** @param {string} itemId */
  async function pump(itemId) {
    const lane = laneOf(itemId);
    if (stopped || held || lane.running || lane.timer !== null || lane.blocked !== null) return;
    lane.running = true;
    try {
      while (!stopped && !held && lane.entries.length > 0 && lane.blocked === null) {
        const entry = lane.entries[0];
        /** @type {{ rev: number, seq: number, replayed: boolean }} */
        let answer;
        try {
          answer = await api.put(itemPath(entry.itemId), entry.bytes, { shape: "put_item_res" });
        } catch (error) {
          if (stopped) return;
          const err = /** @type {import("../api.mjs").ApiError} */ (error);
          const kind = classify(err);
          const settled = kind === "conflict" ? alreadyDone(entry, err) : null;
          if (settled !== null) {
            answer = settled; // the server already holds this very write: done, and no conflict is shown
          } else if (kind === "epoch_changed") {
            // The write was not stored (the epoch is checked before anything is). It stays as it is at the head of its lane; no lane
            // sends until the engine has looked at the server and lets go. Its bytes are never changed here: a write that may have been
            // stored must be sent again exactly as it was.
            held = true;
            hooks.onRestoreEpochChanged?.(entry, err);
            return;
          } else if (kind === "retry") {
            lane.attempt += 1;
            const delay = backoffMs(lane.attempt - 1, err.retryAfter);
            hooks.onRetry?.(entry, delay, err);
            lane.timer = timers.set(() => {
              lane.timer = null;
              void pump(itemId);
            }, delay);
            return;
          } else {
            lane.blocked = kind;
            hooks.onBlocked?.(entry, err, kind);
            return;
          }
        }
        if (stopped) return;
        lane.attempt = 0;
        lane.entries.shift();
        try {
          const db = await store.open();
          await store.outbox.remove(db, scope, entry.idem);
        } catch (error) {
          // The write is on the server. If the entry stays in the store it is
          // sent once more after a restart and comes back as a replay.
          hooks.onStorageError?.(error);
        }
        hooks.onDone?.(entry, answer);
      }
    } finally {
      lane.running = false;
      if (!stopped && lanes.get(itemId) === lane && lane.entries.length === 0 && lane.timer === null) lanes.delete(itemId);
      wakeIdle();
    }
  }

  return {
    /** Reads the stored entries (after a restart) and starts sending them. @returns {Promise<OutboxEntry[]>} */
    async load() {
      const db = await store.open();
      const entries = await store.outbox.all(db, scope);
      for (const entry of entries) laneOf(entry.itemId).entries.push(entry);
      return entries;
    },

    /**
     * Stores the entry, then starts sending it. The store write is done before
     * the first request is made.
     * @param {OutboxEntry} entry
     */
    async enqueue(entry) {
      const db = await store.open();
      await store.outbox.enqueue(db, scope, entry);
      if (stopped) return;
      laneOf(entry.itemId).entries.push(entry);
      void pump(entry.itemId);
    },

    /** Sends everything that is waiting for a first try (after `load`) or was not blocked. */
    start() {
      for (const itemId of [...lanes.keys()]) void pump(itemId);
    },

    /** Keeps everything from being sent until `release()`: entries are still stored and queued. A request in flight is not taken back. */
    hold() {
      held = true;
    },

    /** Resolves when no request is in flight (a request that was sent before `hold()` is not taken back). @returns {Promise<void>} */
    whenIdle() {
      if (![...lanes.values()].some((lane) => lane.running)) return Promise.resolve();
      return new Promise((resolve) => idleWaiters.push(resolve));
    },

    /**
     * Makes `entry` the only queued write of its item. The new entry is stored first and the old ones are removed after,
     * so a crash in between leaves the newest write (never none): the next start sees both and the last one wins. The lane
     * is not blocked afterwards, and nothing is sent while the runner is held.
     * @param {OutboxEntry} entry
     * @returns {Promise<string[]>} the idempotency keys of the writes that were dropped
     */
    async replace(entry) {
      await this.whenIdle();
      const db = await store.open();
      await store.outbox.enqueue(db, scope, entry);
      const old = (await store.outbox.all(db, scope)).filter((stored) => stored.itemId === entry.itemId && stored.idem !== entry.idem);
      for (const stored of old) await store.outbox.remove(db, scope, stored.idem);
      if (stopped) return [];
      const lane = laneOf(entry.itemId);
      const dropped = new Set([...old, ...lane.entries].filter((one) => one.idem !== entry.idem).map((one) => one.idem));
      cancelWait(lane);
      lane.entries.length = 0;
      lane.entries.push(entry);
      lane.attempt = 0;
      lane.blocked = null;
      void pump(entry.itemId);
      return [...dropped];
    },

    /**
     * Puts new entries in the place of the queued writes of an item, one for one and in the same order (the same writes made again,
     * for example with a new idempotency key and a new restore epoch). Only for writes the server has certainly not stored (it
     * refused them with `restore_epoch_changed`). The new entries are stored first and the old ones removed after, so a crash in
     * between leaves the writes (twice, never none). The lane is not blocked afterwards, and nothing is sent while the runner is held.
     * @param {string} itemId
     * @param {(entry: OutboxEntry) => OutboxEntry} remake
     * @returns {Promise<string[]>} the idempotency keys of the writes that were taken out
     */
    async restamp(itemId, remake) {
      await this.whenIdle();
      const lane = lanes.get(itemId);
      const old = [...(lane?.entries ?? [])];
      if (old.length === 0) return [];
      const next = old.map(remake);
      const db = await store.open();
      for (const entry of next) await store.outbox.enqueue(db, scope, entry);
      for (const entry of old) await store.outbox.remove(db, scope, entry.idem);
      if (stopped) return [];
      const now = lanes.get(itemId);
      if (now === undefined) return [];
      cancelWait(now);
      now.entries.splice(0, now.entries.length, ...next);
      now.attempt = 0;
      void pump(itemId);
      return old.map((entry) => entry.idem);
    },

    /** Lets the entries go out again after `hold()`. */
    release() {
      if (!held) return;
      held = false;
      for (const itemId of [...lanes.keys()]) void pump(itemId);
    },

    /** Lets the lanes that were stopped by a 401 try again (the user is signed in again). */
    resume() {
      for (const [itemId, lane] of lanes) {
        if (lane.blocked === "unauthorized") {
          lane.blocked = null;
          void pump(itemId);
        }
      }
    },

    /** Keeps the queue of an item from being sent (its first write was refused before a restart). @param {string} itemId */
    block(itemId) {
      laneOf(itemId).blocked = "other";
    },

    /**
     * Removes every queued write of an item (from the store too) and lets the item be written again.
     * @param {string} itemId
     * @returns {Promise<string[]>} the idempotency keys of the writes that were dropped
     */
    async discard(itemId) {
      // The store first, read by item (the lane may be gone already): if that fails, nothing in memory has changed.
      const db = await store.open();
      const stored = (await store.outbox.all(db, scope)).filter((entry) => entry.itemId === itemId);
      for (const entry of stored) await store.outbox.remove(db, scope, entry.idem);
      const lane = lanes.get(itemId);
      const idems = new Set([...stored, ...(lane?.entries ?? [])].map((entry) => entry.idem));
      if (lane) {
        cancelWait(lane);
        lane.entries.length = 0;
        lanes.delete(itemId);
      }
      return [...idems];
    },

    /** The queued entries of an item, oldest first (not yet confirmed by the server). @param {string} itemId */
    entriesOf(itemId) {
      return [...(lanes.get(itemId)?.entries ?? [])];
    },

    /** Item ids that have a queued write. */
    itemsWithEntries() {
      return [...lanes.entries()].filter(([, lane]) => lane.entries.length > 0).map(([id]) => id);
    },

    /** Stops every wait and every send. Entries stay in the store. */
    stop() {
      stopped = true;
      for (const lane of lanes.values()) cancelWait(lane);
      lanes.clear();
    },
  };
}
