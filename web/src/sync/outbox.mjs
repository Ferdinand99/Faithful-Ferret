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
//     409 (`conflict`)              not done and not sent again: the draft stays
//                                   in the outbox and the engine hears of it
//     400, 403, 413, 422            refused for good: same, with the server's code
//     401                           sign in again: every lane waits for `resume()`
//     404 and any other answer      not sent again; the draft stays
// Nothing here reads or writes a decrypted field: an entry is ciphertext and
// public numbers.

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
 * What to do with a write that failed.
 *   retry         the server may not have seen it, or is busy: send it again
 *   conflict      409: another write got there first; keep the draft
 *   unauthorized  401: sign in again, then resume
 *   terminal      400, 403, 413, 422: sending it again cannot help
 *   other         404 and anything else not understood: do not send it again
 * @param {import("../api.mjs").ApiError} error
 * @returns {"retry" | "conflict" | "unauthorized" | "terminal" | "other"}
 */
export function classify(error) {
  if (!error || typeof error.status !== "number") return "retry";
  if (error.code === "conflict" || error.status === 409) return "conflict";
  if (error.status === 401) return "unauthorized";
  if (error.terminal) return "terminal";
  if (error.status === 0 || error.status >= 500 || error.status === 408 || error.status === 429) return "retry";
  // A 200 that did not read as a write answer is a proxy page or a broken server: the write may have gone through.
  if (error.code === "bad_response" && error.status >= 200 && error.status < 300) return "retry";
  return "other";
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
    if (stopped || lane.running || lane.timer !== null || lane.blocked !== null) return;
    lane.running = true;
    try {
      while (!stopped && lane.entries.length > 0 && lane.blocked === null) {
        const entry = lane.entries[0];
        /** @type {{ rev: number, seq: number, replayed: boolean }} */
        let answer;
        try {
          answer = await api.put(itemPath(entry.itemId), entry.bytes, { shape: "put_item_res" });
        } catch (error) {
          if (stopped) return;
          const err = /** @type {import("../api.mjs").ApiError} */ (error);
          const kind = classify(err);
          if (kind === "retry") {
            lane.attempt += 1;
            const delay = backoffMs(lane.attempt - 1, err.retryAfter);
            hooks.onRetry?.(entry, delay, err);
            lane.timer = timers.set(() => {
              lane.timer = null;
              void pump(itemId);
            }, delay);
            return;
          }
          lane.blocked = kind;
          hooks.onBlocked?.(entry, err, kind);
          return;
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
