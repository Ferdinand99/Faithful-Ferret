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
// * The writes of an import (an entry with the import mark, see `OutboxEntry.import`) go in batches instead: the head of each lane that
//   has one, at most 100 operations and 5 MiB to a request, to `POST /api/sync/batch` with the id of the import window they count
//   against. The answer of the server has one result for each operation, and each is handled as the answer to a `PUT` would be (the
//   table above), so an entry is done, retried, held or refused for itself. A batch that the server refuses as a whole with
//   `409 import_window_invalid` (the window ran out, or the server started again) holds every import lane: nothing of the import is sent
//   until `resumeImport` gives the entries that are left a new window, and the engine hears of it. The entries keep their keys and
//   bytes, so what the server may already have stored comes back as a replay. Writes that are not an import still go with `PUT`, also
//   to an item whose first write was part of an import, and an entry without the mark (one stored before the mark existed) is such a
//   write: it is never turned into a batch operation, because a key that was used by a single write is `idem_reuse` in a batch.
// Nothing here reads or writes a decrypted field: an entry is ciphertext and
// public numbers.
import { ApiError } from "../api.mjs";
import { b64u } from "../b64.mjs";
import { MAX_BATCH_OPS } from "../wire.mjs";
import { SyncError } from "./errors.mjs";

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
 * @property {(info: { remaining: number }) => void} [onImportWindowClosed] the server refused a batch because its import window is not valid
 *   (it ran out, or the server started again): the import lanes are held until `resumeImport`; `remaining` entries of the import are left
 * @property {() => void} [onBatchEnd] a batch has been answered and each of its entries handled (`onDone`, `onBlocked`, ...)
 */

/** The longest wait between two tries of one write. */
export const MAX_BACKOFF_MS = 60_000;

/** The most bytes of operations in one batch (the server takes 6 MiB; this leaves room for the rest of the body). */
export const MAX_BATCH_BYTES = 5 * 1024 * 1024;

/** The path of a batch. */
export const BATCH_PATH = "/api/sync/batch";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
 * The operation of a batch for an entry: the text of the request body of the single write with the item id in front of it. The same
 * entry always gives the same text.
 * @param {OutboxEntry} entry
 * @returns {string}
 */
export function batchOp(entry) {
  const text = decoder.decode(entry.bytes);
  if (!text.startsWith("{") || text.length < 3) throw new SyncError("outbox_entry", "an entry is a JSON object");
  return `{"id":"${entry.itemId}",${text.slice(1)}`;
}

/**
 * The body of a batch: the operations of `entries` and the window they count against.
 * @param {OutboxEntry[]} entries @param {string} window
 */
export function batchBody(entries, window) {
  return encoder.encode(`{"ops":[${entries.map(batchOp).join(",")}],"import_window":"${window}"}`);
}

/**
 * The error that the answer to one operation of a batch stands for, in the form the answer to a single write has: `classify` and
 * `alreadyDone` read it as they read that. A result is checked by the wire shape before this sees it.
 * @param {any} result
 */
export function errorOfResult(result) {
  if (result.status === 409 && result.error === "restore_epoch_changed") {
    return new ApiError(409, "restore_epoch_changed", null, { error: "restore_epoch_changed", restore_epoch: result.restore_epoch });
  }
  if (result.status === 409) {
    const { status: _status, ...row } = result;
    return new ApiError(409, "conflict", null, row);
  }
  return new ApiError(result.status, result.error, null, { error: result.error });
}

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
  /** A batch is being sent or its answer handled. */
  let batchRunning = false;
  /** The wait before the batch is sent again, when there is one. @type {unknown} */
  let batchTimer = null;
  /** Failed tries of the batch at the head of the import lanes. */
  let batchAttempt = 0;
  /** Why the import lanes are not sent: `window` (the server refused the window) or `unauthorized`; null when nothing stops them. @type {string | null} */
  let batchStop = null;

  /** Whether a request is in flight: a write of a lane, or a batch. */
  const requestInFlight = () => batchRunning || [...lanes.values()].some((lane) => lane.running);

  /** Wakes the callers of `whenIdle` once no lane has a request in flight. */
  function wakeIdle() {
    if (requestInFlight()) return;
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

  /** Sends what is waiting for an item: its writes one by one, or, when the one at its head is a write of an import, the import. @param {string} itemId */
  function wake(itemId) {
    if (lanes.get(itemId)?.entries[0]?.import !== undefined) void pumpBatch();
    else void pump(itemId);
  }

  /** @param {string} itemId */
  async function pump(itemId) {
    const lane = laneOf(itemId);
    if (stopped || held || lane.running || lane.timer !== null || lane.blocked !== null) return;
    if (lane.entries[0]?.import !== undefined) return; // an import goes in batches (`pumpBatch`)
    lane.running = true;
    try {
      while (!stopped && !held && lane.entries.length > 0 && lane.blocked === null) {
        const entry = lane.entries[0];
        if (entry.import !== undefined) break; // the write of an item after the import of it: the batch goes first
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
    if (!stopped && lane.entries[0]?.import !== undefined) void pumpBatch(); // an import entry came to the head of the lane
  }

  /**
   * The head of each lane that has a write of an import there and can be sent now, oldest lane first, all for one window: at most
   * `MAX_BATCH_OPS` operations and `MAX_BATCH_BYTES` bytes. A lane has one operation at most: two writes of one item in one batch are
   * refused as a whole by the server.
   * @returns {Array<{ lane: Lane, entry: OutboxEntry }>}
   */
  function pickBatch() {
    /** @type {Array<{ lane: Lane, entry: OutboxEntry }>} */
    const picked = [];
    let bytes = 0;
    /** @type {string | undefined} */
    let window;
    for (const lane of lanes.values()) {
      const entry = lane.entries[0];
      if (entry === undefined || entry.import === undefined || lane.running || lane.timer !== null || lane.blocked !== null) continue;
      if (window !== undefined && entry.import !== window) continue;
      const size = entry.bytes.length + 80; // the id, the comma
      if (picked.length > 0 && bytes + size > MAX_BATCH_BYTES) break;
      window = entry.import;
      bytes += size;
      picked.push({ lane, entry });
      if (picked.length >= MAX_BATCH_OPS) break;
    }
    return picked;
  }

  /** How many writes of an import are left in the lanes (not done, whether blocked or not). */
  function importEntriesLeft() {
    let count = 0;
    for (const lane of lanes.values()) for (const entry of lane.entries) if (entry.import !== undefined) count += 1;
    return count;
  }

  /** The batches of an import, one at a time, until none is left to send or something stops them. */
  async function pumpBatch() {
    if (stopped || held || batchRunning || batchTimer !== null || batchStop !== null) return;
    batchRunning = true;
    try {
      while (!stopped && !held && batchStop === null && batchTimer === null) {
        const picked = pickBatch();
        if (picked.length === 0) break;
        for (const { lane } of picked) lane.running = true;
        try {
          await sendBatch(picked);
        } finally {
          for (const { lane } of picked) lane.running = false;
        }
        hooks.onBatchEnd?.();
      }
    } finally {
      batchRunning = false;
      if (!stopped) for (const [itemId, lane] of [...lanes]) if (lane.entries.length === 0 && lane.timer === null && lanes.get(itemId) === lane) lanes.delete(itemId);
      wakeIdle();
    }
    // The writes that follow an import entry in its lane (an edit made meanwhile) go with PUT now.
    if (!stopped && !held) for (const [itemId, lane] of lanes) if (lane.entries.length > 0 && lane.entries[0].import === undefined) void pump(itemId);
  }

  /**
   * Sends one batch and handles the answer. A failure of the whole request is handled like the failure of a write (retry after a wait,
   * sign in again, refused for good), except `409 import_window_invalid`: nothing is wrong with the entries, the import waits for a window.
   * @param {Array<{ lane: Lane, entry: OutboxEntry }>} picked
   */
  async function sendBatch(picked) {
    const window = /** @type {string} */ (picked[0].entry.import);
    /** @type {any} */
    let answer;
    try {
      answer = await api.post(BATCH_PATH, batchBody(picked.map((one) => one.entry), window), { shape: "batch_res" });
      if (!Array.isArray(answer?.results) || answer.results.length !== picked.length) {
        throw new ApiError(200, "bad_response"); // not an answer to this batch: the writes may be stored, and are sent again as they were
      }
    } catch (error) {
      if (stopped) return;
      const err = error instanceof ApiError ? error : new ApiError(0, "network");
      if (err.status === 409 && err.code === "import_window_invalid") {
        batchStop = "window";
        hooks.onImportWindowClosed?.({ remaining: importEntriesLeft() });
        return;
      }
      const kind = classify(err);
      if (kind === "retry") {
        batchAttempt += 1;
        const delay = backoffMs(batchAttempt - 1, err.retryAfter);
        hooks.onRetry?.(picked[0].entry, delay, err);
        batchTimer = timers.set(() => {
          batchTimer = null;
          void pumpBatch();
        }, delay);
        return;
      }
      if (kind === "unauthorized") {
        batchStop = "unauthorized";
        hooks.onBlocked?.(picked[0].entry, err, "unauthorized");
        return;
      }
      // Refused as a whole, for good (a body the server cannot take, or an answer nobody knows): none of its entries is sent again.
      for (const { lane, entry } of picked) {
        lane.blocked = kind === "other" ? "other" : "terminal";
        hooks.onBlocked?.(entry, err, lane.blocked);
      }
      return;
    }
    if (stopped) return;
    /** @type {Array<{ lane: Lane, entry: OutboxEntry, answer: { rev: number, seq: number, replayed: boolean } }>} */
    const done = [];
    /** @type {{ entry: OutboxEntry, error: ApiError } | null} */
    let retry = null;
    for (let at = 0; at < picked.length; at += 1) {
      const { lane, entry } = picked[at];
      const result = answer.results[at];
      if (result.status === 200) {
        done.push({ lane, entry, answer: { rev: result.rev, seq: result.seq, replayed: result.replayed === true } });
        continue;
      }
      const err = errorOfResult(result);
      const kind = classify(err);
      const settled = kind === "conflict" ? alreadyDone(entry, err) : null;
      if (settled !== null) {
        done.push({ lane, entry, answer: settled });
      } else if (kind === "epoch_changed") {
        held = true; // the write was not stored: it stays at the head of its lane unchanged, and the engine hears of it
        hooks.onRestoreEpochChanged?.(entry, err);
      } else if (kind === "retry") {
        retry ??= { entry, error: err };
      } else if (kind === "unauthorized") {
        batchStop = "unauthorized";
        hooks.onBlocked?.(entry, err, "unauthorized");
      } else {
        lane.blocked = kind;
        hooks.onBlocked?.(entry, err, kind);
      }
    }
    for (const { lane, entry } of done) if (lane.entries[0] === entry) lane.entries.shift();
    if (done.length > 0) {
      try {
        const db = await store.open();
        await store.outbox.removeMany(db, scope, done.map((one) => one.entry.idem));
      } catch (error) {
        // The writes are on the server. Entries that stay in the store are sent once more after a restart and come back as replays.
        hooks.onStorageError?.(error);
      }
    }
    for (const { entry, answer: one } of done) hooks.onDone?.(entry, one);
    if (retry !== null && !stopped) {
      batchAttempt += 1;
      const delay = backoffMs(batchAttempt - 1, retry.error.retryAfter);
      hooks.onRetry?.(retry.entry, delay, retry.error);
      batchTimer = timers.set(() => {
        batchTimer = null;
        void pumpBatch();
      }, delay);
    } else {
      batchAttempt = 0;
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
      wake(entry.itemId);
    },

    /**
     * Stores the writes of an import, then starts sending them in batches. They are all stored (a few hundred to a transaction) before the
     * first request is made; a write that fails the check of the store keeps the whole call from storing the chunk it is in, and the
     * call throws. Each entry has the import mark.
     * @param {OutboxEntry[]} entries
     */
    async enqueueMany(entries) {
      if (entries.some((entry) => entry.import === undefined)) throw new TypeError("the writes of an import carry the import mark");
      const db = await store.open();
      try {
        await store.outbox.enqueueMany(db, scope, entries);
      } catch (error) {
        // Chunks before the one that failed are stored: they are taken out again, so a call that failed has stored nothing (best effort).
        try {
          await store.outbox.removeMany(db, scope, entries.map((entry) => entry.idem));
        } catch {
          // The next start sends what is left, as any queued write.
        }
        throw error;
      }
      if (stopped) return;
      for (const entry of entries) laneOf(entry.itemId).entries.push(entry);
      void pumpBatch();
    },

    /**
     * Gives every write of an import that is still queued the window `windowId` and lets the import go on: the server refused the window
     * (`onImportWindowClosed`), or the page was reloaded after the window had run out. The keys and the bytes of the entries are not
     * touched, so what the server stored before the window closed comes back as a replay. Entries that were refused for good stay refused.
     * @param {string} windowId
     * @returns {Promise<number>} how many writes of the import are queued
     */
    async resumeImport(windowId) {
      await this.whenIdle();
      /** @type {string[]} */
      const idems = [];
      for (const lane of lanes.values()) for (const entry of lane.entries) if (entry.import !== undefined) idems.push(entry.idem);
      if (idems.length > 0) {
        const db = await store.open();
        await store.outbox.remark(db, scope, idems, windowId);
        if (stopped) return 0;
        // In place: a batch that is in flight holds these very objects (it finds its entry at the head of its lane by identity).
        for (const lane of lanes.values()) for (const entry of lane.entries) if (entry.import !== undefined) entry.import = windowId;
      }
      if (batchTimer !== null) timers.clear(batchTimer);
      batchTimer = null;
      batchAttempt = 0;
      if (batchStop === "window") batchStop = null;
      void pumpBatch();
      return idems.length;
    },

    /** How the import stands: the writes of it that are queued, and whether the server refused the window. */
    importState() {
      return { queued: importEntriesLeft(), windowClosed: batchStop === "window" };
    },

    /** Sends everything that is waiting for a first try (after `load`) or was not blocked. */
    start() {
      for (const itemId of [...lanes.keys()]) wake(itemId);
      void pumpBatch();
    },

    /** Keeps everything from being sent until `release()`: entries are still stored and queued. A request in flight is not taken back. */
    hold() {
      held = true;
    },

    /** Resolves when no request is in flight (a request that was sent before `hold()` is not taken back). @returns {Promise<void>} */
    whenIdle() {
      if (!requestInFlight()) return Promise.resolve();
      return new Promise((resolve) => idleWaiters.push(resolve));
    },

    /**
     * Makes `entry` the only queued write of its item. The new entry is stored first and the old ones are removed after,
     * so a crash in between leaves the newest write (never none): the next start sees both and the last one wins. The lane
     * is not blocked afterwards, and nothing is sent while the runner is held.
     * With `expect` (the keys of the writes the caller has looked at) the new entry goes in and exactly those go out in one
     * transaction, and nothing is done when the store holds other writes of the item than those (another tab queued one meanwhile,
     * even a moment ago): it throws `SyncError("outbox_changed")`, and the caller decides again. A write is never dropped unseen.
     * @param {OutboxEntry} entry
     * @param {string[] | null} [expect]
     * @returns {Promise<string[]>} the idempotency keys of the writes that were dropped
     */
    async replace(entry, expect = null) {
      await this.whenIdle();
      const db = await store.open();
      /** @type {string[]} */
      let old;
      if (expect !== null) {
        try {
          await store.outbox.swap(db, scope, expect, [entry], { itemId: entry.itemId, keys: expect });
        } catch (error) {
          if (/** @type {any} */ (error)?.code === "outbox_changed") throw new SyncError("outbox_changed");
          throw error;
        }
        old = expect.filter((idem) => idem !== entry.idem);
      } else {
        await store.outbox.enqueue(db, scope, entry);
        old = (await store.outbox.all(db, scope)).filter((stored) => stored.itemId === entry.itemId && stored.idem !== entry.idem).map((stored) => stored.idem);
        for (const idem of old) await store.outbox.remove(db, scope, idem);
      }
      if (stopped) return [];
      const lane = laneOf(entry.itemId);
      const dropped = new Set([...old, ...lane.entries.map((one) => one.idem)].filter((idem) => idem !== entry.idem));
      cancelWait(lane);
      lane.entries.length = 0;
      lane.entries.push(entry);
      lane.attempt = 0;
      lane.blocked = null;
      wake(entry.itemId);
      return [...dropped];
    },

    /**
     * Puts new entries in the place of the queued writes of an item, one for one and in the same order (the same writes made again,
     * for example with a new idempotency key and a new restore epoch). Only for writes the server has certainly not stored (it
     * refused them with `restore_epoch_changed`) or that were never sent. The old entries leave the store and the new ones enter it
     * in one transaction. Only the entries that were queued when it began are replaced: one that is queued meanwhile stays where it is
     * (the caller should keep writes of the item from being made meanwhile, so the order in the store is the order of the lane). The
     * lane is not blocked afterwards, and nothing is sent while the runner is held.
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
      await store.outbox.swap(db, scope, old.map((entry) => entry.idem), next);
      if (stopped) return [];
      const now = lanes.get(itemId);
      if (now === undefined) return [];
      cancelWait(now);
      now.entries.splice(0, old.length, ...next);
      now.attempt = 0;
      wake(itemId);
      return old.map((entry) => entry.idem);
    },

    /** Lets the entries go out again after `hold()`. */
    release() {
      if (!held) return;
      held = false;
      for (const itemId of [...lanes.keys()]) wake(itemId);
      void pumpBatch();
    },

    /** Lets the lanes that were stopped by a 401 try again (the user is signed in again). */
    resume() {
      for (const [itemId, lane] of lanes) {
        if (lane.blocked === "unauthorized") {
          lane.blocked = null;
          wake(itemId);
        }
      }
      if (batchStop === "unauthorized") {
        batchStop = null;
        void pumpBatch();
      }
    },

    /** Keeps the queue of an item from being sent (its first write was refused before a restart). @param {string} itemId */
    block(itemId) {
      laneOf(itemId).blocked = "other";
    },

    /**
     * Removes every queued write of an item (from the store too) and lets the item be written again. With `expect` (the keys of the
     * writes the caller has looked at) nothing is done when the store holds other writes of the item: it throws `SyncError("outbox_changed")`.
     * @param {string} itemId
     * @param {string[] | null} [expect]
     * @returns {Promise<string[]>} the idempotency keys of the writes that were dropped
     */
    async discard(itemId, expect = null) {
      // The store first, read by item (the lane may be gone already): if that fails, nothing in memory has changed.
      const db = await store.open();
      const stored = (await store.outbox.all(db, scope)).filter((entry) => entry.itemId === itemId);
      if (expect !== null && (stored.length !== expect.length || !stored.every((entry) => expect.includes(entry.idem)))) throw new SyncError("outbox_changed");
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
      if (batchTimer !== null) timers.clear(batchTimer);
      batchTimer = null;
      lanes.clear();
    },
  };
}
