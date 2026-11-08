// The sync memory in front of the engine: what this device has seen of the
// server's history (the highest revision of every item, the highest `seq`), so
// that a server that shows an older state is noticed.
//
// The core keeps the rules (`accept_rows` never lowers a floor). This file keeps
// the discipline around it:
// * every read-modify-write of the stored `SyncState` runs under the Web Lock
//   `ferret-sync-memory:<server>:<account>` and reads the state again inside the
//   lock, so two tabs of one browser cannot lower each other's floors;
// * the new bytes are stored before the lock is released, and only then does a
//   caller get its answer, so nothing is acted on that the memory has not kept;
// * one bad row on a page does not hide the others, and a refused row changes
//   nothing.
//
// Spec: Fase 1 section 8.6 ("Lokalt minne").
import { hex16 } from "../b64.mjs";
import { serverKey } from "../store/idb.mjs";
import { codeOf, isFatal, SyncError } from "./errors.mjs";

/**
 * @typedef {import("../store/cache.mjs").CachedRow} CachedRow
 * @typedef {import("../store/syncState.mjs").SyncState} SyncState
 * @typedef {{ row: CachedRow, code: string }} Refused
 *
 * @typedef {object} MemoryStore
 * @property {(fn: (state: SyncState, info: { existed: boolean }) => Promise<SyncState | null>) => Promise<void>} withLock
 *   Under the lock: reads the state again, calls `fn` with it, stores what `fn` returns (null stores nothing), and releases the lock.
 *   `existed` is false when nothing was stored yet and `state` is a new one.
 * @property {() => Promise<SyncState>} load the stored state (a new one when nothing is stored), for a read that changes nothing
 */

/** The code of the core for a row below the highest revision this device has seen of its item. */
export const REV_BELOW_REMEMBERED = "checkpoint_rev_below_remembered";

/**
 * The row the core takes: a cached row with its id as bytes and its kind spelled out.
 * @param {CachedRow} row
 */
export function coreRow(row) {
  const item_id = hex16.decode(row.itemId);
  if (row.deleted) return { item_id, rev: row.rev, state: /** @type {"deleted"} */ ("deleted"), tomb: /** @type {Uint8Array} */ (row.tomb) };
  return {
    item_id,
    rev: row.rev,
    state: /** @type {"live"} */ ("live"),
    envelope: /** @type {Uint8Array} */ (row.envelope),
    tag: /** @type {Uint8Array} */ (row.tag),
  };
}

/** @param {Uint8Array} a @param {Uint8Array} b */
const sameBytes = (a, b) => a.length === b.length && a.every((n, i) => n === b[i]);

/**
 * Asks the core to remember rows. A call the core refuses for one row is tried
 * row by row, so the others are still accepted. Nothing is stored here.
 * @param {{ client: any, bytes: Uint8Array, rows: CachedRow[], topSeq: number }} options
 * @returns {Promise<{ bytes: Uint8Array, accepted: CachedRow[], refused: Refused[] }>}
 */
async function remember({ client, bytes, rows, topSeq }) {
  /** @param {CachedRow[]} list @param {Uint8Array} memory @returns {Promise<Uint8Array>} */
  const call = async (list, memory) => (await client.vault.accept_rows(list.map(coreRow), topSeq, memory)).newSyncMemory;
  /** The refusals that end the whole call, whichever row they came from. @param {unknown} error */
  const final = (error) => {
    const code = codeOf(error);
    if (code === "checkpoint_top_seq_below_remembered") {
      return new SyncError("rollback_suspected", "The server shows a state older than this device has seen.");
    }
    if (code === "too_large") {
      return new SyncError("sync_memory_full", "This device cannot remember more items from this server. Forget the server to start again.");
    }
    return isFatal(error) ? error : null;
  };
  try {
    return { bytes: await call(rows, bytes), accepted: [...rows], refused: [] };
  } catch (error) {
    const ended = final(error);
    if (ended) throw ended;
    if (rows.length === 0) throw error; // nothing to pick out: the memory itself is bad
  }
  /** @type {CachedRow[]} */
  const accepted = [];
  /** @type {Refused[]} */
  const refused = [];
  let current = bytes;
  for (const row of rows) {
    try {
      current = await call([row], current);
      accepted.push(row);
    } catch (error) {
      const ended = final(error);
      if (ended) throw ended;
      refused.push({ row, code: codeOf(error) });
    }
  }
  // Every row refused: one call without rows still says whether the top and the memory are in order (and raises the top).
  if (accepted.length === 0) current = await call([], current);
  return { bytes: current, accepted, refused };
}

/**
 * Remembers the rows of a page, under the lock. The promise resolves when the new
 * memory is stored and the lock is released (a failed store rejects, and nothing
 * on the page may be used). Call it for an empty page as well: the top `seq` of
 * the page is checked and remembered either way.
 *
 * A top `seq` below the remembered one rejects with `SyncError("rollback_suspected")`;
 * a full memory with `SyncError("sync_memory_full")`; in both nothing is stored.
 * A row the core refuses is returned in `refused` with the core's code, and is not remembered.
 * @param {{ client: any, memory: MemoryStore, rows: CachedRow[], topSeq: number }} options
 * @returns {Promise<{ accepted: CachedRow[], refused: Refused[] }>}
 */
export async function acceptPage({ client, memory, rows, topSeq }) {
  /** @type {{ accepted: CachedRow[], refused: Refused[] }} */
  let result = { accepted: [], refused: [] };
  await memory.withLock(async (state) => {
    const done = await remember({ client, bytes: state.memory, rows, topSeq });
    result = { accepted: done.accepted, refused: done.refused };
    return sameBytes(done.bytes, state.memory) ? null : { ...state, memory: done.bytes };
  });
  return result;
}

/**
 * The first start after the memory was introduced: there is no stored state, so
 * it is made from the rows this device already holds (they were checked when
 * they were cached). Does nothing when a state is stored. Under the lock.
 * @param {{ client: any, memory: MemoryStore, rows: CachedRow[], topSeq: number }} options
 * @returns {Promise<SyncState>} the state that is stored now
 */
export async function seedMemory({ client, memory, rows, topSeq }) {
  /** @type {{ state: SyncState | null }} */
  const seen = { state: null };
  await memory.withLock(async (state, info) => {
    seen.state = state;
    if (info.existed) return null;
    const done = await remember({ client, bytes: state.memory, rows, topSeq });
    seen.state = { ...state, memory: done.bytes };
    return seen.state;
  });
  return /** @type {SyncState} */ (seen.state);
}

/**
 * The memory of one account on one server, over the store service and the Web
 * Locks of the browser. Without Web Locks it refuses to be made (`unsupported`):
 * two tabs could not be kept apart.
 * @param {{
 *   store: any,
 *   serverUrl: string,
 *   accountId: string,
 *   locks?: { request(name: string, callback: () => Promise<unknown>): Promise<unknown> } | undefined,
 *   newMemory?: () => Promise<Uint8Array> | Uint8Array,
 * }} options
 *   `store` is the store service (`open`, `loadSyncState`, `saveSyncState`). `newMemory` makes the empty memory of a
 *   device that has seen nothing (`client.vault.sync_memory_new`); it is called only when no state is stored.
 * @returns {MemoryStore & { name: string }}
 */
export function memoryStore({ store, serverUrl, accountId, locks = /** @type {any} */ (globalThis).navigator?.locks, newMemory }) {
  if (!locks || typeof locks.request !== "function") {
    throw new SyncError("unsupported", "This browser has no Web Locks, which the sync memory needs to keep tabs apart.");
  }
  const server = serverKey(serverUrl);
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
  const name = `ferret-sync-memory:${server}:${accountId}`;

  /** @returns {Promise<SyncState>} */
  async function fresh() {
    if (typeof newMemory !== "function") throw new TypeError("a memory store needs newMemory to start an empty state");
    return { memory: await newMemory(), restoreEpoch: null, verifiedAt: null, uploadedAt: null, uploadedSeq: null, hardWarning: null, restore: null };
  }

  return {
    name,
    async withLock(fn) {
      await locks.request(name, async () => {
        const db = await store.open();
        const stored = await store.loadSyncState(db, serverUrl, accountId);
        const next = await fn(stored ?? (await fresh()), { existed: stored !== null });
        if (next !== null) await store.saveSyncState(db, serverUrl, accountId, next);
      });
    },
    async load() {
      const db = await store.open();
      return (await store.loadSyncState(db, serverUrl, accountId)) ?? fresh();
    },
  };
}

/**
 * A memory that is not there: every use fails with `error`, so an engine that
 * is given it halts with that error's code (`unsupported`) and nothing is read
 * or written.
 * @param {unknown} error
 * @returns {MemoryStore}
 */
export function unavailableMemory(error) {
  return {
    withLock: () => Promise.reject(error),
    load: () => Promise.reject(error),
  };
}
