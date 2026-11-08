// The sync state of an account on a server: what this device has seen of the
// server's history, kept across sessions. It holds the core's sync memory
// (opaque bytes the core makes, with a floor for every item it has seen), the
// restore epoch the server last showed, and the bookkeeping of checkpoints and
// of a restore that is under way. It is not secret: it holds no key and no item
// content. It stays when the user signs out or clears the cache, and only
// "forget this server" removes it.
//
// This file stores and loads; it takes no lock. Every read-modify-write of the
// state (load, `accept_*` or `verify_*` in the core, save) has to run under the
// Web Lock `ferret-sync-memory:<server>:<account>`, and has to read the state
// again inside the lock, so that two tabs cannot lower each other's floors. The
// caller does that.
import { hex16 } from "../b64.mjs";
import { req, run, serverKey, StoreError } from "./idb.mjs";

/**
 * @typedef {object} SyncState
 * @property {Uint8Array} memory the core's sync memory, as the core serialized it
 * @property {number | null} restoreEpoch the highest restore epoch this device has accepted
 * @property {number | null} verifiedAt when a checkpoint last verified (ms since the epoch)
 * @property {number | null} uploadedAt when this device last uploaded a checkpoint (ms)
 * @property {number | null} uploadedSeq the `seq` of that checkpoint
 * @property {string | null} hardWarning the code of a warning that stays until a later check clears it
 * @property {{ epoch: number, phase: "memory_saved" | "queued" } | null} restore a restore that was started and not finished
 */

/** The only fields a state may have, and the only phases of a restore. */
export const STATE_FIELDS = Object.freeze(["memory", "restoreEpoch", "verifiedAt", "uploadedAt", "uploadedSeq", "hardWarning", "restore"]);
export const RESTORE_PHASES = Object.freeze(["memory_saved", "queued"]);

/** @param {unknown} value @returns {value is number | null} */
const wholeOrNull = (value) => value === null || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);

/**
 * Checks a state and returns the value to store: the fields of the state, with
 * a copy of the memory bytes (a view over a larger buffer would otherwise keep
 * the whole buffer, and the caller's bytes could change after the save).
 * Each field is read once, so a getter cannot show another value after the check.
 * @param {SyncState} state
 * @returns {SyncState}
 */
function clean(state) {
  const bad = (/** @type {string} */ message) => new StoreError("sync_state_malformed", message);
  if (state === null || typeof state !== "object" || Array.isArray(state)) throw bad("a sync state is an object");
  for (const key of Object.keys(state)) {
    if (!STATE_FIELDS.includes(key)) throw bad(`a sync state has no field ${key}`);
  }
  const { memory, restoreEpoch, verifiedAt, uploadedAt, uploadedSeq, hardWarning, restore } = state;
  if (!(memory instanceof Uint8Array)) throw bad("memory is bytes");
  if (!wholeOrNull(restoreEpoch) || !wholeOrNull(verifiedAt) || !wholeOrNull(uploadedAt) || !wholeOrNull(uploadedSeq)) {
    throw bad("restoreEpoch, verifiedAt, uploadedAt and uploadedSeq are whole numbers or null");
  }
  if (hardWarning !== null && (typeof hardWarning !== "string" || hardWarning === "")) throw bad("hardWarning is a code or null");
  /** @type {SyncState["restore"]} */
  let kept = null;
  if (restore !== null) {
    if (typeof restore !== "object" || Array.isArray(restore) || Object.keys(restore).sort().join() !== "epoch,phase") {
      throw bad("restore is { epoch, phase } or null");
    }
    const { epoch, phase } = restore;
    if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0 || !RESTORE_PHASES.includes(phase)) {
      throw bad("restore holds a whole epoch and a known phase");
    }
    kept = { epoch, phase };
  }
  return { memory: memory.slice(), restoreEpoch, verifiedAt, uploadedAt, uploadedSeq, hardWarning, restore: kept };
}

/**
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {[string, string]}
 */
function keyOf(serverUrl, accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
  return [serverKey(serverUrl), accountId];
}

/**
 * The stored state of an account on a server, or null when there is none (a
 * first start on this device). A stored record that does not pass the checks of
 * a save is refused (`StoreError`, code `sync_state_malformed`).
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<SyncState | null>}
 */
export async function loadSyncState(store, serverUrl, accountId) {
  const key = keyOf(serverUrl, accountId);
  const row = await run(store, ["sync_state"], "readonly", ([table]) => req(table.get(key)));
  if (row === undefined) return null;
  // A stored record that is damaged (another version, or edited by hand) is not
  // handed on: it fails the same check as a save.
  const { serverUrl: _server, accountId: _account, ...state } = row;
  return clean(state);
}

/**
 * Stores the state of an account on a server, replacing the one that is there.
 * The state is refused (`StoreError`, code `sync_state_malformed`) when a field
 * has the wrong type, a number is fractional, negative or too large, the phase
 * is unknown, or there is a field the state does not have. The memory is stored
 * as a copy.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {SyncState} state
 * @returns {Promise<void>}
 */
export async function saveSyncState(store, serverUrl, accountId, state) {
  const key = keyOf(serverUrl, accountId);
  const value = clean(state);
  await run(store, ["sync_state"], "readwrite", async ([table]) => {
    await req(table.put({ serverUrl: key[0], accountId: key[1], ...value }));
  });
}
