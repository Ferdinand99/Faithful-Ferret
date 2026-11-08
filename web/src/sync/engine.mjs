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
// * The sync memory (see memory.mjs) is the floor that survives a cleared cache
//   and a restart: every accepted row of a page, the manifest row included, goes
//   through `acceptPage` (under the Web Lock, stored before the rows are used),
//   and a row it refuses changes nothing here: no row, no index entry, no
//   overlay, no mark. The exception is a row this device wrote itself for an
//   item that was uploaded again (the server numbers it from 1): it is accepted
//   by the digest of what was sent, and the memory keeps the old floor. A top
//   `seq` below the remembered one, a lower restore epoch, a memory that is full
//   and a browser without Web Locks halt the engine: nothing is pulled or sent,
//   local data stays, and `health()` says why.
// * The feed is read from the `seq` of the last row of the last page, never
//   from `latest_seq`: a server that lies about `latest_seq` must not be able
//   to make the client skip rows. A 410 (the cursor is below the floor of the
//   feed) is answered once per cycle with a full listing (`GET /api/sync/items`,
//   page by page, each page checked by `checkListingPage`), then the feed goes on
//   from the `as_of_seq` of the first page; if that is answered with 410 as well,
//   the cycle ends with the error `gone`. A listing never deletes anything here:
//   items it does not show are kept, marked `missing_on_server` and uploaded
//   again; only the user can discard them. (This departs from the rule of the
//   first version, that the cursor never comes from what the server says its top
//   is: it is safe here because everything above `as_of_seq` is read from the
//   feed afterwards.)
// * Checkpoints (see checkpoint.mjs). At the end of a pass that has read the
//   whole feed, the checkpoint of the server is verified against the rows this
//   device holds: in the first such pass after a start when the last verification
//   is missing or older than a day, when a session that has not verified has a checkpoint to store, after a listing, and when asked. A failure is
//   named by `hardWarningOf`, kept in the sync state and shown until a later
//   verification succeeds. Nothing is uploaded before a verification has
//   succeeded in this session; the one exception is a device that has verified
//   before and whose only failures are a forged checkpoint or a bad feed, so a
//   junk checkpoint cannot freeze the checkpoints of every device. A device
//   uploads at most every ten minutes, only for a `seq` above the head of the
//   server and its own last upload, and never with a state warning, a stop, a
//   mark or a write in the outbox.
// * A server that was restored from a backup (a higher restore epoch with something lower than this device remembers,
//   the same revision with other bytes, a live row this device holds that the server no longer lists, or a checkpoint that does not
//   verify) stops the engine with `server_restored`. A higher restore epoch is never stored before the vault has been listed in
//   full through the normal page path (seq numbers are used again after a restore, so the feed alone cannot show what is lost).
// * A listing is noted in the settings from its first row until the feed after it has been read to its end: a start that finds the
//   note lists again from the beginning and never takes the cursor from the highest cached `seq` (a listing caches rows in the order of ids).
//   Only `acceptOlderState`, after the user has confirmed, lowers the floors, in three stored phases (see restore.mjs for
//   what is sent and what is kept back): the older state is verified and becomes the memory; the local versions the
//   server lacks are queued again, built on the server's rows, and an item the server changed since the restore is kept
//   as a conflict instead (what is sent and what is kept back is decided with the restore sequence number and the rows the server froze
//   at the restore, see restore.mjs); then the rows and the cache are replaced. Writes are not sent before the last phase is done,
//   and a restart carries on from the stored phase before the outbox runner starts. `resumeAfterHalt` lifts a stop and
//   reads the feed again; it clears no warning, since only a verification that succeeds does that.
// * A write that the server refuses for good (409 or a final code) blocks its
//   item: the draft stays in the outbox, the screen shows the server's version,
//   edits are refused until `discard(id)` drops the draft. A 409 that is a real
//   disagreement (and the writes that an accepted older state keeps back) is a
//   conflict: the sealed local version is the draft, the server's version is the
//   row from the feed, and the user chooses (`conflict`, `resolve`): keep mine
//   writes the local version on top of the server's revision (over a deleted row
//   as a resurrection, the one place a client does that, and only on that choice),
//   keep theirs drops the draft (over a deleted server row the draft goes to the trash first). Nothing is merged. A 409 that shows our own write
//   (same blob and tag, or deleted at the revision our tombstone makes) is done.
// * A verified tombstone that replaces a live row puts that row in the local trash
//   for 30 days (ciphertext only; `trash`, `restoreFromTrash`). Nothing is removed
//   locally on the server's word alone: an unverified tombstone touches nothing.
// * Writes go through the outbox (see outbox.mjs): stored before the request,
//   resent byte for byte under the same key. Every new write and every upload of a checkpoint names the restore epoch this device has
//   accepted (`restore_epoch`), and the server refuses it with `409 restore_epoch_changed` when its own is another: that answer
//   holds every lane and stops the engine with `server_restored` (the write was not stored; it is made again, with a new key and the
//   new epoch, only after the user has accepted the older state). The bytes of a write that may have been stored never change.
import { b64u, hex16 } from "../b64.mjs";
import { rowOfChange } from "../store/cache.mjs";
import { encodeWireBytes } from "../wire.mjs";
import { codeOf, isFatal, SyncError } from "./errors.mjs";
import {
  checkListingPage, checkpointBody, checkRestoreRowsPage, entriesOf, escalate, failingIds, fetchCheckpoint, hardWarningOf, MAX_PAGE, STOP_CODES,
  UPLOAD_EVERY_MS, VERIFY_AFTER_MS, VERIFY_RETRY_MS, VERIFY_WARNINGS, warningRank,
} from "./checkpoint.mjs";
import { compareFields, TRASH_MS } from "./conflict.mjs";
import { acceptPage, coreRow, REV_BELOW_REMEMBERED, seedMemory } from "./memory.mjs";
import { createOutboxRunner, isRestoreEpochChanged } from "./outbox.mjs";
import { planRestore, restoreItems, rowHash } from "./restore.mjs";

export { SyncError };

/**
 * @typedef {object} ItemSummary
 * @property {string} id 32 hex characters
 * @property {number} rev
 * @property {string} type
 * @property {string} name
 * @property {boolean} favorite
 * @property {string[]} urls
 * @property {string} username the plain user name field, for the list and its search ("" when the item has none)
 * @property {number} modified
 * @property {boolean} pending a write of this item is waiting for the server
 * @property {boolean} damaged the server's newest row could not be opened (the last good version is shown)
 * @property {boolean} quarantined the server says deleted but the tombstone did not verify (the local copy is kept)
 * @property {boolean} missingOnServer a full listing did not show this item: it is kept, and being uploaded again until the user discards it
 * @property {boolean} blocked a write of this item was refused for good (conflict or a final answer): the server's version is shown; `discard` drops the draft
 * @property {string | null} blockedReason the code of the answer that blocked it (`conflict`, `reupload_refused`, `quota_exceeded`, ...)
 * @property {boolean} conflict the item has a conflict that waits for the user (`conflict(id)` shows both versions, `resolve` ends it)
 * @property {boolean} readOnly
 *
 * @typedef {import("../store/cache.mjs").Scope} Scope
 * @typedef {import("../store/cache.mjs").CachedRow} CachedRow
 * @typedef {{ set(fn: () => void, ms: number): unknown, clear(handle: unknown): void }} Timers
 */

/** The all-zero id of the unlock-method manifest: a row, never an item. */
export const MANIFEST_ID = "00000000000000000000000000000000";

/** Rows asked for in one page of the feed (the server's maximum). */
const PAGE_LIMIT = MAX_PAGE;

/**
 * The codes that stop the engine: nothing is pulled or sent until the user acts.
 * `server_restored` and `restore_epoch_lowered` are about the restore epoch,
 * `rollback_suspected` about the top `seq`, `sync_memory_full` and `unsupported`
 * about the memory itself.
 */
export const HALT_CODES = STOP_CODES;

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
 *   memory: import("./memory.mjs").MemoryStore,
 *   deviceName?: string | (() => string | Promise<string>),
 *   now?: () => number,
 *   pollMs?: number,
 *   rand?: (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>,
 *   timers?: Timers,
 *   win?: any,
 * }} options
 *   `store` is the store service (`open()`, `cache`, `outbox`, `getSetting`, ...);
 *   `client` the worker client (`client.vault.open_item(...)`); `memory` the sync
 *   memory of this account on this server (see memory.mjs; it is required);
 *   `deviceName` is written into the body of every item this engine creates or
 *   changes (a function is called once, when the engine starts); `timers` and
 *   `win` are for tests (a fake clock; a target for the `focus` event).
 */
export function createSyncEngine({
  api,
  client,
  store,
  scope,
  memory,
  deviceName,
  now = Date.now,
  pollMs = 300_000,
  rand = crypto.getRandomValues.bind(crypto),
  timers = realTimers,
  win = globalThis,
}) {
  if (!memory || typeof memory.withLock !== "function" || typeof memory.load !== "function") {
    throw new TypeError("the sync engine needs a sync memory");
  }
  const flagsKey = `sync.flags.${scope.accountId}.${scope.vaultId}.${scope.vkEpoch}`;
  /**
   * The note that a listing has been begun and the feed after it not yet read to its end (under the prefix "forget" removes). It is
   * one note for the browser, and only the engine of the tab that holds the owner lock (`sync/owner.mjs`) writes or removes it; a tab on
   * standby has no engine.
   */
  const listingKey = `${flagsKey}.listing`;

  let started = false;
  let stopped = false;
  let paused = false; // the server said 401: wait for a manual `syncNow`
  /** The `seq` of the last row of the last page that was read. */
  let cursor = 0;
  /** The code that stopped the engine, or null. @type {string | null} */
  let halted = null;
  /** The warnings that stand until a later check clears them. @type {Set<string>} */
  const standing = new Set();
  /** The name of this device, for the body of what it writes. @type {string | undefined} */
  let device = typeof deviceName === "string" ? deviceName : undefined;
  /** @type {unknown} */
  let pollTimer = null;
  /** @type {string} */
  let lastStatus = "";
  /** @type {Promise<void> | null} */
  let inflight = null;
  let again = false;
  /** The ids a full listing has shown so far, while one is going on. @type {Set<string> | null} */
  let listing = null;
  /**
   * The note of an unfinished listing is stored: the rows a listing caches come in the order of the ids, not of their `seq`, so until the
   * feed after the listing has been read to its end the highest `seq` among the cached rows says nothing about what has been read.
   */
  let listingNoted = false;
  /** The page was closed before a listing was finished (the note was stored): the first pass lists the vault again, from the beginning. */
  let relistFirst = false;
  /** The highest restore epoch for which a full listing has been made in this session and found nothing lower. */
  let listedEpoch = -1;
  /** The restore epoch the pages of `listing` carried (one value for the whole listing), and the pass that made it. */
  let listingEpoch = -1;
  let listingPass = -1;
  /**
   * What the last pass that read the whole feed found, for the checkpoint step: the `latest_seq` of its last page (`seq`),
   * the head of the checkpoint that page showed (`head`), whether a full listing was part of it, whether it refused rows, and
   * the sync memory as this pass left it (`memory`: another tab's save after that makes the verification read the feed again).
   * `head` may be raised by the verification (the checkpoint it read); `pageHead` is what the feed showed.
   * `epoch` is a higher restore epoch the pass saw with nothing lower: it is stored when the checkpoint verifies (`from` is the one
   * that was stored).
   * @type {{ seq: number, head: number | null, pageHead: number | null, listed: boolean, refused: boolean, memory: Uint8Array, epoch: { from: number | null, to: number } | null } | null}
   */
  let lastDrain = null;
  /** A verification has succeeded in this session (the engine has run since `start`). */
  let verifiedInSession = false;
  /** The last verification failed only with `checkpoint_forged` or `bad_feed`, on a device that had verified before. */
  let forgedUnlock = false;
  /** Someone asked for a verification (`verifyNow`, a listing): the next drained pass makes one whatever the time. */
  let verifyRequested = false;
  /** The answer of the last verification that was made, for `verifyNow`. @type {string | null} */
  let verifyOutcome = null;
  /** No automatic verification before this time (ms): the last one failed. */
  let verifyNotBefore = 0;
  /** No upload of a checkpoint before this time (ms): the server asked for a wait. */
  let uploadNotBefore = 0;
  /** The last verification ended in a pause: what the feed showed then, so it is not tried again until that moves (or a day passes). @type {{ seq: number, head: number | null, at: number } | null} */
  let deferredAt = null;
  /** The next verification is the second try of a round (another tab had moved the memory, or the checkpoint was newer than the feed). */
  let retryPending = false;
  /** An older state is being accepted right now (see `acceptOlderState`): nothing else changes the rows or the outbox meanwhile. */
  let restoring = false;
  /** A restore was started and its state is stored but it is not finished: nothing is pulled until it is. */
  let restorePending = false;
  /** A higher restore epoch was seen with nothing lower and has not been accepted yet (its checkpoint has not verified): writes are held. */
  let epochPending = false;
  /** The focus and online listeners are registered. */
  let listening = false;
  /** The number of the last pass that began (a pass takes the next one). */
  let passes = 0;
  /**
   * The server refused a write or a checkpoint for its restore epoch (the number is the pass that was last begun then): a higher epoch
   * a pass sees is a restore, whatever else it shows, until a pass that began later has found none (null: nothing was refused).
   * @type {number | null}
   */
  let epochMovedAt = null;
  /** Answers `restore_epoch_changed` per item since its last write that was done: a server that keeps refusing the epoch it announces is not trusted with more. @type {Map<string, number>} */
  const epochRefusals = new Map();
  /** The keys of writes made before a restore epoch was stored (they name none): they have never been sent, since nothing is sent before the first pass has ended well. @type {Set<string>} */
  const unconditioned = new Set();
  /** Writes refused for the restore epoch that are being looked at: the runner is not let go until they have been dealt with. */
  let epochHolds = 0;
  /** No release of the runner before this time (ms): a server kept refusing an epoch it shows, and the polls try again, not a loop. */
  let epochRetryAt = 0;

  /** The server-accepted rows, ciphertext only (what the cache holds). @type {Map<string, CachedRow>} */
  const rows = new Map();
  /**
   * The newest local write of an item that the feed has not yet confirmed.
   * @type {Map<string, { rev: number, deleted: boolean, envelope: Uint8Array | null, tag: Uint8Array | null }>}
   */
  const overlay = new Map();
  /** The decrypted item index, in memory only. @type {Map<string, Omit<ItemSummary, "id" | "pending" | "damaged" | "quarantined" | "missingOnServer" | "blocked" | "blockedReason" | "conflict">>} */
  const index = new Map();
  /**
   * Marks on items (saved, ids, numbers and digests only). `damaged` and
   * `quarantined`: the server's newest row is not usable. `missing_on_server`: a
   * full listing did not show the item; `rev` is the revision of the local copy
   * and stays the floor of the item. `reuploaded`: the copy was uploaded again
   * (the server numbers it from 1) and the old floor is kept. `sent` lists the
   * writes of this device made since (`<rev>:<r|t>:<digest>`): they are the only
   * rows below the floor that are accepted, byte for byte. `fresh` (only on a mark that was made again) lists
   * the ones made since that mark.
   * @type {Map<string, { kind: "damaged" | "quarantined" | "missing_on_server" | "reuploaded", rev: number, sent?: string[], fresh?: string[] }>}
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
  /**
   * What the server showed when a write was refused as a conflict (saved): its revision and whether it is deleted. Only an item
   * that is blocked with the code `conflict` has a conflict; the server's version itself is always the verified row from the feed.
   * @type {Map<string, { serverRev: number, serverDeleted: boolean }>}
   */
  const conflictNotes = new Map();
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

  /**
   * Stops the engine from pulling and sending. What is stored stays; the screen
   * keeps what it shows; writes are still stored in the outbox but not sent.
   * @param {string} code one of `HALT_CODES`
   */
  function halt(code) {
    if (halted !== null) return;
    halted = code;
    listing = null; // a listing that was under way is not finished: the ids it has seen so far say nothing about what is missing
    if (pollTimer !== null) timers.clear(pollTimer);
    pollTimer = null;
    runner.hold();
    setStatus("halted", { code });
  }

  /** A warning that stands until a later check clears it. @param {string} code */
  function raiseWarning(code) {
    if (standing.has(code)) return;
    standing.add(code);
    emit("state", { kind: "warning", code });
  }

  /** @param {string} code */
  function clearWarning(code) {
    if (standing.delete(code)) emit("state", { kind: "warning_cleared", code });
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

  /**
   * The value of the field with the id `username`, when the core shows it (a
   * hidden field has no value in the view).
   * @param {any} view
   */
  function usernameOf(view) {
    const field = Array.isArray(view.fields) ? view.fields.find((/** @type {any} */ f) => f?.id === "username") : null;
    return typeof field?.value === "string" ? field.value : "";
  }

  /** @param {any} view @param {number} rev */
  function summaryOf(view, rev) {
    return {
      rev,
      type: String(view.item_type ?? ""),
      name: String(view.name ?? ""),
      favorite: view.favorite === true,
      urls: Array.isArray(view.urls) ? view.urls.map((/** @type {any} */ u) => String(u?.url ?? "")) : [],
      username: usernameOf(view),
      modified: Number.isSafeInteger(view.modified) ? view.modified : 0,
      readOnly: view.read_only === true,
    };
  }

  // -------------------------------------------------------- the outbox

  /**
   * A write was refused for good: the item is blocked, the draft stays in the outbox, the screen goes back to the server's version
   * (or keeps the draft when the server has deleted the item), and nothing more is queued behind it.
   * @param {import("../store/outbox.mjs").OutboxEntry} entry @param {import("../api.mjs").ApiError} error @param {string} kind @param {boolean} automatic
   */
  function refuse(entry, error, kind, automatic) {
    /** @type {Record<string, any>} */
    const detail = { code: automatic ? "reupload_refused" : kind === "conflict" ? "conflict" : error.code, id: entry.itemId };
    if (kind === "conflict") {
      const current = error.body?.current_rev;
      if (Number.isSafeInteger(current)) detail.currentRev = current;
      detail.deleted = error.body?.deleted === true;
      if (!automatic) conflictNotes.set(entry.itemId, { serverRev: Number.isSafeInteger(current) ? current : 0, serverDeleted: detail.deleted });
    }
    blocked.set(entry.itemId, detail.code);
    flagsDirty = true;
    overlay.delete(entry.itemId);
    void persistFlags();
    void showServerVersion(entry.itemId).then(persistFlags);
    emit("error", detail);
    // A 409 on a deleted item carries no tombstone, and a live one carries a
    // row without a `seq`: both come through the feed, where they are checked.
    if (kind === "conflict") void syncNow();
  }

  /**
   * Whether nothing is left to choose for an item: this device holds a verified tombstone row for it (rows come from the feed and the
   * listing, where a tombstone is verified before it is kept) and the last write that waits for it is a deletion. The edits before that
   * deletion in the chain go with it: the user's last word was the deletion, and the server has deleted the item.
   * @param {string} id
   */
  function mootChain(id) {
    if (rows.get(id)?.deleted !== true) return false;
    const last = runner.entriesOf(id).at(-1);
    return last !== undefined && "tomb" in last.body;
  }

  /**
   * Drops the whole chain of writes of an item for which `mootChain` holds, and what blocked it, and shows the screen as the server's
   * deletion shows it. Only the writes that were looked at go (`discard` with `expect`): a write another tab queued meanwhile is never
   * dropped unseen. Answers false, and changes nothing, when the chain is not moot (any more) or the store refuses.
   * @param {string} id
   * @returns {Promise<boolean>}
   */
  async function dropMoot(id) {
    const chain = runner.entriesOf(id);
    if (chain.length > 0 && !mootChain(id)) return false;
    try {
      for (const idem of await runner.discard(id, chain.map((entry) => entry.idem))) droppedIdems.add(idem);
    } catch (error) {
      if (!stopped && codeOf(error) !== "outbox_changed") emit("error", { code: "storage" });
      return false;
    }
    if (stopped) return false;
    blocked.delete(id);
    conflictNotes.delete(id);
    overlay.delete(id);
    if (rows.get(id)?.deleted === true) index.delete(id);
    flagsDirty = true;
    await persistFlags();
    changed([id]);
    return true;
  }

  const runner = createOutboxRunner({
    api,
    store,
    scope,
    timers,
    hooks: {
      onRestoreEpochChanged: (entry, error) => void onEpochChanged(entry, error),
      onDone: (entry, answer) => {
        epochRefusals.delete(entry.itemId);
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
        if (kind === "conflict" && showsOurRow(entry, error)) {
          void serverHidItem(entry.itemId);
          return;
        }
        // An upload nobody asked for (a copy of an item the server left out, sent again by this engine) that the server
        // refuses is not a change of the user's: it says so, and it is not a conflict the user can resolve with a choice.
        const automatic = kind === "conflict" && entry.baseRev === 0 && flags.get(entry.itemId)?.kind === "missing_on_server";
        // The refusal of a write over an item this device already holds a verified tombstone for, when everything that waits for the
        // item ends in a deletion: the item is deleted on both sides and there is nothing to choose, so the chain is dropped and the
        // checkpoints can go on. Decided from the verified row, never from what the 409 says: a server that says "deleted" does not make
        // a chain moot. The 409 can only keep a chain: when it says the item is live again (another device brought it back, and this device
        // has not read that yet), the verified tombstone is out of date, and dropping the chain would hide a live item. A chain that cannot
        // be dropped is a conflict.
        if (kind === "conflict" && !automatic && mootChain(entry.itemId) && /** @type {any} */ (error)?.body?.deleted !== false) {
          void dropMoot(entry.itemId).then((dropped) => {
            if (stopped) return;
            if (dropped) void syncNow();
            else refuse(entry, error, kind, automatic);
          });
          return;
        }
        refuse(entry, error, kind, automatic);
      },
      onStorageError: () => emit("error", { code: "storage" }),
    },
  });

  /**
   * The exact bytes of a write: the request body, with the restore epoch it is conditional on (null: no condition, a device that has
   * not yet stored an epoch). The bytes are fixed here and never rebuilt for a retry.
   * @param {{ baseRev: number, body: { blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }, idem: string, resurrect?: boolean, restoreEpoch: number | null }} write
   */
  function writeBytes({ baseRev, body, idem, resurrect = false, restoreEpoch }) {
    return encodeWireBytes("put_item_req", {
      base_rev: baseRev,
      ...("tomb" in body ? { deleted: true, tomb: b64u.encode(body.tomb) } : { blob: b64u.encode(body.blob), tag: b64u.encode(body.tag) }),
      idem,
      ...(resurrect && !("tomb" in body) ? { resurrect: true } : {}),
      ...(restoreEpoch === null ? {} : { restore_epoch: restoreEpoch }),
    });
  }

  /**
   * The restore epoch this device has accepted, or null before the first contact has stored one. A browser without Web Locks has no
   * memory and the engine is stopped (`unsupported`): what the user writes is kept, without a condition, and nothing is sent.
   * @returns {Promise<number | null>}
   */
  async function acceptedEpoch() {
    /** @type {number | null} */
    let epoch;
    try {
      epoch = (await memory.load()).restoreEpoch;
    } catch (error) {
      if (codeOf(error) !== "unsupported") throw error;
      epoch = null;
    }
    alive();
    return epoch;
  }

  /**
   * The server answered a write with `409 restore_epoch_changed`: it is not the vault the write was made for, and nothing was stored.
   * The runner has held every lane. The feed is read once more (a higher epoch is a restore and stops the engine; `finishEpoch`).
   * When the pass finds nothing to stop for, this device has already accepted the server's epoch (it was only stored after the write was
   * made), and the write, certain not to have been stored, is made again with a new key and that epoch. A server that keeps
   * refusing an epoch it does not show leaves the lane held; the polls try again.
   * @param {import("../store/outbox.mjs").OutboxEntry} entry @param {import("../api.mjs").ApiError} error
   */
  async function onEpochChanged(entry, error) {
    if (stopped || abandoned.has(entry.itemId) || droppedIdems.has(entry.idem)) return;
    epochHolds += 1;
    epochRefusals.set(entry.itemId, (epochRefusals.get(entry.itemId) ?? 0) + 1);
    epochMovedAt = passes;
    try {
      await syncNow();
      await madeAgainAfterEpoch(entry, error.body?.restore_epoch);
    } catch (failure) {
      if (!stopped) emit("error", { code: "storage", reason: codeOf(failure) });
    } finally {
      epochHolds -= 1;
    }
    releaseIfClear();
  }

  /**
   * The same write made again: the same body, a new key, and `epoch` (null: none) named in the request.
   * @param {import("../store/outbox.mjs").OutboxEntry} old @param {number | null} epoch
   * @returns {import("../store/outbox.mjs").OutboxEntry}
   */
  function remade(old, epoch) {
    const asked = JSON.parse(new TextDecoder().decode(old.bytes));
    const idem = randomId();
    return {
      idem, itemId: old.itemId, baseRev: old.baseRev, body: old.body,
      bytes: writeBytes({ baseRev: old.baseRev, body: old.body, idem, resurrect: asked.resurrect === true, restoreEpoch: epoch }),
    };
  }

  /**
   * After the pass that follows `restore_epoch_changed`: when that pass has ended well and found no higher epoch (nothing stops
   * the engine), the epoch the server showed is one this device has accepted, and the refused write (certain not to be stored) is made
   * again with a new key and that epoch, together with the writes queued behind it. A pass that did not end well settles nothing.
   * @param {import("../store/outbox.mjs").OutboxEntry} entry @param {unknown} served the epoch the server named
   */
  async function madeAgainAfterEpoch(entry, served) {
    if (stopped || halted !== null || epochPending || restorePending || restoring || epochMovedAt !== null) return;
    const stored = await acceptedEpoch();
    if (!Number.isSafeInteger(served) || stored === null || /** @type {number} */ (served) > stored) return; // the server is ahead of this device: a pass has to see it first
    if ((epochRefusals.get(entry.itemId) ?? 0) > 3) {
      epochRetryAt = now() + pollMs;
      emit("error", { code: "restore_epoch_refused", id: entry.itemId });
      return;
    }
    // Under the item: a write of it that is made meanwhile waits, so the order of the lane and of the store stays the same.
    const gone = await withItem(entry.itemId, () => runner.restamp(entry.itemId, (old) => remade(old, stored)));
    for (const idem of gone) droppedIdems.add(idem);
    alive();
  }

  /**
   * Writes made before the first contact stored a restore epoch name none. Now that one is stored, the lanes that hold only such
   * writes (never sent: nothing is sent before a pass has ended well, and that pass stores the epoch) are made again naming it.
   */
  async function conditionAfterFirstContact() {
    if (unconditioned.size === 0) return;
    const epoch = await acceptedEpoch();
    if (epoch === null) return;
    for (const itemId of runner.itemsWithEntries()) {
      await withItem(itemId, async () => {
        const entries = runner.entriesOf(itemId);
        if (entries.length === 0 || blocked.has(itemId) || !entries.every((entry) => unconditioned.has(entry.idem))) return;
        const gone = await runner.restamp(itemId, (old) => remade(old, epoch));
        for (const idem of gone) {
          droppedIdems.add(idem);
          unconditioned.delete(idem);
        }
      });
      alive();
    }
  }

  /**
   * Whether a refused upload of a missing item says the server holds the very row this device has cached: the copy was
   * uploaded against nothing (`base_rev` 0), and the conflict shows the same blob and tag.
   * @param {import("../store/outbox.mjs").OutboxEntry} entry @param {import("../api.mjs").ApiError} error
   */
  function showsOurRow(entry, error) {
    const row = rows.get(entry.itemId);
    const body = error.body;
    if (entry.baseRev !== 0 || flags.get(entry.itemId)?.kind !== "missing_on_server") return false;
    if (!row || row.deleted || !row.envelope || !row.tag || !body || body.deleted === true) return false;
    return body.blob === b64u.encode(row.envelope) && body.tag === b64u.encode(row.tag);
  }

  /**
   * The server hid an item (the listing left it out) and shows it again when the copy is uploaded: it had the row all
   * along. The mark goes and so does the upload that was queued; the row comes through the feed. A warning, nothing more.
   * @param {string} id
   */
  async function serverHidItem(id) {
    try {
      for (const idem of await runner.discard(id)) droppedIdems.add(idem);
      alive();
      if (flags.get(id)?.kind === "missing_on_server") flags.delete(id);
      acked.delete(id);
      flagsDirty = true;
      await persistFlags();
    } catch (error) {
      if (!stopped) emit("error", { code: "storage" });
      return;
    }
    if (stopped) return;
    standing.add("server_hid_item");
    warn("server_hid_item", { id });
    changed([id]);
    void syncNow();
  }

  // ----------------------------------------------------------- the feed

  /** Reads the feed from the cursor to its end. */
  async function cycle() {
    lastDrain = null;
    const db = await store.open();
    let since = cursor;
    let restarted = false;
    /** What this pass has learned about the restore epoch of the server. @type {PassState} */
    const pass = { id: (passes += 1), stored: (await memory.load()).restoreEpoch, first: null, raised: null, lower: false, refused: false };
    /** The page was fetched again once, because another tab had moved the memory since the first fetch. */
    let refetched = false;
    /** The last page of the feed that was used. @type {any} */
    let last = null;
    if (relistFirst) {
      // The page was closed in the middle of a listing: the rows it cached say nothing about what was read, so the vault is listed again from the beginning.
      await relist(db, pass);
      if (stopped) return;
      relistFirst = false;
      restarted = true; // one listing in a pass, as after a 410
      since = cursor;
    }
    for (;;) {
      // What the memory held before this page was asked for. If it has moved by the time the page is given to
      // it, another tab saved in between, and a page that now looks too old may only be older than that.
      const snapshot = (await memory.load()).memory;
      if (stopped) return; // stopped while the memory was read: nothing is asked of the server any more
      /** @type {any} */
      let page;
      try {
        page = await api.get(`/api/sync/changes?since=${since}&limit=${PAGE_LIMIT}`, { shape: "changes_res" });
      } catch (error) {
        if (/** @type {any} */ (error)?.code === "gone" && !restarted) {
          restarted = true; // the cursor is below the floor: list the vault again, then go on from where the listing began
          await relist(db, pass);
          if (stopped) return;
          since = cursor;
          continue;
        }
        throw error;
      }
      if (stopped) return;
      checkPage(page, since);
      await checkEpoch(pass, page.restore_epoch);
      const outcome = await applyPage(db, page, pass, { snapshot, mayRefetch: !refetched });
      if (outcome === "refetch") {
        refetched = true; // once: a server that is really lying says the same again, and the engine halts then
        continue;
      }
      refetched = false;
      if (stopped) return;
      last = page;
      if (page.changes.length > 0) {
        since = page.changes[page.changes.length - 1].seq; // the last row, not latest_seq
        cursor = since;
      }
      if (!page.has_more) {
        // A higher restore epoch is never stored before the vault has been listed in full: seq numbers are used again after a restore, so
        // rows below the cursor are never sent by the feed, and what the restore lost is only seen by comparing with the listing.
        const listed = await listForRaisedEpoch(db, pass);
        if (stopped) return;
        if (listed) {
          since = cursor;
          continue; // the feed goes on from where the listing began
        }
        break;
      }
    }
    const raised = await finishEpoch(pass);
    if (stopped) return;
    // A pass that began after the server refused something for its restore epoch, and found no higher one, has settled it.
    if (epochMovedAt !== null && pass.id > epochMovedAt) epochMovedAt = null;
    await conditionAfterFirstContact();
    if (stopped) return;
    // The feed is read to its end: the checkpoint step needs the `latest_seq` of that last page (the drained state, even when
    // the last row was a tombstone that has since been purged), and what the listing, if any, showed.
    lastDrain = {
      seq: last.latest_seq, head: last.checkpoint?.seq ?? null, pageHead: last.checkpoint?.seq ?? null, listed: listing !== null,
      refused: pass.refused, memory: (await memory.load()).memory, epoch: raised === null ? null : { from: pass.stored, to: raised },
    };
    if (listing !== null) await finishListing(db); // the marks of what the listing did not show are saved first
    if (stopped) return;
    await clearListingNote(db); // the feed after the listing (if there was one) has been read to its end
  }

  /**
   * Reads the full listing, `GET /api/sync/items`, page by page in the order of the ids. Every page is checked
   * (`checkListingPage`, and the key epoch against the scope) before `use` sees it. `use(page, { snapshot, mayRefetch })`
   * answers "refetch" to have the same page asked for again (the memory moved under it, see `applyPage`). Returns the
   * `as_of_seq` of the FIRST page, or null when the engine was stopped. `as_of_seq` is not compared with the rows of
   * other pages: an honest server takes writes while it lists.
   * @param {(page: any, again: { snapshot: Uint8Array, mayRefetch: boolean }) => Promise<"done" | "refetch" | undefined | void>} use
   * @returns {Promise<number | null>}
   */
  async function readListing(use) {
    /** @type {any} */
    let previous = null;
    /** @type {number | null} */
    let first = null;
    let refetched = false;
    for (;;) {
      // What the memory held before the page was asked for (see `cycle`).
      const snapshot = (await memory.load()).memory;
      if (stopped) return null; // stopped while the memory was read: nothing is asked of the server any more
      const after = previous === null ? "" : `&after=${previous.next_after}`;
      const page = await api.get(`/api/sync/items?limit=${PAGE_LIMIT}${after}`, { shape: "items_res" });
      if (stopped) return null;
      checkListingPage(page, previous, PAGE_LIMIT);
      if (page.vk_epoch !== scope.vkEpoch) throw new SyncError("epoch_mismatch");
      if ((await use(page, { snapshot, mayRefetch: !refetched })) === "refetch") {
        refetched = true; // once, as for the feed
        continue;
      }
      refetched = false;
      if (stopped) return null;
      if (first === null) first = page.as_of_seq;
      previous = page;
      if (!page.has_more) return first;
    }
  }

  /**
   * The full listing after a 410: every page is used like a page of the feed (its rows go through the same judging and the
   * sync memory; the `as_of_seq` of the page is its top `seq`). When the listing is done the cursor is the `as_of_seq` of
   * the FIRST page: a row written while the listing went on is on a later page, or above that `seq` and in the feed that
   * follows, and a row read twice is the same row.
   * Spec: Fase 1 section 8.4 ("Retention": full reconciliation after a 410).
   * @param {any} db @param {PassState} pass
   */
  async function relist(db, pass) {
    listing = new Set();
    try {
      await noteListing(db); // before a row of it is cached: a page closed from here on lists again, it never reads on from the cached rows
      const first = await readListing(async (page, again) => {
        await checkEpoch(pass, page.restore_epoch);
        listingEpoch = page.restore_epoch;
        listingPass = pass.id;
        return applyPage(db, { changes: page.items, latest_seq: page.as_of_seq }, pass, again);
      });
      if (first !== null) cursor = first;
    } catch (error) {
      listing = null; // the ids seen so far are not a listing: nothing may be marked missing from them
      throw error;
    }
  }

  /** Stores the note of an unfinished listing, before any row of the listing is cached. @param {any} db */
  async function noteListing(db) {
    if (listingNoted) return;
    await store.setSetting(db, listingKey, { v: 1 });
    listingNoted = true;
  }

  /** Removes the note once the feed after the listing has been read to its end. @param {any} db */
  async function clearListingNote(db) {
    if (!listingNoted) return;
    await store.deleteSetting(db, listingKey);
    listingNoted = false;
  }

  /**
   * The feed has been read to its end and the server shows a restore epoch above the stored one: before it is stored (by the
   * verification of the checkpoint, or at once on a first contact) the vault is listed in full, through the normal page path
   * (the checks of `checkListingPage`, the judging and the sync memory of `applyPage`). Rows that lie below what this device holds
   * make `applyPage` stop with `server_restored`; so does a live row this device holds that the listing leaves out (the restore lost
   * it; a write that only waits in the outbox is not a held row). Otherwise the cursor is the `as_of_seq` of the first page, and the
   * caller reads the feed on from there. A write that the server refused for its restore epoch already stops the engine in `finishEpoch`.
   * Spec: Fase 1 section 8.6 ("Legitimate rollbacks").
   * @param {any} db @param {PassState} pass
   * @returns {Promise<boolean>} true when the vault was listed now (the feed has to be read on from the new cursor)
   */
  async function listForRaisedEpoch(db, pass) {
    if (pass.raised === null || pass.lower || epochMovedAt !== null || listedEpoch >= pass.raised) return false;
    let listedNow = false;
    // A listing made earlier in this pass (after a 410, or the one a start owed) counts only when its pages carried the raised epoch; one left
    // behind by a pass that failed says nothing about the server as it is now (it is still finished for the items it did not show).
    if (listing === null || listingPass !== pass.id || listingEpoch < pass.raised) {
      await relist(db, pass);
      if (stopped) return false;
      listedNow = true;
    }
    const seen = /** @type {Set<string>} */ (listing);
    for (const [id, row] of rows) {
      if (seen.has(id) || id === MANIFEST_ID || row.deleted || abandoned.has(id)) continue;
      if (flags.get(id)?.kind === "missing_on_server") continue; // the server already lacked it before the restore
      throw new SyncError("server_restored", "The server was restored to an earlier state.");
    }
    listedEpoch = Math.max(listedEpoch, /** @type {number} */ (pass.raised));
    return listedNow;
  }

  /**
   * @typedef {object} PassState what one pass over the feed has learned about the restore epoch
   * @property {number} id the number of the pass
   * @property {number | null} stored the highest epoch this device has accepted (null: none yet, a first contact)
   * @property {number | null} first on a first contact: the epoch the server shows, to be stored when the pass has gone well
   * @property {number | null} raised the highest epoch the server showed that is above `stored` (on a first contact: above zero)
   * @property {boolean} lower something the server showed is below what this device remembers
   * @property {boolean} refused the memory refused a row in this pass (the rows this device holds are not all the server shows)
   */

  /**
   * What a page must look like for the engine to go on.
   * @param {any} page @param {number} since
   */
  function checkPage(page, since) {
    if (page.vk_epoch !== scope.vkEpoch) throw new SyncError("epoch_mismatch");
    if (page.changes.length > PAGE_LIMIT) throw new SyncError("bad_feed"); // more than was asked for
    let last = since;
    for (const change of page.changes) {
      if (change.seq <= last) throw new SyncError("bad_feed"); // not strictly rising: the loop could never end
      last = change.seq;
    }
    if (page.has_more && page.changes.length === 0) throw new SyncError("bad_feed");
  }

  /**
   * Stores a restore epoch under the lock, unless a higher one is stored (a second
   * tab may have got there first). @param {number} epoch @returns {Promise<number>} the epoch that is stored now
   */
  async function saveEpoch(epoch) {
    let now_ = epoch;
    await memory.withLock(async (state) => {
      if (state.restoreEpoch !== null && state.restoreEpoch >= epoch) {
        now_ = state.restoreEpoch;
        return null;
      }
      return { ...state, restoreEpoch: epoch };
    });
    return now_;
  }

  /**
   * The restore epoch of a page against the one this device has accepted. A lower one
   * halts. A higher one is not stored until the pass has seen nothing below what the
   * device remembers (`finishEpoch`). With none stored yet (a first contact) the epoch
   * is stored only when the pass has gone well, and any epoch above zero counts as
   * raised, so a server that was restored before this device ever stored one is told
   * apart from a plain rollback.
   * @param {PassState} pass @param {number} epoch
   */
  async function checkEpoch(pass, epoch) {
    if (pass.stored === null) {
      if (pass.first === null || epoch > pass.first) pass.first = epoch;
      if (epoch > 0 && (pass.raised === null || epoch > pass.raised)) {
        pass.raised = epoch;
        runner.hold(); // nothing is sent from the moment the server shows a restore, whoever released the runner before
      }
      return;
    }
    if (epoch < pass.stored) {
      throw new SyncError("restore_epoch_lowered", "The server shows an older restore epoch than this device has seen.");
    }
    if (epoch > pass.stored && (pass.raised === null || epoch > pass.raised)) {
      pass.raised = epoch;
      runner.hold();
    }
  }

  /**
   * The end of a pass. A higher epoch with something lower on the server means the
   * server was restored from a backup: the engine halts and the user decides. A
   * higher epoch without it is not stored here: it is stored, with a message, when
   * the checkpoint of the server verifies (`checkpointStep`), and a checkpoint that
   * does not verify is a restore as well. A first contact stores its epoch without
   * a message: there was nothing to compare with.
   * @param {PassState} pass
   * @returns {Promise<number | null>} the higher epoch that waits for the verification, or null
   */
  async function finishEpoch(pass) {
    if (pass.raised === null && pass.first === null) return null;
    if (pass.raised !== null && (pass.lower || epochMovedAt !== null)) {
      // Something lower than this device remembers, or the server has refused a write for its restore epoch and no pass has shown
      // since that nothing is higher: the user decides. The mark stays until the older state is accepted.
      throw new SyncError("server_restored", "The server was restored to an earlier state.");
    }
    if (pass.stored === null) {
      pass.stored = await saveEpoch(/** @type {number} */ (pass.first));
      pass.first = null;
      pass.raised = null;
      return null;
    }
    return pass.raised;
  }

  /**
   * One page of the feed. First every row is judged without changing anything
   * (the core opens it, the tombstone is verified, the floors of this device are
   * compared); what the judging would do besides (marks, warnings, the list of ids a
   * listing has shown) is kept and done only when the page is used. Then the rows
   * that stand are given to the sync memory; only the rows the memory takes change
   * the rows, the index, the overlay and the marks. A page that halts the engine, or
   * that is fetched again, has therefore changed nothing.
   *
   * Answers "refetch" when the memory refused something that another tab's save may
   * explain (see `acceptPage`) and the page has not been fetched again yet.
   * @param {any} db @param {any} page @param {PassState} pass
   * @param {{ snapshot: Uint8Array, mayRefetch: boolean }} again
   * @returns {Promise<"done" | "refetch" | undefined>}
   */
  async function applyPage(db, page, pass, { snapshot, mayRefetch }) {
    const changes = /** @type {any[]} */ (page.changes);
    /**
     * A row that stands, and what it does to the engine once the memory has it.
     * @type {Array<{ id: string, row: CachedRow, ours: boolean, touch: boolean, trash?: CachedRow | null, apply: (() => void) | null }>}
     */
    const plan = [];
    /** The rows of this page as the later rows of it see them (an honest server shows one row per item). @type {Map<string, CachedRow>} */
    const staged = new Map();
    /** @type {Set<string>} */
    const touched = new Set();
    /** What judging a row would do besides planning it: marks, warnings. Done only when the page is used. @type {Array<() => void>} */
    const later = [];
    /** The ids of this page, for the list of a full listing. @type {string[]} */
    const shown = [];
    /** Something on this page is below what this device remembers. */
    let lowerHere = false;
    /** Marks that end with this page; they go only after the rows are in the cache. @type {Map<string, "clear" | "drop">} */
    const ending = new Map();
    /** Items whose refused draft only deleted (the server deleted them too): the draft is moot and goes after the rows are stored. @type {Set<string>} */
    const moot = new Set();
    /** Items that became a conflict with a deleted server while this page was being used, with a live draft whose summary was not made: shown after the rows are stored. @type {Set<string>} */
    const draftLate = new Set();
    /** The rows this page replaced, to put back when the cache write fails. @type {Map<string, CachedRow | undefined>} */
    const replaced = new Map();
    /** @param {string} itemId @param {CachedRow} next */
    const setRow = (itemId, next) => {
      if (!replaced.has(itemId)) replaced.set(itemId, rows.get(itemId));
      rows.set(itemId, next);
    };
    /** A row below what this device remembers. @param {string} code @param {Record<string, any>} extra */
    const lowerSeen = (code, extra) => {
      lowerHere = true;
      later.push(() => warn(code, extra));
    };
    /** @param {string} id @param {number} rev @param {string} reason */
    const damaged = (id, rev, reason) => {
      later.push(() => {
        markDamaged(id, rev, reason);
        touched.add(id);
      });
    };
    for (const change of changes) {
      if (stopped) return;
      const id = /** @type {string} */ (change.id);
      shown.push(id);
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
          lowerSeen("rev_lower_than_local", { id, rev: change.rev, localRev: floor });
          continue;
        }
        damaged(id, change.rev, "malformed");
        continue;
      }
      let local = staged.get(id) ?? rows.get(id);
      const lastLive = local; // the live row this one may replace, for the trash (`local` can be dropped below)
      const mark = flags.get(id);
      let ours = false;
      if ((mark?.kind === "missing_on_server" || mark?.kind === "reuploaded") && row.rev <= mark.rev) {
        // At or below the floor of an item that was uploaded again: only a row this device wrote is accepted.
        const key = await ownKeyOf(row);
        alive();
        if (mark.sent?.includes(key)) {
          ours = true;
          // The row that replaces the old copy skips the check against the local row; a replay of an own earlier version
          // still has to be above what this device has now. The first copy was at the floor itself. After the item was
          // left out a second time, the copy uploaded after the new mark is below the floor: that is why the keys of
          // writes made since the mark are listed apart (`fresh`), and only they get the wider rule. A key that was kept
          // from before (a write still queued when the mark was made again) is held to the narrow one.
          const replaces = local !== undefined && (local.rev === mark.rev || (mark.fresh?.includes(key) === true && local.rev <= mark.rev));
          if (mark.kind === "missing_on_server" && replaces) local = undefined;
        } else if (row.rev < mark.rev) {
          lowerSeen("rev_lower_than_local", { id, rev: row.rev, localRev: mark.rev });
          continue;
        } else if (mark.kind === "missing_on_server" && !row.deleted && local && sameRow(row, local)) {
          // The server shows the item again with the row this device has: it was only left out.
          plan.push({ id, row, ours: false, touch: true, apply: () => ending.set(id, "clear") });
          staged.set(id, row);
          continue;
        } else {
          // Exactly the old floor, and not a row this device wrote: no honest path leads here.
          lowerSeen("rev_same_row_changed", { id, rev: row.rev });
          continue;
        }
      }
      if (local) {
        if (row.rev < local.rev) {
          lowerSeen("rev_lower_than_local", { id, rev: row.rev, localRev: local.rev });
          continue;
        }
        if (row.rev === local.rev) {
          if (sameRow(row, local)) {
            // already known: only make sure it is cached
            plan.push({ id, row, ours: false, touch: false, apply: null });
            staged.set(id, row);
          } else {
            lowerSeen("rev_same_row_changed", { id, rev: row.rev });
          }
          continue;
        }
      }
      if (id === MANIFEST_ID) {
        // Kept in the cache, never an item. The memory checks its tag like any other row's.
        plan.push({ id, row, ours: false, touch: false, apply: () => setRow(id, row) });
        staged.set(id, row);
        continue;
      }
      if (row.deleted) {
        try {
          await client.vault.verify_tombstone(hex16.decode(id), row.rev, /** @type {Uint8Array} */ (row.tomb));
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
          later.push(() => {
            // A mark that keeps a floor is not replaced: the floor would go with it.
            if (!keepsFloor(id)) {
              flags.set(id, { kind: "quarantined", rev: row.rev });
              flagsDirty = true;
            }
            touched.add(id);
            warn("tombstone_unverified", { id, rev: row.rev });
          });
          continue;
        }
        alive();
        // A write of this item that was refused and waits for the user: a live draft is a conflict with a deleted server (it stays
        // on screen, with the choice to bring the item back or to accept the deletion); a draft that only deletes is moot.
        // The summary of the draft is made now when the item is blocked; whether it is blocked is decided again when the row is used,
        // because a refusal can come in between (the page is judged, given to the memory and written to the trash first).
        const draft = blocked.has(id) ? liveDraftOf(id) : null;
        /** @type {ReturnType<typeof summaryOf> | null} */
        let draftSummary = null;
        if (draft) {
          try {
            draftSummary = await summarize(id, draft.baseRev + 1, draft.body.blob, draft.body.tag);
            alive();
          } catch (error) {
            if (stopped || isFatal(error)) throw error;
          }
        }
        plan.push({
          id, row, ours, touch: true,
          // The last live row, kept in the local trash when this tombstone is used (and the memory has taken it).
          trash: lastLive && !lastLive.deleted ? lastLive : null,
          apply: () => {
            settleMark(id, row.rev, ours, ending);
            setRow(id, row);
            const waits = blocked.has(id);
            const draftNow = waits ? liveDraftOf(id) : null;
            const summarized = draftNow !== null && draft !== null && draftSummary !== null && draftNow.idem === draft.idem;
            if (summarized) index.set(id, /** @type {any} */ (draftSummary));
            else index.delete(id);
            overlay.delete(id);
            if (waits) {
              if (draftNow) {
                blocked.set(id, "conflict");
                conflictNotes.set(id, { serverRev: row.rev, serverDeleted: true });
                if (!summarized) draftLate.add(id);
              } else {
                moot.add(id);
              }
              flagsDirty = true;
            }
          },
        });
        staged.set(id, row);
        continue;
      }
      try {
        const summary = await summarize(id, row.rev, /** @type {Uint8Array} */ (row.envelope), /** @type {Uint8Array} */ (row.tag));
        alive();
        plan.push({
          id, row, ours, touch: true,
          apply: () => {
            settleMark(id, row.rev, ours, ending);
            setRow(id, row);
            const mine = overlay.get(id);
            if (mine && mine.rev > row.rev) {
              // A local write is ahead of this row: it stays on screen.
            } else {
              overlay.delete(id);
              index.set(id, summary);
            }
          },
        });
        staged.set(id, row);
      } catch (error) {
        if (stopped || isFatal(error)) throw error;
        damaged(id, row.rev, codeOf(error));
      }
    }
    // The memory, even for a page without rows: its top `seq` is checked and remembered. The rows this device wrote
    // itself for an item that was uploaded again are not given to it (they are below its floor, by design).
    /** @type {Set<CachedRow>} */
    let refusedRows = new Set();
    /** @type {Array<{ row: CachedRow, code: string }>} */
    let refused = [];
    try {
      const verdict = await acceptPage({
        client, memory, rows: plan.filter((p) => !p.ours).map((p) => p.row), topSeq: page.latest_seq, since: snapshot,
      });
      alive();
      refused = verdict.refused;
      refusedRows = new Set(refused.map((r) => r.row));
      // Below the remembered revision, and another tab has saved since the page was asked for: it may only be older than that.
      if (mayRefetch && verdict.moved && refused.some((r) => r.code === REV_BELOW_REMEMBERED)) return "refetch";
    } catch (error) {
      if (mayRefetch && /** @type {any} */ (error)?.code === "rollback_suspected" && /** @type {any} */ (error).memoryMoved === true) {
        return "refetch";
      }
      // A top `seq` below the remembered one, while the server also shows a higher restore epoch, is a restore.
      if (pass.raised !== null && /** @type {any} */ (error)?.code === "rollback_suspected") {
        throw new SyncError("server_restored", "The server was restored to an earlier state.");
      }
      throw error;
    }
    const refusedBelow = refused.some((r) => r.code === REV_BELOW_REMEMBERED);
    // Something lower than this device remembers, on a server that now shows a higher epoch: a restore. Nothing of this page is used.
    if (pass.raised !== null && (pass.lower || lowerHere || refusedBelow)) {
      throw new SyncError("server_restored", "The server was restored to an earlier state.");
    }
    // A verified tombstone that replaces a live row: the row goes to the local trash first. The cache is written over it next, and
    // nothing is deleted on the server's word alone. A trash that cannot be written stops the page: the next pass tries it again.
    for (const step of plan) {
      const last = step.trash;
      if (!last || (!step.ours && refusedRows.has(step.row))) continue;
      // A copy that cannot be made (the cached row does not open, or no version lies below the tombstone) does not stall the page:
      // the tombstone is verified and used, the trash only lacks that copy, and a warning says so.
      /** @type {import("../store/trash.mjs").TrashEntry | null} */
      let entry = null;
      try {
        entry = await trashCopy(step.id, last.rev, /** @type {Uint8Array} */ (last.envelope), /** @type {Uint8Array} */ (last.tag), step.row.rev);
      } catch (error) {
        if (stopped || isFatal(error)) throw error;
        later.push(() => warn("trash_copy_skipped", { id: step.id, rev: step.row.rev, reason: codeOf(error) }));
      }
      alive();
      if (entry) await store.trash.put(db, scope, entry);
      alive();
    }
    // The page is used: now what judging it kept for later is done.
    if (lowerHere || refusedBelow) pass.lower = true;
    if (refused.length > 0 || lowerHere) pass.refused = true;
    for (const id of shown) listing?.add(id);
    for (const step of later) step();
    for (const { row, code } of refused) {
      if (code === REV_BELOW_REMEMBERED) warn("rev_below_remembered", { id: row.itemId, rev: row.rev });
      else warn("row_damaged", { id: row.itemId, rev: row.rev, reason: code });
    }
    /** @type {CachedRow[]} */
    const accepted = [];
    for (const step of plan) {
      if (!step.ours && refusedRows.has(step.row)) continue; // refused: nothing changes
      step.apply?.();
      accepted.push(step.row);
      if (step.touch) touched.add(step.id);
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
    for (const itemId of moot) {
      // The refused writes only delete the item, and the server has deleted it: there is nothing left to choose.
      await dropMoot(itemId);
    }
    for (const itemId of draftLate) await showServerVersion(itemId); // a refusal came in while the page was used: the draft is what the screen shows
    // A conflict follows the server's row: its revision and whether it is deleted are what the user will be shown.
    for (const row of accepted) {
      if (conflictNotes.has(row.itemId) && blocked.get(row.itemId) === "conflict") {
        conflictNotes.set(row.itemId, { serverRev: row.rev, serverDeleted: row.deleted });
        flagsDirty = true;
      }
    }
    await saveFlags(db);
    changed(touched);
    return "done";
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
    if (ours && (mark.kind === "missing_on_server" || mark.kind === "reuploaded") && rev <= mark.rev) {
      // At the floor itself counts as below it: a copy of an item whose floor is revision 1 comes back at revision 1, and a
      // checkpoint that lists the old hash of that revision must still be explained by the mark. It ends when a row above comes.
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
      if (seen.has(id) || id === MANIFEST_ID || row.deleted) continue;
      // Another mark stays as it is. An item that was uploaded again and is left out once more is marked again, with
      // the floor it already has. The keys of its own writes are kept only for writes that are still queued or in
      // flight (their echo must still be taken as ours); the others belong to a copy the server has dropped. Keys
      // of writes made from now on are listed apart, in `fresh`: the wider rule for the copy that replaces the old
      // one applies to them only.
      const mark = flags.get(id);
      if (mark !== undefined && mark.kind !== "reuploaded") continue;
      /** @type {string[]} */
      let kept = [];
      if (mark !== undefined) {
        const queued = await Promise.all(runner.entriesOf(id).map((entry) => ownKeyOfBody(entry.baseRev + 1, entry.body)));
        alive();
        kept = (mark.sent ?? []).filter((key) => queued.includes(key));
      }
      flags.set(id, {
        kind: "missing_on_server",
        rev: floorOf(id) ?? row.rev,
        ...(kept.length > 0 ? { sent: kept } : {}),
        ...(mark !== undefined ? { fresh: [] } : {}),
      });
      acked.delete(id); // the earlier upload was answered, but the server has lost that copy: it is uploaded again
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
        // Also when the copy sits at the old floor itself (a floor of revision 1): the mark stays until a row above it comes.
        flags.set(id, { kind: "reuploaded", rev: mark.rev, sent: mark.sent });
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
        // The server deleted the item. A live draft that waits for the user's choice stays on screen (as the draft); otherwise it is gone.
        const draft = blocked.has(id) ? liveDraftOf(id) : null;
        if (draft) {
          const summary = await summarize(id, draft.baseRev + 1, draft.body.blob, draft.body.tag);
          alive();
          if (rows.get(id) === row) index.set(id, summary);
        } else {
          index.delete(id);
        }
      }
      // No server row at all: a draft the server never took. Its summary stays, marked blocked.
    } catch {
      // The marks still say what is wrong; the list keeps what it has.
    }
    changed([id]);
  }

  /**
   * The newest write that waits for an item, when it is a live one (not a tombstone): the local version a conflict is about.
   * @param {string} id
   * @returns {(import("../store/outbox.mjs").OutboxEntry & { body: { blob: Uint8Array, tag: Uint8Array } }) | null}
   */
  function liveDraftOf(id) {
    const last = runner.entriesOf(id).at(-1);
    return last !== undefined && !("tomb" in last.body) ? /** @type {any} */ (last) : null;
  }

  /**
   * The conflict of an item, or null: blocked with the code `conflict`. The numbers come from the saved note, or, for a
   * conflict that was saved before the note existed, from the row the engine holds.
   * @param {string} id
   * @returns {{ serverRev: number, serverDeleted: boolean } | null}
   */
  function conflictOf(id) {
    if (blocked.get(id) !== "conflict") return null;
    const kept = conflictNotes.get(id);
    if (kept) return kept;
    const row = rows.get(id);
    return { serverRev: row?.rev ?? 0, serverDeleted: row?.deleted === true };
  }

  /** The items that are blocked with the code `conflict`: they stay conflicts when an older state is accepted. */
  function conflictIds() {
    return [...blocked].filter(([, code]) => code === "conflict").map(([id]) => id);
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
      const noted = [...conflictNotes].filter(([id]) => blocked.get(id) === "conflict");
      await store.setSetting(db, flagsKey, {
        v: 1, marks: Object.fromEntries(flags), blocked: Object.fromEntries(blocked), conflicts: Object.fromEntries(noted),
      });
    } catch (error) {
      flagsDirty = true; // not saved: the next save writes it
      throw error;
    }
  }

  // ------------------------------------------------------- checkpoints

  /** The failures of the core that another tab's save can explain: its memory knows more than the rows or the checkpoint here. */
  const TAB_RACE = new Set(["checkpoint_seq_below_remembered", "checkpoint_top_seq_below_remembered", REV_BELOW_REMEMBERED]);

  /** @param {Uint8Array} a @param {Uint8Array} b */
  const sameMemory = (a, b) => a.length === b.length && a.every((n, i) => n === b[i]);

  /**
   * Whether every item the checkpoint disagrees with is one that was uploaded again (an item with a `missing_on_server` or `reuploaded` mark), so the disagreement is
   * explained and verification is only put off. An item without a mark, or a disagreement nobody can name, is not.
   * Spec: Fase 1 section 8.6 ("What a recipient checks").
   *
   * The core checks the memory last, after the entries, so the first failure it names can hide a row that is below its floor
   * for no reason a mark can give. Before a failure is put off, the rows without a mark are therefore given to the memory
   * on their own (the answer is thrown away): if the core refuses one of them, the failure is hard. A checkpoint below the
   * highest one that has verified is an old one shown again, and is hard as well.
   *
   * An item the server hid whose floor is revision 1 keeps its mark as well, when the copy that was uploaded again comes
   * back at revision 1: the mark ends only when a row above the floor arrives (`settleMark`), so a checkpoint that lists the
   * old hash of that revision is a pause here, and not a hard warning.
   * @param {string} code the failure of the core
   * @param {import("./checkpoint.mjs").Checkpoint} checkpoint @param {number} topSeq
   * @param {import("../store/syncState.mjs").SyncState} state the state the verification ran against
   */
  async function explainedByMarks(code, checkpoint, topSeq, state) {
    if (hardWarningOf(code, { deferred: true }) !== "verify_deferred") return false;
    if (state.verifiedSeq !== null && checkpoint.seq < state.verifiedSeq) return false;
    /** @type {Set<string>} */
    const marked = new Set();
    for (const [id, mark] of flags) if (mark.kind === "missing_on_server" || mark.kind === "reuploaded") marked.add(id);
    if (marked.size === 0) return false;
    const failing = await failingIds(checkpoint.entries, rows, checkpoint.seq === topSeq);
    if (failing === null) return false;
    // A row below what this device remembers (the copy that was uploaded again is below its old floor, by design) is not
    // a disagreement between entries and rows: it is explained when nothing unmarked disagrees.
    if (code !== REV_BELOW_REMEMBERED && failing.size === 0) return false;
    if (![...failing].every((id) => marked.has(id))) return false;
    const unmarked = [...rows.values()].filter((row) => !marked.has(row.itemId)).map(coreRow);
    try {
      await client.vault.accept_rows(unmarked, topSeq, state.memory);
    } catch (error) {
      if (isFatal(error)) throw error;
      return false;
    }
    return true;
  }

  /**
   * Verifies the checkpoint of the server against the rows this device holds, under the lock of the sync memory: the new
   * memory, the time and a cleared warning are stored in one go, or a warning is. Answers `"ok"`, the code of the warning,
   * `"retry"` (another tab's memory knows more than these rows, or the checkpoint is newer than the feed this pass read:
   * read the feed again first, once), or null (the server could not be reached; nothing changed). A stop (`rollback_suspected`,
   * `sync_memory_full`) is thrown as a `SyncError`.
   * Spec: Fase 1 section 8.6 ("What a recipient checks", "Local memory").
   * @param {{ seq: number, head: number | null, pageHead: number | null, memory: Uint8Array }} drain
   * @param {import("../store/syncState.mjs").SyncState} before the stored state when the step began
   * @param {boolean} mayRetry
   * @param {boolean} [offer] the server shows a higher restore epoch: a checkpoint that does not verify is then a restore, the
   *   engine stops with `server_restored` (the user may accept the older state) and no warning is stored or shown
   * @returns {Promise<string | null>}
   */
  async function verifyStep(drain, before, mayRetry, offer = false) {
    /** @type {import("./checkpoint.mjs").Checkpoint} */
    let checkpoint;
    try {
      checkpoint = await fetchCheckpoint(api);
    } catch (error) {
      const status = /** @type {any} */ (error)?.status;
      if (status === 401 || status === 403) {
        // The session, not the checkpoint: the pass handles it like any other refused session.
        /** @type {any} */ (error).sessionProblem = true;
        throw error;
      }
      if (typeof status !== "number" || status === 0 || status === 408 || status === 429 || status >= 500) return null; // not reachable now
      // The server answers, and not with a checkpoint it can have: nothing can be verified. A warning that is stored stays.
      if (offer) throw new SyncError("server_restored", "The server was restored to an earlier state.");
      let kept = "bad_feed";
      await memory.withLock(async (state) => {
        kept = escalate(state.hardWarning, "bad_feed");
        return kept === state.hardWarning ? null : { ...state, hardWarning: kept };
      });
      alive();
      return settleFailure("bad_feed", kept, before, drain);
    }
    alive();
    drain.head = Math.max(drain.head ?? 0, checkpoint.seq);
    // A checkpoint above the feed that was read: another device uploaded one since. Read again before calling it a lie.
    if (checkpoint.seq > drain.seq && mayRetry) return "retry";
    const rowsNow = [...rows.values()];
    const coreRows = rowsNow.map(coreRow);
    /** @typedef {{ ok: true } | { ok: false, code: string, moved: boolean, warning: string, kept: string, offered?: boolean }} Verdict */
    /** @type {{ verdict: Verdict | null }} */
    const box = { verdict: null };
    await memory.withLock(async (state) => {
      const moved = !sameMemory(state.memory, drain.memory); // another tab has saved since this pass left the memory
      try {
        const done = await client.vault.verify_checkpoint(checkpoint, coreRows, drain.seq, state.memory);
        box.verdict = { ok: true };
        return {
          ...state, memory: done.newSyncMemory, verifiedAt: now(), verifiedSeq: Math.max(state.verifiedSeq ?? 0, checkpoint.seq), hardWarning: null,
        };
      } catch (error) {
        if (isFatal(error)) throw error;
        const code = codeOf(error);
        if (moved && mayRetry && TAB_RACE.has(code)) {
          box.verdict = { ok: false, code, moved, warning: "", kept: "" };
          return null; // the other tab has seen more: nothing is said before the feed has been read again
        }
        if (offer && hardWarningOf(code) !== "sync_memory_full") {
          box.verdict = { ok: false, code, moved, warning: "", kept: "", offered: true };
          return null; // a restored server that shows what this device cannot verify: the user is offered the older state, nothing is said
        }
        const warning = hardWarningOf(code, { deferred: await explainedByMarks(code, checkpoint, drain.seq, state) });
        // What is stored after a failure can only go up: a warning that stands is not replaced by a lesser one.
        const kept = STOP_CODES.includes(warning) ? warning : escalate(state.hardWarning, warning);
        box.verdict = { ok: false, code, moved, warning, kept };
        if (STOP_CODES.includes(warning) || state.hardWarning === kept) return null;
        return { ...state, hardWarning: kept };
      }
    });
    alive();
    const verdict = /** @type {Verdict} */ (box.verdict);
    if (verdict.ok) {
      verifiedInSession = true;
      forgedUnlock = false;
      verifyNotBefore = 0;
      deferredAt = null;
      for (const code of VERIFY_WARNINGS) clearWarning(code);
      return "ok";
    }
    if (verdict.offered === true) throw new SyncError("server_restored", "The server was restored to an earlier state.");
    if (verdict.warning === "") return "retry";
    if (STOP_CODES.includes(verdict.warning)) {
      throw new SyncError(verdict.warning, verdict.warning === "rollback_suspected"
        ? "The server shows a state older than this device has seen."
        : "This device cannot remember more items from this server. Forget the server to start again.");
    }
    return settleFailure(verdict.warning, verdict.kept, before, drain);
  }

  /**
   * A verification that did not succeed. `warning` is what this attempt found and `kept` what is stored now (the warning
   * that stood, when it is more serious). A failure never clears a state warning or a pause: those go only when a
   * verification succeeds. What stands afterwards is `kept`, and the warning of this attempt next to it when it is only
   * information (a forged checkpoint, a bad feed). Uploads may be unlocked by the exception for those two on a device that has
   * verified before, but never while a state warning or a pause stands. The next automatic try waits.
   * @param {string} warning @param {string} kept @param {import("../store/syncState.mjs").SyncState} before
   * @param {{ seq: number, pageHead: number | null }} drain
   * @returns {string} the most serious warning that stands
   */
  function settleFailure(warning, kept, before, drain) {
    const wanted = new Set([kept]);
    if (warningRank(warning) === 1) wanted.add(warning);
    for (const code of VERIFY_WARNINGS) if (!wanted.has(code)) clearWarning(code);
    for (const code of wanted) raiseWarning(code);
    forgedUnlock = warningRank(warning) === 1 && warningRank(kept) < 2 && before.verifiedAt !== null;
    verifyNotBefore = now() + VERIFY_RETRY_MS;
    deferredAt = kept === "verify_deferred" ? { seq: drain.seq, head: drain.pageHead, at: now() } : null;
    return warningRank(kept) > warningRank(warning) ? kept : warning;
  }

  /**
   * After a pass that read the whole feed: verify the checkpoint of the server when it is due, then upload one of this
   * device's own when that is allowed.
   */
  async function checkpointStep() {
    const drain = lastDrain;
    lastDrain = null;
    if (!drain || stopped || halted !== null) return;
    const mayRetry = !retryPending;
    retryPending = false;
    const before = await memory.load();
    alive();
    const at = now();
    const age = before.verifiedAt === null ? Infinity : at - before.verifiedAt;
    // Due: never verified, a day old (or from the future), a warning to look at again, a listing, or asked for. The automatic
    // tries wait a while after a failure; a listing and a request do not.
    const due = before.verifiedAt === null || age < 0 || age >= VERIFY_AFTER_MS || before.hardWarning !== null;
    // While only a pause stands, the checkpoint is not asked for again until the feed has moved (its top or the head of the
    // checkpoint), or a day has passed: nothing but a change can end a pause.
    const unchanged = deferredAt !== null && deferredAt.seq === drain.seq && deferredAt.head === drain.pageHead && at - deferredAt.at < VERIFY_AFTER_MS;
    // A session that has not verified yet and has a checkpoint to store (every other condition of an upload holds) verifies now, whatever
    // the time of the last verification: a device that is reloaded at least once a day would otherwise never store one.
    const wantsUpload = !due && !verifiedInSession && !forgedUnlock && (await uploadReady(drain)) !== null;
    alive();
    // A higher restore epoch is accepted only after the checkpoint has verified: that is asked for whatever the time.
    const pending = drain.epoch;
    epochPending = pending !== null;
    if (pending !== null) runner.hold(); // nothing is sent to a server that may have been restored, until its checkpoint has verified
    if (verifyRequested || drain.listed || pending !== null || ((due || wantsUpload) && at >= verifyNotBefore && !unchanged)) {
      verifyRequested = false;
      const result = await verifyStep(drain, before, mayRetry, pending !== null);
      if (result === "retry") {
        retryPending = true;
        verifyRequested = true;
        again = true; // the feed is read once more, and the verification made then
        return;
      }
      verifyOutcome = result ?? "not_checked";
      if (result === null) verifyNotBefore = now() + VERIFY_RETRY_MS;
      if (pending !== null) {
        if (result !== "ok") return; // not checked: the epoch waits for the next pass, and nothing is uploaded meanwhile
        await saveEpoch(pending.to);
        alive();
        epochPending = false;
        warn("restore_epoch_raised", { from: pending.from, to: pending.to });
      }
    }
    await uploadStep(drain);
  }

  /**
   * Every condition of an upload except the verification of this session: nothing stands against it, nothing waits or is marked, the
   * pace of one upload in ten minutes, and something new to store. Answers the sync memory as it is now, or null.
   * @param {{ seq: number, head: number | null, refused: boolean }} drain
   * @returns {Promise<import("../store/syncState.mjs").SyncState | null>}
   */
  async function uploadReady(drain) {
    for (const code of standing) if (warningRank(code) >= 2) return null; // a code nobody named ranks as serious: it blocks
    if (drain.refused || flags.size > 0 || blocked.size > 0 || runner.itemsWithEntries().length > 0) return null;
    const at = now();
    if (at < uploadNotBefore) return null;
    const seq = drain.seq;
    const state = await memory.load();
    alive();
    if (warningRank(state.hardWarning) >= 2) return null; // another tab may have stored one that this engine has not shown
    const since = state.uploadedAt === null ? Infinity : at - state.uploadedAt;
    if (since >= 0 && since < UPLOAD_EVERY_MS) return null;
    if (state.uploadedSeq !== null && seq <= state.uploadedSeq) return null; // nothing new since the last upload
    if (drain.head !== null && seq <= drain.head) return null; // the server already holds one at least this new
    if ([...rows.values()].some((row) => row.seq > seq)) return null; // rows above the top the server named: no honest feed
    return state;
  }

  /**
   * Signs what this device holds and uploads it, when every condition holds (see the head of this file). A `409` that says
   * the stored checkpoint is newer counts as done; a `429` waits for the time the server named.
   * Spec: Fase 1 section 8.6 ("Checkpoint": the entries at `S`, at most one upload in ten minutes, only when something changed).
   * @param {{ seq: number, head: number | null, refused: boolean }} drain
   */
  async function uploadStep(drain) {
    if (stopped || halted !== null || !(verifiedInSession || forgedUnlock)) return;
    const state = await uploadReady(drain);
    if (state === null) return;
    const seq = drain.seq;
    const held = [...rows.values()];
    try {
      const signed = await client.vault.make_checkpoint(seq, await entriesOf(held));
      alive();
      await api.put("/api/sync/checkpoint", checkpointBody(signed, state.restoreEpoch), { shape: "checkpoint_put_res" });
    } catch (error) {
      if (stopped) return;
      const status = /** @type {any} */ (error)?.status;
      const code = codeOf(error);
      if (isFatal(error) || status === 401) throw error;
      if (status === 409 && code === "checkpoint_stale") {
        // The server holds one at least as new: nothing is lost by not sending ours.
      } else if (isRestoreEpochChanged(error)) {
        // The vault was restored since this device last looked. Nothing was stored. The feed is read again at once: a higher epoch is a
        // restore and stops the engine; the upload waits a while in any case, so a server that keeps saying this cannot make a loop.
        epochMovedAt = passes;
        uploadNotBefore = now() + VERIFY_RETRY_MS;
        again = true;
        return;
      } else if (status === 429) {
        const wait = /** @type {any} */ (error).retryAfter;
        uploadNotBefore = now() + 1000 * Math.min(3600, Math.max(1, typeof wait === "number" ? wait : UPLOAD_EVERY_MS / 1000));
        return;
      } else {
        uploadNotBefore = now() + VERIFY_RETRY_MS;
        emit("error", { code: "checkpoint_upload_failed", reason: code });
        return;
      }
    }
    await memory.withLock(async (current) => ({
      ...current,
      uploadedAt: now(),
      uploadedSeq: Math.max(current.uploadedSeq ?? 0, seq),
    }));
  }

  /** What a failure of a pass shows: a stop, a pause for the session, or a status and an event. @param {unknown} error */
  function failWith(error) {
    const code = codeOf(error);
    const status = /** @type {any} */ (error)?.status;
    if (error instanceof SyncError && code === "restore_not_verified") {
      // What the server shows now cannot be verified: the user is offered the older state again, and nothing is retried unasked.
      emit("error", { code, reason: error.reason });
      halt("server_restored");
    } else if (error instanceof SyncError && HALT_CODES.includes(code)) {
      halt(code);
    } else if (status === 401 || /** @type {any} */ (error)?.sessionProblem === true) {
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

  /** One pass: the feed. Failures become events; they never reject. */
  async function runCycle() {
    if (halted !== null) return;
    setStatus("syncing");
    try {
      // A restore that was started and not finished is finished first: the rows here are of the old history.
      if (restorePending) {
        await resumeRestore();
        if (stopped) return;
      }
      await cycle();
      if (stopped) return;
      await checkpointStep();
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
      releaseIfClear();
    } catch (error) {
      if (stopped) return;
      failWith(error);
    }
  }

  /** Reads the feed now. Calls that arrive while a pass runs make it run once more. @returns {Promise<void>} */
  function syncNow() {
    if (stopped || halted !== null) return Promise.resolve();
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
    if (stopped || paused || halted !== null || pollTimer !== null) return;
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

  /** Registers the focus and online listeners once, also for an engine that starts stopped (the user may try again later). */
  function listen() {
    if (listening || stopped) return;
    listening = true;
    for (const name of FOCUS_EVENTS) win?.addEventListener?.(name, onFocus);
  }

  /**
   * The writes in the outbox go out only when nothing speaks against the server: not stopped, no restore half done, no higher
   * restore epoch that has not been accepted. The runner is held from the start of the engine, and is let go only here, at the end
   * of a pass that read the feed to its end: a pass that fails (offline, a bad answer) lets nothing go.
   */
  function releaseIfClear() {
    if (stopped || halted !== null || restorePending || epochPending || epochHolds > 0 || epochMovedAt !== null || now() < epochRetryAt) return;
    runner.release();
  }

  /** A restore is one at a time in a browser: the Web Lock of the account, when the memory has one. @template T @param {() => Promise<T>} fn @returns {Promise<T>} */
  function exclusive(fn) {
    return typeof memory.withRestoreLock === "function" ? memory.withRestoreLock(fn) : fn();
  }

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
   * @param {boolean} [resurrect] the write brings a deleted item back (`base_rev` is the tombstone's revision): only on the user's choice
   */
  async function queue(id, baseRev, body, next, summary, resurrect = false) {
    const idem = randomId();
    const restoreEpoch = await acceptedEpoch();
    const bytes = writeBytes({ baseRev, body, idem, resurrect, restoreEpoch });
    if (restoreEpoch === null) unconditioned.add(idem);
    const kept = flags.get(id)?.kind;
    const key = kept === "missing_on_server" || kept === "reuploaded" ? await ownKeyOfBody(baseRev + 1, body) : null;
    alive();
    const why = blocked.get(id);
    if (why !== undefined) throw new SyncError("blocked", "blocked", why); // a refusal came in while this write was being made
    const mark = flags.get(id);
    if (key !== null && mark && (mark.kind === "missing_on_server" || mark.kind === "reuploaded")) {
      const previousSent = mark.sent;
      const previousFresh = mark.fresh;
      mark.sent = [...(previousSent ?? []), key].slice(-256);
      if (previousFresh !== undefined) mark.fresh = [...previousFresh, key].slice(-256);
      flagsDirty = true;
      try {
        // Saved before the write is stored, and a failed save stops the write: without its key the row would be
        // refused when it comes back. A crash in between leaves a key nobody used, which is harmless.
        await saveFlags(await store.open());
      } catch (error) {
        mark.sent = previousSent;
        mark.fresh = previousFresh;
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

  /** The draft with the name of this device, which the conflict view shows. @param {object} draft */
  const withDevice = (draft) => (device ? { ...draft, device } : draft);

  /** The seal of a draft at `rev`. @param {string} id @param {number} rev @param {object} draft @param {number | undefined} handle */
  async function seal(id, rev, draft, handle) {
    const sealed = await client.vault.encrypt_item(hex16.decode(id), rev, draft, handle, now());
    const summary = await summarize(id, rev, sealed.envelope, sealed.tag);
    return { sealed, summary };
  }

  /**
   * What the screen shows for the writes that wait in the outbox: the newest of each item, as pending. A write of an item
   * the server has moved past is not shown; a blocked item shows the server's version (a draft of an item the server never
   * took is shown as it is).
   * @param {import("../store/outbox.mjs").OutboxEntry[]} queued oldest first
   */
  async function showDrafts(queued) {
    for (const entry of queued) {
      const rev = entry.baseRev + 1;
      const held = rows.get(entry.itemId);
      if (blocked.has(entry.itemId) && !("tomb" in entry.body) && (held === undefined || held.deleted)) {
        // Refused for good, and the server has no live version: a draft of an item the server never took, or of one it deleted
        // (a conflict that waits for the user's choice). The draft is what is shown.
        try {
          index.set(entry.itemId, await summarize(entry.itemId, rev, entry.body.blob, entry.body.tag));
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
        }
        continue;
      }
      if (rev <= (held?.rev ?? 0)) continue; // the feed already has this item beyond the draft
      if (blocked.has(entry.itemId)) continue; // refused for good before the restart: the server's version stays on screen
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
  }

  // ---------------------------------------------------------- an older state

  /**
   * What the server shows now, for the older state: the whole listing as rows, the `as_of_seq` of its first page, its
   * restore epoch, and (when `withCheckpoint`) the checkpoint it holds. Nothing is changed here.
   * @param {boolean} [withCheckpoint]
   * The rows the server froze when it was restored (`restore`) are read as well when its listing names a restore sequence number
   * above 0, and are null otherwise.
   * @returns {Promise<{ rows: CachedRow[], asOf: number, epoch: number, checkpoint: import("./checkpoint.mjs").Checkpoint | null, restore: import("./restore.mjs").Restore | null }>}
   */
  async function readRestoreInputs(withCheckpoint = true) {
    /** @type {CachedRow[]} */
    const listed = [];
    const seen = { epoch: /** @type {number | null} */ (null), restoreSeq: 0 };
    const asOf = await readListing(async (page) => {
      if (seen.epoch === null) {
        seen.epoch = page.restore_epoch;
        seen.restoreSeq = page.restore_seq;
      }
      for (const change of page.items) {
        try {
          listed.push(rowOfChange(change));
        } catch {
          throw new SyncError("bad_feed", "The server's listing cannot be right.");
        }
      }
      return "done";
    });
    alive();
    if (asOf === null || seen.epoch === null) throw new SyncError("stopped");
    const epoch = seen.epoch;
    const restore = await readRestoreRows({ restoreEpoch: epoch, restoreSeq: seen.restoreSeq, asOfSeq: asOf });
    if (restore !== null) await crossCheckRestoreRows(listed, restore);
    /** @type {import("./checkpoint.mjs").Checkpoint | null} */
    let checkpoint = null;
    if (withCheckpoint) {
      try {
        checkpoint = await fetchCheckpoint(api);
      } catch (error) {
        if (/** @type {any} */ (error)?.status === 404) {
          throw new SyncError("restore_not_verified", "The server holds no checkpoint to compare the older state with.", "no_checkpoint");
        }
        throw error;
      }
      alive();
    }
    return { rows: listed, asOf, epoch, checkpoint, restore };
  }

  /**
   * The frozen rows against the listing: a row of the listing that has not been written since the restore (its `seq` is at or below
   * `restore_seq`) was there when the rows were frozen, and is the very row that was frozen (the same revision and the same hash).
   * Anything else is a list that cannot be right.
   * @param {CachedRow[]} listed @param {import("./restore.mjs").Restore} restore
   */
  async function crossCheckRestoreRows(listed, restore) {
    for (const row of listed) {
      if (row.seq > restore.restoreSeq) continue;
      const frozen = restore.frozen.get(row.itemId);
      if (frozen === undefined || frozen.rev !== row.rev || frozen.hash !== (await rowHash(row))) {
        throw new SyncError("bad_feed", "The server's list of rows at the restore does not fit its listing.");
      }
      alive();
    }
  }

  /**
   * The rows the server froze when it was restored, all pages (`GET /api/sync/restore-rows`), each checked against the listing they go
   * with (`checkRestoreRowsPage`). Null when the listing names no restore sequence number (an older server, or none was recorded): the
   * interim rules of `restoreItems` apply then. The list has no MAC: it is information for the honest case.
   * @param {{ restoreEpoch: number, restoreSeq: number, asOfSeq: number }} listed
   * @returns {Promise<import("./restore.mjs").Restore | null>}
   */
  async function readRestoreRows(listed) {
    if (listed.restoreSeq === 0) return null;
    /** @type {Map<string, { rev: number, seq: number, hash: string | null }>} */
    const frozen = new Map();
    /** @type {any} */
    let previous = null;
    for (;;) {
      const after = previous === null ? "" : `&after=${previous.next_after}`;
      /** @type {any} */
      let page;
      try {
        page = await api.get(`/api/sync/restore-rows?limit=${PAGE_LIMIT}${after}`, { shape: "restore_rows_res" });
      } catch (error) {
        // An answer that is not the shape of the list (a position without more rows, or the other way round) is a list that cannot be right.
        const status = /** @type {any} */ (error)?.status;
        if (/** @type {any} */ (error)?.code === "bad_response" && status >= 200 && status < 300) {
          throw new SyncError("bad_feed", "The server's list of rows at the restore cannot be right.");
        }
        throw error;
      }
      alive();
      checkRestoreRowsPage(page, previous, listed, PAGE_LIMIT);
      for (const row of page.rows) frozen.set(row.id, { rev: row.rev, seq: row.seq, hash: row.hash ?? null });
      if (!page.has_more) return { restoreSeq: listed.restoreSeq, frozen };
      previous = page;
    }
  }

  /** @typedef {Awaited<ReturnType<typeof readRestoreInputs>>} RestoreInputs */

  /**
   * The core's check of an older state: the checkpoint against the listing, without the memory. The answer holds the memory that
   * state would give; nothing is stored here.
   * @param {RestoreInputs} inputs
   */
  async function checkOlderState(inputs) {
    try {
      return await client.vault.accept_older_state(inputs.checkpoint, inputs.rows.map(coreRow), inputs.asOf);
    } catch (error) {
      if (isFatal(error)) throw error;
      throw new SyncError("restore_not_verified", "The older state of the server could not be verified.", codeOf(error));
    }
  }

  /**
   * Phase 1. The listing and the checkpoint are verified by the core, and the memory it gives (the floors of that older
   * state: the only place where floors go down) is stored together with the note that a restore is under way. The restore
   * epoch has to be a higher one than this device has accepted, or the floors are not lowered at all.
   * Spec: Fase 1 section 8.6 ("Legitimate rollbacks").
   * @param {RestoreInputs} inputs
   */
  async function saveOlderMemory(inputs) {
    await memory.withLock(async (state) => {
      if (inputs.epoch <= (state.restoreEpoch ?? 0)) {
        throw new SyncError("invalid_state", "The server does not show a restore epoch above the one this device has accepted.");
      }
      const done = await checkOlderState(inputs);
      return {
        ...state,
        memory: done.newSyncMemory,
        // The state that verified is the one this device stands on now: its checkpoint is the highest verified one, nothing of
        // the old history counts as an uploaded checkpoint, and a warning of the old history has no more to say.
        verifiedAt: now(),
        verifiedSeq: /** @type {import("./checkpoint.mjs").Checkpoint} */ (inputs.checkpoint).seq,
        uploadedSeq: null,
        hardWarning: null,
        restore: { epoch: inputs.epoch, phase: /** @type {"memory_saved"} */ ("memory_saved") },
      };
    });
    alive();
  }

  /**
   * The same check on a restart that finds the restore half done: the floors stay where phase 1 put them (nothing is lowered a
   * second time on a word that was given once), and the checkpoint has to verify against what the server shows now.
   * @param {RestoreInputs} inputs
   */
  async function checkAgain(inputs) {
    await memory.withLock(async (state) => {
      try {
        const done = await client.vault.verify_checkpoint(inputs.checkpoint, inputs.rows.map(coreRow), inputs.asOf, state.memory);
        return {
          ...state, memory: done.newSyncMemory, verifiedAt: now(),
          verifiedSeq: Math.max(state.verifiedSeq ?? 0, /** @type {import("./checkpoint.mjs").Checkpoint} */ (inputs.checkpoint).seq),
        };
      } catch (error) {
        if (isFatal(error)) throw error;
        const code = codeOf(error);
        if (code === "checkpoint_top_seq_below_remembered") {
          throw new SyncError("rollback_suspected", "The server shows a state older than this device has seen.");
        }
        throw new SyncError("restore_not_verified", "The server shows a state this device cannot verify.", code);
      }
    });
    alive();
  }

  /**
   * The write that carries the newest local version of an item over to the server's rows: sealed again at `base + 1`, opened from
   * the row this device holds or from the write that was waiting in the outbox. A tombstone is made at `base + 1`.
   * @param {import("./restore.mjs").Decision} decision
   * @param {import("../store/outbox.mjs").OutboxEntry[]} waiting the queued writes of the item, oldest first
   * @returns {Promise<{ blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }>}
   */
  async function sealOlder(decision, waiting) {
    const id = decision.id;
    if (decision.kind === "tombstone") {
      return { tomb: (await client.vault.make_tombstone(hex16.decode(id), decision.baseRev + 1)).tomb };
    }
    const last = waiting.at(-1);
    /** @type {number} */
    let handle;
    if (decision.source === "outbox" && last !== undefined && !("tomb" in last.body)) {
      handle = await client.vault.open_item(hex16.decode(id), last.baseRev + 1, last.body.blob, last.body.tag);
    } else {
      const row = rows.get(id);
      if (!row || row.deleted) throw new SyncError("invalid_state");
      handle = await client.vault.open_item(hex16.decode(id), row.rev, row.envelope, row.tag);
    }
    try {
      const sealed = await client.vault.encrypt_item(hex16.decode(id), decision.baseRev + 1, {}, handle, now());
      return { blob: sealed.envelope, tag: sealed.tag };
    } finally {
      await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
    }
  }

  /**
   * Phase 2. Every local version that is newer than the server's row is queued again, built on what the server has now
   * (`server rev + 1`; a tombstone is brought back with `resurrect`; an item the server lacks starts at revision 0), and
   * replaces the old writes of that item in the outbox. An item the server changed after the restore (see `restoreItems`)
   * is queued as a draft that is not sent and marked as a conflict. Nothing is sent: the runner is held until the rows have
   * been replaced. The new write is stored before the old ones are dropped, and the mark of a conflict is saved before its
   * draft is stored, so a crash at any point resumes to the same answer.
   * @param {RestoreInputs} inputs
   * @returns {Promise<{ reuploaded: number, conflicts: number }>}
   */
  async function queueNewer(inputs) {
    const db = await store.open();
    await runner.whenIdle();
    /** @type {import("../store/outbox.mjs").OutboxEntry[]} */
    const stored = await store.outbox.all(db, scope);
    alive();
    const decisions = await restoreItems({
      listing: inputs.rows, restore: inputs.restore, rows: rows.values(), outbox: stored, blocked: conflictIds(), marks: flags,
    });
    const served = new Map(inputs.rows.map((row) => [row.itemId, row]));

    /**
     * Carries out one decision. Throws `outbox_changed` when the store holds writes of the item that the decision was not made
     * from (another tab queued one meanwhile): nothing has been dropped then.
     * @param {import("./restore.mjs").Decision} decision
     * @param {import("../store/outbox.mjs").OutboxEntry[]} waiting the queued writes of the item the decision was made from
     * @returns {Promise<"skipped" | "conflict" | "again" | "unreadable">}
     */
    async function carryOut(decision, waiting) {
      const id = decision.id;
      const seen = waiting.map((entry) => entry.idem);
      if (decision.kind === "skip") {
        // Nothing to send. An old write waiting for this item belonged to the old history (the server has the newer version, or
        // both are deleted), or is this device's own write that the server already has.
        if (waiting.length > 0) for (const idem of await runner.discard(id, seen)) droppedIdems.add(idem);
        if (blocked.delete(id)) flagsDirty = true;
        return "skipped";
      }
      /** @type {{ blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }} */
      let body;
      try {
        body = await sealOlder(decision, waiting);
      } catch (error) {
        if (stopped || isFatal(error)) throw error;
        emit("error", { code: "restore_item_unreadable", id }); // no copy of it can be opened: nothing can be sent for it
        return "unreadable";
      }
      alive();
      // A new key, and the epoch that is being accepted: the epoch is part of what the server hashes under the key, so a write
      // that was queued for the old epoch cannot be sent again as it was.
      let idem = randomId();
      while (seen.includes(idem)) idem = randomId(); // never the key of a write that waits (the random source of a test may repeat)
      const bytes = writeBytes({ baseRev: decision.baseRev, body, idem, resurrect: decision.kind === "resurrect", restoreEpoch: inputs.epoch });
      if (decision.conflict) {
        blocked.set(id, "conflict");
        const shown = served.get(id);
        conflictNotes.set(id, { serverRev: shown?.rev ?? 0, serverDeleted: shown?.deleted === true });
        flagsDirty = true;
        await saveFlags(db);
      } else if (blocked.delete(id)) {
        flagsDirty = true;
      }
      for (const gone of await runner.replace({ idem, itemId: id, baseRev: decision.baseRev, body, bytes }, seen)) droppedIdems.add(gone);
      alive();
      if (!decision.conflict) return "again";
      runner.block(id);
      const row = served.get(id);
      emit("error", { code: "conflict", id, currentRev: row?.rev ?? 0, deleted: row?.deleted === true });
      return "conflict";
    }

    let reuploaded = 0;
    let conflicts = 0;
    for (const first of decisions) {
      const id = first.id;
      let decision = first;
      let waiting = stored.filter((entry) => entry.itemId === id);
      for (let attempt = 0; ; attempt += 1) {
        try {
          const done = await carryOut(decision, waiting);
          if (done === "conflict") conflicts += 1;
          else if (done === "again") reuploaded += 1;
          break;
        } catch (error) {
          if (!(error instanceof SyncError) || error.code !== "outbox_changed") throw error;
          if (attempt >= 4) throw new SyncError("busy", "The writes of an item keep changing while an older state is accepted.");
          // Another tab queued a write of this item meanwhile: it is decided again from what the store holds now, so that edit is
          // neither dropped nor left behind.
          /** @type {import("../store/outbox.mjs").OutboxEntry[]} */
          const nowStored = await store.outbox.all(db, scope);
          waiting = nowStored.filter((entry) => entry.itemId === id);
          alive();
          const mine = rows.get(id);
          const [again] = await restoreItems({
            listing: inputs.rows.filter((row) => row.itemId === id), restore: inputs.restore, rows: mine ? [mine] : [], outbox: waiting,
            blocked: conflictIds().filter((one) => one === id), marks: flags,
          });
          if (again === undefined) break;
          decision = again;
        }
      }
    }
    await saveFlags(db);
    return { reuploaded, conflicts };
  }

  /**
   * Phase 3. The rows and the cache become what the server shows (the memory takes them first: a restart may find newer ones,
   * and nothing is lowered here), the marks of the old history are dropped (the drafts of conflicts stay: they are in the outbox,
   * blocked), the screen is rebuilt from the new rows and the writes that wait, the feed continues from the `as_of_seq` of
   * the listing, and last of all the restore epoch is stored and the note of the restore removed.
   * @param {RestoreInputs} inputs
   */
  async function replaceRows(inputs) {
    const db = await store.open();
    const verdict = await acceptPage({ client, memory, rows: inputs.rows, topSeq: inputs.asOf });
    alive();
    if (verdict.refused.length > 0) {
      throw new SyncError("restore_not_verified", "The server shows rows this device cannot accept.", verdict.refused[0].code);
    }
    /** @type {import("../store/outbox.mjs").OutboxEntry[]} */
    const waiting = await store.outbox.all(db, scope);
    alive();
    const withCopy = new Set(waiting.map((entry) => entry.itemId));
    const keep = new Set(inputs.rows.map((row) => row.itemId));
    // A live row of this device that the listing does not show and that has no write waiting for it is the only copy there is:
    // the server may be hiding it, and nothing is deleted on its word. It stays (cached with seq 0, so the cursor does not follow
    // the old history), and is marked and sent again like any item a listing left out. A tombstone the server does not show is not kept.
    const only = [...rows.values()]
      .filter((row) => !keep.has(row.itemId) && !row.deleted && row.itemId !== MANIFEST_ID && !withCopy.has(row.itemId))
      .map((row) => ({ ...row, seq: 0 }));
    const onlyIds = new Set(only.map((row) => row.itemId));
    // A verified tombstone (the memory has just checked the listing) over a live row of this device: the row goes to the local
    // trash before the cache is written over it, exactly as in the feed.
    for (const row of inputs.rows) {
      const last = rows.get(row.itemId);
      if (!row.deleted || !last || last.deleted || row.rev <= last.rev || row.itemId === MANIFEST_ID) continue;
      await store.trash.put(db, scope, {
        itemId: row.itemId, rev: last.rev, envelope: /** @type {Uint8Array} */ (last.envelope), tag: /** @type {Uint8Array} */ (last.tag),
        tombRev: row.rev, deletedAt: now(),
      });
      alive();
    }
    // The rows of a listing come in the order of the ids: until the feed after it has been read to its end, a restart must not take the cursor from them.
    await noteListing(db);
    alive();
    await store.cache.putRows(db, scope, [...inputs.rows, ...only]);
    alive();
    /** @type {CachedRow[]} */
    const cached = await store.cache.getRows(db, scope);
    const stale = cached.map((row) => row.itemId).filter((id) => !keep.has(id) && !onlyIds.has(id));
    if (stale.length > 0) await store.cache.removeRows(db, scope, stale);
    alive();
    // What the screen will show, made before anything is swapped.
    /** @type {Map<string, ReturnType<typeof summaryOf>>} */
    const summaries = new Map();
    /** @type {Array<{ id: string, rev: number, code: string }>} */
    const unreadable = [];
    for (const row of [...inputs.rows, ...only]) {
      if (row.deleted || row.itemId === MANIFEST_ID) continue;
      try {
        summaries.set(row.itemId, await summarize(row.itemId, row.rev, /** @type {Uint8Array} */ (row.envelope), /** @type {Uint8Array} */ (row.tag)));
        alive();
      } catch (error) {
        if (stopped || isFatal(error)) throw error;
        unreadable.push({ id: row.itemId, rev: row.rev, code: codeOf(error) });
      }
    }
    const before = [...index.keys()];
    rows.clear();
    for (const row of inputs.rows) rows.set(row.itemId, row);
    for (const row of only) rows.set(row.itemId, row);
    flags.clear();
    acked.clear();
    overlay.clear();
    index.clear();
    for (const [id, summary] of summaries) index.set(id, summary);
    for (const { id, rev, code } of unreadable) markDamaged(id, rev, code);
    for (const row of only) if (!flags.has(row.itemId)) flags.set(row.itemId, { kind: "missing_on_server", rev: row.rev });
    flagsDirty = true;
    for (const id of [...blocked.keys()]) if (!withCopy.has(id)) blocked.delete(id); // a block needs its draft
    await showDrafts(waiting);
    await saveFlags(db);
    cursor = inputs.asOf;
    relistFirst = false; // this listing is the one that was owed
    await memory.withLock(async (state) => ({ ...state, restoreEpoch: Math.max(state.restoreEpoch ?? 0, inputs.epoch), restore: null }));
    alive();
    changed(new Set([...before, ...index.keys()]));
  }

  /**
   * Whether the manifest of the restored server is older than the one this device holds (a lower revision, or none): the unlock
   * methods of the older state are what the server will show, and the user is told.
   * @param {CachedRow[]} listed
   */
  function manifestOlder(listed) {
    const mine = rows.get(MANIFEST_ID);
    if (mine === undefined) return false;
    const theirs = listed.find((row) => row.itemId === MANIFEST_ID);
    return theirs === undefined || theirs.rev < mine.rev;
  }

  /** What stands again once an older state is accepted: nothing from the old history is held against the new one. */
  function afterRestore() {
    restorePending = false;
    epochPending = false;
    listing = null;
    lastDrain = null;
    for (const code of VERIFY_WARNINGS) clearWarning(code);
    // The checkpoint verified against the listing in phase 1: this device has verified in this session, and the next pass checks again.
    verifiedInSession = true;
    forgedUnlock = false;
    verifyNotBefore = 0;
    uploadNotBefore = 0;
    deferredAt = null;
    retryPending = false;
    verifyRequested = true;
    epochRefusals.clear();
    epochRetryAt = 0;
    epochMovedAt = null;
  }

  /**
   * Carries on a restore whose note is stored (the page was closed, or a phase failed): from the stored phase, with the
   * listing read again and verified against the checkpoint. The runner stays held; the pass that follows lets it go. A listing that shows a different restore epoch than the one that
   * was being accepted is not the same restore: the engine stops and the user decides again.
   */
  async function resumeRestore() {
    await exclusive(async () => {
      const state = await memory.load();
      alive();
      if (state.restore === null) {
        restorePending = false;
        return;
      }
      if (restoring) return;
      restoring = true;
      try {
        runner.hold();
        await runner.whenIdle();
        await Promise.all([...itemQueues.values()]);
        const { epoch, phase } = state.restore;
        // The listing is checked against the checkpoint again, whichever phase the note is in: rows are never replaced from a listing nobody verified.
        const inputs = await readRestoreInputs();
        if (inputs.epoch > epoch) throw new SyncError("server_restored", "The server was restored again.");
        if (inputs.epoch < epoch) throw new SyncError("restore_epoch_lowered", "The server shows an older restore epoch than this device has seen.");
        await checkAgain(inputs);
        if (phase === "memory_saved") {
          await queueNewer(inputs);
          await memory.withLock(async (current) => ({ ...current, restore: { epoch, phase: /** @type {"queued"} */ ("queued") } }));
          alive();
        }
        await replaceRows(inputs);
        afterRestore();
      } finally {
        restoring = false;
      }
    });
  }

  // ------------------------------------------------- conflicts and the trash

  /** The writes of the user's choices are refused while an older state is being accepted. */
  function notWhileRestoring() {
    if (stopped) throw new SyncError("stopped");
    if (restoring || restorePending) throw new SyncError("busy", "An older state is being accepted.");
  }

  /**
   * The server's version of an item in conflict: the verified row from the feed. The revision a 409 names is not verified (a
   * server can say any number), so it is never a reason to refuse the user's choice: when it is above the rows here the feed is
   * read first, and then the verified row that is held is used as it is. A wrong base revision is refused by the server with
   * another 409, which makes a new conflict. Only when no row is held at all is there nothing to choose between.
   * @param {string} id
   * @returns {Promise<CachedRow>}
   */
  async function settledServerRow(id) {
    const noted = conflictOf(id)?.serverRev ?? 0;
    let row = rows.get(id);
    if (row === undefined || row.rev < noted) {
      await syncNow();
      alive();
      row = rows.get(id);
    }
    if (row === undefined) throw new SyncError("conflict_unsettled", "The server's version of this item has not arrived yet.");
    return row;
  }

  /** Whether the server's row has nothing to show: a tombstone, or a row without its sealed body. The one rule `conflict` and `resolve` share. @param {CachedRow} row */
  function isGone(row) {
    return row.deleted || !row.envelope || !row.tag;
  }

  /**
   * A choice is made against the server row the user was shown, and no other: a row with another revision, or one that is deleted
   * where the user saw a live one (or the reverse), is a different conflict.
   * @param {CachedRow} row the verified row this device holds now @param {{ rev: number, deleted: boolean }} seen
   * @throws {SyncError} `conflict_changed`
   */
  function assertSeen(row, seen) {
    if (row.rev !== seen.rev || isGone(row) !== seen.deleted) {
      throw new SyncError("conflict_changed", "The server's version of this item changed after it was shown.");
    }
  }

  /**
   * The saved record of the flags, read again from the store just before a choice is written: another tab of this browser may have
   * made the same choice already, and this tab's memory would be stale. Unsaved changes of this tab are saved first.
   * @returns {Promise<any>}
   */
  async function savedFlags() {
    const db = await store.open();
    if (flagsDirty) await saveFlags(db);
    alive();
    return store.getSetting(db, flagsKey);
  }

  /**
   * An entry for the local trash: the live version `rev` of an item that a tombstone at `tombRev` deletes. An entry is a live
   * row below its tombstone (the store insists), and its tag binds the revision; a version that is not below the tombstone (a
   * draft sealed at the tombstone's own revision or above) is sealed again at `tombRev - 1`, from the same content.
   * @param {string} id @param {number} rev @param {Uint8Array} envelope @param {Uint8Array} tag @param {number} tombRev
   * @returns {Promise<import("../store/trash.mjs").TrashEntry>}
   * @throws {SyncError} `invalid_state` when `tombRev` is below 2 (there is no revision below it to be the copy)
   */
  async function trashCopy(id, rev, envelope, tag, tombRev) {
    // A deletion at revision 1 has no earlier version below it to keep: refused, so a draft is never dropped without its copy.
    if (tombRev < 2) throw new SyncError("invalid_state", "There is no earlier version of this item to keep in the trash.");
    if (rev < tombRev) return { itemId: id, rev, envelope, tag, tombRev, deletedAt: now() };
    const handle = await client.vault.open_item(hex16.decode(id), rev, envelope, tag);
    try {
      const sealed = await client.vault.encrypt_item(hex16.decode(id), tombRev - 1, {}, handle, now());
      return { itemId: id, rev: tombRev - 1, envelope: sealed.envelope, tag: sealed.tag, tombRev, deletedAt: now() };
    } finally {
      await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
    }
  }

  /**
   * Drops the draft of a refused write and everything queued behind it, and lets the item be written again; the screen goes
   * back to the server's version. The store goes first and the block stays until that has worked.
   * @param {string} id
   */
  async function dropDraft(id) {
    // The server has deleted the item and the draft is the user's newest version of it: it goes to the local trash first, so
    // dropping it (keeping the server's deletion) does not lose it, and it can be restored like any other entry.
    const gone = rows.get(id);
    const draft = gone?.deleted ? liveDraftOf(id) : null;
    if (gone && draft) {
      const entry = await trashCopy(id, draft.baseRev + 1, draft.body.blob, draft.body.tag, gone.rev); // refuses when no copy can be made
      alive();
      await store.trash.put(await store.open(), scope, entry);
      alive();
    }
    for (const idem of await runner.discard(id)) droppedIdems.add(idem);
    alive();
    blocked.delete(id);
    conflictNotes.delete(id);
    flagsDirty = true;
    overlay.delete(id);
    if (!rows.has(id)) index.delete(id);
    await showServerVersion(id);
    await persistFlags();
  }

  /**
   * Notes the digest of a write of an item whose mark keeps a floor, and saves it before the write is stored: without its key the
   * row would be refused when it comes back. Gives back what undoes the note.
   * @param {string} id @param {number} rev @param {{ blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }} body
   * @returns {Promise<() => void>}
   */
  async function rememberOwn(id, rev, body) {
    const kind = flags.get(id)?.kind;
    if (kind !== "missing_on_server" && kind !== "reuploaded") return () => {};
    const key = await ownKeyOfBody(rev, body);
    alive();
    const mark = flags.get(id);
    if (!mark || (mark.kind !== "missing_on_server" && mark.kind !== "reuploaded")) return () => {};
    const previousSent = mark.sent;
    const previousFresh = mark.fresh;
    mark.sent = [...(previousSent ?? []), key].slice(-256);
    if (previousFresh !== undefined) mark.fresh = [...previousFresh, key].slice(-256);
    flagsDirty = true;
    const undo = () => {
      mark.sent = previousSent;
      mark.fresh = previousFresh;
    };
    try {
      await saveFlags(await store.open());
    } catch (error) {
      undo();
      throw error;
    }
    alive();
    return undo;
  }

  /**
   * "Keep mine" in a conflict: the local version, exactly as it was sealed, is written again on top of the server's version: sealed
   * at `server rev + 1`, `base_rev` the server's revision. Over a row the server has deleted that is a resurrection
   * (`resurrect: true`, `base_rev` the tombstone's revision), and this is the only place the client asks for one, after the user's choice. A local
   * deletion against a server edit becomes a tombstone at `server rev + 1`. Both sides deleted leaves nothing to keep. There is no merge: the
   * server's fields are not mixed in. The draft is replaced (the new write is stored before the old ones go), and the block
   * and the conflict note are saved before that, so a crash at any point leaves a conflict that can be chosen again.
   * Spec: Fase 1 section 8.4 ("No resurrection without an active choice") and section 8.5.
   * @param {string} id @param {{ rev: number, deleted: boolean }} [seen] the server row the user was shown, when the caller has it
   */
  async function keepMineInConflict(id, seen) {
    const row = await settledServerRow(id);
    if (seen !== undefined) assertSeen(row, seen);
    const last = runner.entriesOf(id).at(-1);
    if (last === undefined) throw new SyncError("not_found");
    const base = row.rev;
    /** @type {{ blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }} */
    let body;
    /** @type {ReturnType<typeof summaryOf> | null} */
    let summary = null;
    let resurrect = false;
    if ("tomb" in last.body) {
      if (row.deleted) return dropDraft(id); // deleted on both sides: the server's version is the same as the local one
      body = { tomb: (await client.vault.make_tombstone(hex16.decode(id), base + 1)).tomb };
    } else {
      const handle = await client.vault.open_item(hex16.decode(id), last.baseRev + 1, last.body.blob, last.body.tag);
      try {
        const made = await seal(id, base + 1, {}, handle);
        body = { blob: made.sealed.envelope, tag: made.sealed.tag };
        summary = made.summary;
      } finally {
        await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
      }
      resurrect = row.deleted;
    }
    alive();
    const idem = randomId();
    const bytes = writeBytes({ baseRev: base, body, idem, resurrect, restoreEpoch: await acceptedEpoch() });
    const undoKey = await rememberOwn(id, base + 1, body);
    const note = conflictNotes.get(id);
    blocked.delete(id);
    conflictNotes.delete(id);
    flagsDirty = true;
    try {
      await saveFlags(await store.open());
      for (const gone of await runner.replace({ idem, itemId: id, baseRev: base, body, bytes })) droppedIdems.add(gone);
    } catch (error) {
      // Nothing was replaced (or only the store failed): the conflict is still there, and so is the old draft.
      blocked.set(id, "conflict");
      if (note) conflictNotes.set(id, note);
      undoKey();
      flagsDirty = true;
      void persistFlags();
      throw error;
    }
    alive();
    overlay.set(id, "tomb" in body
      ? { rev: base + 1, deleted: true, envelope: null, tag: null }
      : { rev: base + 1, deleted: false, envelope: body.blob, tag: body.tag });
    if (summary) index.set(id, summary);
    else index.delete(id);
    changed([id]);
  }

  /**
   * "Keep mine" for an item whose newest server row could not be opened (`damaged`): the last good local version is written at
   * `flag.rev + 1` on top of that row. Nothing is read from the damaged row.
   * @param {string} id @param {number} flagRev
   */
  async function keepMineDamaged(id, flagRev) {
    const good = rows.get(id);
    if (good === undefined || good.deleted) throw new SyncError("damaged", "There is no good version of this item to keep.");
    /** @type {number} */
    let handle;
    try {
      handle = await client.vault.open_item(hex16.decode(id), good.rev, /** @type {Uint8Array} */ (good.envelope), /** @type {Uint8Array} */ (good.tag));
    } catch (error) {
      if (stopped || isFatal(error)) throw error;
      throw new SyncError("damaged", "There is no good version of this item to keep.");
    }
    try {
      const { sealed, summary } = await seal(id, flagRev + 1, {}, handle);
      await queue(id, flagRev, { blob: sealed.envelope, tag: sealed.tag }, { rev: flagRev + 1, deleted: false, envelope: sealed.envelope, tag: sealed.tag }, summary);
    } finally {
      await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
    }
    if (flags.get(id)?.kind === "damaged") {
      flags.delete(id);
      flagsDirty = true;
      await persistFlags();
    }
  }

  /**
   * "Keep mine" for an item whose deletion by the server could not be verified (`quarantined`): the local copy is written again
   * on top of the server's tombstone at its revision, as a resurrection, sealed at `flag.rev + 1`.
   * @param {string} id @param {number} flagRev
   */
  async function keepMineQuarantined(id, flagRev) {
    const copy = rows.get(id);
    if (copy === undefined || copy.deleted) throw new SyncError("quarantined", "There is no local copy of this item to keep.");
    const handle = await client.vault.open_item(hex16.decode(id), copy.rev, /** @type {Uint8Array} */ (copy.envelope), /** @type {Uint8Array} */ (copy.tag));
    try {
      const { sealed, summary } = await seal(id, flagRev + 1, {}, handle);
      await queue(id, flagRev, { blob: sealed.envelope, tag: sealed.tag }, { rev: flagRev + 1, deleted: false, envelope: sealed.envelope, tag: sealed.tag }, summary, true);
    } finally {
      await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
    }
    if (flags.get(id)?.kind === "quarantined") {
      flags.delete(id);
      flagsDirty = true;
      await persistFlags();
    }
  }

  // -------------------------------------------------------------- the API

  const engine = {
    async start() {
      if (started || stopped) throw new SyncError("invalid_state");
      started = true;
      runner.hold(); // the writes that wait go out after the first pass has shown that the server is not a restored one
      const db = await store.open();
      let cached = /** @type {CachedRow[]} */ (await store.cache.getRows(db, scope));
      const saved = await store.getSetting(db, flagsKey);
      // A listing was begun and the feed after it was not read to its end: the cached rows are not a prefix of the feed (see `listingNoted`).
      const unfinished = (await store.getSetting(db, listingKey)) != null;
      if (typeof deviceName === "function") {
        try {
          device = await deviceName();
        } catch {
          device = undefined; // a name that cannot be worked out does not stop the engine; the service gives a default of its own
        }
      }
      alive();
      for (const row of cached) {
        rows.set(row.itemId, row);
        cursor = Math.max(cursor, row.seq);
      }
      const cachedTop = cursor;
      const savedMarks = saved?.v === 1 && saved.marks && typeof saved.marks === "object" ? saved.marks : {};
      for (const [id, flag] of Object.entries(savedMarks)) {
        const kinds = ["damaged", "quarantined", "missing_on_server", "reuploaded"];
        if (hex16.is(id) && kinds.includes(flag?.kind) && Number.isSafeInteger(flag.rev)) {
          const keys = (/** @type {unknown} */ list) => (Array.isArray(list) ? list.filter((/** @type {unknown} */ k) => typeof k === "string").slice(-256) : []);
          const sent = keys(flag.sent);
          flags.set(id, { kind: flag.kind, rev: flag.rev, ...(sent.length > 0 ? { sent } : {}), ...(Array.isArray(flag.fresh) ? { fresh: keys(flag.fresh) } : {}) });
        }
      }
      const savedBlocked = saved?.v === 1 && saved.blocked && typeof saved.blocked === "object" ? saved.blocked : {};
      for (const [id, code] of Object.entries(savedBlocked)) {
        if (hex16.is(id) && typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code)) blocked.set(id, code);
      }
      // What the server showed when a conflict began. A conflict saved without it (before it existed) is read from the row.
      const savedConflicts = saved?.v === 1 && saved.conflicts && typeof saved.conflicts === "object" ? saved.conflicts : {};
      for (const [id, note] of Object.entries(savedConflicts)) {
        if (blocked.get(id) === "conflict" && Number.isSafeInteger(note?.serverRev) && note.serverRev >= 0 && typeof note.serverDeleted === "boolean") {
          conflictNotes.set(id, { serverRev: note.serverRev, serverDeleted: note.serverDeleted });
        }
      }
      // The local trash keeps a deleted item for 30 days. What is older goes now; a store that cannot be cleaned does not stop the engine.
      try {
        await store.trash.purgeBefore(db, scope, Math.max(0, now() - TRASH_MS));
      } catch {
        if (!stopped) emit("error", { code: "storage" });
      }
      alive();
      // The sync memory: a first start with no stored state makes it from the rows that are cached (they were checked
      // when they were cached), so a device that had them before the memory existed gets floors too. Rows of an item
      // that was uploaded again are left out: the copy is below the floor the item had, which this device no longer
      // knows, and a floor made from it would be too low to mean anything. A cached row the core refuses is dropped
      // from the cache (and the feed is read again from the start, so an honest server shows it afresh). A halt here
      // (no Web Locks, a full memory) leaves the local data to be read, and nothing to be pulled or sent.
      try {
        const seeded = await seedMemory({ client, memory, rows: cached.filter((row) => !keepsFloor(row.itemId)), topSeq: cachedTop });
        alive();
        if (seeded.state.hardWarning !== null) raiseWarning(seeded.state.hardWarning);
        if (seeded.refused.length > 0) {
          const dropped = new Set(seeded.refused.map(({ row }) => row.itemId));
          await store.cache.removeRows(db, scope, [...dropped]);
          alive();
          for (const { row, code } of seeded.refused) {
            rows.delete(row.itemId);
            warn("cached_row_dropped", { id: row.itemId, rev: row.rev, reason: code });
          }
          cached = cached.filter((row) => !dropped.has(row.itemId));
          cursor = 0;
        }
      } catch (error) {
        if (!(error instanceof SyncError && HALT_CODES.includes(error.code))) throw error;
        halt(error.code);
      }
      if (unfinished) {
        // Never read on from the highest cached `seq` while a listing is unfinished: the first pass lists the vault again, and its first page sets the cursor.
        listingNoted = true;
        relistFirst = true;
        cursor = 0;
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
      // A refused chain that ends in a deletion, of an item this device holds a verified tombstone for, was left behind (the page was
      // closed before it was dropped): nothing is left to choose, and it would keep this device from storing checkpoints.
      for (const id of [...blocked.keys()]) if (mootChain(id)) await dropMoot(id);
      alive();
      await showDrafts(queued.filter((entry) => runner.entriesOf(entry.itemId).some((held) => held.idem === entry.idem)));
      if (stopped) return;
      await saveFlags(db);
      changed(index.keys());
      if (halted !== null) {
        listen();
        return; // what is stored is shown; nothing is pulled, and nothing queued is sent
      }
      // An older state that was being accepted when the page went away is carried on first, while the runner is held: no write
      // goes out before the rows have been replaced. If that cannot be done now (no network), the passes try again and the
      // runner stays held until it is done.
      if ((await memory.load()).restore !== null) {
        alive();
        restorePending = true;
        runner.hold();
        try {
          await resumeRestore();
        } catch (error) {
          if (stopped) return;
          failWith(error);
        }
        if (stopped) return;
        if (halted !== null) {
          listen();
          return;
        }
      }
      runner.start(); // nothing goes out yet: the runner is held, and only a pass that ends well lets it go
      await syncNow();
      if (stopped) return;
      listen();
      schedule();
    },

    stop() {
      if (stopped) return;
      stopped = true;
      if (pollTimer !== null) timers.clear(pollTimer);
      pollTimer = null;
      for (const name of FOCUS_EVENTS) win?.removeEventListener?.(name, onFocus);
      listening = false;
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
      conflictNotes.clear();
      acked.clear();
      sealing.clear();
      abandoned.clear();
      droppedIdems.clear();
      unconditioned.clear();
      epochRefusals.clear();
      standing.clear();
      lastDrain = null;
      verifyRequested = false;
      retryPending = false;
      restoring = false;
      restorePending = false;
      flagsDirty = false;
      itemQueues.clear();
      listing = null;
      listingNoted = false;
      relistFirst = false;
      for (const set of Object.values(listeners)) set.clear();
    },

    syncNow,

    /**
     * Why the engine has stopped (one of `HALT_CODES`, or null) and the warnings that stand until a later check clears them.
     * Changes come as `state` events: `{ kind: "halted", code }`, `{ kind: "warning", code }`, `{ kind: "warning_cleared", code }`.
     * @returns {{ halted: string | null, warnings: string[] }}
     */
    health() {
      return { halted, warnings: [...standing] };
    },

    /**
     * Verifies the checkpoint of the server now ("Check again"): the feed is read to its end, then the checkpoint is
     * checked against the rows this device holds, whatever the time of the last check. Answers `"ok"`, the code of the
     * warning that now stands (`server_shows_older_state`, `checkpoint_rolled_back`, `checkpoint_forged`, `bad_feed`,
     * `verify_deferred`), the code of the stop when the engine is halted, or `"not_checked"` when the server could not
     * be reached.
     * @returns {Promise<string>}
     */
    async verifyNow() {
      if (stopped) throw new SyncError("stopped");
      if (halted !== null) return halted;
      verifyRequested = true;
      verifyOutcome = null;
      await syncNow();
      if (halted !== null) return halted;
      return verifyOutcome ?? "not_checked";
    },

    /**
     * What accepting the older state would do, for the screen that asks the user: how many local versions the server lacks and
     * would be sent again, and how many would be kept as conflicts because the server holds something else for them now.
     * Only while the engine is stopped with `server_restored`. The older state is verified first (the answer is the same refusal
     * `acceptOlderState` would give); nothing is stored or sent.
     * `manifestOlder` is true when the unlock methods of the restored server are older than this device's.
     * @returns {Promise<{ reupload: number, conflicts: number, manifestOlder: boolean }>}
     */
    async restorePreview() {
      if (stopped) throw new SyncError("stopped");
      if (halted !== "server_restored" || restoring) throw new SyncError("invalid_state", "There is no restored server to look at.");
      const inputs = await readRestoreInputs();
      await checkOlderState(inputs);
      const db = await store.open();
      const plan = await planRestore({
        listing: inputs.rows, restore: inputs.restore, rows: rows.values(), outbox: await store.outbox.all(db, scope),
        blocked: conflictIds(), marks: flags,
      });
      alive();
      return { reupload: plan.upload.length, conflicts: plan.conflicts.length, manifestOlder: manifestOlder(inputs.rows) };
    },

    /**
     * "Accept older state": the user has confirmed that the server was restored from a backup. Only while the engine is stopped
     * with `server_restored`; anything else is `invalid_state`. In three phases, each stored, so a crash carries on from the
     * stored one at the next start: (1) the listing and the checkpoint are verified and the floors of that state become the
     * memory; (2) every local version the server has no row for is queued again (revision 0), and every local version over a row the server has is kept as an
     * unsent draft (a conflict) when the server has a row for it; (3) the rows and the cache
     * become the listing, the old marks go, the feed continues from its `as_of_seq`, and the restore epoch is stored. Writes
     * are not sent before phase 3 is done. A state that does not verify leaves the engine stopped.
     * Spec: Fase 1 section 8.6 ("Legitimate rollbacks").
     * `manifestOlder` is true when the unlock methods of the restored server are older than this device's.
     * @returns {Promise<{ reuploaded: number, conflicts: number, manifestOlder: boolean }>}
     */
    async acceptOlderState() {
      if (stopped) throw new SyncError("stopped");
      if (halted !== "server_restored" || restoring) throw new SyncError("invalid_state", "There is no restored server to accept.");
      restoring = true;
      try {
        return await exclusive(async () => {
          if (inflight) await inflight;
          await Promise.all([...itemQueues.values()]); // writes that were being made when the user confirmed finish first
          await runner.whenIdle();
          alive();
          const inputs = await readRestoreInputs();
          const older = manifestOlder(inputs.rows);
          await saveOlderMemory(inputs); // phase 1
          restorePending = true;
          const counts = await queueNewer(inputs); // phase 2
          await memory.withLock(async (state) => ({ ...state, restore: { epoch: inputs.epoch, phase: /** @type {"queued"} */ ("queued") } }));
          alive();
          await replaceRows(inputs); // phase 3
          afterRestore();
          halted = null;
          lastStatus = "";
          emit("state", { kind: "warning_cleared", code: "server_restored" });
          schedule(); // the runner stays held until the pass that follows ends well
          void syncNow();
          return { ...counts, manifestOlder: older };
        });
      } finally {
        restoring = false;
      }
    },

    /**
     * "Try again" after a stop: the stop is lifted and the feed is read once. If the cause is still there the engine stops
     * again, with the same code. Nothing that was earned is kept: the checkpoint has to verify again before this session
     * uploads one. A warning that is stored is not cleared here; only a verification that succeeds clears it. The runner stays
     * held until the pass has shown that nothing stops the engine.
     * @returns {Promise<void>}
     */
    async resumeAfterHalt() {
      if (stopped) throw new SyncError("stopped");
      if (halted === null || restoring) throw new SyncError("invalid_state", "The engine is not stopped.");
      halted = null;
      lastStatus = "";
      verifiedInSession = false;
      forgedUnlock = false;
      verifyNotBefore = 0;
      retryPending = false;
      deferredAt = null;
      lastDrain = null;
      listedEpoch = -1;
      verifyRequested = true;
      await syncNow(); // the runner is let go by that pass, if it ends well
      if (stopped || halted !== null) return;
      schedule();
    },

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
          username: s.username,
          modified: s.modified,
          pending: runner.entriesOf(id).length > 0,
          damaged: flag?.kind === "damaged",
          quarantined: flag?.kind === "quarantined",
          missingOnServer: flag?.kind === "missing_on_server",
          blocked: blocked.has(id),
          blockedReason: blocked.get(id) ?? null,
          conflict: conflictOf(id) !== null,
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
      if (restoring || restorePending) throw new SyncError("busy", "An older state is being accepted.");

      const id = randomId();
      await withItem(id, async () => {
        const { sealed, summary } = await seal(id, 1, withDevice(draft), undefined);
        await queue(id, 0, { blob: sealed.envelope, tag: sealed.tag }, { rev: 1, deleted: false, envelope: sealed.envelope, tag: sealed.tag }, summary);
      });
      return id;
    },

    /**
     * Changes an item: the draft is applied to the newest version this device
     * has, inside the core. The write goes out as revision base + 1.
     * `expectedRev` is required: the revision the caller's form was built from.
     * When this device has a different one by now (another device's change
     * arrived), the edit is refused with `item_changed` and nothing is written.
     * A caller that leaves it out has a bug and gets a `TypeError`; an edit is
     * never applied to whatever version happens to be newest.
     * @param {string} id @param {object} draft @param {number} expectedRev
     */
    async update(id, draft, expectedRev) {
      if (!Number.isSafeInteger(expectedRev)) throw new TypeError("update needs the revision the edit was made from");
      if (stopped) throw new SyncError("stopped");
      if (restoring || restorePending) throw new SyncError("busy", "An older state is being accepted.");

      await withItem(id, async () => {
        const version = editable(id);
        if (version.rev !== expectedRev) throw new SyncError("item_changed");
        const rev = version.rev + 1;
        const handle = await client.vault.open_item(hex16.decode(id), version.rev, version.envelope, version.tag);
        try {
          const { sealed, summary } = await seal(id, rev, withDevice(draft), handle);
          await queue(id, version.rev, { blob: sealed.envelope, tag: sealed.tag }, { rev, deleted: false, envelope: sealed.envelope, tag: sealed.tag }, summary);
        } finally {
          await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
        }
      });
    },

    /** Deletes an item: a tombstone at revision base + 1. @param {string} id */
    async remove(id) {
      if (stopped) throw new SyncError("stopped");
      if (restoring || restorePending) throw new SyncError("busy", "An older state is being accepted.");

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
      if (restoring || restorePending) throw new SyncError("busy", "An older state is being accepted.");

      if (typeof id !== "string" || !blocked.has(id)) throw new SyncError("not_found");
      await withItem(id, () => dropDraft(id)); // the stored entries go first; the block stays until that has worked
    },

    /**
     * The two versions of an item in conflict, for the screen that asks the user to choose. `local` is the version this device
     * wrote (the newest draft in the outbox, sealed), `server` the verified row the server shows. Each side has its `rev`, whether
     * it is `deleted`, and, when it is a live version, its `view` (no secret in it) and an open `handle` for revealing one value
     * at a time; a deleted side has neither. `fields` tells for each field of the two views whether it is the same on both sides
     * (`null` for a secret: its value is not in a view). `seen` is the server row these versions were shown against (its revision
     * and whether it is deleted): `resolve` takes it back, and refuses when the row has changed since. `close()` closes both handles, and
     * so does `stop()`. Nothing is merged.
     * Spec: Fase 1 section 8.5.
     * @param {string} id
     * @returns {Promise<{
     *   local: { rev: number, deleted: boolean, view: any, handle: number | null },
     *   server: { rev: number, deleted: boolean, view: any, handle: number | null },
     *   fields: import("./conflict.mjs").FieldCompare[],
     *   seen: { rev: number, deleted: boolean },
     *   close(): Promise<void>,
     * }>}
     */
    async conflict(id) {
      notWhileRestoring();
      if (typeof id !== "string" || conflictOf(id) === null) throw new SyncError("not_found");
      const server = await settledServerRow(id);
      const last = runner.entriesOf(id).at(-1);
      if (last === undefined) throw new SyncError("not_found");
      /** @type {number[]} */
      const opened = [];
      const closeAll = async () => {
        for (const handle of opened.splice(0)) {
          if (handles.delete(handle)) await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
        }
      };
      /** @param {number} rev @param {Uint8Array} envelope @param {Uint8Array} tag */
      const side = async (rev, envelope, tag) => {
        const handle = await client.vault.open_item(hex16.decode(id), rev, envelope, tag);
        opened.push(handle);
        handles.add(handle);
        if (stopped) throw new SyncError("stopped");
        return { rev, deleted: false, view: await client.vault.item_view(handle), handle };
      };
      try {
        const mine = "tomb" in last.body
          ? { rev: last.baseRev + 1, deleted: true, view: null, handle: null }
          : await side(last.baseRev + 1, last.body.blob, last.body.tag);
        const theirs = isGone(server)
          ? { rev: server.rev, deleted: true, view: null, handle: null }
          : await side(server.rev, /** @type {Uint8Array} */ (server.envelope), /** @type {Uint8Array} */ (server.tag));
        if (stopped) throw new SyncError("stopped");
        return { local: mine, server: theirs, fields: compareFields(mine.view, theirs.view), seen: { rev: server.rev, deleted: isGone(server) }, close: closeAll };
      } catch (error) {
        await closeAll();
        throw error;
      }
    },

    /**
     * Ends a conflict on the user's choice. "mine": the local version is written on top of the server's version (a resurrection
     * when the server has deleted the item, a deletion when the local version is a deletion). "theirs": the draft is dropped and
     * the server's version stands (a deletion by the server is accepted). Nothing is merged.
     * `seen` (the `seen` of `conflict(id)`) is the server row the user looked at: when the row this device holds for the item is another
     * one by now (another revision, or deleted where it was live), nothing is done and the answer is `conflict_changed`, so the user is shown
     * both versions again. A choice is never carried out against a row the user has not seen: "mine" could bring back a deletion nobody saw.
     * Spec: Fase 1 section 8.5 ("Resolution").
     * @param {string} id @param {"mine" | "theirs"} choice @param {{ rev: number, deleted: boolean }} [seen]
     * @returns {Promise<void>}
     */
    async resolve(id, choice, seen) {
      if (choice !== "mine" && choice !== "theirs") throw new TypeError("a conflict is resolved with mine or theirs");
      if (seen !== undefined && !(Number.isSafeInteger(seen?.rev) && typeof seen?.deleted === "boolean")) throw new TypeError("seen is the rev and deleted of what the user was shown");
      notWhileRestoring();
      if (typeof id !== "string" || conflictOf(id) === null) throw new SyncError("not_found");
      return exclusive(() => withItem(id, async () => {
        notWhileRestoring();
        if (conflictOf(id) === null) throw new SyncError("not_found");
        // Another tab of this browser may have chosen already: the saved record is read again, and a conflict that is not in it
        // any more is over (this tab's memory is stale and must not write it back).
        if ((await savedFlags())?.blocked?.[id] !== "conflict") throw new SyncError("not_found");
        // The draft this tab holds must still be in the store: another tab may have replaced it (a keep mine) or sent it, and this tab's
        // lane is then stale. Dropping or replacing it would take away what the other tab did, so the block is over here and nothing is done.
        const draft = runner.entriesOf(id).at(-1);
        /** @type {import("../store/outbox.mjs").OutboxEntry[]} */
        const storedDrafts = draft === undefined ? [] : await store.outbox.all(await store.open(), scope);
        alive();
        if (draft === undefined || !storedDrafts.some((entry) => entry.idem === draft.idem)) {
          blocked.delete(id);
          conflictNotes.delete(id);
          changed([id]);
          throw new SyncError("not_found");
        }
        if (choice === "theirs") {
          if (seen !== undefined) assertSeen(await settledServerRow(id), seen);
          await dropDraft(id);
        } else await keepMineInConflict(id, seen);
      }));
    },

    /**
     * "Keep mine" for an item that is not in a conflict but cannot be used as it is. In a conflict this is `resolve(id, "mine")`.
     * For an item whose newest server row could not be opened (`damaged`) it writes the last good local version on top of that
     * row (`rev + 1`); for an item whose deletion by the server could not be verified (`quarantined`) it brings the local copy
     * back on top of that tombstone as a resurrection. Only on the user's choice.
     * @param {string} id
     * @returns {Promise<void>}
     */
    async keepMine(id) {
      notWhileRestoring();
      if (typeof id !== "string" || !hex16.is(id) || id === MANIFEST_ID) throw new SyncError("not_found");
      if (conflictOf(id) !== null) return engine.resolve(id, "mine");
      return exclusive(() => withItem(id, async () => {
        notWhileRestoring();
        if (blocked.has(id)) throw new SyncError("blocked", "blocked", blocked.get(id));
        if (runner.entriesOf(id).length > 0) throw new SyncError("busy", "A change of this item is waiting to be sent.");
        const flag = flags.get(id);
        if (flag !== undefined && (await savedFlags())?.marks?.[id]?.kind !== flag.kind) throw new SyncError("not_found"); // another tab has dealt with it
        if (flag?.kind === "damaged") await keepMineDamaged(id, flag.rev);
        else if (flag?.kind === "quarantined") await keepMineQuarantined(id, flag.rev);
        else throw new SyncError("not_found");
      }));
    },

    /**
     * What the local trash holds: the items a verified deletion took away in the last 30 days, the most recent first. The names are
     * read out of the sealed items now and kept nowhere. An item that cannot be opened is listed with an empty name (it can still
     * be removed). An entry of an item that is not deleted any more is dropped.
     * @returns {Promise<Array<{ id: string, name: string, deletedAt: number }>>}
     */
    async trash() {
      if (stopped) throw new SyncError("stopped");
      const db = await store.open();
      await store.trash.purgeBefore(db, scope, Math.max(0, now() - TRASH_MS));
      alive();
      const entries = await store.trash.all(db, scope);
      alive();
      // What the store holds decides whether an item is alive again (another tab may have written rows this tab has not read).
      const stored = entries.length > 0 ? new Map(/** @type {CachedRow[]} */ (await store.cache.getRows(db, scope)).map((row) => [row.itemId, row])) : new Map();
      alive();
      /** @type {Array<{ id: string, name: string, deletedAt: number }>} */
      const out = [];
      for (const entry of entries) {
        const row = stored.get(entry.itemId);
        if (row !== undefined && !row.deleted && row.rev > entry.tombRev) {
          await store.trash.remove(db, scope, entry.itemId); // the item is alive again above its deletion: a copy of its old row is of no use
          continue;
        }
        let name = "";
        try {
          const handle = await client.vault.open_item(hex16.decode(entry.itemId), entry.rev, entry.envelope, entry.tag);
          try {
            name = String((await client.vault.item_view(handle)).name ?? "");
          } finally {
            await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
          }
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
        }
        out.push({ id: entry.itemId, name, deletedAt: entry.deletedAt });
        alive();
      }
      return out;
    },

    /**
     * Brings an item back from the trash: the saved version is sealed again at the revision above the tombstone the server shows
     * now and written with `base_rev` = that tombstone's revision and `resurrect: true`. Only while the server's row is a tombstone
     * (the entry's or a newer one), and nothing else waits for the item. The entry leaves the trash once the write is stored in the outbox.
     * Spec: Fase 1 section 8.4 ("Local trash", "No resurrection without an active choice").
     * @param {string} id
     * @returns {Promise<void>}
     */
    async restoreFromTrash(id) {
      notWhileRestoring();
      if (typeof id !== "string" || !hex16.is(id) || id === MANIFEST_ID) throw new SyncError("not_found");
      return exclusive(() => withItem(id, async () => {
        notWhileRestoring();
        const db = await store.open();
        const entry = await store.trash.get(db, scope, id);
        alive();
        if (entry === null) throw new SyncError("not_found");
        const row = rows.get(id);
        // On top of the tombstone the server shows now (it may be a newer one than the entry's: the item was brought back and deleted again).
        if (!row?.deleted || row.rev < entry.tombRev) throw new SyncError("invalid_state", "The server no longer shows this item as deleted.");
        if (blocked.has(id)) throw new SyncError("blocked", "blocked", blocked.get(id));
        if (runner.entriesOf(id).length > 0) throw new SyncError("busy", "A change of this item is waiting to be sent.");
        const handle = await client.vault.open_item(hex16.decode(id), entry.rev, entry.envelope, entry.tag);
        try {
          const rev = row.rev + 1;
          const { sealed, summary } = await seal(id, rev, {}, handle);
          await queue(id, row.rev, { blob: sealed.envelope, tag: sealed.tag }, { rev, deleted: false, envelope: sealed.envelope, tag: sealed.tag }, summary, true);
        } finally {
          await Promise.resolve(client.vault.close_item(handle)).catch(() => {});
        }
        await store.trash.remove(db, scope, id);
      }));
    },

    /**
     * Throws a trash entry away for good (the user asked). The item stays deleted.
     * @param {string} id
     * @returns {Promise<void>}
     */
    async removeFromTrash(id) {
      if (stopped) throw new SyncError("stopped");
      if (typeof id !== "string" || !hex16.is(id)) throw new SyncError("not_found");
      await store.trash.remove(await store.open(), scope, id);
    },

    /**
     * Gives up an item that a full listing did not show, on the user's word:
     * the local copy, its row and its revision floor are removed, and so is
     * the upload that was queued for it (or is under way: its result is dropped).
     * @param {string} id
     */
    async discardMissing(id) {
      if (stopped) throw new SyncError("stopped");
      if (restoring || restorePending) throw new SyncError("busy", "An older state is being accepted.");

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
