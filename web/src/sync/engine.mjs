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
//   answered with 410 as well, the cycle ends with the error `gone`.
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
  /** @param {string} code @param {string} [message] */
  constructor(code, message = code) {
    super(message);
    this.name = "SyncError";
    /** @type {string} */
    this.code = code;
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
  /** The decrypted item index, in memory only. @type {Map<string, Omit<ItemSummary, "id" | "pending" | "damaged" | "quarantined">>} */
  const index = new Map();
  /** Items the server's newest row of which is not usable. @type {Map<string, { kind: "damaged" | "quarantined", rev: number }>} */
  const flags = new Map();
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
    if (kind === lastStatus && kind !== "warning") return;
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
      onDone: (entry) => {
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
        /** @type {Record<string, any>} */
        const detail = { code: kind === "conflict" ? "conflict" : error.code, id: entry.itemId };
        if (kind === "conflict") {
          const current = error.body?.current_rev;
          if (Number.isSafeInteger(current)) detail.currentRev = current;
          detail.deleted = error.body?.deleted === true;
        }
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
    if (page.latest_seq < cursor && (restoreEpoch === null || restoreEpoch === page.restore_epoch)) {
      if (behind !== `${page.latest_seq}/${cursor}`) {
        behind = `${page.latest_seq}/${cursor}`;
        warn("server_behind", { latestSeq: page.latest_seq, cursor });
      }
    }
    restoreEpoch = page.restore_epoch;
  }

  /** @param {any} db @param {any[]} changes */
  async function applyPage(db, changes) {
    /** @type {CachedRow[]} */
    const accepted = [];
    /** @type {Set<string>} */
    const touched = new Set();
    for (const change of changes) {
      if (stopped) return;
      const id = /** @type {string} */ (change.id);
      listing?.add(id);
      const row = rowOfChange(change);
      const local = rows.get(id);
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
        rows.set(id, row); // kept in the cache, never an item
        accepted.push(row);
        continue;
      }
      if (row.deleted) {
        try {
          await client.vault.verify_tombstone(hex16.decode(id), row.rev, /** @type {Uint8Array} */ (row.tomb));
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
          flags.set(id, { kind: "quarantined", rev: row.rev });
          flagsDirty = true;
          touched.add(id);
          warn("tombstone_unverified", { id, rev: row.rev });
          continue;
        }
        alive();
        rows.set(id, row);
        accepted.push(row);
        index.delete(id);
        overlay.delete(id);
        if (flags.delete(id)) flagsDirty = true;
        touched.add(id);
        continue;
      }
      try {
        const summary = await summarize(id, row.rev, /** @type {Uint8Array} */ (row.envelope), /** @type {Uint8Array} */ (row.tag));
        alive();
        rows.set(id, row);
        accepted.push(row);
        if (flags.delete(id)) flagsDirty = true;
        const mine = overlay.get(id);
        if (mine && mine.rev > row.rev) {
          // A local write is ahead of this row: it stays on screen.
        } else {
          overlay.delete(id);
          index.set(id, summary);
        }
      } catch (error) {
        if (stopped || isFatal(error)) throw error;
        flags.set(id, { kind: "damaged", rev: row.rev });
        flagsDirty = true;
        if (!index.has(id)) index.set(id, summaryOf({}, row.rev)); // nothing good to show
        warn("row_damaged", { id, rev: row.rev, reason: codeOf(error) });
      }
      touched.add(id);
    }
    if (accepted.length > 0) await store.cache.putRows(db, scope, accepted);
    await saveFlags(db);
    changed(touched);
  }

  /** After a full listing: what the server no longer shows is gone from here too. @param {any} db */
  async function finishListing(db) {
    const seen = /** @type {Set<string>} */ (listing);
    listing = null;
    /** @type {string[]} */
    const removed = [];
    for (const id of [...rows.keys()]) {
      if (seen.has(id) || id === MANIFEST_ID || flags.has(id)) continue;
      rows.delete(id);
      const mine = overlay.get(id);
      if (!mine || runner.entriesOf(id).length === 0) {
        overlay.delete(id);
        index.delete(id);
      }
      removed.push(id);
    }
    if (removed.length > 0) {
      await store.cache.clear(db, scope);
      await store.cache.putRows(db, scope, [...rows.values()]);
      warn("relisted", { removed: removed.length });
      changed(removed);
    }
  }

  /** @param {any} db */
  async function saveFlags(db) {
    if (!flagsDirty) return;
    flagsDirty = false;
    if (flags.size === 0) {
      await store.deleteSetting(db, flagsKey);
      return;
    }
    await store.setSetting(db, flagsKey, Object.fromEntries(flags));
  }

  /** One pass: the feed. Failures become events; they never reject. */
  async function runCycle() {
    setStatus("syncing");
    try {
      await cycle();
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
      } else if (error instanceof SyncError || isFatal(error) || code === "gone" || code === "bad_request" || code.startsWith("malformed")) {
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
    const flag = flags.get(id);
    if (flag) throw new SyncError(flag.kind);
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
   * @param {{ rev: number, deleted: boolean, envelope: Uint8Array | null, tag: Uint8Array | null }} next what the item is after the write
   * @param {ReturnType<typeof summaryOf> | null} summary null for a deletion
   */
  async function queue(id, baseRev, body, next, summary) {
    const idem = randomId();
    const request =
      "tomb" in body
        ? { base_rev: baseRev, deleted: true, tomb: b64u.encode(body.tomb), idem }
        : { base_rev: baseRev, blob: b64u.encode(body.blob), tag: b64u.encode(body.tag), idem };
    const bytes = encodeWireBytes("put_item_req", request);
    alive();
    const before = { overlay: overlay.get(id), index: index.get(id) };
    overlay.set(id, next);
    if (summary) index.set(id, summary);
    else index.delete(id);
    try {
      await runner.enqueue({ idem, itemId: id, baseRev, body, bytes });
    } catch (error) {
      // Not stored, so not sent: the screen goes back to what it showed.
      if (before.overlay) overlay.set(id, before.overlay);
      else overlay.delete(id);
      if (before.index) index.set(id, before.index);
      else index.delete(id);
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
      for (const [id, flag] of Object.entries(saved && typeof saved === "object" ? saved : {})) {
        if (hex16.is(id) && (flag?.kind === "damaged" || flag?.kind === "quarantined") && Number.isSafeInteger(flag.rev)) {
          flags.set(id, { kind: flag.kind, rev: flag.rev });
        }
      }
      for (const row of cached) {
        if (row.deleted || row.itemId === MANIFEST_ID) continue;
        try {
          const summary = await summarize(row.itemId, row.rev, /** @type {Uint8Array} */ (row.envelope), /** @type {Uint8Array} */ (row.tag));
          alive();
          index.set(row.itemId, summary);
        } catch (error) {
          if (stopped || isFatal(error)) throw error;
          flags.set(row.itemId, { kind: "damaged", rev: row.rev });
          flagsDirty = true;
          index.set(row.itemId, summaryOf({}, row.rev));
        }
      }
      for (const [id, flag] of [...flags]) {
        // A flag needs its item: a damaged one may have no good version, but a quarantine keeps one.
        if (!rows.has(id) && flag.kind === "quarantined") flags.delete(id);
        else if (!index.has(id)) index.set(id, summaryOf({}, flag.rev));
      }
      await saveFlags(db);
      if (stopped) return;

      // Writes that were queued before the restart show as pending, newest last.
      const queued = await runner.load();
      alive();
      for (const entry of queued) {
        const rev = entry.baseRev + 1;
        if (rev <= (rows.get(entry.itemId)?.rev ?? 0)) continue; // the feed already has this item beyond the draft
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
