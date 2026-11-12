// One active sync engine per server and account in a browser. Two tabs that both ran an engine would
// keep two copies of the outbox, the marks and the conflict notes in memory over one stored copy, and
// one tab could drop or hide what the other had queued. So only the tab that holds the owner lock
// `ferret-sync-owner:<server>:<account>` runs an engine; every other tab is on standby and shows a
// notice with a button, "Use here".
//
// "Use here" moves the engine to the tab where it was pressed:
//   1. the lock is asked for with `ifAvailable`: when nobody holds it (the owner tab was closed) it is ours;
//   2. otherwise the owner is asked, over `BroadcastChannel("ferret-sync-owner:<server>:<account>")`, to
//      stop its engine and let go of the lock, and the lock is waited for;
//   3. when no answer has come after about 3 seconds (the owner tab is frozen, or gone without letting
//      go), the lock is taken with `steal: true`. The owner then loses it (its `locks.request` ends with
//      an `AbortError`) and is told with `onLost`.
// Nothing is lost when an engine stops in the middle of a write: the outbox is stored, and a request
// that was on its way is sent again with the same idempotency key.
//
// This file knows nothing of the engine. The caller gives `onYield` and `onLost`, which stop it.
import { TAB_ID } from "../tabId.mjs";

/** How long the owner is given to answer "use here" before its lock is taken. */
export const STEAL_AFTER_MS = 3000;

/** The name of the lock and of the channel. @param {string} server @param {string} accountId */
export const ownerName = (server, accountId) => `ferret-sync-owner:${server}:${accountId}`;

/**
 * @typedef {object} Held a lock this tab holds
 * @property {() => void} release
 * @property {Promise<void>} ended settles when the lock request has ended: the lock is free again (or was taken from this tab)
 * @property {(() => void) | null} onLost set by the owner of the handle; called when the lock is taken from this tab
 *
 * @typedef {object} OwnerOptions
 * @property {{ request(name: string, options: any, callback: (lock: unknown) => Promise<unknown>): Promise<unknown> } | null | undefined} locks the page's Web Locks
 * @property {string} server the server key
 * @property {string} accountId
 * @property {() => any} [makeChannel] makes the channel (a `BroadcastChannel` named `ownerName(server, accountId)`)
 * @property {(reason: "asked") => unknown} [onYield] the owner is asked to give the lock up: stop the engine. The lock is let go when this is done.
 * @property {(reason: "stolen") => unknown} [onLost] the lock was taken from this tab
 * @property {{ setTimeout(fn: () => void, ms: number): unknown, clearTimeout(handle: unknown): void }} [timers]
 * @property {number} [stealAfterMs]
 * @property {string} [tabId]
 */

/**
 * @param {OwnerOptions} options
 */
export function createOwner({
  locks, server, accountId, makeChannel, onYield, onLost, timers = globalThis, stealAfterMs = STEAL_AFTER_MS, tabId = TAB_ID,
}) {
  const name = ownerName(server, accountId);
  const supported = locks != null && typeof locks.request === "function";
  /** @type {Held | null} */
  let held = null;
  /** @type {any} */
  let listener = null;
  let yielding = false;

  /** @returns {any} */
  const openChannel = () => {
    try {
      if (typeof makeChannel === "function") return makeChannel();
      if (typeof BroadcastChannel === "function") return new BroadcastChannel(name);
    } catch {
      // No channel: the lock is still taken, after the wait
    }
    return null;
  };

  /**
   * Asks for the lock. Answers the handle when it was granted, or null (not available, or the wait was given up).
   * @param {Record<string, unknown>} options options of `locks.request`
   * @returns {Promise<Held | null>}
   */
  function hold(options) {
    return new Promise((resolve) => {
      let granted = false;
      /** @type {() => void} */
      let letGo = () => {};
      const kept = new Promise((done) => {
        letGo = () => done(undefined);
      });
      /** @type {() => void} */
      let finished = () => {};
      const ended = new Promise((done) => {
        finished = () => done(undefined);
      });
      /** @type {Held} */
      const handle = { release: () => letGo(), ended, onLost: null };
      /** @type {Promise<unknown>} */
      let request;
      try {
        request = Promise.resolve(/** @type {any} */ (locks).request(name, options, async (/** @type {unknown} */ lock) => {
          if (!lock) {
            resolve(null);
            return;
          }
          granted = true;
          resolve(handle);
          await kept;
        }));
      } catch {
        resolve(null);
        return;
      }
      request.then(finished, () => {
        // Refused before it was granted (the wait was aborted), or taken from us afterwards (`steal`).
        finished();
        if (!granted) {
          resolve(null);
          return;
        }
        letGo();
        handle.onLost?.();
      });
    });
  }

  function stopListening() {
    if (listener === null) return;
    try {
      listener.close?.();
    } catch {
      // Closed already
    }
    listener = null;
  }

  /** Listens for "use here" from other tabs while this tab holds the lock. @param {Held} handle */
  function adopt(handle) {
    held = handle;
    handle.onLost = () => {
      if (held !== handle) return;
      held = null;
      stopListening();
      void Promise.resolve(onLost?.("stolen")).catch(() => {});
    };
    stopListening();
    listener = openChannel();
    listener?.addEventListener?.("message", (/** @type {any} */ event) => {
      const data = event?.data;
      if (data === null || typeof data !== "object" || data.type !== "yield") return;
      if (typeof data.from !== "string" || data.from === tabId) return;
      void giveUp(handle);
    });
  }

  /** @param {Held} handle */
  async function giveUp(handle) {
    if (held !== handle || yielding) return;
    yielding = true;
    try {
      await onYield?.("asked");
    } catch {
      // The engine's stop does not throw; whatever it did, the lock goes
    } finally {
      yielding = false;
      if (held === handle) release();
    }
  }

  /** @returns {Promise<void>} resolves when the lock is free again */
  function release() {
    const handle = held;
    held = null;
    stopListening();
    handle?.release();
    return handle?.ended ?? Promise.resolve();
  }

  /** Asks the owner to let go, waits about `stealAfterMs`, then takes the lock. @returns {Promise<Held>} */
  async function askThenSteal() {
    const channel = openChannel();
    try {
      try {
        channel?.postMessage({ type: "yield", from: tabId });
      } catch {
        // A channel that cannot send: the lock is taken after the wait
      }
      const controller = new AbortController();
      const queued = hold({ signal: controller.signal });
      /** @type {unknown} */
      let timer = null;
      const late = new Promise((resolve) => {
        timer = timers.setTimeout(() => resolve(null), stealAfterMs);
      });
      const first = await Promise.race([queued, late]);
      timers.clearTimeout(timer);
      if (first !== null) return /** @type {Held} */ (first);
      controller.abort();
      const granted = await queued; // granted at the very moment of the abort, or null
      if (granted !== null) return granted;
      const stolen = await hold({ steal: true });
      if (stolen === null) throw Object.assign(new Error("the owner lock could not be taken"), { code: "owner_unavailable" });
      return stolen;
    } finally {
      try {
        channel?.close?.();
      } catch {
        // Closed already
      }
    }
  }

  return {
    /** Whether this tab holds the lock now. */
    isOwner: () => held !== null,
    /**
     * Takes the lock when nobody holds it. Answers "owner", or "standby" when another tab holds it. A browser without
     * Web Locks answers "owner": the engine then stops by itself with `unsupported`.
     * @returns {Promise<"owner" | "standby">}
     */
    async acquire() {
      if (!supported) return "owner";
      if (held !== null) return "owner";
      const handle = await hold({ ifAvailable: true });
      if (handle === null) return "standby";
      adopt(handle);
      return "owner";
    },
    /**
     * "Use here": makes this tab the owner (see the top of the file). Rejects with `owner_unavailable` when even
     * the stealing fails.
     * @returns {Promise<void>}
     */
    async takeOver() {
      if (!supported || held !== null) return;
      const handle = (await hold({ ifAvailable: true })) ?? (await askThenSteal());
      adopt(handle);
    },
    /**
     * Lets go of the lock (the engine stopped, the vault locked, the page goes away). Safe when not held. The promise
     * resolves when the lock is free again: an `acquire()` that comes right after waits for it, or it finds the lock held (by this very tab).
     */
    release,
  };
}
