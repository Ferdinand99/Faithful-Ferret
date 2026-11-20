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
// Before it asks the owner to let go, a tab asks it whether it holds changes that are not saved (`askUnsaved`): a form that is
// open and edited. Yes, or no answer within a second, is a warning for the user to decide on; the answer "no" lets the lock move
// on. Nothing of the form travels over the channel, only a yes or a no.
//
// A tab that waits (it is unlocked and has no engine) stands in the queue of the lock (`wait`). When the owner locks, signs out
// or closes, the first tab in the queue is granted the lock. A tab that sees another tab ask for the lock ("use here") passes a
// grant on, so that the tab that asked is the one that gets it.
//
// This file knows nothing of the engine. The caller gives `onYield` and `onLost`, which stop it.
import { TAB_ID } from "../tabId.mjs";

/** How long the owner is given to answer "use here" before its lock is taken. */
export const STEAL_AFTER_MS = 3000;

/** How long the owner is given to say whether it holds unsaved changes. */
export const ANSWER_WITHIN_MS = 1000;

/** How long after another tab asked for the lock a waiting tab passes a grant on to it. */
export const CLAIM_MS = 4000;

/** The pause between passing a grant on and standing in the queue again. */
const PASS_ON_PAUSE_MS = 250;

/** The name of the lock and of the channel. @param {string} server @param {string} accountId */
export const ownerName = (server, accountId) => `ferret-sync-owner:${server}:${accountId}`;

/**
 * @typedef {{ cancelled: boolean, controller: AbortController, channel: any, claimed: boolean, timer: unknown, pause: unknown }} WaitState
 */

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
 * @property {() => unknown} [onFreed] the lock has been given up or taken from this tab (called after `onYield` / `onLost`)
 * @property {() => boolean} [hasUnsaved] whether this tab holds changes that are not saved; asked of the owner by a tab that wants the lock
 * @property {{ setTimeout(fn: () => void, ms: number): unknown, clearTimeout(handle: unknown): void }} [timers]
 * @property {number} [stealAfterMs]
 * @property {number} [answerWithinMs]
 * @property {number} [claimMs]
 * @property {string} [tabId]
 */

/**
 * @param {OwnerOptions} options
 */
export function createOwner({
  locks, server, accountId, makeChannel, onYield, onLost, onFreed, hasUnsaved, timers = globalThis, stealAfterMs = STEAL_AFTER_MS,
  answerWithinMs = ANSWER_WITHIN_MS, claimMs = CLAIM_MS, tabId = TAB_ID,
}) {
  const name = ownerName(server, accountId);
  const supported = locks != null && typeof locks.request === "function";
  /** @type {Held | null} */
  let held = null;
  /** @type {any} */
  let listener = null;
  let yielding = false;
  /** The tab's place in the queue of the lock, when it is waiting. @type {WaitState | null} */
  let waiting = null;

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
    stopWaiting();
    held = handle;
    handle.onLost = () => {
      if (held !== handle) return;
      held = null;
      stopListening();
      void Promise.resolve(onLost?.("stolen")).catch(() => {}).then(() => onFreed?.());
    };
    stopListening();
    listener = openChannel();
    const channel = listener;
    channel?.addEventListener?.("message", (/** @type {any} */ event) => {
      const data = event?.data;
      if (data === null || typeof data !== "object") return;
      if (typeof data.from !== "string" || data.from === tabId) return;
      if (data.type === "yield") {
        void giveUp(handle);
      } else if (data.type === "unsaved?" && typeof data.nonce === "string" && held === handle) {
        // Only a yes or a no goes back. A check that fails counts as a yes.
        let dirty = true;
        try {
          dirty = hasUnsaved?.() === true;
        } catch {
          dirty = true;
        }
        try {
          channel.postMessage({ type: "unsaved", to: data.from, nonce: data.nonce, dirty });
        } catch {
          // The asker waits for a second and then warns
        }
      }
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
      if (held === handle) {
        release();
        void Promise.resolve(onFreed?.()).catch(() => {});
      }
    }
  }

  /** @returns {Promise<void>} resolves when the lock is free again */
  function release() {
    stopWaiting();
    const handle = held;
    held = null;
    stopListening();
    handle?.release();
    return handle?.ended ?? Promise.resolve();
  }

  /** Leaves the queue of the lock. Safe when the tab does not wait. */
  function stopWaiting() {
    const state = waiting;
    waiting = null;
    if (state === null) return;
    state.cancelled = true;
    timers.clearTimeout(state.timer);
    timers.clearTimeout(state.pause);
    state.controller.abort();
    try {
      state.channel?.close?.();
    } catch {
      // Closed already
    }
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
      stopWaiting(); // the lock is asked for again below, with the owner told
      const handle = (await hold({ ifAvailable: true })) ?? (await askThenSteal());
      adopt(handle);
    },
    /**
     * Asks the tab that holds the lock whether it has changes that are not saved, before "use here" moves the lock.
     * Answers "free" when nobody holds the lock (it is taken here), "clear" when the owner has none (or this tab is the
     * owner), "unsaved" when it has, and "no_answer" when nothing came back within about a second (a frozen tab, or no channel).
     * @returns {Promise<"free" | "clear" | "unsaved" | "no_answer">}
     */
    async askUnsaved() {
      if (!supported || held !== null) return "clear";
      const handle = await hold({ ifAvailable: true });
      if (handle !== null) {
        adopt(handle);
        return "free";
      }
      const channel = openChannel();
      if (channel === null) return "no_answer";
      const nonce = `${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
      /** @type {unknown} */
      let timer = null;
      try {
        const answer = new Promise((resolve) => {
          channel.addEventListener?.("message", (/** @type {any} */ event) => {
            const data = event?.data;
            if (data === null || typeof data !== "object" || data.type !== "unsaved") return;
            if (data.to !== tabId || data.nonce !== nonce) return;
            resolve(data.dirty === false ? "clear" : "unsaved");
          });
          timer = timers.setTimeout(() => resolve("no_answer"), answerWithinMs);
        });
        try {
          channel.postMessage({ type: "unsaved?", from: tabId, nonce });
        } catch {
          // No way to ask: the wait ends in "no_answer"
        }
        return /** @type {"clear" | "unsaved" | "no_answer"} */ (await answer);
      } finally {
        timers.clearTimeout(timer);
        try {
          channel.close?.();
        } catch {
          // Closed already
        }
      }
    },
    /**
     * Stands in the queue of the lock (this tab has no engine and is unlocked). Resolves with "granted" when the lock came
     * to this tab (it is held, and a "use here" from another tab can ask for it), or "cancelled" when the tab left the queue
     * (`release`, `takeOver`, `adopt`) or the browser has no Web Locks. A grant that comes soon after another tab asked for
     * the lock is passed on, and the tab goes back into the queue.
     * @returns {Promise<"granted" | "cancelled">}
     */
    async wait() {
      if (!supported || held !== null || waiting !== null) return "cancelled";
      /** @type {WaitState} */
      const state = { cancelled: false, controller: new AbortController(), channel: openChannel(), claimed: false, timer: null, pause: null };
      waiting = state;
      state.channel?.addEventListener?.("message", (/** @type {any} */ event) => {
        const data = event?.data;
        if (data === null || typeof data !== "object" || data.type !== "yield") return;
        if (typeof data.from !== "string" || data.from === tabId) return;
        state.claimed = true;
        timers.clearTimeout(state.timer);
        state.timer = timers.setTimeout(() => {
          state.claimed = false;
        }, claimMs);
      });
      for (;;) {
        const handle = await hold({ signal: state.controller.signal });
        if (state.cancelled || handle === null) {
          handle?.release();
          return "cancelled";
        }
        if (!state.claimed) {
          adopt(handle); // leaves the queue
          return "granted";
        }
        handle.release();
        await handle.ended;
        await new Promise((resolve) => {
          state.pause = timers.setTimeout(() => resolve(undefined), PASS_ON_PAUSE_MS);
        });
        if (state.cancelled) return "cancelled";
      }
    },
    /**
     * Lets go of the lock (the engine stopped, the vault locked, the page goes away). Safe when not held. The promise
     * resolves when the lock is free again: an `acquire()` that comes right after waits for it, or it finds the lock held (by this very tab).
     */
    release,
  };
}
