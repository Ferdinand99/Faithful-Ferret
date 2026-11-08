// The auto-lock (design document, sections 7.1 and 7.2). It fails closed.
//
// `lockAt` is an absolute time in milliseconds. It is kept in `storage.session`
// (a deadline is not a secret) and checked:
//   - before every message that is not in LOCK_EXEMPT (`checkOrLock`),
//   - when the `alarms` alarm for it fires,
//   - when the browser reports that the screen is locked.
// A missing or unreadable `lockAt` while the vault is open means locked. A
// lock is `coreHost.lock(reason)`: the worker that holds the keys is ended.
// Nothing here keeps the background page alive.

/**
 * Message types that need no vault key and so are not checked: they must work
 * while the vault is locked (a user cannot unlock otherwise), and `lock` must
 * never be refused.
 */
export const LOCK_EXEMPT = Object.freeze(["sign_in", "unlock", "state", "settings", "lock"]);

export const LOCK_AT_KEY = "lock_at";
export const ALARM_NAME = "ferret-lock";
export const MIN_MINUTES = 1;
export const MAX_MINUTES = 480;
const MS_PER_MINUTE = 60_000;

/**
 * @typedef {{ lock: (reason: "timeout" | "idle" | "manual" | "sign_out" | "restart") => Promise<void>, state: () => "locked" | "unlocked", onLocked: (listener: (reason: string) => void) => unknown }} Locker
 * @typedef {{
 *   alarms: { create: (name: string, info: { when: number }) => unknown, clear: (name: string) => unknown, onAlarm: { addListener: (fn: (alarm: { name: string }) => unknown) => void } },
 *   idle: { onStateChanged: { addListener: (fn: (state: string) => void) => void } },
 *   storageSession: { get: (key: string) => Promise<Record<string, unknown>>, set: (items: Record<string, unknown>) => Promise<void>, remove: (key: string) => Promise<void> },
 *   now: () => number,
 *   coreHost: Locker,
 *   minutes?: number,
 * }} LockOptions
 */

/** @param {unknown} n */
function validMinutes(n) {
  return typeof n === "number" && Number.isInteger(n) && n >= MIN_MINUTES && n <= MAX_MINUTES;
}

/**
 * Registers its listeners at once, so call it while the background page loads
 * (a listener added later misses the event that woke the page).
 *
 * @param {LockOptions} options
 */
export function createLock({ alarms, idle, storageSession, now, coreHost, minutes = 15 }) {
  if (!validMinutes(minutes)) throw new RangeError("minutes must be a whole number from 1 to 480");
  let idleMinutes = minutes;
  // Writes to the session storage run one after the other, and a check waits
  // for the writes that came before it.
  /** @type {Promise<unknown>} */
  let writes = Promise.resolve();

  /** @param {() => unknown} job */
  const queue = (job) => {
    writes = writes.then(job).catch(() => {});
    return writes;
  };

  /** @returns {Promise<number | null>} null when there is no usable deadline */
  const readLockAt = async () => {
    await writes;
    try {
      const stored = (await storageSession.get(LOCK_AT_KEY))?.[LOCK_AT_KEY];
      return typeof stored === "number" && Number.isFinite(stored) ? stored : null;
    } catch {
      return null;
    }
  };

  /** @param {number} when */
  const arm = (when) => {
    try {
      const result = /** @type {any} */ (alarms.create(ALARM_NAME, { when }));
      result?.catch?.(() => {});
    } catch {
      // No alarm: the check on every message still locks.
    }
  };

  const disarm = () => {
    try {
      const result = /** @type {any} */ (alarms.clear(ALARM_NAME));
      result?.catch?.(() => {});
    } catch {
      // Nothing to clear.
    }
  };

  // Whatever locks the vault also drops the deadline.
  coreHost.onLocked(() => {
    disarm();
    queue(() => storageSession.remove(LOCK_AT_KEY));
  });

  /** Locks when the deadline has passed or is missing; otherwise arms the alarm for it. */
  const expire = async () => {
    if (coreHost.state() === "locked") return;
    const at = await readLockAt();
    if (at === null) await coreHost.lock("restart");
    else if (now() >= at) await coreHost.lock("timeout");
    else arm(at);
  };

  alarms.onAlarm.addListener((alarm) => {
    if (alarm?.name !== ALARM_NAME) return undefined;
    // The browser ignores what a listener returns; the tests wait for it.
    return expire().catch(() => coreHost.lock("timeout").catch(() => {}));
  });

  idle.onStateChanged.addListener((state) => {
    if (state === "locked") coreHost.lock("idle").catch(() => {});
  });

  return {
    /** Moves the deadline to `minutes` from now. Call it for activity in Ferret's own UI. */
    touch() {
      const at = now() + idleMinutes * MS_PER_MINUTE;
      queue(() => storageSession.set({ [LOCK_AT_KEY]: at }));
      arm(at);
    },

    /**
     * True when the call may go on. A type in LOCK_EXEMPT always may. Any other
     * type may only while the vault is open and the deadline is in the future;
     * a passed or missing deadline locks first and answers false.
     *
     * @param {string} type
     * @returns {Promise<boolean>}
     */
    async checkOrLock(type) {
      if (LOCK_EXEMPT.includes(type)) return true;
      const at = await readLockAt();
      if (coreHost.state() === "locked") return false;
      if (at === null) {
        await coreHost.lock("restart");
        return false;
      }
      if (now() >= at) {
        await coreHost.lock("timeout");
        return false;
      }
      return true;
    },

    /**
     * Sets the idle time before the lock, from 1 to 480 minutes. It applies from
     * the next touch.
     *
     * @param {number} n
     */
    setMinutes(n) {
      if (!validMinutes(n)) throw new RangeError("minutes must be a whole number from 1 to 480");
      idleMinutes = n;
    },
  };
}
