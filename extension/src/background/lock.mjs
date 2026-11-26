// The auto-lock (design document, sections 7.1 and 7.2). It fails closed.
//
// `lockAt` is an absolute time in milliseconds. It is kept in `storage.session`
// (a deadline is not a secret) and checked:
//   - before every message that is not in LOCK_EXEMPT (`checkOrLock`),
//   - when the `alarms` alarm for it fires, and when a timer of the page fires
//     (the alarm may come late, and for the short choices only at the browser's
//     own granularity),
//   - when the browser reports the system idle for as long as the setting, or
//     the screen locked (Firefox does not report the latter, so the former is
//     what runs), and when it reports the user active again after a sleep.
// A missing or unreadable `lockAt` while the vault is open means locked. A
// lock is `coreHost.lock(reason)`: the worker that holds the keys is ended.
// Nothing here keeps the background page alive.
//
// How long the vault stays open without activity in Ferret's own pages is the
// setting "Lock after": one of the fixed LOCK_CHOICES (seconds), kept in
// `storage.local`, 15 minutes by default; a stored value that is not one of the
// choices is read as the default. Activity is only what the user does in
// Ferret's pages (the router calls `touch` for it); nothing in a web page moves
// the deadline.
//
// The vault never opens without a deadline: the core host tells this module in
// the turn it opens, and the deadline is set then. Every message, also one in
// LOCK_EXEMPT, first locks a vault whose deadline has passed.

import { DEFAULT_LOCK_SECONDS, LOCK_CHOICES } from "../shared/protocol.mjs";

export { DEFAULT_LOCK_SECONDS, LOCK_CHOICES };

/**
 * Message types that need no vault key and so are not checked: they must work
 * while the vault is locked (a user cannot unlock otherwise), and `lock` must
 * never be refused. `server_check` reads the address a user typed on the
 * sign-in page with a stateless function of the core, before any sign-in.
 * `sync_state` reads the codes of the sync (no key; a poll of it must not move
 * the deadline), and `forget_server` must work on a locked or signed-out device
 * too (it needs no key: it revokes the device and removes local records).
 * `forget_preview` is the question before it, on the same devices: it reads two
 * counts of the local records (unsent changes, and whether another address
 * keeps the account), needs no key and changes nothing.
 * `form_capture`, `form_gone` and `page_ready` are the capture script's reports: they are taken while the vault is locked,
 * never touch a key and never move the deadline (a page's activity is not the user's); `capture_settings` is the settings
 * page's "Offer to save passwords", which must work on a locked device like the other settings. `pin_unlock` opens the vault
 * (it is the way to unlock, so it needs no open vault) and `unlock_policy` reads what the device knows of the PIN rule and
 * the PIN, which the popup shows before it unlocks; neither is a use of the vault. `prf_unlock` opens the vault too (with a
 * passkey) and `prf_options` reads what the unlock window needs for it; all three work while locked (`prf_window` only opens the page). `pin_off` only deletes the PIN (the safe
 * direction, and it needs no key: someone who forgot the PIN turns it off from the locked popup). `pin_set` makes a copy of
 * the vault key, so it is checked like every other message.
 * `passkey_request`, `passkey_abort`, `passkey_foreign` and `passkey_ping` are the passkey bridge's reports of a page:
 * taken while the vault is locked (Ferret's own window opens it), and a page's activity never moves the deadline.
 * `passkey_pending`, `passkey_cancel` and `passkey_browser` are Ferret's chooser window for such a request: it shows the
 * request, cancels it or hands it to the browser while the vault is locked (it is where the vault is opened), and none of
 * them uses a key. `passkey_site` asks the core, so it needs the open vault. `passkey_tab` (what the popup shows for its tab, read
 * on a timer) and `passkey_tab_open` (the popup's card opens that window) work locked too and use no key.
 */
export const LOCK_EXEMPT = Object.freeze([
  "sign_in",
  "unlock",
  "state",
  "settings",
  "lock",
  "server_check",
  "sync_state",
  "forget_preview",
  "forget_server",
  "form_capture",
  "form_gone",
  "page_ready",
  "capture_settings",
  "pin_unlock",
  "unlock_policy",
  "pin_off",
  "prf_options",
  "prf_unlock",
  "prf_window",
  "passkey_request",
  "passkey_abort",
  "passkey_foreign",
  "passkey_ping",
  "passkey_pending",
  "passkey_cancel",
  "passkey_browser",
  "passkey_settings",
  "passkey_tab",
  "passkey_tab_open",
]);

export const LOCK_AT_KEY = "lock_at";
export const ALARM_NAME = "ferret-lock";
export const SETTING_KEY = "lock_seconds";
const MS_PER_SECOND = 1000;
/**
 * The longest the page's timer waits before it reads the wall clock again (it reads no storage and calls no API). A timer is a delay on the browser's own
 * clock, which may stand still while the machine sleeps, so a timer set for the whole deadline could fire long after it.
 * With this cap a deadline that passed in a sleep is seen at most this long after the machine wakes.
 */
export const RECHECK_MS = 15_000;

/**
 * @typedef {{
 *   lock: (reason: "timeout" | "idle" | "manual" | "sign_out" | "restart" | "worker_failed") => Promise<void>,
 *   state: () => "locked" | "unlocked",
 *   onLocked: (listener: (reason: string) => void) => unknown,
 *   onUnlocked: (listener: () => void) => unknown,
 * }} Locker
 * @typedef {{
 *   alarms: { create: (name: string, info: { when: number }) => unknown, clear: (name: string) => unknown, onAlarm: { addListener: (fn: (alarm: { name: string }) => unknown) => void } },
 *   idle: { onStateChanged: { addListener: (fn: (state: string) => void) => void }, setDetectionInterval?: (seconds: number) => unknown },
 *   storageSession: { get: (key: string) => Promise<Record<string, unknown>>, set: (items: Record<string, unknown>) => Promise<void>, remove: (key: string) => Promise<void> },
 *   storageLocal?: { get: (key: string) => Promise<Record<string, unknown>>, set: (items: Record<string, unknown>) => Promise<void> } | null,
 *   timers?: { setTimeout: (fn: () => void, ms: number) => unknown, clearTimeout: (id: any) => void },
 *   now: () => number,
 *   coreHost: Locker,
 *   seconds?: number,
 * }} LockOptions
 */

/** @param {unknown} n @returns {n is number} */
function isChoice(n) {
  return typeof n === "number" && LOCK_CHOICES.includes(n);
}

const pageTimers = {
  setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (/** @type {any} */ id) => globalThis.clearTimeout(id),
};

/**
 * Registers its listeners at once, so call it while the background page loads
 * (a listener added later misses the event that woke the page).
 *
 * @param {LockOptions} options
 */
export function createLock({ alarms, idle, storageSession, storageLocal = null, timers = pageTimers, now, coreHost, seconds = DEFAULT_LOCK_SECONDS }) {
  if (!isChoice(seconds)) throw new RangeError("seconds must be one of the lock choices");
  let lockSeconds = seconds;
  // The setting is read from `storage.local` once. A missing, unreadable or unlisted value leaves the default.
  const ready = (async () => {
    if (storageLocal === null) return;
    try {
      const stored = (await storageLocal.get(SETTING_KEY))?.[SETTING_KEY];
      if (isChoice(stored)) lockSeconds = stored;
    } catch {
      // The default stands.
    }
  })();
  const applyIdleInterval = () => {
    try {
      const result = /** @type {any} */ (idle.setDetectionInterval?.(lockSeconds));
      result?.catch?.(() => {});
    } catch {
      // The browser keeps its own interval; the deadline still locks.
    }
  };
  ready.then(applyIdleInterval);
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

  /** The page's own timer for the deadline. @type {unknown} */
  let timer = null;
  const clearTimer = () => {
    if (timer !== null) {
      try {
        timers.clearTimeout(timer);
      } catch {
        // Nothing to clear.
      }
      timer = null;
    }
  };

  /**
   * The page's timer, for at most RECHECK_MS: when it fires, `expire` reads the wall clock and either locks or sets it again.
   * @param {number} when
   */
  const armTimer = (when) => {
    clearTimer();
    try {
      timer = timers.setTimeout(() => {
        timer = null;
        if (coreHost.state() === "locked") return;
        // The copy of the deadline and the clock: no call of the extension API, so this check does not keep a
        // background page alive that the browser would end. A deadline that is not known is read from the storage.
        if (knownLockAt === null) expire(armTimer).catch(() => coreHost.lock("timeout").catch(() => {}));
        else if (now() >= knownLockAt) coreHost.lock("timeout").catch(() => {});
        else armTimer(knownLockAt);
      }, Math.min(Math.max(0, when - now()), RECHECK_MS));
      // A node test run must not wait for it; a browser's handle is a number.
      /** @type {any} */ (timer)?.unref?.();
    } catch {
      // No timer: the alarm and the check on every message still lock.
    }
  };

  /** The alarm and the timer. @param {number} when */
  const arm = (when) => {
    try {
      const result = /** @type {any} */ (alarms.create(ALARM_NAME, { when }));
      result?.catch?.(() => {});
    } catch {
      // No alarm: the timer and the check on every message still lock.
    }
    armTimer(when);
  };

  /**
   * The deadline as this page knows it, for the guard of the core host. It is only a copy of what is in the session
   * storage, kept here so a check needs no await: a call that needs the vault must not wait for a read.
   * @type {number | null}
   */
  let knownLockAt = null;

  const disarm = () => {
    clearTimer();
    try {
      const result = /** @type {any} */ (alarms.clear(ALARM_NAME));
      result?.catch?.(() => {});
    } catch {
      // Nothing to clear.
    }
  };

  // Whatever locks the vault also drops the deadline.
  coreHost.onLocked(() => {
    knownLockAt = null;
    disarm();
    queue(() => storageSession.remove(LOCK_AT_KEY));
  });

  /**
   * Locks when the deadline has passed or is missing; otherwise arms the alarm and the timer for it (or only what
   * `rearm` says).
   * @param {(when: number) => void} [rearm]
   */
  const expire = async (rearm = arm) => {
    if (coreHost.state() === "locked") return;
    const at = await readLockAt();
    if (at === null) await coreHost.lock("restart");
    else if (now() >= at) await coreHost.lock("timeout");
    else rearm(at);
  };

  alarms.onAlarm.addListener((alarm) => {
    if (alarm?.name !== ALARM_NAME) return undefined;
    // The browser ignores what a listener returns; the tests wait for it.
    return expire().catch(() => coreHost.lock("timeout").catch(() => {}));
  });

  idle.onStateChanged.addListener((state) => {
    // "idle" is the system idle for as long as the setting (the detection interval); "locked" is the
    // screen lock, where the browser reports it. Either one locks.
    if (state === "locked" || state === "idle") coreHost.lock("idle").catch(() => {});
    // Back from a sleep or an absence: a deadline that passed meanwhile locks now, not at the next message.
    else if (state === "active") expire().catch(() => {});
  });

  const touch = () => {
    const at = now() + lockSeconds * MS_PER_SECOND;
    knownLockAt = at;
    queue(() => storageSession.set({ [LOCK_AT_KEY]: at }));
    arm(at);
  };

  // The deadline starts in the turn the vault opens.
  coreHost.onUnlocked(touch);

  return {
    /** Moves the deadline to `minutes` from now. Call it for activity in Ferret's own UI. */
    touch,

    /**
     * True when the call may go on. A type in LOCK_EXEMPT always may (after the
     * lock of a passed or missing deadline, as below). Any other
     * type may only while the vault is open and the deadline is in the future;
     * a passed or missing deadline locks first and answers false.
     *
     * @param {string} type
     * @returns {Promise<boolean>}
     */
    async checkOrLock(type) {
      await ready;
      if (LOCK_EXEMPT.includes(type)) {
        // No key is needed, but an open vault whose time has run out is locked
        // first, so a state poll never reports a vault that should be closed.
        try {
          await expire();
        } catch {
          // The lock is already in force whatever went wrong; a message that
          // needs no key (above all `lock`) is never refused for it.
        }
        return true;
      }
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
     * True when the vault may not be used now: the deadline this page knows has passed, or there is none. It reads
     * the clock and a copy of the deadline and awaits nothing, so the core host can ask it before every call that
     * uses the vault, whoever makes the call.
     */
    isDue() {
      return knownLockAt === null || now() >= knownLockAt;
    },

    /**
     * Sets "Lock after" to one of LOCK_CHOICES (seconds) and keeps it in `storage.local`. Anything else is a
     * RangeError and changes nothing. The new value is used only once it is saved, so a touch while the save is
     * pending (or a save that fails) never uses a value that is not kept. A shorter time shortens the deadline of
     * an open vault at once; a longer one applies from the next touch.
     *
     * @param {number} n
     */
    async setSeconds(n) {
      if (!isChoice(n)) throw new RangeError("seconds must be one of the lock choices");
      await ready;
      if (storageLocal !== null) await storageLocal.set({ [SETTING_KEY]: n });
      lockSeconds = n;
      applyIdleInterval();
      if (coreHost.state() === "unlocked") {
        const current = await readLockAt();
        const shorter = now() + n * MS_PER_SECOND;
        if (current !== null && shorter < current) {
          knownLockAt = shorter;
          queue(() => storageSession.set({ [LOCK_AT_KEY]: shorter }));
          arm(shorter);
        }
      }
    },

    /** The setting, in seconds. @returns {Promise<number>} */
    async getSeconds() {
      await ready;
      return lockSeconds;
    },
  };
}
