// Locking the vault: an idle timer that cannot be trusted alone, and the one
// way to lock.
//
// Browsers slow timers down in a background tab and stop them while a laptop
// sleeps, so the time the vault must lock at (`lockAt`) is kept in memory as an
// absolute time and compared with the clock on every user action and every time
// the tab becomes visible again. The timer only makes the lock happen on time
// in the common case; the comparison is what makes it certain (Spec: Fase 1
// section 7.1, the same rule as the extension's `lockAt`).
//
// Locking ends the vault worker through the session (that is what wipes the
// keys and every open item) and stops the sync engine, which drops the decrypted
// item index. Nothing here keeps a secret.

/** Fifteen minutes without activity (Spec: Fase 1 section 7.1, default). */
export const DEFAULT_IDLE_MS = 15 * 60_000;

/** @param {unknown} ms */
function checkIdle(ms) {
  if (typeof ms !== "number" || !Number.isSafeInteger(ms) || ms <= 0) {
    throw new TypeError("lock: the idle time is a positive whole number of milliseconds");
  }
  return ms;
}

/**
 * The idle lock.
 *
 * `touch()` is called before every user action. It returns `true` when the
 * vault is still open and the idle time has been moved on, and `false` when the
 * lock time had already passed or the vault is already locked: the action must
 * not go on.
 *
 * @param {{
 *   session: { lock(): Promise<unknown> },
 *   now?: () => number,
 *   timers?: { setTimeout(fn: () => void, ms: number): unknown, clearTimeout(handle: unknown): void },
 *   idleMs?: number,
 *   onLock?: () => void,
 *   doc?: { visibilityState?: string, addEventListener?: Function, removeEventListener?: Function } | null,
 * }} options
 * @returns {{
 *   touch(): boolean, start(): void, stop(): void, setIdle(ms: number): void,
 *   lock(): Promise<void>, running(): boolean, lockAt(): number | null,
 * }}
 */
export function createAutoLock({
  session,
  now = Date.now,
  timers = globalThis,
  idleMs = DEFAULT_IDLE_MS,
  onLock,
  doc = globalThis.document ?? null,
}) {
  let idle = checkIdle(idleMs);
  /** @type {number | null} */
  let lockAt = null;
  /** @type {unknown} */
  let handle = null;
  /** @type {Promise<void> | null} */
  let locking = null;
  let locked = false;

  function disarm() {
    if (handle !== null) timers.clearTimeout(handle);
    handle = null;
  }

  function arm() {
    disarm();
    if (lockAt === null) return;
    handle = timers.setTimeout(onTimer, Math.max(0, lockAt - now()));
  }

  function onTimer() {
    handle = null;
    if (lockAt === null) return;
    // Activity moves `lockAt` later without a new timer; wait again if so.
    if (now() >= lockAt) void lock();
    else arm();
  }

  function onVisibility() {
    if (lockAt !== null && now() >= lockAt) void lock();
  }

  function stop() {
    disarm();
    lockAt = null;
    doc?.removeEventListener?.("visibilitychange", onVisibility);
  }

  /** Ends the worker. Safe to call twice; the second call waits for the first. */
  function lock() {
    stop();
    locked = true;
    locking ??= (async () => {
      try {
        await session.lock();
      } catch {
        // The worker is gone or cannot be reached either way; the screen is wiped below.
      } finally {
        locking = null;
        try {
          onLock?.();
        } catch {
          // A listener must not keep the vault open.
        }
      }
    })();
    return locking;
  }

  return {
    touch() {
      if (locked) return false;
      if (lockAt === null) return true;
      if (now() >= lockAt) {
        void lock();
        return false;
      }
      lockAt = now() + idle;
      return true;
    },
    start() {
      stop();
      locked = false;
      lockAt = now() + idle;
      doc?.addEventListener?.("visibilitychange", onVisibility);
      arm();
    },
    stop,
    setIdle(ms) {
      idle = checkIdle(ms);
      if (lockAt !== null) {
        lockAt = now() + idle;
        arm();
      }
    },
    lock,
    running: () => lockAt !== null,
    lockAt: () => lockAt,
  };
}

/**
 * The one way to lock: the sync engine stops first (it closes its open items
 * and drops the decrypted index), then the session ends the worker. Either
 * step alone would leave something behind; both are safe to repeat.
 * @param {{ session: { lock(): Promise<unknown> }, sync?: { stop(): void } | null }} options
 */
export async function lockVault({ session, sync }) {
  try {
    sync?.stop();
  } catch {
    // The engine is already gone; the worker still has to end.
  }
  await session.lock();
}

/** @type {WeakMap<object, ReturnType<typeof createAutoLock>>} */
const byLocker = new WeakMap();

/**
 * The idle lock of a session, made on first use. One page has one session, so
 * every screen shares one timer.
 * @param {{ lock(): Promise<unknown>, onLock?(fn: () => void): () => void }} session
 * @param {{ stop(): void } | null | undefined} sync
 * @param {Partial<Parameters<typeof createAutoLock>[0]>} [options]
 */
export function autoLockFor(session, sync, options = {}) {
  let lock = byLocker.get(session);
  if (!lock) {
    lock = createAutoLock({ ...options, session: { lock: () => lockVault({ session, sync }) } });
    const made = lock;
    // A lock by any other path (a sign-out, a worker that died) stops the timer too.
    session.onLock?.(() => made.stop());
    byLocker.set(session, lock);
  }
  return lock;
}
