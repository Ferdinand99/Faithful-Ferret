// Copying a secret to the clipboard, and taking it off again after 30 seconds.
//
// One helper for every secret the web vault copies: a password, a one-time code, a card number, any other hidden field, a
// previous password, and a value from the generator. A user name or an address is not a secret and is written as it is.
//
// After CLEAR_AFTER_MS the helper clears the clipboard, but only when it still holds what it wrote:
//   - Where the browser lets the page read the clipboard (the permission is already granted: the helper never asks), it reads
//     the clipboard back and clears it only when the text is the same as the one it wrote.
//   - Elsewhere it cannot read, so it goes by its own bookkeeping: it clears the last secret it wrote, and a newer copy through
//     this helper replaces the older one (the older timer is cancelled). What the user copied from another program in
//     between cannot be seen then, and is cleared too. That is the best a page can do, and the text says "if this tab is open".
//   - A browser may refuse a write while the tab is not in focus. The clear is then tried again, once, when the tab gets focus
//     back. If that fails too, the clipboard is left as it is.
//   - A lock and a sign-out clear it at once (`clearOnLock`), and the timer is stopped.
//
// The value is kept in memory only until the clear (to compare with what is read back) and is dropped with it. Nothing is
// written to a store, an address or a log.

/** How long a copied secret stays on the clipboard. */
export const CLEAR_AFTER_MS = 30_000;

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/**
 * @typedef {{ writeText(text: string): Promise<void>, readText?: () => Promise<string> }} ClipboardLike
 * @typedef {{ value: string, timer: any, retried: boolean, offFocus: (() => void) | null }} Held
 */

/**
 * @param {{
 *   clipboard: ClipboardLike | null,
 *   doc?: { hasFocus?: () => boolean } | null,
 *   win?: { addEventListener?: Function, removeEventListener?: Function } | null,
 *   permissions?: { query(descriptor: { name: string }): Promise<{ state: string }> } | null,
 *   setTimer?: (fn: () => void, ms: number) => any,
 *   clearTimer?: (id: any) => void,
 *   ttlMs?: number,
 * }} options the browser's pieces; tests give their own
 */
export function createSecretClipboard({
  clipboard,
  doc = globalThis.document,
  win = /** @type {any} */ (globalThis).window ?? globalThis,
  permissions = globalThis.navigator?.permissions,
  setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimer = (id) => globalThis.clearTimeout(id),
  ttlMs = CLEAR_AFTER_MS,
}) {
  /** What was written and is waiting to be cleared. @type {Held | null} */
  let held = null;

  /** @param {Held} mine */
  function forget(mine) {
    if (mine.timer !== null) clearTimer(mine.timer);
    mine.timer = null;
    mine.offFocus?.();
    mine.offFocus = null;
    mine.value = "";
    if (held === mine) held = null;
  }

  /** Whether the page may read the clipboard without asking: only when the permission is granted already. */
  async function mayRead() {
    try {
      if (typeof clipboard?.readText !== "function" || typeof permissions?.query !== "function") return false;
      return (await permissions.query({ name: /** @type {any} */ ("clipboard-read") })).state === "granted";
    } catch {
      return false;
    }
  }

  /**
   * One try at clearing. Resolves true when the matter is closed (cleared, or the clipboard holds something else now) and false
   * when the browser refused.
   * @param {Held} mine
   */
  async function clearIfOurs(mine) {
    try {
      if (await mayRead()) {
        const now = await /** @type {any} */ (clipboard).readText();
        if (now !== mine.value) return true;
      }
      await /** @type {any} */ (clipboard).writeText("");
      return true;
    } catch {
      return false;
    }
  }

  /** @param {Held} mine */
  function waitForFocus(mine) {
    if (typeof win?.addEventListener !== "function") {
      forget(mine);
      return;
    }
    const onFocus = () => {
      mine.offFocus = null;
      void attempt(mine);
    };
    win.addEventListener("focus", onFocus, { once: true });
    mine.offFocus = () => win?.removeEventListener?.("focus", onFocus);
  }

  /** @param {Held} mine */
  async function attempt(mine) {
    if (held !== mine) return;
    const closed = await clearIfOurs(mine);
    if (held !== mine) return;
    if (closed || mine.retried) {
      forget(mine);
      return;
    }
    // Refused (the tab is probably not in focus): once more when it is.
    mine.retried = true;
    waitForFocus(mine);
  }

  /** @param {Held} mine */
  function expire(mine) {
    if (held !== mine) return;
    mine.timer = null;
    if (doc?.hasFocus?.() === false) {
      waitForFocus(mine);
      return;
    }
    void attempt(mine);
  }

  return {
    /**
     * Writes a secret and starts the 30 seconds. A write that is refused is `clipboard`, and the older secret keeps its timer.
     * @param {string} text
     */
    async copy(text) {
      if (typeof clipboard?.writeText !== "function") throw fail("clipboard");
      try {
        await clipboard.writeText(text);
      } catch {
        throw fail("clipboard");
      }
      if (held !== null) forget(held);
      /** @type {Held} */
      const mine = { value: text, timer: null, retried: false, offFocus: null };
      held = mine;
      mine.timer = setTimer(() => expire(mine), ttlMs);
      // A timer that only waits for the clear never keeps a process (a test run) alive.
      mine.timer?.unref?.();
    },

    /** Clears what is waiting, now, and stops the timer (a lock, a sign-out). Does not wait for the tab to have focus. */
    async clearNow() {
      const mine = held;
      if (mine === null) return;
      if (mine.timer !== null) clearTimer(mine.timer);
      mine.timer = null;
      mine.offFocus?.();
      mine.offFocus = null;
      await clearIfOurs(mine);
      forget(mine);
    },

    /** Whether a secret is waiting to be cleared. */
    pending: () => held !== null,
  };
}

/** The helper of each clipboard, so that a secret copied on one page is still cleared (or replaced) from another. @type {WeakMap<object, ReturnType<typeof createSecretClipboard>>} */
const byClipboard = new WeakMap();

/** The helper that stands for no clipboard: every copy is the `clipboard` error. */
const NONE = createSecretClipboard({ clipboard: null });

/**
 * The shared helper for a clipboard (the page's own by default).
 * @param {ClipboardLike | null | undefined} [clipboard]
 */
export function secretClipboardFor(clipboard = globalThis.navigator?.clipboard ?? null) {
  if (clipboard === null || typeof clipboard !== "object") return NONE;
  let made = byClipboard.get(clipboard);
  if (made === undefined) {
    made = createSecretClipboard({ clipboard });
    byClipboard.set(clipboard, made);
  }
  return made;
}

/** The sessions that already clear the clipboard on a lock. @type {WeakSet<object>} */
const watched = new WeakSet();

/**
 * Every lock and sign-out of the session clears a secret that is waiting on the clipboard. Asked for once per session.
 * @param {any} session @param {ClipboardLike | null} [clipboard]
 */
export function clearOnLock(session, clipboard = globalThis.navigator?.clipboard ?? null) {
  if (typeof session?.onLock !== "function" || watched.has(session)) return;
  watched.add(session);
  session.onLock(() => void secretClipboardFor(clipboard).clearNow());
}
