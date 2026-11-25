// The toolbar button's badge (design document, section 10.9), in a build with saving from the extension on.
//
// Three things show on the badge of one tab and on no other:
//
//   - the number of offers to save or update a password that are ready for the tab (the store of offers calls
//     `set(tabId, count)` whenever a tab's count may have changed);
//   - "!" for thirty seconds after a shortcut or a context menu click was refused (the fill did not go through and
//     there was no popup to say why); the popup then shows the reason;
//   - with Ferret as a passkey provider (the `passkeys` feature), PASSKEY_MARK while a passkey request of the tab waits
//     for the user outside Ferret's window (a conditional request, or a modal one without a window: the popup shows it);
//     the request broker calls `passkey(tabId, on)`. A refusal shows over it, and it shows over a count.
//
// All are per tab (the text is set with the tab's id, never for the whole button), both are plain numbers and a
// reason code from a fixed list: the badge never holds a host, a user name or a password. A refusal ends by the
// clock, checked on every access (a timer is only a convenience: it does not run while a machine sleeps). The browser
// resets a tab's badge when the tab goes to a new page, so the module can paint a tab again (`reapply`).
//
// `onAppear(tabId)` is called when the count of a tab goes up: the capture host uses it to open the popup
// by itself where that is allowed (autoOpen.mjs).

/** How long the "!" of a refusal stays. */
export const REFUSAL_MS = 30_000;

/** The reasons a refusal can have; anything else is stored as `not_filled`. They are the fill's own reasons. */
export const REFUSAL_REASONS = Object.freeze([
  "not_offered",
  "origin_changed",
  "busy",
  "frame_gone",
  "no_report",
  "no_fields",
  "no_value",
  "no_answer",
  "value_too_long",
  "wrong_kind",
  "covered",
  "frame_hidden",
  "frame_unchecked",
  "not_filled",
]);

/** The text of the passkey mark. */
export const PASSKEY_MARK = "•";

/** The longest count that is written out; more shows as this and a plus. */
const MAX_SHOWN = 9;

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * @typedef {{
 *   setBadgeText(details: { text: string, tabId?: number }): unknown,
 *   setBadgeBackgroundColor(details: { color: string, tabId?: number }): unknown,
 * }} ActionApi
 * @typedef {{ setTimeout(fn: () => void, ms: number): unknown, clearTimeout(id: any): void }} Timers
 */

/**
 * @param {{
 *   action: ActionApi,
 *   now: () => number,
 *   onAppear?: ((tabId: number) => void) | null,
 *   timers?: Timers,
 * }} deps
 */
export function createBadge({
  action,
  now,
  onAppear = null,
  timers = { setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms), clearTimeout: (id) => globalThis.clearTimeout(id) },
}) {
  /** The count of ready offers of each tab. @type {Map<number, number>} */
  const counts = new Map();
  /** The refusal of each tab: its reason and the moment it ends. @type {Map<number, { reason: string, until: number }>} */
  const refusals = new Map();
  /** The timer that ends a tab's refusal. @type {Map<number, unknown>} */
  const timersByTab = new Map();
  /** The tabs with a passkey request that waits for the user outside Ferret's window. @type {Set<number>} */
  const passkeys = new Set();
  /** What was painted last, so an unchanged tab is not painted again. @type {Map<number, string>} */
  const painted = new Map();

  /** The refusal a tab has now, by the clock: one that ended is removed here. @param {number} tabId */
  function activeRefusal(tabId) {
    const refusal = refusals.get(tabId);
    if (refusal === undefined) return null;
    const at = now();
    // A clock that went backwards must not keep a refusal for longer than it was meant to stay.
    if (at >= refusal.until || refusal.until - at > REFUSAL_MS) {
      refusals.delete(tabId);
      return null;
    }
    return refusal;
  }

  /** The text of a tab's badge. @param {number} tabId */
  function textOf(tabId) {
    if (activeRefusal(tabId) !== null) return "!";
    if (passkeys.has(tabId)) return PASSKEY_MARK;
    const count = counts.get(tabId) ?? 0;
    if (count <= 0) return "";
    return count > MAX_SHOWN ? `${MAX_SHOWN}+` : String(count);
  }

  /** @param {number} tabId @param {boolean} force paint although nothing changed (the browser reset the tab's badge) */
  function paint(tabId, force = false) {
    const text = textOf(tabId);
    if (!force && (painted.get(tabId) ?? "") === text) return;
    if (text === "") painted.delete(tabId);
    else painted.set(tabId, text);
    try {
      const done = /** @type {any} */ (action.setBadgeText({ text, tabId }));
      done?.catch?.(() => {});
      if (text !== "") {
        // The refusal is a warning; an offer is the button's own colour.
        const color = text === "!" ? "#c20012" : "#6656e8";
        const colored = /** @type {any} */ (action.setBadgeBackgroundColor({ color, tabId }));
        colored?.catch?.(() => {});
      }
    } catch {
      // A tab that is gone has no badge to set.
    }
  }

  /** @param {number} tabId */
  function forgetTimer(tabId) {
    const timer = timersByTab.get(tabId);
    if (timer === undefined) return;
    try {
      timers.clearTimeout(timer);
    } catch {
      // Nothing to clear.
    }
    timersByTab.delete(tabId);
  }

  return {
    /**
     * The number of offers that are ready for a tab. Called by the store of offers; 0 takes the number away.
     * @param {number} tabId @param {number} count
     */
    set(tabId, count) {
      if (!isIndex(tabId) || !isIndex(count)) return;
      const before = counts.get(tabId) ?? 0;
      if (count === 0) counts.delete(tabId);
      else counts.set(tabId, count);
      paint(tabId);
      if (count > before) {
        try {
          onAppear?.(tabId);
        } catch {
          // The popup may not open by itself; the badge is there.
        }
      }
    },

    /**
     * Whether a passkey request of a tab waits for the user outside Ferret's window (the request broker says so).
     * @param {number} tabId @param {boolean} on
     */
    passkey(tabId, on) {
      if (!isIndex(tabId)) return;
      if (on === true) passkeys.add(tabId);
      else passkeys.delete(tabId);
      paint(tabId);
    },

    /**
     * A shortcut or a menu click was refused: "!" for thirty seconds, and the reason for the popup to show.
     * @param {number} tabId @param {unknown} reason
     */
    refuse(tabId, reason) {
      if (!isIndex(tabId)) return;
      const code = typeof reason === "string" && REFUSAL_REASONS.includes(reason) ? reason : "not_filled";
      forgetTimer(tabId);
      refusals.set(tabId, { reason: code, until: now() + REFUSAL_MS });
      paint(tabId);
      try {
        const timer = timers.setTimeout(() => {
          timersByTab.delete(tabId);
          activeRefusal(tabId);
          paint(tabId);
        }, REFUSAL_MS);
        // A node test run must not wait for it; a browser's handle is a number.
        /** @type {any} */ (timer)?.unref?.();
        timersByTab.set(tabId, timer);
      } catch {
        // No timer: every access still reads the clock.
      }
    },

    /**
     * The reason of the refusal a tab shows now, or null.
     * @param {number} tabId
     * @returns {string | null}
     */
    refusalFor(tabId) {
      const refusal = isIndex(tabId) ? activeRefusal(tabId) : null;
      // A refusal that ended by the clock: its mark goes.
      if (refusal === null && isIndex(tabId) && painted.get(tabId) === "!") paint(tabId);
      return refusal?.reason ?? null;
    },

    /** The popup has shown the reason: the "!" goes. @param {number} tabId */
    acknowledge(tabId) {
      if (!isIndex(tabId)) return;
      forgetTimer(tabId);
      refusals.delete(tabId);
      paint(tabId);
    },

    /** The tab went to a new page (the browser reset its badge) or was reloaded: paint what it should show. @param {number} tabId */
    reapply(tabId) {
      if (!isIndex(tabId)) return;
      if (painted.has(tabId) || textOf(tabId) !== "") paint(tabId, true);
    },

    /** The tab was closed. @param {number} tabId */
    forget(tabId) {
      forgetTimer(tabId);
      counts.delete(tabId);
      refusals.delete(tabId);
      passkeys.delete(tabId);
      painted.delete(tabId);
    },

    /** A lock cleared everything: no number and no refusal stay on any tab. */
    clearAll() {
      const tabs = new Set([...counts.keys(), ...refusals.keys(), ...painted.keys()]);
      for (const tabId of tabs) {
        forgetTimer(tabId);
        counts.delete(tabId);
        refusals.delete(tabId);
        paint(tabId);
      }
    },
  };
}
