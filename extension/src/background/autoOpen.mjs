// The popup that opens by itself when an offer to save a password is ready (design document, section 10.9), in a build
// with saving from the extension on.
//
// It is a setting (on by default, kept in `storage.local`) and it is only ever an attempt: a browser may refuse to open
// the popup without a user gesture, and then the badge on the toolbar button (badge.mjs) is all there is. The attempt is
// made only when all of this is true:
//
//   - the setting is on;
//   - the vault is open (a popup that opens by itself to ask for the master password would be a prompt nobody asked for);
//   - the browser has not refused an earlier attempt in this run of the background page (the first refusal is the
//     probe: from then on the badge alone is used, and the settings page says so);
//   - the tab of the offer is the active tab of its window, and that window has the focus.
//
// Opening is not saving: the popup it opens shows the offer with no default button, no initial focus on a button that
// writes, nothing that Enter can answer and clicks that are ignored for the first 400 milliseconds (offerCards.mjs), so
// an offer that appears under the user's hand cannot be accepted by a keystroke or a click that was meant for the page.

/** The key of the setting in `storage.local`; a stored value that is not `false` means on. */
export const AUTO_OPEN_KEY = "auto_open_popup";

/**
 * @typedef {"unknown" | "works" | "fails"} Probe what the browser has shown about opening the popup without a gesture
 * @typedef {"off" | "locked" | "unsupported" | "no_tab" | "not_active" | "not_focused" | "opened" | "refused"} Outcome
 */

/**
 * @param {{
 *   storageLocal: { get(key: string): Promise<Record<string, unknown>>, set(items: Record<string, unknown>): Promise<unknown> },
 *   action: { openPopup(): Promise<unknown> | unknown },
 *   tabs: { get(tabId: number): Promise<{ active?: boolean, windowId?: number } | undefined> },
 *   windows: { get(windowId: number): Promise<{ focused?: boolean } | undefined> },
 *   unlocked: () => boolean,
 * }} deps
 */
export function createAutoOpen({ storageLocal, action, tabs, windows, unlocked }) {
  /** @type {Probe} */
  let probe = "unknown";
  let attempting = false;

  /** @returns {Promise<boolean>} */
  async function isOn() {
    try {
      return (await storageLocal.get(AUTO_OPEN_KEY))?.[AUTO_OPEN_KEY] !== false;
    } catch {
      return true;
    }
  }

  return {
    isOn,

    /** Turns the setting on or off. @param {boolean} on */
    async setOn(on) {
      await storageLocal.set({ [AUTO_OPEN_KEY]: on === true });
    },

    /** What the browser has shown so far about opening the popup without a gesture. @returns {Probe} */
    probe: () => probe,

    /**
     * An offer is ready for the tab: open the popup if every condition holds.
     * @param {number} tabId
     * @returns {Promise<Outcome>}
     */
    async maybeOpen(tabId) {
      if (attempting) return "refused";
      attempting = true;
      try {
        if (!(await isOn())) return "off";
        if (!unlocked()) return "locked";
        if (probe === "fails") return "unsupported";
        /** @type {{ active?: boolean, windowId?: number } | undefined} */
        let tab;
        try {
          tab = await tabs.get(tabId);
        } catch {
          return "no_tab";
        }
        if (tab === undefined || typeof tab.windowId !== "number") return "no_tab";
        if (tab.active !== true) return "not_active";
        /** @type {{ focused?: boolean } | undefined} */
        let win;
        try {
          win = await windows.get(tab.windowId);
        } catch {
          return "no_tab";
        }
        if (win?.focused !== true) return "not_focused";
        // The setting or the lock may have changed while the tab and the window were looked at.
        if (!(await isOn()) || !unlocked()) return "off";
        try {
          await action.openPopup();
          probe = "works";
          return "opened";
        } catch {
          probe = "fails";
          return "refused";
        }
      } finally {
        attempting = false;
      }
    },
  };
}
