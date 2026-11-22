// What this browser remembers about how the menu looks.
//
// The folded flag of the side menu is kept per device in localStorage (one word, like the theme in theme.mjs).
//
// The pinned folders are NOT kept at rest. A folder's name is an encrypted label of the vault, and it must never sit
// in clear on the device, so a pin lives in memory only: it is gone when the page is closed and when the vault locks
// (the frame clears it). The pins are empty until the vault has folders; a later task persists them encrypted.
//
// Storage can be blocked, so every access is in a try block; a blocked store only means the choice is not remembered.

export const UI_PREFS_KEY = "ferret-ui";

/** More pins than this are never held. */
export const MAX_PINNED = 50;

/** A folder name as the menu accepts it: one line of at most 128 characters. */
const FOLDER_NAME = /^[^\u0000-\u001f\u007f]{1,128}$/u;

/** The pins of this page, by folder name: in memory, shared by the frames of the page, never written anywhere. @type {string[]} */
const sessionPins = [];

/** @typedef {{ getItem(key: string): string | null, setItem(key: string, value: string): void, removeItem(key: string): void }} PrefStorage */

/** The page's storage, or null when the browser blocks it. @returns {PrefStorage | null} */
function pageStorage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/**
 * The folded flag, checked on the way in: anything that is not the expected shape reads as the default.
 * @param {PrefStorage | null} storage
 * @returns {boolean}
 */
function readCollapsed(storage) {
  try {
    const text = storage?.getItem(UI_PREFS_KEY);
    if (typeof text !== "string" || text.length > 8192) return false;
    const value = JSON.parse(text);
    return value !== null && typeof value === "object" && !Array.isArray(value) && value.collapsed === true;
  } catch {
    return false;
  }
}

/**
 * The menu preferences of this device. The folded flag is read again on every call, so two tabs agree on the last
 * choice; the pins are the memory of the page.
 * @param {PrefStorage | null} [storage]
 * @param {string[]} [pins] where the pins are held (the page's memory unless a test gives its own)
 */
export function createUiPrefs(storage = pageStorage(), pins = sessionPins) {
  // A value written by an older build may hold folder names: it is rewritten with the flag alone.
  try {
    const text = storage?.getItem(UI_PREFS_KEY);
    if (typeof text === "string" && text.includes("pinned")) {
      if (readCollapsed(storage)) storage?.setItem(UI_PREFS_KEY, JSON.stringify({ collapsed: true }));
      else storage?.removeItem(UI_PREFS_KEY);
    }
  } catch {
    // Left as it is.
  }
  return {
    /** Whether the side menu is folded to the icon rail. */
    collapsed: () => readCollapsed(storage),
    /** @param {boolean} value */
    setCollapsed(value) {
      try {
        if (value === true) storage?.setItem(UI_PREFS_KEY, JSON.stringify({ collapsed: true }));
        else storage?.removeItem(UI_PREFS_KEY);
      } catch {
        // Not remembered; the page still changes.
      }
    },
    /** The names of the pinned folders, in the order they were pinned. */
    pinned: () => [...pins],
    /** @param {string} name */
    isPinned: (name) => pins.includes(name),
    /** @param {string} name @returns {boolean} whether the folder is pinned now */
    pin(name) {
      if (typeof name !== "string" || !FOLDER_NAME.test(name)) return false;
      if (pins.includes(name)) return true;
      if (pins.length >= MAX_PINNED) return false;
      pins.push(name);
      return true;
    },
    /** @param {string} name */
    unpin(name) {
      const at = pins.indexOf(name);
      if (at >= 0) pins.splice(at, 1);
    },
    /** Forgets every pin (the vault locked). */
    clearPins() {
      pins.length = 0;
    },
  };
}
