// What this browser remembers about how the menu looks: whether the side menu is
// folded to a rail, and which folders are pinned to it. Both are per device and
// are not secrets: only the folded flag and folder ids are kept, never a folder
// name (a name is decrypted vault data and stays in memory). The theme is kept
// the same way (theme.mjs). Storage can be blocked, so every access is in a try
// block; a blocked store only means the choice is not remembered.

export const UI_PREFS_KEY = "ferret-ui";

/** More pins than this are never kept. */
export const MAX_PINNED = 50;

/** A folder id as the menu accepts it: plain characters only. */
const FOLDER_ID = /^[A-Za-z0-9_-]{1,64}$/;

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
 * The remembered choices, with each one checked on the way in: anything that is
 * not the expected shape reads as the default.
 * @param {PrefStorage | null} storage
 * @returns {{ collapsed: boolean, pinned: string[] }}
 */
function read(storage) {
  /** @type {{ collapsed: boolean, pinned: string[] }} */
  const fallback = { collapsed: false, pinned: [] };
  try {
    const text = storage?.getItem(UI_PREFS_KEY);
    if (typeof text !== "string" || text.length > 8192) return fallback;
    const value = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value)) return fallback;
    const pinned = Array.isArray(value.pinned)
      ? [...new Set(value.pinned.filter((/** @type {unknown} */ id) => typeof id === "string" && FOLDER_ID.test(id)))].slice(0, MAX_PINNED)
      : [];
    return { collapsed: value.collapsed === true, pinned: /** @type {string[]} */ (pinned) };
  } catch {
    return fallback;
  }
}

/**
 * The menu preferences of this device. Every call reads the store again, so two
 * tabs agree on the last choice.
 * @param {PrefStorage | null} [storage]
 */
export function createUiPrefs(storage = pageStorage()) {
  /** @param {{ collapsed: boolean, pinned: string[] }} next */
  const write = (next) => {
    try {
      if (!next.collapsed && next.pinned.length === 0) storage?.removeItem(UI_PREFS_KEY);
      else storage?.setItem(UI_PREFS_KEY, JSON.stringify(next));
    } catch {
      // Not remembered; the page still changes.
    }
  };
  return {
    /** Whether the side menu is folded to the icon rail. */
    collapsed: () => read(storage).collapsed,
    /** @param {boolean} value */
    setCollapsed(value) {
      write({ ...read(storage), collapsed: value === true });
    },
    /** The ids of the pinned folders, in the order they were pinned. */
    pinned: () => read(storage).pinned,
    /** @param {string} id */
    isPinned: (id) => read(storage).pinned.includes(id),
    /** @param {string} id @returns {boolean} whether the folder is pinned now */
    pin(id) {
      if (typeof id !== "string" || !FOLDER_ID.test(id)) return false;
      const now = read(storage);
      if (now.pinned.includes(id)) return true;
      if (now.pinned.length >= MAX_PINNED) return false;
      write({ ...now, pinned: [...now.pinned, id] });
      return true;
    },
    /** @param {string} id */
    unpin(id) {
      const now = read(storage);
      write({ ...now, pinned: now.pinned.filter((one) => one !== id) });
    },
  };
}
