// Which columns of the item list this device shows. One small value in localStorage (like the folded flag of the side
// menu in uiPrefs.mjs): the names of the columns that are switched off, from a fixed list. It holds nothing of the
// vault, no item name and no folder name. Storage can be blocked, so every access is in a try block; a blocked store
// only means the choice is not remembered.

export const LIST_PREFS_KEY = "ferret-list";

/** The columns that can be switched off. The name and the options of a row are always there. */
export const COLUMNS = Object.freeze(["folders", "changed"]);

/** @typedef {{ getItem(key: string): string | null, setItem(key: string, value: string): void, removeItem(key: string): void }} PrefStorage */

/** @returns {PrefStorage | null} */
function pageStorage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/**
 * @param {PrefStorage | null} storage
 * @returns {string[]} the columns switched off, checked on the way in: anything unexpected reads as none
 */
function readHidden(storage) {
  try {
    const text = storage?.getItem(LIST_PREFS_KEY);
    if (typeof text !== "string" || text.length > 1024) return [];
    const value = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value) || !Array.isArray(value.hidden)) return [];
    return COLUMNS.filter((column) => value.hidden.includes(column));
  } catch {
    return [];
  }
}

/** @param {PrefStorage | null} [storage] */
export function createListPrefs(storage = pageStorage()) {
  // What was chosen on this page: read once and kept, so the page follows the choice even when the store is blocked.
  let hidden = readHidden(storage);
  return {
    /** Whether a column is shown. @param {string} column */
    shows: (column) => !hidden.includes(column),
    /** @param {string} column @param {boolean} shown */
    setShown(column, shown) {
      if (!COLUMNS.includes(column)) return;
      hidden = hidden.filter((name) => name !== column);
      if (!shown) hidden.push(column);
      try {
        if (hidden.length === 0) storage?.removeItem(LIST_PREFS_KEY);
        else storage?.setItem(LIST_PREFS_KEY, JSON.stringify({ hidden }));
      } catch {
        // Not remembered; the page still changes.
      }
    },
  };
}
