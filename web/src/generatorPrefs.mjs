// The generator's options on this device. One small value in the page's local storage (like the folded flag of the side menu in
// uiPrefs.mjs and the columns of the list in listPrefs.mjs): the options (length, classes, words, separator), checked key by key on
// the way in, and never a value the generator made. Storage can be blocked, so every access is in a try block; a blocked store only
// means the choice is not remembered.
import { readOptions } from "./views/generatorModel.mjs";

/** The key of the options. */
export const GENERATOR_PREFS_KEY = "ferret-generator";

/** @typedef {import("./views/generatorModel.mjs").Options} Options */

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
 * The options on this device, read and kept.
 * @param {PrefStorage | null} [storage]
 */
export function createOptionsStore(storage = pageStorage()) {
  /** @returns {Options} */
  const read = () => {
    try {
      const text = storage?.getItem(GENERATOR_PREFS_KEY);
      if (typeof text !== "string" || text.length > 1024) return readOptions(null);
      return readOptions(JSON.parse(text));
    } catch {
      return readOptions(null);
    }
  };
  return {
    read,
    /** @param {Options} options */
    save(options) {
      try {
        storage?.setItem(GENERATOR_PREFS_KEY, JSON.stringify(readOptions(options)));
      } catch {
        // Not remembered; the page still works with them.
      }
    },
  };
}
