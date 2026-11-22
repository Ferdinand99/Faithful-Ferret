// What this browser remembers about how the menu looks.
//
// The folded flag of the side menu is kept per device in localStorage (one word, like the theme in theme.mjs).
//
// The pinned folders are never kept in clear. A folder's name is an encrypted label of the vault, so here a pin lives in
// memory only, and the page that opened the vault hands in a saver (pinStore.mjs) that seals the names under the vault
// key and keeps that sealed record; after an unlock the names come back from it (`restorePins`). A lock forgets the
// pins and the saver (the frame and the session's lock both call `clearPins`).
//
// Storage can be blocked, so every access is in a try block; a blocked store only means the choice is not remembered.
import { checkFolderName, normalizeFolder, sameFolder, MAX_FOLDERS } from "./folders.mjs";

export const UI_PREFS_KEY = "ferret-ui";

/** More pins than this are never held (the sealed record holds them as the folders of one body). */
export const MAX_PINNED = MAX_FOLDERS;

/** The pins of this page, by folder name: in memory, shared by the frames of the page, never written anywhere in clear. @type {string[]} */
const sessionPins = [];

/**
 * Where a change of the pins is kept (sealed), while the vault is open: shared by the frames of the page.
 * @type {{ save: ((names: readonly string[]) => Promise<void>) | null }}
 */
const sessionSaver = { save: null };

/**
 * The last save of each saver: a change waits for the one before it, so two quick changes are kept in the order they
 * were made (the record never ends up holding the older list). @type {WeakMap<object, Promise<void>>}
 */
const lastSave = new WeakMap();

/** Who is told that the pins changed (the side menu of the frame on the page). @type {Set<() => void>} */
const pinWatchers = new Set();

/**
 * Tells `fn` each time the pins change (a pin, an unpin, a rename, an unlock or a lock), on any frame of the page.
 * @param {() => void} fn
 * @returns {() => void} stops telling it
 */
export function watchPins(fn) {
  pinWatchers.add(fn);
  return () => void pinWatchers.delete(fn);
}

function pinsChanged() {
  for (const fn of [...pinWatchers]) {
    try {
      fn();
    } catch {
      // One watcher that fails does not stop the others.
    }
  }
}

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
 * @param {{ save: ((names: readonly string[]) => Promise<void>) | null }} [saver] where a change of the pins is kept (the page's unless a test gives its own)
 */
export function createUiPrefs(storage = pageStorage(), pins = sessionPins, saver = sessionSaver) {
  /** Keeps the pins as they are now; a failure only means they are not remembered after the next lock. */
  const persist = () => {
    pinsChanged();
    const save = saver.save;
    if (save === null) return;
    // The list as it is now: a later change (or a lock) does not change what this write keeps.
    const list = [...pins];
    // After the save before it, whatever became of that one.
    const next = (lastSave.get(saver) ?? Promise.resolve())
      .then(() => save(list))
      .catch(() => undefined);
    lastSave.set(saver, next);
  };
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
    isPinned: (name) => pins.some((pin) => sameFolder(pin, name)),
    /** @param {string} name @returns {boolean} whether the folder is pinned now */
    pin(name) {
      if (checkFolderName(name) !== null) return false;
      if (pins.some((pin) => sameFolder(pin, name))) return true;
      if (pins.length >= MAX_PINNED) return false;
      pins.push(normalizeFolder(name));
      persist();
      return true;
    },
    /** @param {string} name */
    unpin(name) {
      const before = pins.length;
      for (let i = pins.length - 1; i >= 0; i -= 1) if (sameFolder(pins[i], name)) pins.splice(i, 1);
      if (pins.length !== before) persist();
    },
    /** A pinned folder was renamed: the pin follows it. @param {string} from @param {string} to */
    renamePin(from, to) {
      const at = pins.findIndex((pin) => sameFolder(pin, from));
      if (at < 0 || checkFolderName(to) !== null) return;
      const next = normalizeFolder(to);
      if (pins.some((pin, i) => i !== at && sameFolder(pin, next))) pins.splice(at, 1);
      else pins[at] = next;
      persist();
    },
    /**
     * The vault was unlocked: the pins kept for it come back, and later changes are kept through `save`.
     * @param {readonly string[]} names @param {((names: readonly string[]) => Promise<void>) | null} save
     */
    restorePins(names, save) {
      pins.length = 0;
      for (const name of names) {
        if (pins.length >= MAX_PINNED) break;
        if (checkFolderName(name) === null && !pins.some((pin) => sameFolder(pin, name))) pins.push(normalizeFolder(name));
      }
      saver.save = save;
      pinsChanged();
    },
    /** Forgets every pin and the way to keep them (the vault locked). */
    clearPins() {
      const had = pins.length > 0;
      pins.length = 0;
      saver.save = null;
      if (had) pinsChanged();
    },
  };
}
