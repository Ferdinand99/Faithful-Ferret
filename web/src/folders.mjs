// Folders are labels inside each item's encrypted body (`folders`, a list of names). There is no list of folders
// anywhere else: the folders of the vault are the names its items carry, so a folder with no item does not exist.
// This file is the plain logic the screens share, with no DOM and no storage:
//
// * the rules of a name, the same as the core's (the core has the last word and refuses a draft that breaks them with a
//   code; the screens check first so the user is told while typing): put in NFC, trimmed of white space, 1 to 64
//   characters, none of the control, line or paragraph separator, bidirectional control, zero width space or byte order
//   mark characters, at most 20 on one item, and no two the same when case is ignored;
// * when two names are the same folder: NFC, then each character in lower case on its own (the core's `same_folder`;
//   simple lower-case mapping, so "ß" and "SS" stay apart);
// * the folders of a list of items, each with the spelling most items use, and the items in it;
// * the new list of an item when a folder is renamed or deleted.

/** At most this many folders on one item (the core's MAX_FOLDERS). */
export const MAX_FOLDERS = 20;

/** At most this many characters in a name, counted as Unicode scalar values (the core's MAX_FOLDER_CHARS). */
export const MAX_FOLDER_CHARS = 64;

/**
 * The characters a name may not hold, besides the control characters (Cc): the line and paragraph separators, the
 * bidirectional controls, the zero width space and the byte order mark, as ranges of code points. ZWJ and ZWNJ (200C,
 * 200D) are allowed: scripts and emoji need them.
 */
const REFUSED_RANGES = Object.freeze([[0x2028, 0x2029], [0x061c, 0x061c], [0x200e, 0x200f], [0x202a, 0x202e], [0x2066, 0x2069], [0x200b, 0x200b], [0xfeff, 0xfeff]]);

const CONTROL = /\p{Cc}/u;

/** @param {string} text whether a character of it is one a name may not hold */
function hasRefused(text) {
  for (const c of text) {
    if (CONTROL.test(c)) return true;
    const cp = /** @type {number} */ (c.codePointAt(0));
    if (REFUSED_RANGES.some(([from, to]) => cp >= from && cp <= to)) return true;
  }
  return false;
}

/** White space at either end, as Rust's `str::trim` sees it (the White_Space property). */
const EDGE_SPACE = /^\p{White_Space}+|\p{White_Space}+$/gu;

/**
 * A name as the core stores it: NFC, then trimmed. Not checked.
 * @param {string} name
 */
export function normalizeFolder(name) {
  return String(name).normalize("NFC").replace(EDGE_SPACE, "");
}

/**
 * The key two names share when they are the same folder.
 * @param {string} name a name as the core shows it (NFC already) or as typed
 */
export function foldKey(name) {
  let out = "";
  for (const c of normalizeFolder(name)) out += c.toLowerCase();
  return out;
}

/**
 * Whether two names are the same folder.
 * @param {string} a @param {string} b
 */
export const sameFolder = (a, b) => foldKey(a) === foldKey(b);

/**
 * What is wrong with one name, as the core's code, or null when it is a good name.
 * @param {unknown} name
 * @returns {"folder_empty" | "folder_bad_character" | "folder_too_long" | null}
 */
export function checkFolderName(name) {
  if (typeof name !== "string") return "folder_empty";
  const clean = normalizeFolder(name);
  if (clean === "") return "folder_empty";
  if (hasRefused(clean)) return "folder_bad_character";
  if ([...clean].length > MAX_FOLDER_CHARS) return "folder_too_long";
  return null;
}

/**
 * What is wrong with the list of one item, as the core's code, or null.
 * @param {readonly unknown[]} names
 * @returns {string | null}
 */
export function checkFolderList(names) {
  if (names.length > MAX_FOLDERS) return "folder_too_many";
  const seen = new Set();
  for (const name of names) {
    const wrong = checkFolderName(name);
    if (wrong !== null) return wrong;
    const key = foldKey(/** @type {string} */ (name));
    if (seen.has(key)) return "folder_duplicate";
    seen.add(key);
  }
  return null;
}

/**
 * The names in the order they are shown: by the user's language, ignoring case; the same folder once.
 * @param {readonly string[]} names
 * @param {string} [locale]
 * @returns {string[]}
 */
export function sortFolders(names, locale) {
  const seen = new Set();
  /** @type {string[]} */
  const out = [];
  for (const name of names) {
    if (typeof name !== "string") continue;
    const key = foldKey(name);
    if (key === "" || seen.has(key)) continue;
    seen.add(key);
    out.push(name);
  }
  return out.sort((a, b) => a.localeCompare(b, locale, { sensitivity: "base", numeric: true }) || (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * The labels of an item for a row or a header: the first `max` in display order, and how many more there are.
 * @param {readonly string[] | undefined} names
 * @param {number} max
 * @param {string} [locale]
 */
export function folderChips(names, max, locale) {
  const sorted = sortFolders(names ?? [], locale);
  return { shown: sorted.slice(0, Math.max(0, max)), more: Math.max(0, sorted.length - Math.max(0, max)) };
}

/**
 * @typedef {object} FolderInfo one folder of the vault
 * @property {string} key the key its names share (`foldKey`)
 * @property {string} name the spelling shown: the one most of its items use (on a tie, the one met first)
 * @property {string[]} ids the items that carry it, in the order of `items`
 */

/**
 * The folders of the items, in display order.
 * @param {readonly { id: string, folders?: readonly string[] }[]} items
 * @param {string} [locale]
 * @returns {FolderInfo[]}
 */
export function folderIndex(items, locale) {
  /** @type {Map<string, { ids: string[], spellings: Map<string, number> }>} */
  const byKey = new Map();
  for (const item of items) {
    if (!Array.isArray(item?.folders)) continue;
    const own = new Set();
    for (const name of item.folders) {
      if (typeof name !== "string") continue;
      const key = foldKey(name);
      if (key === "" || own.has(key)) continue;
      own.add(key);
      let entry = byKey.get(key);
      if (!entry) {
        entry = { ids: [], spellings: new Map() };
        byKey.set(key, entry);
      }
      entry.ids.push(item.id);
      entry.spellings.set(name, (entry.spellings.get(name) ?? 0) + 1);
    }
  }
  /** @type {FolderInfo[]} */
  const out = [];
  for (const [key, entry] of byKey) {
    // The spelling most of its items use; on a tie, the one met first (the order of `items`). The sort is stable.
    const best = [...entry.spellings].sort((a, b) => b[1] - a[1])[0][0];
    out.push({ key, name: best, ids: entry.ids });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name, locale, { sensitivity: "base", numeric: true }) || (a.key < b.key ? -1 : 1));
}

/**
 * The items with each of their folder names in the spelling the vault shows for that folder, so that "Work" on one item
 * and "work" on another are one folder in a filter. Items without folders are handed on as they are.
 * @template {{ folders?: readonly string[] }} T
 * @param {readonly T[]} items
 * @param {readonly FolderInfo[]} index
 * @returns {T[]}
 */
export function withShownNames(items, index) {
  const names = new Map(index.map((folder) => [folder.key, folder.name]));
  return items.map((item) => {
    if (!Array.isArray(item.folders) || item.folders.length === 0) return item;
    const shown = [...new Set(item.folders.map((name) => names.get(foldKey(name)) ?? name))];
    return { ...item, folders: shown };
  });
}

/**
 * The list of an item after the folder `from` is renamed to `to`: `from` is replaced where it stands, and dropped when the
 * item is in `to` already. Null when the item is not in `from` (it is not written).
 * @param {readonly string[]} folders
 * @param {string} from
 * @param {string} to
 * @returns {string[] | null}
 */
export function renamedList(folders, from, to) {
  if (!folders.some((name) => sameFolder(name, from))) return null;
  const target = normalizeFolder(to);
  const hasTarget = folders.some((name) => sameFolder(name, target) && !sameFolder(name, from));
  /** @type {string[]} */
  const out = [];
  for (const name of folders) {
    if (sameFolder(name, from)) {
      if (!hasTarget && !out.some((n) => sameFolder(n, target))) out.push(target);
    } else {
      out.push(name);
    }
  }
  return out;
}

/**
 * The list of an item after the folder `name` is deleted. Null when the item is not in it (it is not written).
 * @param {readonly string[]} folders
 * @param {string} name
 * @returns {string[] | null}
 */
export function withoutFolder(folders, name) {
  if (!folders.some((n) => sameFolder(n, name))) return null;
  return folders.filter((n) => !sameFolder(n, name));
}

/**
 * Whether two lists of one item hold the same folders in the same order (a draft is only sent when they do not).
 * @param {readonly string[]} a @param {readonly string[]} b
 */
export function sameList(a, b) {
  return a.length === b.length && a.every((name, i) => name === b[i]);
}
