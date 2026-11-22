// What the item list decides, as plain data: which items match, in which order, what the filters say in the address,
// what a window of a long list holds, and how a moment reads. No DOM, no secrets, no request. list.mjs draws it.

/** Plain ASCII, which most text is, folds without the slower compatibility step. */
const ASCII = /^[\x00-\x7f]*$/;

/** @param {string} text */
const fold = (text) => {
  const value = String(text);
  return ASCII.test(value) ? value.toLowerCase() : value.normalize("NFKC").toLocaleLowerCase();
};

/**
 * Whether an item matches a query typed by the user: every word of the query
 * must be in the name, in one of the addresses or in the user name. Case is
 * ignored.
 * @param {{ name: string, urls: readonly string[], username?: string }} item
 * @param {string} query
 */
export function matches(item, query) {
  const words = fold(query).split(/\s+/).filter((w) => w !== "");
  if (words.length === 0) return true;
  const haystack = [item.name, item.username ?? "", ...item.urls].map(fold).join("\n");
  return words.every((word) => haystack.includes(word));
}

/**
 * A search over a long list that does not fold every item on every key: the folded text of an item is kept until its name,
 * user name or addresses change.
 */
export function createMatcher() {
  /** @type {Map<string, { name: string, username: string, urls: readonly string[], hay: string }>} */
  const cache = new Map();
  /** @param {{ id: string, name: string, urls: readonly string[], username?: string }} item */
  function haystack(item) {
    const username = item.username ?? "";
    const seen = cache.get(item.id);
    if (seen && seen.name === item.name && seen.username === username && sameList(seen.urls, item.urls)) return seen.hay;
    const hay = [item.name, username, ...item.urls].map(fold).join("\n");
    cache.set(item.id, { name: item.name, username, urls: [...item.urls], hay });
    return hay;
  }
  return {
    /**
     * @template {{ id: string, name: string, urls: readonly string[], username?: string }} T
     * @param {readonly T[]} items @param {string} query @returns {T[]}
     */
    filter(items, query) {
      const words = fold(query).split(/\s+/).filter((w) => w !== "");
      if (words.length === 0) return /** @type {T[]} */ (items);
      return items.filter((item) => {
        const hay = haystack(item);
        return words.every((word) => hay.includes(word));
      });
    },
    /**
     * Folds the text of some items before a search asks for them (a long list, after it was drawn), so the first key is not the slow one.
     * @param {readonly { id: string, name: string, urls: readonly string[], username?: string }[]} items @param {number} from @param {number} to
     */
    warm(items, from, to) {
      for (let i = from; i < Math.min(to, items.length); i += 1) haystack(items[i]);
    },
    /** How many items have their folded text kept. */
    size: () => cache.size,
    /** Forgets everything that was folded (the vault locked). */
    clear() {
      cache.clear();
    },
    /** Lets go of what was kept for items that are no longer in the list. @param {readonly { id: string }[]} items */
    prune(items) {
      if (cache.size <= items.length + 64) return;
      const live = new Set(items.map((item) => item.id));
      for (const id of cache.keys()) if (!live.has(id)) cache.delete(id);
    },
  };
}

/** @param {readonly string[]} a @param {readonly string[]} b */
function sameList(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

// ---------------------------------------------------------------- filters

/** The item types the vault knows, in the order the filter lists them. */
export const TYPE_ORDER = Object.freeze(["login", "note", "card", "identity"]);

/** The columns the list can be ordered by. */
export const SORT_KEYS = Object.freeze(["name", "changed"]);

/** At most this many values of one filter are read from the address. */
const MAX_VALUES = 8;

const TYPE_VALUE = /^[a-z][a-z0-9_-]{0,23}$/;

/**
 * @typedef {object} ListState what the user chose
 * @property {string[]} types item types to show (none: every type)
 * @property {boolean} favorite only the favourites
 * @property {string[]} folders folder names to show (none: every item); the list has them only when the vault has folders
 * @property {"name" | "changed"} sort
 * @property {"asc" | "desc"} dir
 */

/** The first direction of a column: names from A, changes from the newest. @param {string} sort @returns {"asc" | "desc"} */
export const defaultDir = (sort) => (sort === "changed" ? "desc" : "asc");

/** @returns {ListState} */
export const defaultState = () => ({ types: [], favorite: false, folders: [], sort: "name", dir: "asc" });

/** @param {ListState} state Whether any filter (not the order) is on. */
export const hasFilters = (state) => state.types.length > 0 || state.favorite || state.folders.length > 0;

/**
 * Reads the filters out of the query of the address. Whatever is not in the expected shape is left out, so a made-up
 * address gives the default list. The search text is never in the address, and neither is a folder name (the names are
 * labels inside the encrypted items, and the address stays in the history of the browser): the folder filter lives in the
 * memory of the list alone, so it is always empty here.
 * @param {string} query the part after `?`
 * @returns {ListState}
 */
export function parseListQuery(query) {
  const state = defaultState();
  /** @type {Map<string, string>} */
  const pairs = new Map();
  for (const part of String(query ?? "").split("&")) {
    const cut = part.indexOf("=");
    if (cut <= 0) continue;
    const key = part.slice(0, cut);
    if (!pairs.has(key)) pairs.set(key, part.slice(cut + 1));
  }
  const types = (pairs.get("type") ?? "").split(",").filter((v) => TYPE_VALUE.test(v));
  state.types = [...new Set(types)].slice(0, MAX_VALUES);
  state.favorite = pairs.get("fav") === "1";
  const sort = pairs.get("sort");
  if (sort === "changed") state.sort = "changed";
  const dir = pairs.get("dir");
  state.dir = dir === "asc" || dir === "desc" ? dir : defaultDir(state.sort);
  return state;
}

/**
 * The query of the address for a state: only what is not the default, in one fixed order, so that a state has one
 * spelling and `parseListQuery(formatListQuery(s))` gives `s` back.
 * @param {ListState} state
 * @returns {string}
 */
export function formatListQuery(state) {
  /** @type {string[]} */
  const out = [];
  const types = [...new Set(state.types.filter((v) => TYPE_VALUE.test(v)))].slice(0, MAX_VALUES);
  if (types.length > 0) out.push(`type=${[...types].sort().join(",")}`);
  if (state.favorite) out.push("fav=1");
  if (state.sort !== "name") out.push(`sort=${state.sort}`);
  if (state.dir !== defaultDir(state.sort)) out.push(`dir=${state.dir}`);
  return out.join("&");
}

/** Two states with the same meaning. @param {ListState} a @param {ListState} b */
export function sameState(a, b) {
  return JSON.stringify(normalState(a)) === JSON.stringify(normalState(b));
}

/**
 * The same state, in a normal form: filters sorted, duplicates gone. What `parseListQuery` reads from `formatListQuery`.
 * @param {ListState} state
 * @returns {ListState}
 */
export function normalState(state) {
  return {
    types: [...new Set(state.types)].sort(), favorite: state.favorite === true, folders: [...new Set(state.folders)].sort(),
    sort: state.sort === "changed" ? "changed" : "name", dir: state.dir === "desc" ? "desc" : "asc",
  };
}

/**
 * The item types to offer, in the order of the filter: the known ones first, then any other the vault holds.
 * @param {readonly { type: string }[]} items
 * @param {readonly string[]} [selected] types chosen but with no item (kept so that the chip can still be taken off)
 * @returns {string[]}
 */
export function typesPresent(items, selected = []) {
  const seen = new Set([...items.map((item) => item.type), ...selected].filter((type) => typeof type === "string" && type !== ""));
  const known = TYPE_ORDER.filter((type) => seen.has(type));
  const other = [...seen].filter((type) => !TYPE_ORDER.includes(type)).sort();
  return [...known, ...other];
}

/**
 * How many items each type has among `items`.
 * @param {readonly { type: string }[]} items
 * @returns {Map<string, number>}
 */
export function countByType(items) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const item of items) counts.set(item.type, (counts.get(item.type) ?? 0) + 1);
  return counts;
}

/**
 * How many items each folder name has among `items` (an item can have several).
 * @param {readonly { folders?: readonly string[] }[]} items
 * @returns {Map<string, number>}
 */
export function countByFolder(items) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const item of items) for (const name of item.folders ?? []) counts.set(name, (counts.get(name) ?? 0) + 1);
  return counts;
}

/**
 * Applies the type, favourite and folder filters; the order of `items` is kept. `skip` leaves one filter out, so a
 * dropdown can show how many items each of its values would give.
 * @template {{ type: string, favorite?: boolean, folders?: readonly string[] }} T
 * @param {readonly T[]} items
 * @param {ListState} state
 * @param {"types" | "folders" | null} [skip]
 * @returns {T[]}
 */
export function applyFilters(items, state, skip = null) {
  const types = skip === "types" ? [] : state.types;
  const folders = skip === "folders" ? [] : state.folders;
  if (types.length === 0 && !state.favorite && folders.length === 0) return [...items];
  return items.filter((item) => {
    if (types.length > 0 && !types.includes(item.type)) return false;
    if (state.favorite && item.favorite !== true) return false;
    // An item shows when it has any of the folders chosen.
    if (folders.length > 0 && !(item.folders ?? []).some((name) => folders.includes(name))) return false;
    return true;
  });
}

// ------------------------------------------------------------------ order

const collator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });

/**
 * A copy in the order of a column. Names are compared without case and accents, numbers inside them by value; a tie
 * goes by the other column and then by id, so that the order never wobbles between two renderings.
 * @template {{ id: string, name: string, modified?: number }} T
 * @param {readonly T[]} items
 * @param {"name" | "changed"} sort
 * @param {"asc" | "desc"} dir
 * @returns {T[]}
 */
export function sortItems(items, sort, dir) {
  const sign = dir === "desc" ? -1 : 1;
  const byName = (/** @type {T} */ a, /** @type {T} */ b) => collator.compare(a.name, b.name) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const out = [...items];
  if (sort === "changed") out.sort((a, b) => sign * ((a.modified ?? 0) - (b.modified ?? 0)) || byName(a, b));
  else out.sort((a, b) => sign * byName(a, b));
  return out;
}

/**
 * The list in the order of a column, from lists already in the order of that column in the up direction: a descending
 * list is the same list read from the end. Keeps a long list from being sorted again on every key.
 * @template T
 * @param {readonly T[]} ascending
 * @param {"asc" | "desc"} dir
 * @returns {T[]}
 */
export function inDirection(ascending, dir) {
  return dir === "desc" ? [...ascending].reverse() : /** @type {T[]} */ (ascending);
}

// ----------------------------------------------------------------- window

/** How many rows are drawn above and below what can be seen. */
export const OVERSCAN = 8;

/** A list this short is drawn whole. */
export const WINDOW_FROM = 150;

/**
 * Which rows of a long list to draw: the ones that cross the screen, with a few more above and below.
 * @param {{ count: number, rowHeight: number, top: number, viewport: number, overscan?: number }} options
 *   `top`: how far the first row is above the top of the screen (negative while it is below the top)
 * @returns {{ start: number, end: number }} rows `start` up to but not including `end`
 */
export function windowRange({ count, rowHeight, top, viewport, overscan = OVERSCAN }) {
  if (count <= 0 || !(rowHeight > 0)) return { start: 0, end: 0 };
  const first = Math.floor(top / rowHeight);
  const last = Math.ceil((top + Math.max(0, viewport)) / rowHeight);
  const start = Math.min(count, Math.max(0, first - overscan));
  const end = Math.max(start, Math.min(count, last + overscan));
  return { start, end };
}

// ------------------------------------------------------------------- rows

/** The letter of the tile of an item: its first letter, in capitals. @param {string} name */
export function initialOf(name) {
  const first = [...String(name ?? "").trim()][0];
  return first === undefined ? "?" : first.toLocaleUpperCase();
}

/** @type {Map<string, Intl.DateTimeFormat>} */
const dateFormats = new Map();
/** @type {Map<string, Intl.RelativeTimeFormat>} */
const relativeFormats = new Map();

/**
 * The exact date and time of a moment, for the title of a cell, or null when the number is not a moment. The formatter is made once per language.
 * @param {unknown} ms
 * @param {string} [locale]
 * @returns {string | null}
 */
export function formatExact(ms, locale) {
  if (typeof ms !== "number" || !Number.isSafeInteger(ms) || ms <= 0) return null;
  try {
    const key = locale ?? "";
    let format = dateFormats.get(key);
    if (!format) {
      format = new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" });
      dateFormats.set(key, format);
    }
    return format.format(new Date(ms));
  } catch {
    return null;
  }
}

/**
 * A moment as a reader says it: "now", "3 days ago", "last month". The exact date is in the title of the cell.
 * @param {number} ms
 * @param {number} now
 * @param {string} [locale]
 * @returns {string | null} null when `ms` is not a moment
 */
export function relativeTime(ms, now, locale) {
  if (typeof ms !== "number" || !Number.isSafeInteger(ms) || ms <= 0) return null;
  try {
    const key = locale ?? "";
    let rtf = relativeFormats.get(key);
    if (!rtf) {
      rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
      relativeFormats.set(key, rtf);
    }
    const seconds = Math.round((ms - now) / 1000);
    const abs = Math.abs(seconds);
    if (abs < 60) return rtf.format(0, "second");
    if (abs < 3600) return rtf.format(Math.trunc(seconds / 60), "minute");
    if (abs < 86400) return rtf.format(Math.trunc(seconds / 3600), "hour");
    if (abs < 86400 * 30) return rtf.format(Math.trunc(seconds / 86400), "day");
    if (abs < 86400 * 365) return rtf.format(Math.trunc(seconds / (86400 * 30)), "month");
    return rtf.format(Math.trunc(seconds / (86400 * 365)), "year");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- address

/**
 * Which entry of the side menu a list address belongs to: the favourites when that filter is on, else all items.
 * @param {string} path `/items`
 * @param {string} query the part after `?`
 * @returns {string} a path the menu knows
 */
export function menuPathOf(path, query) {
  return path === "/items" && parseListQuery(query).favorite ? "/favorites" : path;
}
