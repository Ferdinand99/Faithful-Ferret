// What Ferret filled where, for a short while: the fill flow (fillFlow.mjs)
// notes, after each value it put into a page, which item it came from, and the
// write path (offerWrite.mjs) asks it when a change form is submitted in that
// document. A current password Ferret filled from an item makes that item the
// target of the change.
//
// An entry is `(tab, frame, document or address, kind of field) -> item id`. No
// value is kept: only the id of the item, which the background holds anyway. It
// lives in the memory of the background page only, for five minutes of wall
// clock, checked on every access (a timer stands still while the computer
// sleeps), and every lock of the vault clears it all.

/** How long a fill is remembered. */
export const FILL_CONTEXT_TTL_MS = 300_000;

/** The most fills remembered at once; the oldest goes first. */
export const MAX_FILL_CONTEXT = 64;

/** The kinds of field a fill puts a value in. */
const FIELD_KINDS = Object.freeze(["username", "password", "totp"]);

const ITEM_ID = /^[0-9a-f]{32}$/;

/** @param {unknown} n */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/** @param {unknown} s @param {number} max @returns {s is string} */
const isText = (s, max) => typeof s === "string" && s !== "" && s.length <= max;

/** An address without its fragment: a page that only moves to an anchor is the same document. @param {string} url */
const withoutFragment = (url) => {
  const at = url.indexOf("#");
  return at < 0 ? url : url.slice(0, at);
};

/**
 * @typedef {{ tabId: number, frameId: number, documentId?: string, url: string, fieldKind: string }} FillPlace
 * @typedef {FillPlace & { itemId: string }} FillRecord
 */

/**
 * @param {{ now?: () => number }} [options]
 */
export function createFillContext({ now = Date.now } = {}) {
  /** @type {Array<{ tabId: number, frameId: number, documentId: string | null, url: string, fieldKind: string, itemId: string, at: number }>} */
  let entries = [];

  /** Drops what is older than the limit (and anything from a clock that went back). */
  const prune = () => {
    const t = now();
    entries = entries.filter((e) => t >= e.at && t - e.at < FILL_CONTEXT_TTL_MS);
  };

  /**
   * Whether `entry` is the document of `place`: the same tab, frame and kind of field, and the same document when both
   * name one, otherwise the same address.
   * @param {{ tabId: number, frameId: number, documentId: string | null, url: string, fieldKind: string }} entry
   * @param {FillPlace} place
   */
  const samePlace = (entry, place) => {
    if (entry.tabId !== place.tabId || entry.frameId !== place.frameId || entry.fieldKind !== place.fieldKind) return false;
    if (entry.documentId !== null && typeof place.documentId === "string") return entry.documentId === place.documentId;
    return entry.url === withoutFragment(place.url);
  };

  /** @param {unknown} place @returns {place is FillPlace} */
  const isPlace = (place) => {
    const p = /** @type {any} */ (place);
    return (
      p !== null && typeof p === "object" && isIndex(p.tabId) && isIndex(p.frameId) && isText(p.url, 8192) &&
      FIELD_KINDS.includes(p.fieldKind) && (p.documentId === undefined || p.documentId === null || isText(p.documentId, 64))
    );
  };

  return {
    /**
     * Notes that the value of `fieldKind` from item `itemId` was filled in that document. A malformed record is ignored.
     * @param {FillRecord} record
     */
    record(record) {
      if (!isPlace(record) || !ITEM_ID.test(String(record.itemId))) return;
      prune();
      const documentId = typeof record.documentId === "string" ? record.documentId : null;
      const entry = { tabId: record.tabId, frameId: record.frameId, documentId, url: withoutFragment(record.url), fieldKind: record.fieldKind, itemId: record.itemId, at: now() };
      // The newest fill of a place is the one that counts.
      entries = entries.filter((e) => !samePlace(e, { ...entry, documentId: entry.documentId ?? undefined }));
      entries.push(entry);
      while (entries.length > MAX_FILL_CONTEXT) entries.shift();
    },

    /**
     * The item whose value of `fieldKind` Ferret filled in that document within the last five minutes, or null.
     * @param {FillPlace} place
     * @returns {string | null}
     */
    lookup(place) {
      prune();
      if (!isPlace(place)) return null;
      for (let i = entries.length - 1; i >= 0; i -= 1) {
        if (samePlace(entries[i], place)) return entries[i].itemId;
      }
      return null;
    },

    /** Forgets everything (every lock of the vault). */
    clear() {
      entries = [];
    },

    /** How many fills are remembered now (for the tests). */
    size() {
      prune();
      return entries.length;
    },
  };
}
