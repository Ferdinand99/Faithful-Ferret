// The local trash: when a verified tombstone deletes an item, the last live row
// of that item (ciphertext, tag and revision) is kept here for a while, so the
// user can restore it. An entry is a copy of rows that the server already holds
// or held, so it holds ciphertext fields only and never a decrypted value. The
// trash is kept per scope (account, vault, key epoch), like the rows, and is
// emptied together with them when the cache is cleared or the user signs out.
import { hex16 } from "../b64.mjs";
import { checkScope } from "./cache.mjs";
import { req, run, StoreError } from "./idb.mjs";

/**
 * @typedef {object} TrashEntry
 * @property {string} itemId 32 hex characters
 * @property {number} rev the revision of the live row that was deleted
 * @property {Uint8Array} envelope the sealed item
 * @property {Uint8Array} tag the row tag
 * @property {number} tombRev the revision of the tombstone
 * @property {number} deletedAt when the deletion was verified (ms since the epoch)
 */

/** The only fields an entry may have. Anything else is refused, not dropped. */
export const TRASH_FIELDS = Object.freeze(["itemId", "rev", "envelope", "tag", "tombRev", "deletedAt"]);

/** @param {import("./cache.mjs").Scope} scope */
const prefix = (scope) => [scope.accountId, scope.vaultId, scope.vkEpoch];

/** @param {import("./idb.mjs").Store} store @param {import("./cache.mjs").Scope} scope */
const range = (store, scope) => store.keyRange.bound(prefix(scope), [...prefix(scope), []]);

/** @param {unknown} itemId */
function checkId(itemId) {
  if (!hex16.is(itemId)) throw new TypeError("an item id is 32 lower-case hex characters");
}

/**
 * The entry to store: exactly the allowed fields, of the right types, with copies of the bytes.
 * @param {TrashEntry} entry
 * @returns {TrashEntry}
 */
function clean(entry) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) throw new StoreError("trash_malformed", "an entry is an object");
  for (const key of Object.keys(entry)) {
    if (!TRASH_FIELDS.includes(key)) throw new StoreError("trash_field", `the trash holds ciphertext fields only, not ${key}`);
  }
  const { itemId, rev, envelope, tag, tombRev, deletedAt } = entry;
  const ok =
    hex16.is(itemId) &&
    Number.isSafeInteger(rev) && rev >= 1 &&
    Number.isSafeInteger(tombRev) && tombRev > rev &&
    Number.isSafeInteger(deletedAt) && deletedAt >= 0 &&
    envelope instanceof Uint8Array &&
    tag instanceof Uint8Array;
  if (!ok) throw new StoreError("trash_malformed", "an entry is a live row (envelope, tag, rev) and the revision and time of its deletion");
  return { itemId, rev, envelope: envelope.slice(), tag: tag.slice(), tombRev, deletedAt };
}

/**
 * @param {Record<string, any>} record a stored record
 * @returns {TrashEntry}
 */
const entryOf = ({ itemId, rev, envelope, tag, tombRev, deletedAt }) => ({ itemId, rev, envelope, tag, tombRev, deletedAt });

export const trash = Object.freeze({
  /**
   * Keeps an entry, replacing the one of the same item.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {TrashEntry} entry
   * @returns {Promise<void>}
   */
  async put(store, scope, entry) {
    checkScope(scope);
    const value = clean(entry);
    await run(store, ["trash"], "readwrite", async ([table]) => {
      await req(table.put({ accountId: scope.accountId, vaultId: scope.vaultId, vkEpoch: scope.vkEpoch, ...value }));
    });
  },

  /**
   * Every entry of the scope, the most recently deleted first.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @returns {Promise<TrashEntry[]>}
   */
  async all(store, scope) {
    checkScope(scope);
    const records = await run(store, ["trash"], "readonly", ([table]) => req(table.getAll(range(store, scope))));
    return records.map(entryOf).sort((a, b) => b.deletedAt - a.deletedAt || (a.itemId < b.itemId ? -1 : 1));
  },

  /**
   * The entry of an item, or null.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {string} itemId
   * @returns {Promise<TrashEntry | null>}
   */
  async get(store, scope, itemId) {
    checkScope(scope);
    checkId(itemId);
    const record = await run(store, ["trash"], "readonly", ([table]) => req(table.get([...prefix(scope), itemId])));
    return record === undefined ? null : entryOf(record);
  },

  /**
   * Drops the entry of an item. Nothing happens when it is not there.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {string} itemId
   * @returns {Promise<void>}
   */
  async remove(store, scope, itemId) {
    checkScope(scope);
    checkId(itemId);
    await run(store, ["trash"], "readwrite", async ([table]) => {
      await req(table.delete([...prefix(scope), itemId]));
    });
  },

  /**
   * Drops the entries deleted before `cutoffMs` (strictly before; an entry
   * deleted at the cutoff stays) and returns how many went. The read and the
   * deletions are one transaction.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {number} cutoffMs
   * @returns {Promise<number>}
   */
  async purgeBefore(store, scope, cutoffMs) {
    checkScope(scope);
    if (!Number.isSafeInteger(cutoffMs) || cutoffMs < 0) throw new TypeError("a cutoff is a whole number of milliseconds");
    return run(store, ["trash"], "readwrite", async ([table]) => {
      const records = await req(table.getAll(range(store, scope)));
      let removed = 0;
      for (const record of records) {
        if (record.deletedAt >= cutoffMs) continue;
        await req(table.delete([...prefix(scope), record.itemId]));
        removed += 1;
      }
      return removed;
    });
  },

  /**
   * Drops every entry of the scope.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @returns {Promise<void>}
   */
  async clear(store, scope) {
    checkScope(scope);
    await run(store, ["trash"], "readwrite", async ([table]) => {
      await req(table.delete(range(store, scope)));
    });
  },
});
