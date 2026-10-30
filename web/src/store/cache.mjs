// The local copy of the sync feed: ciphertext rows only. A row is what the
// server sends (envelope, tag, tombstone) plus the numbers that order it; no
// field of a decrypted item is ever stored here (the item index lives in memory
// and is dropped on lock). Rows are kept per scope (account, vault, key epoch),
// so a new epoch never mixes with the rows of an old one.
import { b64u, hex16 } from "../b64.mjs";
import { req, run, StoreError } from "./idb.mjs";

/**
 * @typedef {object} Scope
 * @property {string} accountId 32 hex characters
 * @property {string} vaultId 32 hex characters
 * @property {number} vkEpoch the key epoch the rows are sealed under
 *
 * @typedef {object} CachedRow
 * @property {string} itemId 32 hex characters
 * @property {number} rev
 * @property {number} seq
 * @property {boolean} deleted
 * @property {Uint8Array | null} envelope the sealed item (live rows)
 * @property {Uint8Array | null} tag the 32-byte row tag (live rows)
 * @property {Uint8Array | null} tomb the 40-byte tombstone (deleted rows)
 */

/** The only fields a row may have. Anything else is refused, not dropped. */
export const ROW_FIELDS = Object.freeze(["itemId", "rev", "seq", "deleted", "envelope", "tag", "tomb"]);

/** @param {Scope} scope */
export function checkScope(scope) {
  const ok =
    scope !== null &&
    typeof scope === "object" &&
    hex16.is(scope.accountId) &&
    hex16.is(scope.vaultId) &&
    Number.isSafeInteger(scope.vkEpoch) &&
    scope.vkEpoch >= 0;
  if (!ok) throw new TypeError("a scope is { accountId, vaultId, vkEpoch }");
}

/** @param {Scope} scope */
const prefix = (scope) => [scope.accountId, scope.vaultId, scope.vkEpoch];

/** @param {import("./idb.mjs").Store} store @param {Scope} scope */
const range = (store, scope) => store.keyRange.bound(prefix(scope), [...prefix(scope), []]);

/**
 * @param {unknown} value
 * @returns {value is Uint8Array | null}
 */
const bytesOrNull = (value) => value === null || value instanceof Uint8Array;

/**
 * The row to store: exactly the allowed fields, of the right types.
 * @param {Record<string, any>} row
 * @returns {CachedRow}
 */
function clean(row) {
  if (row === null || typeof row !== "object") throw new StoreError("row_malformed", "a row is an object");
  for (const key of Object.keys(row)) {
    if (!ROW_FIELDS.includes(key)) throw new StoreError("row_field", `the cache holds ciphertext fields only, not ${key}`);
  }
  const { itemId, rev, seq, deleted } = row;
  const envelope = row.envelope ?? null;
  const tag = row.tag ?? null;
  const tomb = row.tomb ?? null;
  const ok =
    hex16.is(itemId) &&
    Number.isSafeInteger(rev) && rev >= 0 &&
    Number.isSafeInteger(seq) && seq >= 0 &&
    typeof deleted === "boolean" &&
    bytesOrNull(envelope) && bytesOrNull(tag) && bytesOrNull(tomb) &&
    (deleted
      ? envelope === null && tag === null && tomb !== null
      : envelope !== null && tag !== null && tomb === null);
  if (!ok) throw new StoreError("row_malformed", "a row is a live row or a tombstone, never both");
  return { itemId, rev, seq, deleted, envelope, tag, tomb };
}

/**
 * A row of the changes feed (`{id, rev, seq, deleted, blob?, tag?, tomb?}`, bytes
 * as base64url) as a cache row.
 * @param {Record<string, any>} change
 * @returns {CachedRow}
 */
export function rowOfChange(change) {
  return clean({
    itemId: change.id,
    rev: change.rev,
    seq: change.seq,
    deleted: change.deleted,
    envelope: change.blob == null ? null : b64u.decode(change.blob),
    tag: change.tag == null ? null : b64u.decode(change.tag),
    tomb: change.tomb == null ? null : b64u.decode(change.tomb, "tombstone_invalid"),
  });
}

export const cache = Object.freeze({
  /**
   * Stores rows (in one transaction), replacing the row of the same item.
   * @param {import("./idb.mjs").Store} store
   * @param {Scope} scope
   * @param {readonly Record<string, any>[]} rows
   * @returns {Promise<void>}
   */
  async putRows(store, scope, rows) {
    checkScope(scope);
    const cleaned = rows.map(clean);
    await run(store, ["rows"], "readwrite", async ([table]) => {
      for (const row of cleaned) await req(table.put(row, [...prefix(scope), row.itemId]));
    });
  },

  /**
   * Every stored row of the scope, in `seq` order.
   * @param {import("./idb.mjs").Store} store
   * @param {Scope} scope
   * @returns {Promise<CachedRow[]>}
   */
  async getRows(store, scope) {
    checkScope(scope);
    /** @type {CachedRow[]} */
    const rows = await run(store, ["rows"], "readonly", ([table]) => req(table.getAll(range(store, scope))));
    return rows.sort((a, b) => a.seq - b.seq);
  },

  /**
   * The highest `seq` stored for the scope, or 0 when nothing is.
   * @param {import("./idb.mjs").Store} store
   * @param {Scope} scope
   * @returns {Promise<number>}
   */
  async maxSeq(store, scope) {
    const rows = await cache.getRows(store, scope);
    return rows.length === 0 ? 0 : rows[rows.length - 1].seq;
  },

  /**
   * Removes the rows of some items (in one transaction). The rest of the scope stays.
   * @param {import("./idb.mjs").Store} store
   * @param {Scope} scope
   * @param {readonly string[]} itemIds 32 hex characters each
   * @returns {Promise<void>}
   */
  async removeRows(store, scope, itemIds) {
    checkScope(scope);
    if (!itemIds.every((id) => hex16.is(id))) throw new TypeError("an item id is 32 lower-case hex characters");
    await run(store, ["rows"], "readwrite", async ([table]) => {
      for (const id of itemIds) await req(table.delete([...prefix(scope), id]));
    });
  },

  /**
   * Removes the rows of the scope. The pinned record, the outbox, the settings
   * and the device secrets stay.
   * @param {import("./idb.mjs").Store} store
   * @param {Scope} scope
   * @returns {Promise<void>}
   */
  async clear(store, scope) {
    checkScope(scope);
    await run(store, ["rows"], "readwrite", async ([table]) => {
      await req(table.delete(range(store, scope)));
    });
  },

  /**
   * Removes the rows of every vault and epoch of an account (sign-out).
   * @param {import("./idb.mjs").Store} store
   * @param {string} accountId
   * @returns {Promise<void>}
   */
  async clearAccount(store, accountId) {
    if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
    await run(store, ["rows"], "readwrite", async ([table]) => {
      await req(table.delete(store.keyRange.bound([accountId], [accountId, []])));
    });
  },
});
