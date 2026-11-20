// The outbox: item writes that the server has not yet confirmed, oldest first.
// An entry keeps the exact bytes of its request body. The server hashes the raw
// body under the idempotency key, so a retry has to send those same bytes (not
// a fresh serialization with another key order) or it gets 422 `idem_reuse`
// instead of a replay of the first answer.
import { b64u, hex16 } from "../b64.mjs";
import { checkStep, readWire } from "../wire.mjs";
import { checkScope } from "./cache.mjs";
import { req, run, StoreError } from "./idb.mjs";

/**
 * @typedef {object} OutboxEntry
 * @property {string} idem 32 hex characters, the idempotency key
 * @property {string} itemId 32 hex characters
 * @property {number} baseRev the revision this write builds on
 * @property {{ blob: Uint8Array, tag: Uint8Array } | { tomb: Uint8Array }} body what is written (a live row or a tombstone)
 * @property {Uint8Array} bytes the serialized request body, sent as it is on every try
 * @property {string} [import] the id (32 hex characters) of the import window the write counts against. Only the writes of an import
 *   have it: they are sent in batches (`POST /api/sync/batch` with `import_window`) and are always a live write of a new item
 *   (`baseRev` 0). An entry without it is an ordinary write and goes with `PUT`: entries stored before the mark existed read that way.
 */

/** The manifest row has this id and is not written as an item. */
const MANIFEST_ITEM_ID = "00000000000000000000000000000000";

const decoder = new TextDecoder("utf-8", { fatal: true });

/** The most writes one `enqueueMany` stores in one transaction (an import of 10 000 items is queued in a few). */
export const ENQUEUE_CHUNK = 500;

/** @param {import("./cache.mjs").Scope} scope */
const prefix = (scope) => [scope.accountId, scope.vaultId, scope.vkEpoch];

/**
 * @param {Uint8Array | undefined} a
 * @param {Uint8Array} b
 */
const same = (a, b) => a instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);

/**
 * Checks an entry and returns the value to store: the fields of the entry, and
 * `bytes` checked to be a valid write request that matches them.
 * @param {OutboxEntry} entry
 * @returns {OutboxEntry}
 */
function clean(entry) {
  const bad = (/** @type {string} */ message) => new StoreError("outbox_entry", message);
  if (entry === null || typeof entry !== "object") throw bad("an entry is an object");
  const { idem, itemId, baseRev, body, bytes } = entry;
  const mark = entry.import;
  if (mark !== undefined && !hex16.is(mark)) throw bad("import is the id of a window, 32 hex characters");
  if (!hex16.is(idem) || !hex16.is(itemId)) throw bad("idem and itemId are 32 hex characters");
  if (itemId === MANIFEST_ITEM_ID) throw bad("the manifest row is not written as an item");
  if (!Number.isSafeInteger(baseRev) || baseRev < 0) throw bad("baseRev is a whole number");
  if (!(bytes instanceof Uint8Array)) throw bad("bytes are the serialized request body");
  /** @type {any} */
  let wire;
  try {
    wire = readWire("put_item_req", decoder.decode(bytes));
    checkStep("put_item_req", wire);
  } catch {
    throw bad("bytes are not a valid write request");
  }
  if (wire.idem !== idem || wire.base_rev !== baseRev) throw bad("bytes do not match idem and baseRev");
  if (body === null || typeof body !== "object") throw bad("body is { blob, tag } or { tomb }");
  const fields = Object.keys(body).sort().join();
  if (wire.deleted === true) {
    const { tomb } = /** @type {{ tomb?: Uint8Array }} */ (body);
    if (fields !== "tomb" || !(tomb instanceof Uint8Array) || b64u.encode(tomb) !== wire.tomb) {
      throw bad("body does not match the bytes");
    }
    if (mark !== undefined) throw bad("an import writes live rows");
    return { idem, itemId, baseRev, body: { tomb }, bytes };
  }
  if (mark !== undefined && (baseRev !== 0 || wire.resurrect === true)) throw bad("an import writes a new item");
  const { blob, tag } = /** @type {{ blob?: Uint8Array, tag?: Uint8Array }} */ (body);
  const matches =
    fields === "blob,tag" && blob instanceof Uint8Array && tag instanceof Uint8Array &&
    b64u.encode(blob) === wire.blob && b64u.encode(tag) === wire.tag;
  if (!matches) throw bad("body does not match the bytes");
  return { idem, itemId, baseRev, body: { blob, tag }, bytes, ...(mark === undefined ? {} : { import: mark }) };
}

export const outbox = Object.freeze({
  /**
   * Adds a write at the end of the queue. The same `idem` twice in a scope is
   * refused (`StoreError`, code `outbox_duplicate`).
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {OutboxEntry} entry
   * @returns {Promise<void>}
   */
  async enqueue(store, scope, entry) {
    checkScope(scope);
    const value = clean(entry);
    try {
      await run(store, ["outbox"], "readwrite", async ([table]) => {
        await req(table.add({ accountId: scope.accountId, vaultId: scope.vaultId, vkEpoch: scope.vkEpoch, ...value }));
      });
    } catch (error) {
      if (/** @type {any} */ (error)?.name === "ConstraintError") {
        throw new StoreError("outbox_duplicate", "that idempotency key is already queued");
      }
      throw error;
    }
  },

  /**
   * Adds writes at the end of the queue, in the order given, a few hundred to a transaction: a crash leaves the first chunks stored and
   * never a part of one. Each is checked like `enqueue`'s; the same `idem` twice in a scope is refused (`outbox_duplicate`), and nothing
   * of the chunk it is in is stored.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {OutboxEntry[]} entries
   * @returns {Promise<void>}
   */
  async enqueueMany(store, scope, entries) {
    checkScope(scope);
    const values = entries.map(clean);
    for (let from = 0; from < values.length; from += ENQUEUE_CHUNK) {
      const chunk = values.slice(from, from + ENQUEUE_CHUNK);
      try {
        await run(store, ["outbox"], "readwrite", async ([table]) => {
          for (const value of chunk) {
            await req(table.add({ accountId: scope.accountId, vaultId: scope.vaultId, vkEpoch: scope.vkEpoch, ...value }));
          }
        });
      } catch (error) {
        if (/** @type {any} */ (error)?.name === "ConstraintError") {
          throw new StoreError("outbox_duplicate", "that idempotency key is already queued");
        }
        throw error;
      }
    }
  },

  /**
   * Gives the writes of an import a new window: the entries with these keys that carry the import mark get `window` in its place, in
   * the place they have in the queue (the bytes and the keys are not touched). The one operation that changes a stored entry.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {string[]} idems
   * @param {string} window the id of the new window, 32 hex characters
   * @returns {Promise<number>} how many entries were changed
   */
  async remark(store, scope, idems, window) {
    checkScope(scope);
    if (!hex16.is(window)) throw new TypeError("a window id is 32 lower-case hex characters");
    for (const idem of idems) if (!hex16.is(idem)) throw new TypeError("idem is 32 lower-case hex characters");
    let changed = 0;
    for (let from = 0; from < idems.length; from += ENQUEUE_CHUNK) {
      await run(store, ["outbox"], "readwrite", async ([table]) => {
        for (const idem of idems.slice(from, from + ENQUEUE_CHUNK)) {
          const key = await req(table.index("by_idem").getKey([...prefix(scope), idem]));
          if (key === undefined) continue;
          const value = await req(table.get(key));
          if (value === undefined || value.import === undefined) continue;
          await req(table.put({ ...value, import: window }, key));
          changed += 1;
        }
      });
    }
    return changed;
  },

  /**
   * Takes the entries with these keys out, a few hundred to a transaction. Nothing happens for a key that is not there.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {string[]} idems
   * @returns {Promise<void>}
   */
  async removeMany(store, scope, idems) {
    checkScope(scope);
    for (const idem of idems) if (!hex16.is(idem)) throw new TypeError("idem is 32 lower-case hex characters");
    for (let from = 0; from < idems.length; from += ENQUEUE_CHUNK) {
      await run(store, ["outbox"], "readwrite", async ([table]) => {
        for (const idem of idems.slice(from, from + ENQUEUE_CHUNK)) {
          const key = await req(table.index("by_idem").getKey([...prefix(scope), idem]));
          if (key !== undefined) await req(table.delete(key));
        }
      });
    }
  },

  /**
   * Puts `entries` at the end of the queue and takes the entries with the keys `remove` out, in one transaction: a crash leaves
   * the queue as it was or as it is meant to be, never both sets. The same `idem` twice in a scope is refused (`outbox_duplicate`).
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {string[]} remove idempotency keys of the entries to take out
   * @param {OutboxEntry[]} entries
   * @param {{ itemId: string, keys: string[] } | null} [only] when given, the transaction first checks that the entries of that item
   *   in the store are exactly those with these keys (another tab may have queued one meanwhile), and refuses with `outbox_changed`
   *   (nothing is changed) when they are not
   * @returns {Promise<void>}
   */
  async swap(store, scope, remove, entries, only = null) {
    checkScope(scope);
    for (const idem of remove) if (!hex16.is(idem)) throw new TypeError("idem is 32 lower-case hex characters");
    const values = entries.map(clean);
    try {
      await run(store, ["outbox"], "readwrite", async ([table]) => {
        if (only !== null) {
          const all = await req(table.index("by_scope").getAll(store.keyRange.only(prefix(scope))));
          const present = all.filter((row) => row.itemId === only.itemId).map((row) => row.idem);
          if (present.length !== only.keys.length || !present.every((idem) => only.keys.includes(idem))) {
            throw new StoreError("outbox_changed", "the queue of the item is not the one that was looked at");
          }
        }
        for (const value of values) {
          await req(table.add({ accountId: scope.accountId, vaultId: scope.vaultId, vkEpoch: scope.vkEpoch, ...value }));
        }
        for (const idem of remove) {
          const key = await req(table.index("by_idem").getKey([...prefix(scope), idem]));
          if (key !== undefined) await req(table.delete(key));
        }
      });
    } catch (error) {
      if (/** @type {any} */ (error)?.name === "ConstraintError") {
        throw new StoreError("outbox_duplicate", "that idempotency key is already queued");
      }
      throw error;
    }
  },

  /**
   * The queued writes of the scope, oldest first, with their exact bytes.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @returns {Promise<OutboxEntry[]>}
   */
  async all(store, scope) {
    checkScope(scope);
    const rows = await run(store, ["outbox"], "readonly", ([table]) =>
      req(table.index("by_scope").getAll(store.keyRange.only(prefix(scope)))),
    );
    return rows.map(({ idem, itemId, baseRev, body, bytes, import: mark }) => ({
      idem, itemId, baseRev, body, bytes, ...(typeof mark === "string" ? { import: mark } : {}),
    }));
  },

  /**
   * Drops the entry with this key (the server has answered it). Nothing
   * happens when it is not there.
   * @param {import("./idb.mjs").Store} store
   * @param {import("./cache.mjs").Scope} scope
   * @param {string} idem
   * @returns {Promise<void>}
   */
  async remove(store, scope, idem) {
    checkScope(scope);
    if (!hex16.is(idem)) throw new TypeError("idem is 32 lower-case hex characters");
    await run(store, ["outbox"], "readwrite", async ([table]) => {
      const key = await req(table.index("by_idem").getKey([...prefix(scope), idem]));
      if (key !== undefined) await req(table.delete(key));
    });
  },
});
