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
 */

/** The manifest row has this id and is not written as an item. */
const MANIFEST_ITEM_ID = "00000000000000000000000000000000";

const decoder = new TextDecoder("utf-8", { fatal: true });

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
    return { idem, itemId, baseRev, body: { tomb }, bytes };
  }
  const { blob, tag } = /** @type {{ blob?: Uint8Array, tag?: Uint8Array }} */ (body);
  const matches =
    fields === "blob,tag" && blob instanceof Uint8Array && tag instanceof Uint8Array &&
    b64u.encode(blob) === wire.blob && b64u.encode(tag) === wire.tag;
  if (!matches) throw bad("body does not match the bytes");
  return { idem, itemId, baseRev, body: { blob, tag }, bytes };
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
    return rows.map(({ idem, itemId, baseRev, body, bytes }) => ({ idem, itemId, baseRev, body, bytes }));
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
