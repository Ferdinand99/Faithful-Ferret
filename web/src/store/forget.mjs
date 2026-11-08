// "Forget this server": the one action that removes what this device remembers of
// a server and account (spec Fase 1 § 8.6). It is explicit; signing out and
// clearing the cache leave the pinned record and the sync state in place.
//
// Everything of the account goes in one transaction, so a failure leaves all of
// it where it was and never a pinned record without its sync state, or the
// reverse. What goes: the pinned record, the sync state, the cached rows, the
// queued writes, the trash, the sync flags in the settings (`sync.flags.<account>.…`)
// and the device secrets. What stays: this browser's device id, and everything
// that belongs to another account or another server.
//
// Rows, the outbox and the trash are kept per account, not per server (an
// account id is 16 random bytes that one server made), so they go by account.
import { hex16 } from "../b64.mjs";
import { req, run, serverKey } from "./idb.mjs";

/** The stores this removes from, in the order the report lists them. */
export const FORGET_STORES = Object.freeze(["pinned", "sync_state", "rows", "outbox", "trash", "settings", "device_secrets"]);

/** @param {unknown} accountId */
function checkAccount(accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
}

/**
 * Removes everything this device keeps for the server and account, in one
 * transaction, and reports how many records went from each store. The device id
 * stays.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<{ removed: Record<string, number> }>}
 */
export async function forgetServer(store, serverUrl, accountId) {
  const server = serverKey(serverUrl);
  checkAccount(accountId);
  const key = [server, accountId];
  const ofAccount = store.keyRange.bound([accountId], [accountId, []]);
  const flags = `sync.flags.${accountId}.`;
  const ofFlags = store.keyRange.bound(flags, `${flags}￿`);

  return run(store, FORGET_STORES, "readwrite", async ([pinned, syncState, rows, outbox, trash, settings, secrets]) => {
    /** @type {Record<string, number>} */
    const removed = {};
    // A record under one key.
    for (const [name, table] of /** @type {[string, IDBObjectStore][]} */ ([["pinned", pinned], ["sync_state", syncState], ["device_secrets", secrets]])) {
      const found = await req(table.getKey(key));
      if (found !== undefined) await req(table.delete(key));
      removed[name] = found === undefined ? 0 : 1;
    }
    // Records under a prefix.
    for (const [name, table, range] of /** @type {[string, IDBObjectStore, IDBKeyRange][]} */ ([
      ["rows", rows, ofAccount],
      ["trash", trash, ofAccount],
      ["settings", settings, ofFlags],
    ])) {
      const keys = await req(table.getAllKeys(range));
      if (keys.length > 0) await req(table.delete(range));
      removed[name] = keys.length;
    }
    // The outbox is keyed by a counter; its entries of the account are found by the scope index.
    const queued = await req(outbox.index("by_scope").getAllKeys(ofAccount));
    for (const primary of queued) await req(outbox.delete(primary));
    removed.outbox = queued.length;
    return { removed: Object.fromEntries(FORGET_STORES.map((name) => [name, removed[name]])) };
  });
}

/**
 * How many writes of the account are still waiting in the outbox, in every vault
 * and epoch. "Forget this server" would lose them, so the screen asks first.
 * @param {import("./idb.mjs").Store} store
 * @param {string} accountId
 * @returns {Promise<number>}
 */
export async function pendingWrites(store, accountId) {
  checkAccount(accountId);
  const range = store.keyRange.bound([accountId], [accountId, []]);
  return run(store, ["outbox"], "readonly", ([outbox]) => req(outbox.index("by_scope").count(range)));
}
