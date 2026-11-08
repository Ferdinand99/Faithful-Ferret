// "Forget this server": the one action that removes what this device remembers of
// a server and account (spec Fase 1 § 8.6). It is explicit; signing out and
// clearing the cache leave the pinned record and the sync state in place.
//
// Everything of the account goes in one transaction, so a failure leaves all of
// it where it was and never a pinned record without its sync state, or the
// reverse. What goes: the pinned record, the sync state, the cached rows, the
// queued writes, the trash, the sync flags in the settings (`sync.flags.<account>.…`),
// the note about an accepted restore (`restore.note.<server>.<account>`, one per
// server, so it goes even when the other records are shared) and the device
// secrets. What stays: this browser's device id, and everything
// that belongs to another account or another server.
//
// Rows, the outbox, the trash and the sync flags are kept per account, not per
// server (an account id is 16 random bytes that one server made). The same
// account id can be pinned under two origins (one server reached by two
// addresses, or a server that reuses an id), and those records are then shared.
// When another origin has the account too, only the records of this origin go
// (pinned, sync state, device secrets); the shared ones stay, are reported as 0,
// and the result says `shared: true`.
//
// Callers run `forgetServer` inside the Web Lock `ferret-sync-memory:<server>:<account>`,
// like every other write of the sync state, so no tab is saving it meanwhile.
import { hex16 } from "../b64.mjs";
import { req, run, serverKey } from "./idb.mjs";
import { restoreNoteKey } from "./restoreNote.mjs";

/** The stores this removes from, in the order the report lists them. */
export const FORGET_STORES = Object.freeze(["pinned", "sync_state", "rows", "outbox", "trash", "settings", "device_secrets"]);

/** @param {unknown} accountId */
function checkAccount(accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
}

/**
 * Removes everything this device keeps for the server and account, in one
 * transaction, and reports how many records went from each store. The device id
 * stays. When another origin has the same account id pinned, the records kept
 * per account (rows, outbox, trash, flags) stay and `shared` is true.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<{ removed: Record<string, number>, shared?: true }>}
 */
export async function forgetServer(store, serverUrl, accountId) {
  const server = serverKey(serverUrl);
  checkAccount(accountId);
  const key = [server, accountId];
  const ofAccount = store.keyRange.bound([accountId], [accountId, []]);
  const flags = `sync.flags.${accountId}.`;
  const ofFlags = store.keyRange.bound(flags, `${flags}\uffff`);
  const noteKey = restoreNoteKey(serverUrl, accountId);

  return run(store, FORGET_STORES, "readwrite", async ([pinned, syncState, rows, outbox, trash, settings, secrets]) => {
    /** @type {Record<string, number>} */
    const removed = {};
    // A record under one key.
    for (const [name, table] of /** @type {[string, IDBObjectStore][]} */ ([["pinned", pinned], ["sync_state", syncState], ["device_secrets", secrets]])) {
      const found = await req(table.getKey(key));
      if (found !== undefined) await req(table.delete(key));
      removed[name] = found === undefined ? 0 : 1;
    }
    // Another origin with the same account id: what is kept per account is not ours alone.
    let shared = false;
    for (const table of [pinned, syncState, secrets]) {
      const keys = await req(table.getAllKeys());
      if (keys.some((other) => Array.isArray(other) && other[1] === accountId && other[0] !== server)) shared = true;
    }
    // Records under a prefix.
    for (const [name, table, range] of /** @type {[string, IDBObjectStore, IDBKeyRange][]} */ ([
      ["rows", rows, ofAccount],
      ["trash", trash, ofAccount],
      ["settings", settings, ofFlags],
    ])) {
      if (shared) {
        removed[name] = 0;
        continue;
      }
      const keys = await req(table.getAllKeys(range));
      if (keys.length > 0) await req(table.delete(range));
      removed[name] = keys.length;
    }
    // The restore note belongs to this server alone, shared account or not.
    if ((await req(settings.getKey(noteKey))) !== undefined) {
      await req(settings.delete(noteKey));
      removed.settings += 1;
    }
    // The outbox is keyed by a counter; its entries of the account are found by the scope index.
    const queued = shared ? [] : await req(outbox.index("by_scope").getAllKeys(ofAccount));
    for (const primary of queued) await req(outbox.delete(primary));
    removed.outbox = queued.length;
    const report = Object.fromEntries(FORGET_STORES.map((name) => [name, removed[name]]));
    return shared ? { removed: report, shared: true } : { removed: report };
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

/**
 * Whether another origin has the same account id pinned, so that forgetting this server
 * would keep the records that are kept per account (rows, outbox, trash, flags). The same
 * test `forgetServer` makes inside its transaction; the screen asks it first, to say what
 * will be lost and what will stay.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<boolean>}
 */
export async function sharedAccount(store, serverUrl, accountId) {
  const server = serverKey(serverUrl);
  checkAccount(accountId);
  return run(store, ["pinned", "sync_state", "device_secrets"], "readonly", async (tables) => {
    for (const table of tables) {
      const keys = await req(table.getAllKeys());
      if (keys.some((other) => Array.isArray(other) && other[1] === accountId && other[0] !== server)) return true;
    }
    return false;
  });
}
