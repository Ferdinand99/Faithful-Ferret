// Helpers for the tests of the local stores: a fresh in-memory IndexedDB per
// test, and a way to close and reopen the same database.
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { hex16 } from "../../src/b64.mjs";
import { openStore } from "../../src/store/idb.mjs";

export const ACCOUNT = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
export const VAULT = "f9e8d7c6b5a4938271605f4e3d2c1b0a";
export const SERVER = "https://vault.example";

/** A new empty database. `reopen()` closes the handle and opens the same data again. */
export async function freshStore(onclose) {
  const factory = new IDBFactory();
  let store = await openStore(factory, "ferret", IDBKeyRange, onclose);
  return {
    factory,
    get store() {
      return store;
    },
    async reopen() {
      store.close();
      store = await openStore(factory, "ferret", IDBKeyRange);
      return store;
    },
  };
}

export const scope = (vkEpoch = 1, accountId = ACCOUNT, vaultId = VAULT) => ({ accountId, vaultId, vkEpoch });

/**
 * A record the way the core hands it over (PinnedDto): ids and keys are bytes.
 * @param {object} [options]
 */
export function pinnedRecord({
  vk = 1,
  ksf = 1,
  floors = [["password", 1], ["recovery", 1]],
  accountId = ACCOUNT,
  vaultId = VAULT,
  server = SERVER,
  skBit = true,
  pkA = 3,
  serverKey = null,
} = {}) {
  return {
    server_url: server,
    account_id: hex16.decode(accountId),
    vault_id: hex16.decode(vaultId),
    ksf_profile: ksf,
    kek_generation_max: floors.map(([type, generation, credential]) => ({
      type,
      credential_id: credential ? new Uint8Array(credential) : null,
      generation,
    })),
    vk_epoch_max: vk,
    sk_bit: skBit,
    pk_a: new Uint8Array(32).fill(pkA),
    server_public_key: serverKey === null ? null : new Uint8Array(32).fill(serverKey),
  };
}
