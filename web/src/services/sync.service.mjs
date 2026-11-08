// The sync engine as a service. A screen starts it once the vault is unlocked
// (`start(scope)`) and the lock stops it (`stop()`), which drops the decrypted
// item index and every open handle. There is at most one engine at a time.
//
// Parts that follow the engine (the live-update client, the warning banner) do
// not poll `current()`: they register with `onEngine`, which hands them each
// engine once it has started and `null` once it has stopped.
import { deviceNameFor } from "../sync/deviceName.mjs";
import { createSyncEngine, SyncError } from "../sync/engine.mjs";
import { memoryStore, unavailableMemory } from "../sync/memory.mjs";

/**
 * The sync memory of an account. Where the browser has no Web Locks the engine
 * is still made, with a memory that fails, and halts with `unsupported`.
 * @param {{ store: any, client: any, serverUrl: string, accountId: string, locks: any }} options
 */
function memoryFor({ store, client, serverUrl, accountId, locks }) {
  try {
    return memoryStore({ store, serverUrl, accountId, locks, newMemory: () => client.vault.sync_memory_new() });
  } catch (error) {
    if (error instanceof SyncError) return unavailableMemory(error);
    throw error;
  }
}

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "sync",
  deps: ["api", "store", "client"],
  // `serverUrl`, `locks` and `nav` are for tests: in the browser they are the page's own.
  create: ({
    api, store, client,
    serverUrl = globalThis.location?.origin,
    locks = /** @type {any} */ (globalThis).navigator?.locks,
    nav = /** @type {any} */ (globalThis).navigator,
  }) => {
    /** @type {ReturnType<typeof createSyncEngine> | null} */
    let engine = null;
    /** The engine the listeners were last told about, so each one is announced once and ended once. @type {ReturnType<typeof createSyncEngine> | null} */
    let announced = null;
    /** @type {Set<(engine: ReturnType<typeof createSyncEngine> | null) => void>} */
    const listeners = new Set();
    /** @param {ReturnType<typeof createSyncEngine> | null} next */
    const announce = (next) => {
      announced = next;
      for (const listener of [...listeners]) {
        try {
          listener(next);
        } catch {
          // A listener that throws must not stop the engine or the other listeners.
        }
      }
    };
    /** Ends the announced engine, if there is one. */
    const retire = () => {
      if (announced !== null) announce(null);
    };
    const running = () => {
      if (!engine) throw new Error("the sync engine is not running");
      return engine;
    };
    return {
      /**
       * Starts an engine for the unlocked vault and returns it. An engine that
       * is already running is stopped first.
       * @param {import("../store/cache.mjs").Scope} scope
       */
      async start(scope) {
        engine?.stop();
        engine = null; // a listener that asks `current()` while it is told about the end sees none
        retire();
        const made = createSyncEngine({
          api, client, store, scope,
          memory: memoryFor({ store, client, serverUrl, accountId: scope.accountId, locks }),
          deviceName: () => deviceNameFor(store, nav),
        });
        engine = made;
        try {
          await made.start();
        } catch (error) {
          made.stop();
          if (engine === made) engine = null;
          throw error;
        }
        // A stop (or another start) that came while this one was starting has
        // replaced the engine: it is not announced.
        if (engine === made) announce(made);
        return made;
      },
      /**
       * Calls `listener` with each engine after it has started, and with null
       * after it has stopped. It is not called for an engine that is running
       * already (see `current()`), nor for a start that failed. A listener that
       * throws is ignored. Returns the function that removes the listener.
       * @param {(engine: ReturnType<typeof createSyncEngine> | null) => void} listener
       * @returns {() => void}
       */
      onEngine(listener) {
        listeners.add(listener);
        return () => void listeners.delete(listener);
      },
      /** The running engine, or null (locked, or not started yet). */
      current: () => engine,
      /** Drops the refused write of a blocked item (see the engine's `discard`). @param {string} id */
      discard: (id) => running().discard(id),
      /** Gives up an item that a full listing did not show, after the user has confirmed it. @param {string} id */
      discardMissing: (id) => running().discardMissing(id),
      /** Stops the engine and forgets it. Safe to call when none runs. */
      stop() {
        engine?.stop();
        engine = null;
        retire();
      },
    };
  },
};
