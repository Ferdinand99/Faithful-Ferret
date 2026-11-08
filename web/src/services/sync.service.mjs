// The sync engine as a service. A screen starts it once the vault is unlocked
// (`start(scope)`) and the lock stops it (`stop()`), which drops the decrypted
// item index and every open handle. There is at most one engine at a time, and
// at most one in all the tabs of a browser: the tab that holds the owner lock
// (`sync/owner.mjs`) runs it. A tab that does not get the lock is on standby: it
// has no engine, `standby()` says so, and `takeOver()` ("Use here") moves the engine
// to it. The tab that held the engine is on standby from then on.
//
// Parts that follow the engine (the live-update client, the warning banner) do
// not poll `current()`: they register with `onEngine`, which hands them each
// engine once it has started and `null` once it has stopped.
import { deviceNameFor } from "../sync/deviceName.mjs";
import { serverKey } from "../store/idb.mjs";
import { createSyncEngine, SyncError } from "../sync/engine.mjs";
import { memoryStore, unavailableMemory } from "../sync/memory.mjs";
import { createOwner, ownerName } from "../sync/owner.mjs";

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
  // `serverUrl`, `locks`, `nav`, `win`, `makeChannel`, `timers` and `tabId` are for tests: in the browser they are the page's own.
  create: ({
    api, store, client,
    serverUrl = globalThis.location?.origin,
    locks = /** @type {any} */ (globalThis).navigator?.locks,
    nav = /** @type {any} */ (globalThis).navigator,
    win = /** @type {any} */ (globalThis).window ?? null,
    makeChannel = /** @type {((name: string) => any) | undefined} */ (undefined),
    timers = /** @type {any} */ (undefined),
    tabId = /** @type {string | undefined} */ (undefined),
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

    // ---- the owner lock (one engine per browser)
    /** The owner lock of the open account, or null when the page has none to ask for. @type {ReturnType<typeof createOwner> | null} */
    let owner = null;
    /** The account the lock is for. @type {string | null} */
    let ownedAccount = null;
    /** The scope of the vault this tab has open: the engine runs for it, or the tab is on standby for it. @type {import("../store/cache.mjs").Scope | null} */
    let openScope = null;
    /** Set while this tab is on standby: the scope an engine will be started for when the user takes over. @type {import("../store/cache.mjs").Scope | null} */
    let standbyScope = null;
    /** @type {Set<(standby: boolean) => void>} */
    const standbyListeners = new Set();
    /** Moves on with each start and stop, so that an answer that comes late is seen to be late. */
    let generation = 0;
    /** The lock of the last owner has been let go when this settles. @type {Promise<void>} */
    let freed = Promise.resolve();
    /** @type {Promise<ReturnType<typeof createSyncEngine> | null> | null} */
    let taking = null;

    /** @param {boolean} on */
    const announceStandby = (on) => {
      for (const listener of [...standbyListeners]) {
        try {
          listener(on);
        } catch {
          // A listener that throws must not stop the others.
        }
      }
    };

    /** Makes the owner lock for an account, or null when the address of the server cannot be told. @param {string} accountId */
    function newOwner(accountId) {
      /** @type {string} */
      let server;
      try {
        server = serverKey(serverUrl);
      } catch {
        return null; // the memory of the engine cannot be made either: the engine halts by itself
      }
      /** @type {ReturnType<typeof createOwner> | null} */
      let made = null;
      made = createOwner({
        locks, server, accountId, timers, tabId,
        makeChannel: makeChannel ? () => makeChannel(ownerName(server, accountId)) : undefined,
        onYield: () => toStandby(made),
        onLost: () => toStandby(made),
      });
      return made;
    }

    /** Lets go of the owner lock. */
    function releaseOwner() {
      if (owner === null) return;
      freed = owner.release();
      owner = null;
      ownedAccount = null;
    }

    /**
     * The engine is stopped and the tab shows the notice: another tab asked for the vault (or took it), or this page goes away.
     * What is queued is stored; the next owner reads it.
     * @param {ReturnType<typeof createOwner> | null} made the lock that is given up; a stale one is ignored
     */
    function toStandby(made) {
      if (made === null || owner !== made || openScope === null || standbyScope !== null) return;
      engine?.stop();
      engine = null;
      retire();
      standbyScope = openScope;
      announceStandby(true);
    }

    /**
     * Makes and starts the engine for a scope this tab has the owner lock for.
     * @param {import("../store/cache.mjs").Scope} scope
     * @param {number} mine the generation of the start that asked
     */
    async function begin(scope, mine) {
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
        if (mine === generation && standbyScope === null) {
          // An engine that cannot start does not keep the vault from another tab; the next try asks for the lock again.
          releaseOwner();
          openScope = null;
        }
        throw error;
      }
      // A stop (or another start, or a hand-over) that came while this one was starting has replaced the engine: it is not announced.
      if (engine !== made) return null;
      announce(made);
      return made;
    }

    /** The starts in a row. @type {Promise<unknown>} */
    let chain = Promise.resolve();

    /**
     * Asks for the owner lock (unless this tab holds it already for the account) and starts the engine, or goes on standby.
     * @param {import("../store/cache.mjs").Scope} scope
     * @param {number} mine the generation of the start that asked
     * @returns {Promise<ReturnType<typeof createSyncEngine> | null>}
     */
    async function launch(scope, mine) {
      if (mine !== generation) return null; // stopped, or started again, while this one waited
      const keep = owner !== null && ownedAccount === scope.accountId && owner.isOwner() && standbyScope === null;
      if (!keep) {
        releaseOwner();
        await freed;
        if (mine !== generation) return null;
        const made = newOwner(scope.accountId);
        if (made !== null) {
          owner = made;
          ownedAccount = scope.accountId;
          openScope = scope;
          const role = await made.acquire();
          if (mine !== generation) {
            // Stopped, started again, or the page went away while the lock was asked for: the lock is let go. A tab that is on
            // standby keeps its lock object, for "Use here".
            if (owner === made) {
              if (standbyScope !== null) freed = made.release();
              else releaseOwner();
            }
            return null;
          }
          if (role === "standby") {
            standbyScope = scope;
            announceStandby(true);
            return null;
          }
        }
      }
      openScope = scope;
      return begin(scope, mine);
    }

    /** Stops the engine, lets go of the lock and forgets the open vault. */
    function close() {
      generation += 1;
      engine?.stop();
      engine = null;
      retire();
      releaseOwner();
      openScope = null;
      taking = null;
      if (standbyScope !== null) {
        standbyScope = null;
        announceStandby(false);
      }
    }

    // A page that goes away (or goes into the back/forward cache) lets go of the vault: the engine stops, and when the page
    // comes back it is on standby, with a button that asks for the vault again.
    win?.addEventListener?.("pagehide", () => {
      if (owner === null || openScope === null) return;
      generation += 1; // a start that is still asking for the lock does not go on to run an engine in a tab that shows the notice
      toStandby(owner);
      freed = owner.release(); // the owner stays: a page that comes back asks for the lock again with "Use here"
    });

    return {
      /**
       * Starts an engine for the unlocked vault and returns it. An engine that
       * is already running is stopped first. When another tab of this browser
       * runs the engine for the account, none is started here: the tab is on
       * standby (`standby()`) and the answer is null.
       * @param {import("../store/cache.mjs").Scope} scope
       * @returns {Promise<ReturnType<typeof createSyncEngine> | null>}
       */
      start(scope) {
        generation += 1;
        const mine = generation;
        engine?.stop();
        engine = null; // a listener that asks `current()` while it is told about the end sees none
        retire();
        if (standbyScope !== null) {
          standbyScope = null;
          announceStandby(false);
        }
        taking = null;
        // One start at a time: a start that comes while another is asking for the lock waits for it.
        const run = chain.then(() => launch(scope, mine));
        chain = run.then(() => {}, () => {});
        return run;
      },
      /** Whether this tab is on standby: another tab of the browser holds the vault. */
      standby: () => standbyScope !== null,
      /**
       * Calls `listener(true)` when this tab goes on standby (another tab took the vault) and `listener(false)` when it is
       * off standby again (taken back, locked). Returns the function that removes the listener.
       * @param {(standby: boolean) => void} listener
       * @returns {() => void}
       */
      onStandby(listener) {
        standbyListeners.add(listener);
        return () => void standbyListeners.delete(listener);
      },
      /**
       * "Use here": the tab on standby asks the tab that runs the engine to stop and let go, takes the lock (by force
       * after about three seconds without an answer) and starts the engine here. Answers the engine, or null when the
       * vault was locked meanwhile. Rejects with `invalid_state` when the tab is not on standby, and with
       * `owner_unavailable` when the lock could not be taken.
       * @returns {Promise<ReturnType<typeof createSyncEngine> | null>}
       */
      takeOver() {
        if (taking !== null) return taking;
        const scope = standbyScope;
        const made = owner;
        if (scope === null || made === null) return Promise.reject(new SyncError("invalid_state"));
        const mine = generation;
        const run = (async () => {
          await made.takeOver();
          if (mine !== generation || owner !== made) {
            void made.release(); // the vault was locked meanwhile: the lock goes with it
            return null;
          }
          standbyScope = null;
          announceStandby(false);
          engine?.stop(); // never a second engine in this tab
          engine = null;
          return begin(scope, mine);
        })();
        taking = run;
        const clear = () => {
          if (taking === run) taking = null;
        };
        run.then(clear, clear);
        return run;
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
      /** Stops the engine and forgets it, and lets go of the owner lock. Safe to call when none runs. */
      stop: close,
    };
  },
};
