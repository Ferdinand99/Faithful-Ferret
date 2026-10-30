// The sync engine as a service. A screen starts it once the vault is unlocked
// (`start(scope)`) and the lock stops it (`stop()`), which drops the decrypted
// item index and every open handle. There is at most one engine at a time.
import { createSyncEngine } from "../sync/engine.mjs";

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "sync",
  deps: ["api", "store", "client"],
  create: ({ api, store, client }) => {
    /** @type {ReturnType<typeof createSyncEngine> | null} */
    let engine = null;
    return {
      /**
       * Starts an engine for the unlocked vault and returns it. An engine that
       * is already running is stopped first.
       * @param {import("../store/cache.mjs").Scope} scope
       */
      async start(scope) {
        engine?.stop();
        const made = createSyncEngine({ api, client, store, scope });
        engine = made;
        try {
          await made.start();
        } catch (error) {
          made.stop();
          if (engine === made) engine = null;
          throw error;
        }
        return made;
      },
      /** The running engine, or null (locked, or not started yet). */
      current: () => engine,
      /** Stops the engine and forgets it. Safe to call when none runs. */
      stop() {
        engine?.stop();
        engine = null;
      },
    };
  },
};
