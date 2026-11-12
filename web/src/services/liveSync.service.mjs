// Live updates as a service. It follows the sync engine: when an engine has
// started, a channel to the server's event stream is opened for it, and when
// the engine stops (the vault locks, or the session ends) the channel is
// closed. An event only makes the engine read the feed now; it carries nothing
// the engine would trust (Spec: Fase 1 section 8.2).
//
// The screen shows `state()` and listens with `on("state", fn)`.
import { createLiveChannel } from "../sync/events.mjs";

/** @typedef {import("../sync/events.mjs").LiveState} LiveState */

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "liveSync",
  deps: ["api", "sync"],
  create: ({ api, sync }) => {
    /** @type {LiveState} */
    let state = "offline";
    /** @type {ReturnType<typeof createLiveChannel> | null} */
    let channel = null;
    /** @type {Set<(state: LiveState) => void>} */
    const listeners = new Set();

    /** @param {LiveState} next */
    function setState(next) {
      if (state === next) return;
      state = next;
      for (const listener of [...listeners]) {
        try {
          listener(next);
        } catch {
          // A listener that throws must not stop the channel or the other listeners.
        }
      }
    }

    /** Stops listening to the engine that is followed. @type {(() => void) | null} */
    let offEngine = null;

    /** @param {any} engine */
    function open(engine) {
      const made = createLiveChannel({
        api,
        onHint: () => engine.syncNow(),
        onState: (next) => {
          if (channel === made) setState(next);
        },
      });
      channel = made;
      made.start();
    }

    function close() {
      const old = channel;
      channel = null;
      old?.stop();
    }

    /**
     * A stopped engine ignores every hint, so an open stream would only hold one of the device's
     * stream places for nothing: the channel is closed while the engine is stopped and opened again
     * when it runs again (a retry, or an older state accepted), which the engine tells with its next
     * `syncing`.
     * @param {ReturnType<typeof import("../sync/engine.mjs").createSyncEngine> | null} engine
     */
    function follow(engine) {
      offEngine?.();
      offEngine = null;
      close();
      if (engine === null) {
        setState("offline");
        return;
      }
      const stopped = () => typeof engine.health === "function" && engine.health().halted !== null;
      if (stopped()) setState("offline");
      else open(engine);
      if (typeof engine.on === "function") {
        offEngine = engine.on("state", (payload) => {
          if (payload?.kind === "halted") {
            close();
            setState("offline");
          } else if (channel === null && !stopped()) {
            open(engine);
          }
        });
      }
    }

    sync.onEngine(follow);
    // `onEngine` does not tell a late listener about an engine that is running already.
    follow(sync.current());

    return {
      /** @returns {LiveState} */
      state: () => state,
      /**
       * @param {"state"} event
       * @param {(state: LiveState) => void} fn
       * @returns {() => void} removes the listener
       */
      on(event, fn) {
        if (event !== "state") throw new TypeError(`no event named ${event}`);
        listeners.add(fn);
        return () => void listeners.delete(fn);
      },
    };
  },
};
