// A stopped engine ignores every hint, so the live channel is closed while the engine is
// stopped and opened again when it runs again.
import assert from "node:assert/strict";
import { test } from "node:test";
import liveSyncService from "../../src/services/liveSync.service.mjs";
import { fakeStreamApi } from "./liveHelpers.mjs";
import { settle } from "./vaultHelpers.mjs";

/** An engine that reads, reports whether it is stopped, and tells its listeners what happens. */
function stoppable({ halted = null } = {}) {
  const listeners = new Set();
  const engine = {
    halted,
    reads: 0,
    syncNow() {
      engine.reads += 1;
      return Promise.resolve();
    },
    health: () => ({ halted: engine.halted, warnings: [] }),
    on(event, fn) {
      assert.equal(event, "state");
      listeners.add(fn);
      return () => void listeners.delete(fn);
    },
    emit: (payload) => {
      for (const fn of [...listeners]) fn(payload);
    },
    get listening() {
      return listeners.size;
    },
  };
  return engine;
}

function fakeSync(initial = null) {
  const listeners = new Set();
  const sync = {
    engine: initial,
    onEngine(listener) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
    current: () => sync.engine,
    announce(engine) {
      sync.engine = engine;
      for (const listener of [...listeners]) listener(engine);
    },
  };
  return sync;
}

test("a_halt_closes_the_live_channel_and_running_again_opens_it", async () => {
  const api = fakeStreamApi();
  const engine = stoppable();
  const sync = fakeSync(engine);
  const live = liveSyncService.create({ api, sync });
  const states = [];
  live.on("state", (state) => states.push(state));
  await settle();
  api.last.hello(1);
  await settle();
  assert.equal(live.state(), "live");
  assert.equal(api.calls.length, 1);

  // The engine halts: the stream is closed, the field says off, and no hint reaches the engine.
  engine.halted = "server_restored";
  engine.emit({ kind: "halted", code: "server_restored" });
  await settle();
  assert.equal(api.connections[0].signal.aborted, true, "the stream is closed");
  assert.equal(live.state(), "offline");
  const reads = engine.reads;
  await settle();
  assert.equal(engine.reads, reads);
  assert.equal(api.calls.length, 1, "and nothing opens another while it is stopped");
  // Other events while it is stopped do not open it.
  engine.emit({ kind: "warning", code: "bad_feed" });
  engine.emit({ kind: "idle" });
  await settle();
  assert.equal(api.calls.length, 1);

  // A retry or an accepted older state: the engine runs and says `syncing`. The stream opens once.
  engine.halted = null;
  engine.emit({ kind: "syncing" });
  engine.emit({ kind: "syncing" });
  await settle();
  assert.equal(api.calls.length, 2);
  assert.equal(live.state(), "connecting");
  api.last.hello(2);
  await settle();
  assert.equal(live.state(), "live");
  assert.deepEqual(states, ["live", "offline", "connecting", "live"]);

  // The end of the engine ends the channel and the listener on the engine.
  sync.announce(null);
  await settle();
  assert.equal(api.last.signal.aborted, true);
  assert.equal(engine.listening, 0);
  assert.equal(live.state(), "offline");
});

test("an_engine_that_is_halted_when_it_is_found_gets_no_channel_until_it_runs", async () => {
  const api = fakeStreamApi();
  const engine = stoppable({ halted: "rollback_suspected" });
  const sync = fakeSync();
  const live = liveSyncService.create({ api, sync });
  sync.announce(engine);
  await settle();
  assert.equal(api.calls.length, 0);
  assert.equal(live.state(), "offline");
  engine.halted = null;
  engine.emit({ kind: "syncing" });
  await settle();
  assert.equal(api.calls.length, 1);
  // A replaced engine is no longer listened to.
  const next = stoppable();
  sync.announce(next);
  await settle();
  assert.equal(engine.listening, 0);
  assert.equal(next.listening, 1);
  sync.announce(null); // ends the stream, whose timers would keep the process alive
});
