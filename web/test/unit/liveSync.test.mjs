// The live-update service: it follows the sync engine. An engine that has
// started gets a channel; the end of the engine ends the channel; an event makes
// the engine read the feed.
import assert from "node:assert/strict";
import { test } from "node:test";
import liveSyncService from "../../src/services/liveSync.service.mjs";
import syncService from "../../src/services/sync.service.mjs";
import { ACCOUNT, VAULT } from "./idbHelpers.mjs";
import { fakeStreamApi } from "./liveHelpers.mjs";
import { settle } from "./vaultHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, Model } from "./syncHelpers.mjs";

/** A sync service that tells its listeners what the test says, with an engine that counts its reads. */
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

function fakeEngine() {
  const engine = {
    reads: 0,
    syncNow() {
      engine.reads += 1;
      return Promise.resolve();
    },
  };
  return engine;
}

test("channel_follows_the_engine_lifecycle", async () => {
  const api = fakeStreamApi();
  const sync = fakeSync();
  const live = liveSyncService.create({ api, sync });
  const states = [];
  live.on("state", (state) => states.push(state));
  assert.equal(live.state(), "offline", "no engine, no channel");
  assert.equal(api.calls.length, 0);

  // An engine has started: the stream opens, and the hello makes the engine read.
  const first = fakeEngine();
  sync.announce(first);
  await settle();
  assert.equal(api.calls.length, 1);
  assert.equal(api.calls[0].path, "/api/sync/events");
  assert.equal(live.state(), "connecting");
  api.last.hello(4);
  await settle();
  assert.equal(live.state(), "live");
  assert.equal(first.reads, 1);
  api.last.sync(5);
  api.last.comment();
  await settle();
  assert.equal(first.reads, 2, "a sync event reads, a comment does not");

  // A new engine replaces the old one: the old stream ends, a new one opens, only the new engine reads.
  const second = fakeEngine();
  sync.announce(second);
  await settle();
  assert.equal(api.connections[0].signal.aborted, true);
  assert.equal(api.calls.length, 2);
  api.last.hello(6);
  await settle();
  assert.equal(second.reads, 1);
  assert.equal(first.reads, 2);

  // The engine stops (the vault locks): the stream ends and nothing comes back.
  sync.announce(null);
  await settle();
  assert.equal(api.connections[1].signal.aborted, true);
  assert.equal(live.state(), "offline");
  assert.deepEqual(states, ["connecting", "live", "connecting", "live", "offline"]);
  assert.equal(api.calls.length, 2);
});

test("an_engine_that_is_running_when_the_service_is_made_gets_a_channel", async () => {
  // `onEngine` does not tell a late listener about a running engine: the service asks `current()`.
  const api = fakeStreamApi();
  const engine = fakeEngine();
  const sync = fakeSync(engine);
  const live = liveSyncService.create({ api, sync });
  await settle();
  assert.equal(api.calls.length, 1);
  assert.equal(live.state(), "connecting");
  api.last.hello(1);
  await settle();
  assert.equal(engine.reads, 1);
  sync.announce(null);
  await settle();
  assert.equal(api.last.signal.aborted, true);
});

test("a_listener_that_throws_does_not_stop_the_others_and_unknown_events_are_refused", async () => {
  const api = fakeStreamApi();
  const sync = fakeSync();
  const live = liveSyncService.create({ api, sync });
  const seen = [];
  live.on("state", () => {
    throw new Error("a broken screen");
  });
  const off = live.on("state", (state) => seen.push(state));
  assert.throws(() => live.on("changed", () => {}), TypeError);
  sync.announce(fakeEngine());
  await settle();
  api.last.hello(1);
  await settle();
  assert.deepEqual(seen, ["connecting", "live"]);
  off();
  sync.announce(null);
  assert.deepEqual(seen, ["connecting", "live"], "a removed listener hears nothing more");
  assert.equal(live.state(), "offline");
});

test("the_service_follows_the_real_sync_service", async () => {
  // The real service over a fake store: start, a stream, a read on a sync event, stop.
  const store = await createFakeStore();
  const client = createFakeClient();
  const model = new Model();
  const streams = fakeStreamApi();
  const api = createFakeApi(model);
  api.stream = (path, options) => streams.stream(path, options);
  const sync = syncService.create({ api, store, client: { vault: client.vault } });
  const live = liveSyncService.create({ api, sync });
  try {
    const engine = await sync.start({ accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 });
    await settle();
    assert.equal(streams.calls.length, 1);
    const before = api.gets.length;
    streams.last.hello(1);
    await settle();
    assert.equal(live.state(), "live");
    assert.ok(api.gets.length > before, "the hello made the engine read the feed");
    const afterHello = api.gets.length;
    streams.last.sync(2);
    await settle();
    assert.ok(api.gets.length > afterHello, "a sync event reads again");
    assert.equal(sync.current(), engine);
  } finally {
    sync.stop();
  }
  await settle();
  assert.equal(live.state(), "offline");
  assert.equal(streams.last.signal.aborted, true);
});
