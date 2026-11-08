// The sync service: the `onEngine` seam that parts which follow the engine use.
import assert from "node:assert/strict";
import { test } from "node:test";
import syncService from "../../src/services/sync.service.mjs";
import { ACCOUNT, VAULT } from "./idbHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, Model } from "./syncHelpers.mjs";

const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };

/** A service over fakes. `store` can be replaced to make the engine fail to start. */
async function service(overrides = {}) {
  const store = overrides.store ?? (await createFakeStore());
  const client = createFakeClient();
  const sync = syncService.create({ api: createFakeApi(new Model()), store, client: { vault: client.vault }, ...overrides });
  return { sync, store };
}

test("service_calls_on_engine_after_start_and_with_null_after_stop", async () => {
  const { sync } = await service();
  const calls = [];
  const off = sync.onEngine((engine) => calls.push(engine));
  assert.deepEqual(calls, [], "nothing before a start");

  const engine = await sync.start(scope);
  assert.equal(calls.length, 1);
  assert.equal(calls[0], engine, "the engine that started");
  assert.equal(sync.current(), engine);

  sync.stop();
  assert.equal(calls.length, 2);
  assert.equal(calls[1], null, "null after the stop");
  assert.equal(sync.current(), null);

  // A stop with nothing running says nothing.
  sync.stop();
  assert.equal(calls.length, 2);

  // Starting again over a running engine ends the old one first, then announces the new.
  const first = await sync.start(scope);
  const second = await sync.start(scope);
  assert.deepEqual(calls.slice(2), [first, null, second]);
  assert.notEqual(first, second);

  // A listener that has been removed hears nothing more.
  off();
  sync.stop();
  assert.equal(calls.length, 5);
});

test("on_engine_serves_several_listeners_and_survives_one_that_throws", async () => {
  const { sync } = await service();
  const seen = [];
  sync.onEngine(() => {
    throw new Error("a broken listener");
  });
  sync.onEngine((engine) => seen.push(engine === null ? "null" : "engine"));
  const unsubscribe = sync.onEngine((engine) => seen.push(engine === null ? "second:null" : "second:engine"));
  await sync.start(scope);
  assert.deepEqual(seen, ["engine", "second:engine"]);
  unsubscribe();
  sync.stop();
  assert.deepEqual(seen, ["engine", "second:engine", "null"]);
});

test("a_failed_start_does_not_call_on_engine", async () => {
  const good = await createFakeStore();
  const failing = { ...good, open: async () => { throw new Error("the database is closed"); } };
  const { sync } = await service({ store: failing });
  const calls = [];
  sync.onEngine((engine) => calls.push(engine));

  await assert.rejects(() => sync.start(scope), /the database is closed/);
  assert.deepEqual(calls, [], "no engine was announced, and none was ended");
  assert.equal(sync.current(), null);
  sync.stop();
  assert.deepEqual(calls, []);
});

test("a_stop_during_a_start_does_not_announce_the_engine", async () => {
  const good = await createFakeStore();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const slow = { ...good, open: async () => { await gate; return good.open(); } };
  const { sync } = await service({ store: slow });
  const calls = [];
  sync.onEngine((engine) => calls.push(engine));

  const starting = sync.start(scope);
  sync.stop();
  release();
  await starting.catch(() => {});
  assert.deepEqual(calls, [], "the engine was stopped before it was ready");
  assert.equal(sync.current(), null);
});
