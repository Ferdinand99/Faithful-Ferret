// The browser extension's write path (extension/src/background/offerWrite.mjs)
// over this repository's sync engine, which the extension ships unchanged: a
// new login saved while the engine is stopped goes into the outbox, is
// kept there, sends nothing, and is answered as pending.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createOfferWriter } from "../../../extension/src/background/offerWrite.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { createSyncEngine, SyncError } from "../../src/sync/engine.mjs";
import { memoryStore, unavailableMemory } from "../../src/sync/memory.mjs";
import { ACCOUNT, scope, SERVER } from "./idbHelpers.mjs";
import { counterRand, createFakeApi, createFakeClient, createFakeStore, FakeTimers, Model, settle } from "./syncHelpers.mjs";

const ORIGIN = "https://login.example.net";
const capture = {
  tabId: 1, frameId: 0, frameUrl: `${ORIGIN}/signin`, origin: ORIGIN, kind: "login", username: "ola", usernameFrom: "typed",
  password: "New-PASSWORD-typed", currentPassword: null, generated: false,
};

/** The fake core of the engine tests, with the page functions the writer reads. @param {any} client */
function writerCore(client) {
  return {
    ...client.vault,
    page_origin: async (/** @type {string} */ url) => new URL(url).origin,
    display_host: async (/** @type {string} */ url) => ({ a_label: new URL(url).hostname, unicode: new URL(url).hostname }),
  };
}

test("a_write_while_the_engine_is_halted_stays_in_the_outbox_and_says_pending", async () => {
  const model = new Model();
  const client = createFakeClient();
  const store = await createFakeStore();
  // A browser without Web Locks: the engine has no memory and stops (`unsupported`) until the user acts.
  let error;
  try {
    memoryStore({ store, serverUrl: SERVER, accountId: ACCOUNT, locks: null });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof SyncError);
  const api = createFakeApi(model);
  const timers = new FakeTimers();
  const engine = createSyncEngine({ api, client: { vault: client.vault }, store, scope: scope(), memory: unavailableMemory(error), timers, rand: counterRand(3), now: () => 1_700_000_000_000 + timers.time });
  await engine.start();
  assert.equal(engine.health().halted, "unsupported");

  const writer = createOfferWriter({ engine, liveClient: { vault: writerCore(client) } });
  const saved = await writer.save(capture, { name: "Example", username: "ola", folder: "Work" });
  assert.equal(saved.pending, true);
  await settle();
  assert.equal(api.puts.length, 0, "nothing was sent");
  const queued = await outbox.all(store.database.store, scope());
  assert.equal(queued.length, 1, "the write is kept in the outbox");
  assert.equal(queued[0].itemId, saved.id);
  const summary = engine.list().find((s) => s.id === saved.id);
  assert.equal(summary?.pending, true);
  assert.deepEqual(summary?.folders, ["Work"]);
  engine.stop();
});
