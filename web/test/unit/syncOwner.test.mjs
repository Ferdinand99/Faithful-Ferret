// The owner lock of a browser: one tab holds `ferret-sync-owner:<server>:<account>`, the others are on standby, and "use here"
// moves the lock (asks the owner first, takes it after about three seconds).
import assert from "node:assert/strict";
import { test } from "node:test";
import { createOwner, ownerName, STEAL_AFTER_MS } from "../../src/sync/owner.mjs";
import { ACCOUNT } from "./idbHelpers.mjs";
import { FakeChannels, FakeLocks, FakeTimers, settle } from "./syncHelpers.mjs";

const SERVER_KEY = "a".repeat(8);
const NAME = ownerName(SERVER_KEY, ACCOUNT);

/** A browser: one set of locks, one set of channels, and a clock for the wait. */
function browser() {
  const locks = new FakeLocks();
  const channels = new FakeChannels();
  const fake = new FakeTimers();
  const timers = { setTimeout: fake.set, clearTimeout: fake.clear };
  const log = [];
  /** A tab. `onYield` and `onLost` write to the log. */
  const tab = (id, { yields = null } = {}) => {
    const made = createOwner({
      locks, server: SERVER_KEY, accountId: ACCOUNT, tabId: id, timers,
      makeChannel: channels.maker(NAME),
      onYield: async () => {
        log.push(`${id}:yield`);
        await yields?.();
        log.push(`${id}:stopped`);
      },
      onLost: () => log.push(`${id}:lost`),
    });
    return made;
  };
  return { locks, channels, fake, log, tab };
}

test("the_first_tab_is_the_owner_and_a_second_tab_is_on_standby", async () => {
  const b = browser();
  const one = b.tab("one");
  const two = b.tab("two");
  assert.equal(await one.acquire(), "owner");
  assert.equal(await two.acquire(), "standby");
  assert.equal(one.isOwner(), true);
  assert.equal(two.isOwner(), false);
  assert.ok(b.locks.held.has(NAME));
});

test("a_browser_without_web_locks_is_its_own_owner_and_the_engine_halts_by_itself", async () => {
  const owner = createOwner({ locks: undefined, server: SERVER_KEY, accountId: ACCOUNT });
  assert.equal(await owner.acquire(), "owner");
  await owner.takeOver(); // nothing to take
  owner.release();
});

test("the_lock_is_free_again_after_a_release", async () => {
  const b = browser();
  const one = b.tab("one");
  const two = b.tab("two");
  await one.acquire();
  one.release();
  await settle(3);
  assert.equal(b.locks.held.has(NAME), false);
  assert.equal(await two.acquire(), "owner");
});

test("use_here_takes_the_lock_at_once_when_the_owner_tab_is_gone", async () => {
  const b = browser();
  const one = b.tab("one");
  const two = b.tab("two");
  await one.acquire();
  assert.equal(await two.acquire(), "standby");
  one.release(); // the page was closed
  await settle(3);
  await two.takeOver();
  assert.equal(two.isOwner(), true);
  assert.deepEqual(b.channels.posted, [], "nobody was asked");
  assert.deepEqual(b.log, []);
});

test("use_here_asks_the_owner_to_stop_first_and_gets_the_lock_when_it_has", async () => {
  const b = browser();
  const order = [];
  const one = b.tab("one", { yields: async () => { await settle(2); order.push("engine stopped"); } });
  const two = b.tab("two");
  await one.acquire();
  await two.acquire();
  await two.takeOver();
  assert.equal(two.isOwner(), true);
  assert.equal(one.isOwner(), false);
  assert.deepEqual(b.log, ["one:yield", "one:stopped"], "the owner stopped, and was not robbed");
  assert.deepEqual(order, ["engine stopped"]);
  assert.deepEqual(b.channels.posted.map((m) => m.data.type), ["yield"]);
  assert.equal(b.fake.pending, 0, "the wait for the answer was cleared");
});

test("the_lock_is_let_go_only_after_the_engine_has_stopped", async () => {
  const b = browser();
  let stopping;
  const gate = new Promise((resolve) => { stopping = resolve; });
  const one = b.tab("one", { yields: () => gate });
  const two = b.tab("two");
  await one.acquire();
  await two.acquire();
  let done = false;
  const taking = two.takeOver().then(() => { done = true; });
  await settle(10);
  assert.equal(done, false, "the owner has not finished stopping");
  assert.equal(two.isOwner(), false);
  stopping();
  await taking;
  assert.equal(two.isOwner(), true);
});

test("steal_after_timeout_when_the_owner_does_not_answer", async () => {
  const b = browser();
  const one = b.tab("one");
  const two = b.tab("two");
  await one.acquire();
  await two.acquire();
  for (const channel of b.channels.all) if (channel.listeners.size > 0) channel.muted = true; // the owner tab is frozen
  let done = false;
  const taking = two.takeOver().then(() => { done = true; });
  await settle(10);
  b.fake.advance(STEAL_AFTER_MS - 1);
  await settle(10);
  assert.equal(done, false, "not before about three seconds");
  assert.equal(two.isOwner(), false);
  b.fake.advance(1);
  await taking;
  assert.equal(two.isOwner(), true);
  await settle(5);
  assert.equal(one.isOwner(), false, "the old owner lost it");
  assert.deepEqual(b.log, ["one:lost"], "and is told, without having been asked to yield");
});

test("a_steal_is_the_last_resort_and_only_one_tab_holds_the_lock_afterwards", async () => {
  const b = browser();
  const one = b.tab("one");
  const two = b.tab("two");
  const three = b.tab("three");
  await one.acquire();
  await two.acquire();
  await three.acquire();
  for (const channel of b.channels.all) if (channel.listeners.size > 0) channel.muted = true;
  const taking = three.takeOver();
  await settle(10);
  b.fake.advance(STEAL_AFTER_MS);
  await taking;
  await settle(5);
  assert.deepEqual([one.isOwner(), two.isOwner(), three.isOwner()], [false, false, true]);
  assert.equal(await two.acquire(), "standby");
});

test("a_tab_that_lost_its_lock_can_use_it_again_and_the_other_tab_is_asked", async () => {
  const b = browser();
  const one = b.tab("one");
  const two = b.tab("two");
  await one.acquire();
  await two.acquire();
  await two.takeOver();
  await settle(5);
  await one.takeOver();
  assert.equal(one.isOwner(), true);
  assert.equal(two.isOwner(), false);
  assert.deepEqual(b.log, ["one:yield", "one:stopped", "two:yield", "two:stopped"]);
});

test("a_message_from_the_tab_itself_or_a_malformed_one_does_not_make_the_owner_yield", async () => {
  const b = browser();
  const one = b.tab("one");
  await one.acquire();
  const other = b.channels.channel(NAME);
  for (const data of [
    { type: "yield", from: "one" }, { type: "yield" }, { type: "yield", from: 7 }, { type: "other", from: "x" }, null, "yield", 7, [],
  ]) other.postMessage(data);
  await settle(10);
  assert.equal(one.isOwner(), true);
  assert.deepEqual(b.log, []);
  other.postMessage({ type: "yield", from: "stranger" });
  await settle(10);
  assert.equal(one.isOwner(), false, "a message from another tab is the real thing");
});

test("a_channel_that_cannot_be_made_still_ends_in_a_steal", async () => {
  const b = browser();
  const timers = { setTimeout: b.fake.set, clearTimeout: b.fake.clear };
  const one = createOwner({ locks: b.locks, server: SERVER_KEY, accountId: ACCOUNT, timers, makeChannel: () => { throw new Error("no channel"); }, tabId: "one" });
  const two = createOwner({ locks: b.locks, server: SERVER_KEY, accountId: ACCOUNT, timers, makeChannel: () => { throw new Error("no channel"); }, tabId: "two" });
  await one.acquire();
  await two.acquire();
  const taking = two.takeOver();
  await settle(10);
  b.fake.advance(STEAL_AFTER_MS);
  await taking;
  assert.equal(two.isOwner(), true);
  assert.equal(one.isOwner(), false);
});

test("the_lock_and_channel_name_has_the_server_and_the_account", () => {
  assert.equal(ownerName("s", ACCOUNT), `ferret-sync-owner:s:${ACCOUNT}`);
});
