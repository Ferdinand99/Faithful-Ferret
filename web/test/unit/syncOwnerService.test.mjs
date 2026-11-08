// The sync service with the owner lock: of the tabs of one browser one runs the engine, the others are on standby; "Use here"
// moves the engine; the lock is let go on lock, sign-out and when the page goes away.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import syncService from "../../src/services/sync.service.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { ownerName, STEAL_AFTER_MS } from "../../src/sync/owner.mjs";
import { serverKey } from "../../src/store/idb.mjs";
import { EMAIL, PASSWORD, scenario } from "./accountHelpers.mjs";
import { ACCOUNT, freshStore, scope as storeScope, SERVER, VAULT } from "./idbHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, FakeChannels, FakeLocks, FakeTimers, Model, settle, until } from "./syncHelpers.mjs";

const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };
const NAME = ownerName(serverKey(SERVER), ACCOUNT);

/** A browser: the storage, the locks and the channels that its tabs share, one server, and a clock for the wait. */
async function browser() {
  const db = await freshStore();
  const locks = new FakeLocks();
  const channels = new FakeChannels();
  const clock = new FakeTimers();
  const model = new Model();
  const client = createFakeClient();
  const tabs = [];
  /** A tab: its own service, api, store (over the shared storage) and window. */
  async function tab(options = {}) {
    const listeners = new Map();
    const win = {
      addEventListener: (type, fn) => listeners.set(type, fn),
      fire: (type, event = {}) => listeners.get(type)?.(event),
    };
    const api = createFakeApi(model);
    const store = await createFakeStore({ db });
    const sync = syncService.create({
      api, store, client: { vault: client.vault }, serverUrl: SERVER, locks: options.locks ?? locks, nav: { userAgent: "" }, win,
      makeChannel: (name) => channels.channel(name), timers: { setTimeout: clock.set, clearTimeout: clock.clear }, tabId: `tab-${tabs.length + 1}`,
    });
    const standby = [];
    sync.onStandby((on) => standby.push(on));
    const one = { sync, api, store, win, standby };
    tabs.push(one);
    return one;
  }
  const stopAll = () => tabs.forEach((t) => t.sync.stop());
  return { db, locks, channels, clock, model, client, tab, stopAll };
}

const draft = (name) => ({ item_type: "login", name });
const held = (b) => b.locks.held.has(NAME);

test("a_second_tab_does_not_start_an_engine_and_shows_the_notice", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const engine = await one.sync.start(scope);
  assert.ok(engine, "the first tab runs the engine");
  assert.equal(one.sync.standby(), false);

  const answer = await two.sync.start(scope);
  assert.equal(answer, null, "no engine in the second tab");
  assert.equal(two.sync.current(), null);
  assert.equal(two.sync.standby(), true, "the notice is what the second tab shows");
  assert.deepEqual(two.standby, [true]);
  assert.equal(two.api.gets.length, 0, "nothing was asked of the server");
  assert.equal(two.api.puts.length, 0);
  assert.deepEqual(two.store.spy.log, [], "nothing was read into or written to the stores of the account");
  assert.deepEqual(two.store.spy.settings, [], "the listing note and the flags are the owner's alone");
  assert.equal(two.store.spy.states.length, 0, "and so is the sync memory");

  // A second start of the standby tab (another screen opening) stays on standby and starts nothing.
  assert.equal(await two.sync.start(scope), null);
  assert.equal(two.sync.standby(), true);
  assert.equal(two.sync.current(), null);
  b.stopAll();
});

test("the_standby_tab_never_writes_the_listing_note_or_the_flags_while_the_owner_does", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const id = "ab".repeat(16);
  b.model.set(id, { rev: 1, ...b.client.wireRow(id, 1, { item_type: "login", name: "row" }) });
  const engine = await one.sync.start(scope);
  await two.sync.start(scope);
  await engine.syncNow();
  await settle(20);
  assert.equal(engine.list().length, 1);
  const keyed = (tab) => tab.store.spy.settings.map(([key]) => key);
  assert.deepEqual(keyed(two).filter((key) => key.includes(".listing") || key.includes("flags")), []);
  assert.deepEqual(two.store.spy.log, []);
  b.stopAll();
});

test("use_here_moves_the_engine_and_the_first_tab_stops_without_losing_a_queued_write", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const first = await one.sync.start(scope);
  await two.sync.start(scope);
  await settle(10);

  // The write is made while the server cannot be reached, so it waits in the outbox of the browser.
  one.api.put = async () => {
    throw new ApiError(0, "network");
  };
  const id = await first.create(draft("written offline"));
  await settle(20);
  assert.equal(b.model.items.size, 0, "the server has not got it");
  assert.equal((await outbox.all(b.db.store, storeScope())).length, 1, "it waits in the outbox");

  const second = await two.sync.takeOver();
  assert.ok(second, "the engine is here now");
  assert.equal(two.sync.standby(), false);
  assert.equal(two.sync.current(), second);
  assert.equal(one.sync.current(), null, "the first tab has no engine");
  assert.equal(one.sync.standby(), true, "and shows the notice");
  assert.deepEqual(one.standby, [true]);
  assert.deepEqual(two.standby, [true, false]);
  assert.equal(held(b), true, "the lock is held by the new owner");

  await until(() => b.model.items.get(id)?.rev === 1, "the write reaches the server");
  assert.equal(b.model.items.size, 1, "once");
  await until(async () => (await outbox.all(b.db.store, storeScope())).length === 0, "the outbox is emptied");
  assert.deepEqual(second.list().map((item) => item.name), ["written offline"]);
  assert.equal(first.list().length, 0, "the stopped engine shows nothing");
  b.stopAll();
});

test("use_here_in_the_tab_that_just_gave_the_vault_up_takes_it_back", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  await one.sync.start(scope);
  await two.sync.start(scope);
  await two.sync.takeOver();
  const back = await one.sync.takeOver();
  assert.ok(back);
  assert.equal(one.sync.current(), back);
  assert.equal(two.sync.current(), null);
  assert.equal(two.sync.standby(), true);
  b.stopAll();
});

test("use_here_in_a_tab_that_is_not_on_standby_is_refused", async () => {
  const b = await browser();
  const one = await b.tab();
  await one.sync.start(scope);
  await assert.rejects(() => one.sync.takeOver(), (error) => error.code === "invalid_state");
  b.stopAll();
});

test("steal_after_timeout_when_the_owner_does_not_answer", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  await one.sync.start(scope);
  await two.sync.start(scope);
  for (const channel of b.channels.all) if (channel.listeners.size > 0) channel.muted = true; // the owner tab is frozen
  let done = null;
  const taking = two.sync.takeOver().then((engine) => { done = engine; });
  await settle(10);
  b.clock.advance(STEAL_AFTER_MS - 1);
  await settle(10);
  assert.equal(done, null, "the owner is given about three seconds");
  assert.equal(two.sync.standby(), true);
  b.clock.advance(1);
  await taking;
  assert.ok(done, "then the lock is taken, and the engine starts here");
  await settle(5);
  assert.equal(one.sync.current(), null, "the old owner lost it and stopped its engine");
  assert.equal(one.sync.standby(), true);
  assert.equal(two.sync.current(), done);
  b.stopAll();
});

test("the_owner_lock_is_released_on_lock_sign_out_and_pagehide", async () => {
  // Lock and sign-out through the account session, whose seam calls the service.
  const b = await browser();
  const one = await b.tab();
  const world = await scenario({ skBit: false, sync: one.sync });
  await world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false });
  assert.ok(one.sync.current(), "the sign-in opened the vault and started the engine");
  assert.equal(held(b), true);
  await world.session.lock();
  await settle(5);
  assert.equal(held(b), false, "lock lets go of the lock");
  assert.equal(one.sync.current(), null);

  await world.session.unlock({ password: PASSWORD });
  assert.equal(held(b), true, "and the next unlock takes it again, at once");
  await world.session.signOut();
  await settle(5);
  assert.equal(held(b), false, "sign-out lets go of the lock");

  // The page goes away: the engine stops, the lock is let go, the tab is on standby.
  const two = await b.tab();
  await two.sync.start(scope);
  assert.equal(held(b), true);
  two.win.fire("pagehide", { persisted: false });
  await settle(5);
  assert.equal(held(b), false, "pagehide lets go of the lock");
  assert.equal(two.sync.current(), null);
  assert.equal(two.sync.standby(), true, "a page that comes back from the cache shows the notice");
  // ... and the button works from there: the lock is free, so it is taken at once.
  const back = await two.sync.takeOver();
  assert.ok(back);
  assert.equal(held(b), true);
  b.stopAll();
});

test("the_lock_is_let_go_by_stop_and_a_start_right_after_it_gets_the_lock_again", async () => {
  const b = await browser();
  const one = await b.tab();
  await one.sync.start(scope);
  one.sync.stop();
  const again = await one.sync.start(scope); // no wait between: the release is waited for, not lost
  assert.ok(again, "the tab is not on standby because of its own lock");
  assert.equal(one.sync.standby(), false);
  b.stopAll();
});

test("a_start_right_after_another_start_is_one_start_and_the_tab_is_not_on_standby", async () => {
  const b = await browser();
  const one = await b.tab();
  // The unlock starts the engine and the screen that opens asks for it too, at the same time.
  const [first, second] = await Promise.all([one.sync.start(scope), one.sync.start(scope)]);
  assert.equal(one.sync.standby(), false);
  assert.equal(one.sync.current(), second ?? first);
  assert.ok(second, "the last start wins");
  b.stopAll();
});

test("a_pagehide_while_the_lock_is_asked_for_starts_no_engine_and_use_here_starts_exactly_one", async () => {
  const b = await browser();
  // The lock request is answered late, as on a busy page.
  let open;
  const gate = new Promise((resolve) => { open = resolve; });
  const slow = { request: async (...args) => { await gate; return b.locks.request(...args); } };
  const one = await b.tab({ locks: slow });
  const engines = [];
  one.sync.onEngine((engine) => engines.push(engine));
  const starting = one.sync.start(scope);
  await settle(5);
  one.win.fire("pagehide", { persisted: true });
  open();
  assert.equal(await starting, null, "the start gives no engine to a page that has gone");
  await settle(10);
  assert.equal(one.sync.current(), null);
  assert.equal(one.sync.standby(), true, "the page shows the notice when it comes back");
  assert.equal(held(b), false, "and holds no lock");
  assert.deepEqual(engines, [], "no engine ran meanwhile");
  assert.equal(one.api.gets.length, 0, "nothing was asked of the server");
  const back = await one.sync.takeOver();
  assert.ok(back);
  assert.equal(one.sync.current(), back);
  assert.deepEqual(engines, [back], "exactly one engine");
  assert.equal(held(b), true);
  b.stopAll();
});

test("use_here_never_leaves_a_running_engine_behind_in_the_same_tab", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const first = await one.sync.start(scope);
  await two.sync.start(scope);
  one.sync.stop(); // the vault is locked in the first tab, the lock is free: the second takes it at once
  const taken = await two.sync.takeOver();
  assert.ok(taken && first);
  await settle(5);
  assert.equal(two.sync.current(), taken);
  b.stopAll();
});

test("a_stop_while_the_lock_is_asked_for_leaves_no_lock_behind", async () => {
  const b = await browser();
  const one = await b.tab();
  const starting = one.sync.start(scope);
  one.sync.stop();
  assert.equal(await starting, null);
  await settle(10);
  assert.equal(held(b), false);
  assert.equal(one.sync.current(), null);
  assert.equal(one.sync.standby(), false);
});

test("a_failed_engine_start_lets_go_of_the_lock_so_another_tab_can_run_it", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const open = one.store.open;
  one.store.open = async () => {
    throw new Error("the database is closed");
  };
  await assert.rejects(() => one.sync.start(scope), /the database is closed/);
  await settle(5);
  assert.equal(held(b), false);
  assert.ok(await two.sync.start(scope), "the other tab can have the vault");
  one.store.open = open;
  b.stopAll();
});

test("without_web_locks_the_engine_is_made_and_halts_by_itself", async () => {
  const client = createFakeClient();
  const sync = syncService.create({
    api: createFakeApi(new Model()), store: await createFakeStore(), client: { vault: client.vault }, serverUrl: SERVER, locks: null, nav: { userAgent: "" },
  });
  try {
    const engine = await sync.start(scope);
    assert.ok(engine, "an engine is made, so the screens work on what is stored");
    assert.equal(engine.health().halted, "unsupported");
    assert.equal(sync.standby(), false);
  } finally {
    sync.stop();
  }
});
