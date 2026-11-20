// The hand-over of the vault between the tabs of one browser: "Use here" asks the owner whether it holds changes that are not
// saved (a yes or a no, and a warning when it says yes or says nothing within a second), and the tabs that wait stand in the
// queue of the lock, so that locking, signing out or closing the owner tab gives the vault to the first one that is unlocked and
// in view.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ANSWER_WITHIN_MS, CLAIM_MS, createOwner } from "../../src/sync/owner.mjs";
import { serverKey } from "../../src/store/idb.mjs";
import { ACCOUNT, SERVER } from "./idbHelpers.mjs";
import { FakeChannels, FakeLocks, FakeTimers, settle, until } from "./syncHelpers.mjs";
import { browser, form, NAME, scope } from "./tabHelpers.mjs";

const SECRET = "typed-secret-NOT-SAVED-9f3";

test("use_here_asks_the_owner_about_unsaved_edits_and_warns", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  await one.sync.start(scope);
  await two.sync.start(scope);

  // The owner holds no edits: the answer is a plain "no", and the lock may move on.
  assert.equal(await two.sync.askOwner(), "clear");

  // The owner has a form with edits that are not saved: the answer is "yes", which the screen turns into a warning.
  const open = form("new", { dirty: true });
  const forget = one.sync.trackUnsaved(open);
  assert.equal(one.sync.hasUnsaved(), true);
  assert.equal(await two.sync.askOwner(), "unsaved");

  // Only a yes or a no goes over the channel: not a name, not a field, not a byte of the form.
  const sent = b.channels.posted.filter((p) => p.name === NAME);
  assert.ok(sent.some((p) => p.data.type === "unsaved?"), "the question was asked");
  const answers = sent.filter((p) => p.data.type === "unsaved");
  assert.ok(answers.length >= 2);
  for (const answer of answers) assert.deepEqual(Object.keys(answer.data).sort(), ["dirty", "nonce", "to", "type"]);
  assert.ok(!JSON.stringify(sent).includes(SECRET));

  // A form that was saved (or wiped, or left) is no longer unsaved.
  forget();
  assert.equal(await two.sync.askOwner(), "clear");
  // A form that cannot tell counts as having edits.
  one.sync.trackUnsaved({ ...form(), dirty: () => { throw new Error("broken"); } });
  assert.equal(await two.sync.askOwner(), "unsaved");

  // Asking moved nothing: the owner still holds the lock and runs its engine.
  assert.ok(one.sync.current());
  assert.equal(two.sync.standby(), true);
  b.stopAll();
});

test("no_answer_within_a_second_also_warns", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  await one.sync.start(scope);
  await two.sync.start(scope);
  one.sync.trackUnsaved(form());
  for (const channel of b.channels.all) if (channel.listeners.size > 0 && channel.name === NAME) channel.muted = true; // the owner tab is frozen

  let answer = null;
  const asking = two.sync.askOwner().then((value) => { answer = value; });
  await settle(10);
  b.clock.advance(ANSWER_WITHIN_MS - 1);
  await settle(10);
  assert.equal(answer, null, "the owner is given a second");
  b.clock.advance(1);
  await asking;
  assert.equal(answer, "no_answer", "then it counts like a yes: the user is warned");
  assert.equal(two.sync.standby(), true, "nothing moved");

  // An owner that is gone (its lock was let go) is not a warning: the lock is simply taken.
  one.sync.stop();
  await settle(10);
  b.stopAll();
});

test("asking_when_nobody_holds_the_vault_takes_it_without_a_warning", async () => {
  const b = await browser();
  const one = await b.tab();
  const away = await b.tab({ visible: false }); // a tab that was out of view never stood in the queue
  await one.sync.start(scope);
  await away.sync.start(scope);
  assert.equal(away.sync.standby(), true);
  one.sync.stop(); // the owner goes: nobody holds the lock, and nobody is in the queue
  await settle(20);
  assert.equal(b.locks.held.has(NAME), false);
  assert.equal(await away.sync.askOwner(), "free", "no owner to ask, so no warning");
  const engine = await away.sync.takeOver();
  assert.ok(engine);
  assert.equal(away.sync.standby(), false);
  b.stopAll();
});

test("locking_or_signing_out_the_owner_hands_the_lock_to_a_waiting_tab", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const three = await b.tab();
  await one.sync.start(scope);
  await two.sync.start(scope);
  await three.sync.start(scope);
  assert.equal(two.sync.standby(), true);
  assert.equal(three.sync.standby(), true);

  // The owner locks (or signs out: both stop the service): the first tab in the queue gets the lock and runs the engine.
  one.sync.stop();
  await until(() => two.standby.length === 2, "the first waiting tab starts its engine");
  assert.equal(two.sync.standby(), false);
  assert.deepEqual(two.standby, [true, false]);
  assert.equal(three.sync.current(), null, "the second waiting tab goes on waiting");
  assert.equal(three.sync.standby(), true);
  assert.equal(one.sync.current(), null);
  assert.equal(b.locks.held.has(NAME), true);

  // And again: the new owner signs out, and the next tab in the queue gets the vault.
  two.sync.stop();
  await until(() => three.sync.current() !== null, "the next waiting tab starts its engine");
  assert.equal(three.sync.standby(), false);

  // The page of the owner closes: the engine stops, and the lock goes on to the tab that waits.
  const four = await b.tab();
  await four.sync.start(scope);
  assert.equal(four.sync.standby(), true);
  three.win.fire("pagehide", { persisted: false });
  await until(() => four.sync.current() !== null, "a closed owner page hands the lock on");
  b.stopAll();
});

test("a_waiting_tab_starts_its_engine_only_when_unlocked_and_visible", async () => {
  const b = await browser();
  const one = await b.tab();
  const hidden = await b.tab();
  const locked = await b.tab(); // a tab whose vault is locked never started the service for the account
  await one.sync.start(scope);
  await hidden.sync.start(scope);
  assert.equal(hidden.sync.standby(), true);
  hidden.doc.hide();
  await settle(5);
  const requests = b.locks.requests;

  one.sync.stop();
  await settle(30);
  // The lock reached the hidden tab, which did not start an engine and let the lock go on; the locked tab never asked.
  assert.equal(hidden.sync.current(), null, "a tab out of view does not start the engine");
  assert.equal(locked.sync.current(), null, "a locked tab does not start the engine");
  assert.equal(b.locks.held.has(NAME), false, "and nobody holds the lock meanwhile");
  assert.ok(b.locks.requests >= requests);
  assert.equal(locked.sync.standby(), false);

  // The tab comes into view: it asks again, gets the lock and starts the engine.
  hidden.doc.show();
  await until(() => hidden.standby.length === 2, "the tab in view starts its engine");
  assert.equal(hidden.sync.standby(), false);
  assert.deepEqual(hidden.standby, [true, false]);

  // A locked tab that unlocks later finds the lock held and goes on standby.
  assert.equal(await locked.sync.start(scope), null);
  assert.equal(locked.sync.standby(), true);

  // A tab that locks while it waits leaves the queue: when the owner locks, the lock goes to the next one.
  const waitsThenLocks = await b.tab();
  const last = await b.tab();
  await waitsThenLocks.sync.start(scope);
  await last.sync.start(scope);
  waitsThenLocks.sync.stop();
  hidden.sync.stop();
  await until(() => locked.sync.current() !== null || last.sync.current() !== null, "a waiting tab gets the vault");
  assert.equal(waitsThenLocks.sync.current(), null, "the tab that locked did not take the vault");
  b.stopAll();
});

test("the_tab_that_asks_for_the_vault_ends_up_with_it_whatever_the_queue_looks_like", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  const three = await b.tab();
  await one.sync.start(scope);
  await two.sync.start(scope); // first in the queue
  await three.sync.start(scope);

  // The third tab presses "Use here". The lock may go to the tab ahead of it first (which then passes it on, or is stood
  // up to after the wait of about three seconds); either way the tab that asked is the one that runs the engine.
  assert.equal(await three.sync.askOwner(), "clear");
  const taking = three.sync.takeOver();
  for (let turn = 0; turn < 10; turn += 1) {
    await settle(10);
    b.clock.advance(500);
  }
  const engine = await taking;
  assert.ok(engine, "the tab that asked has the engine");
  assert.equal(three.sync.standby(), false);
  await settle(20);
  assert.equal(two.sync.current(), null, "the tab that waited ahead of it has none");
  assert.equal(two.sync.standby(), true);
  assert.equal(one.sync.standby(), true);
  assert.equal(b.locks.held.has(NAME), true);

  // The tabs that gave way stand in the queue again: when the new owner locks, one of them gets the vault.
  three.sync.stop();
  for (let turn = 0; turn < 10 && two.sync.current() === null && one.sync.current() === null; turn += 1) {
    await settle(10);
    b.clock.advance(500);
  }
  assert.ok(two.sync.current() !== null || one.sync.current() !== null, "a waiting tab gets the vault");
  b.stopAll();
});

test("a_waiting_tab_passes_a_grant_on_to_a_tab_that_asked_for_the_lock", async () => {
  const locks = new FakeLocks();
  const channels = new FakeChannels();
  const clock = new FakeTimers();
  const timers = { setTimeout: clock.set, clearTimeout: clock.clear };
  const make = (tabId) => createOwner({ locks, server: serverKey(SERVER), accountId: ACCOUNT, timers, tabId, makeChannel: () => channels.channel(NAME) });
  const owner = make("owner");
  const waiter = make("waiter");
  assert.equal(await owner.acquire(), "owner");
  assert.equal(await waiter.acquire(), "standby");
  for (const channel of channels.all) channel.muted = true; // the owner does not answer "yield": it lets go when the test says

  let result = null;
  const waiting = waiter.wait().then((value) => { result = value; });
  await settle(5);
  // Another tab asks for the lock (its request stands in the queue behind the waiter's)...
  let claimantHolds = false;
  channels.channel(NAME).postMessage({ type: "yield", from: "claimant" });
  void locks.request(NAME, async () => {
    claimantHolds = true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
  await settle(5);
  // ...and the owner lets go: the waiter is granted the lock first, sees that someone asked, and passes it on.
  owner.release();
  await settle(20);
  assert.equal(claimantHolds, true, "the tab that asked got the lock");
  assert.equal(result, null, "the waiter did not take it");
  assert.equal(waiter.isOwner(), false);

  // Once the claim has run out the waiter is in the queue again and takes the lock when it is free.
  clock.advance(CLAIM_MS);
  await settle(20);
  clock.advance(500);
  await waiting;
  assert.equal(result, "granted");
  assert.equal(waiter.isOwner(), true);
  waiter.release();
});

test("an_owner_that_goes_while_the_question_is_asked_hands_the_vault_to_the_waiting_tab", async () => {
  const b = await browser();
  const one = await b.tab();
  const two = await b.tab();
  await one.sync.start(scope);
  await two.sync.start(scope);
  assert.equal(await two.sync.askOwner(), "clear");
  one.sync.stop(); // the owner goes after it answered
  await until(() => two.sync.current() !== null, "the waiting tab got the vault");
  b.stopAll();
});
