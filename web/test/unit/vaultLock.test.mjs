// The idle lock is armed where the vault opens: on the account session's sync
// seam, so every path that unlocks has a timer, whichever page the user is on,
// and a lock disarms it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import vaultLock from "../../src/services/vaultLock.service.mjs";
import { ACCOUNT, EMAIL, PASSWORD, RK_CODE, SK_CODE, VAULT, coded, scenario } from "./accountHelpers.mjs";
import { fakeClock, fakePage, settle } from "./vaultHelpers.mjs";

const IDLE = 60_000;

/** The account session over fakes, the lock service on its seam, and an idle lock on a fake clock. */
async function rig({ startFails = false, skBit = false } = {}) {
  const world = await scenario({ skBit });
  const events = [];
  const sync = {
    started: [],
    start: async (scope) => {
      events.push("sync.start");
      sync.started.push(scope);
      if (startFails) throw coded("storage");
    },
    stop: () => void events.push("sync.stop"),
  };
  const clock = fakeClock();
  // The idle lock the service finds for this session; it uses the test's clock.
  const lock = autoLockFor(world.session, sync, { now: clock.now, timers: clock, doc: fakePage(), idleMs: IDLE });
  vaultLock.create({ crypto: world.session, sync });
  return { ...world, sync, clock, lock, events };
}

const signIn = (r) => r.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false });

test("a_sign_in_that_stays_on_a_page_outside_the_vault_has_an_armed_idle_lock", async () => {
  // The sign-in page, or a sign-in whose hand-over to the admin pages failed: no vault route is entered.
  const r = await rig();
  assert.equal(r.lock.running(), false, "nothing is armed before the vault opens");
  await signIn(r);
  assert.ok(r.session.current());
  assert.equal(r.lock.running(), true);
  assert.deepEqual(r.sync.started, [{ accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 }]);

  r.clock.advance(IDLE - 1);
  assert.ok(r.session.current(), "still open just before the idle time");
  r.clock.advance(1);
  await settle();
  assert.equal(r.session.current(), null, "the idle time locked the session");
  assert.ok(r.events.includes("sync.stop"), "and stopped the sync engine");
});

test("the_setup_done_page_has_an_armed_idle_lock", async () => {
  const r = await rig({ skBit: true });
  const flow = await r.session.register({ email: EMAIL, password: PASSWORD, setupToken: "setup-token-1" });
  assert.equal(r.lock.running(), false, "nothing is open before the sheet is confirmed");
  await flow.confirm(RK_CODE, SK_CODE);
  await flow.finish();
  assert.ok(r.session.current());
  assert.equal(r.lock.running(), true, "the done page has a timer");
  r.clock.advance(IDLE);
  await settle();
  assert.equal(r.session.current(), null);
});

test("an_unlock_on_the_sign_in_page_arms_the_idle_lock_again", async () => {
  const r = await rig();
  await signIn(r);
  await r.session.lock();
  assert.equal(r.lock.running(), false, "a lock disarms the timer");
  assert.equal(r.clock.pending, 0, "and leaves none behind");

  await r.session.unlock({ password: PASSWORD });
  assert.ok(r.session.current());
  assert.equal(r.lock.running(), true);
  r.clock.advance(IDLE);
  await settle();
  assert.equal(r.session.current(), null);
});

test("the_idle_lock_is_armed_even_when_the_sync_engine_cannot_start", async () => {
  const r = await rig({ startFails: true });
  await signIn(r);
  assert.ok(r.session.current(), "the sign-in is not undone by a sync failure");
  assert.equal(r.lock.running(), true);
  assert.equal(r.events[0], "sync.start", "sync was tried");
  r.clock.advance(IDLE);
  await settle();
  assert.equal(r.session.current(), null);
});

test("activity_moves_the_idle_time_on_and_a_sign_out_disarms_it", async () => {
  const r = await rig();
  await signIn(r);
  r.clock.advance(IDLE - 1_000);
  assert.equal(r.lock.touch(), true);
  r.clock.advance(IDLE - 1_000);
  assert.ok(r.session.current(), "the touch moved the lock time on");
  await r.session.signOut().catch(() => undefined);
  assert.equal(r.lock.running(), false);
  assert.equal(r.clock.pending, 0);
});
