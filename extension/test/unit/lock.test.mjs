import assert from "node:assert/strict";
import { test } from "node:test";
import { CORE_OPS, createCoreHost } from "../../src/background/coreHost.mjs";
import { ALARM_NAME, LOCK_AT_KEY, LOCK_EXEMPT, createLock } from "../../src/background/lock.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createSessionStorage } from "./backgroundHelpers.mjs";

const MINUTE = 60_000;

/** The deadline in the session storage, once the writes that are queued have run. */
async function deadline(/** @type {ReturnType<typeof createSessionStorage>} */ storage) {
  await new Promise((resolve) => setTimeout(resolve, 0));
  return /** @type {number | undefined} */ ((await storage.get(LOCK_AT_KEY))[LOCK_AT_KEY]);
}

const probes = Object.freeze({
  unlock_probe: {
    vault: false,
    run: async (/** @type {any} */ _client, /** @type {any} */ _args, /** @type {any} */ ctx) => {
      ctx.setUnlocked();
      return { ok: true };
    },
  },
});

/** A lock over the fakes, with the vault unlocked unless `unlocked` is false. */
async function setup({ unlocked = true, minutes = 15 } = {}) {
  const clock = createClock();
  const client = createFakeClient({ vault: { ferret_aaguid: () => new Uint8Array(16) } });
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops: probes, names: [...CORE_OPS, "unlock_probe"] });
  const storage = createSessionStorage();
  const events = createAlarmsAndIdle();
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: storage, now: clock.now, coreHost, minutes });
  if (unlocked) await coreHost.call("unlock_probe");
  return { clock, client, coreHost, storage, events, lock };
}

test("lock_at_in_the_past_locks_before_the_call_runs", async () => {
  const { clock, client, coreHost, storage, lock } = await setup();
  lock.touch();
  clock.advance(15 * MINUTE);
  assert.equal(await lock.checkOrLock("candidates"), false);
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1, "the worker was ended");
  assert.equal(storage.data.has(LOCK_AT_KEY), false, "the deadline is gone with the lock");
  // And the call that follows is refused.
  assert.equal(await lock.checkOrLock("candidates"), false);
});

test("a_deadline_that_has_not_passed_lets_the_call_through", async () => {
  const { clock, coreHost, lock } = await setup();
  lock.touch();
  clock.advance(15 * MINUTE - 1);
  assert.equal(await lock.checkOrLock("candidates"), true);
  assert.equal(coreHost.state(), "unlocked");
});

test("a_missing_lock_at_after_a_restart_means_locked", async () => {
  // The page restarted: nothing in the session storage, and a vault that is open
  // anyway (a worker from before) is closed rather than trusted.
  const { client, coreHost, storage, lock } = await setup();
  assert.equal(storage.data.has(LOCK_AT_KEY), false);
  assert.equal(await lock.checkOrLock("search"), false);
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
});

test("a_lock_at_that_is_not_a_number_or_cannot_be_read_means_locked", async () => {
  for (const bad of ["soon", NaN, null, {}, [1]]) {
    const { coreHost, storage, lock } = await setup();
    storage.data.set(LOCK_AT_KEY, bad);
    assert.equal(await lock.checkOrLock("search"), false, String(bad));
    assert.equal(coreHost.state(), "locked");
  }
  const { coreHost, storage, lock } = await setup();
  lock.touch();
  await lock.checkOrLock("state");
  storage.broken = true;
  assert.equal(await lock.checkOrLock("search"), false);
  assert.equal(coreHost.state(), "locked");
});

test("a_locked_vault_refuses_without_locking_again", async () => {
  const { client, lock } = await setup({ unlocked: false });
  assert.equal(await lock.checkOrLock("candidates"), false);
  assert.equal(client.locks, 0);
});

test("unlock_is_allowed_while_locked_and_sets_lock_at", async () => {
  const { clock, storage, lock, coreHost } = await setup({ unlocked: false });
  assert.equal(coreHost.state(), "locked");
  for (const type of LOCK_EXEMPT) {
    assert.equal(await lock.checkOrLock(type), true, type);
  }
  assert.deepEqual([...LOCK_EXEMPT], ["sign_in", "unlock", "state", "settings", "lock"]);
  // The handler of an unlock touches the lock once the vault is open.
  await coreHost.call("unlock_probe");
  lock.touch();
  assert.equal((await deadline(storage)), clock.now() + 15 * MINUTE);
});

test("an_alarm_after_lock_at_locks", async () => {
  const { clock, client, coreHost, events, lock } = await setup();
  lock.touch();
  assert.equal(events.alarmList.get(ALARM_NAME)?.when, clock.now() + 15 * MINUTE);
  clock.advance(15 * MINUTE);
  await events.fireAlarm(ALARM_NAME);
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
  assert.equal(events.alarmList.has(ALARM_NAME), false, "the alarm is cleared with the lock");
});

test("an_alarm_before_lock_at_arms_again_and_another_alarm_is_ignored", async () => {
  const { clock, client, coreHost, events, lock } = await setup();
  lock.touch();
  const at = clock.now() + 15 * MINUTE;
  clock.advance(5 * MINUTE);
  events.alarmList.clear();
  await events.fireAlarm(ALARM_NAME);
  assert.equal(coreHost.state(), "unlocked");
  assert.equal(events.alarmList.get(ALARM_NAME)?.when, at);
  await events.fireAlarm("something-else");
  assert.equal(client.locks, 0);
});

test("an_alarm_with_no_lock_at_locks", async () => {
  const { coreHost, events } = await setup();
  await events.fireAlarm(ALARM_NAME);
  assert.equal(coreHost.state(), "locked");
});

test("idle_locked_locks", async () => {
  const { client, coreHost, events } = await setup();
  events.fireIdle("idle");
  events.fireIdle("active");
  assert.equal(coreHost.state(), "unlocked", "only the screen lock counts");
  events.fireIdle("locked");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
});

test("touch_moves_lock_at", async () => {
  const { clock, events, storage, lock } = await setup();
  lock.touch();
  const first = await deadline(storage);
  clock.advance(10 * MINUTE);
  lock.touch();
  const second = await deadline(storage);
  assert.equal(second, /** @type {number} */ (first) + 10 * MINUTE);
  assert.equal(events.alarmList.get(ALARM_NAME)?.when, second);
  // The check after the first deadline passed still lets the call through.
  clock.advance(10 * MINUTE);
  assert.equal(await lock.checkOrLock("candidates"), true);
});

test("set_minutes_changes_the_next_deadline_and_takes_one_to_480_only", async () => {
  const { clock, storage, lock } = await setup();
  lock.setMinutes(1);
  lock.touch();
  assert.equal((await deadline(storage)), clock.now() + MINUTE);
  lock.setMinutes(480);
  lock.touch();
  assert.equal((await deadline(storage)), clock.now() + 480 * MINUTE);
  for (const bad of [0, 481, -1, 1.5, NaN, Infinity, "15", null, undefined]) {
    assert.throws(() => lock.setMinutes(/** @type {any} */ (bad)), RangeError, String(bad));
  }
  assert.throws(() => createLock({ ...{ alarms: createAlarmsAndIdle().alarms, idle: createAlarmsAndIdle().idle, storageSession: createSessionStorage(), now: Date.now, coreHost: createCoreHost() }, minutes: 0 }), RangeError);
});

test("every_lock_clears_the_deadline_whatever_started_it", async () => {
  const { coreHost, events, storage, lock } = await setup();
  lock.touch();
  await storage.get(LOCK_AT_KEY);
  await coreHost.lock("manual");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(storage.data.has(LOCK_AT_KEY), false);
  assert.equal(events.alarmList.has(ALARM_NAME), false);
});

test("the_listeners_are_registered_while_the_lock_is_created", async () => {
  const { events } = await setup();
  assert.deepEqual(events.listenerCounts(), { alarm: 1, idle: 1 });
});
