// The lock end to end in the background, over a fake clock: the setting "Lock
// after" (the fixed choices, kept in storage.local), the deadline that only
// activity in Ferret's own pages moves, the three ways it is enforced (every
// message, the alarm, the page's timer), the idle and wake-up events, and the
// one handler of the lock button. The router, the lock, the core host and the
// real handlers are the real modules; the worker is a fake that records what
// reaches it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { CORE_OPS, createCoreHost } from "../../src/background/coreHost.mjs";
import lockHandler from "../../src/background/handlers/lock.handler.mjs";
import sessionHandler from "../../src/background/handlers/session.handler.mjs";
import settingsHandler from "../../src/background/handlers/settings.handler.mjs";
import syncHandler from "../../src/background/handlers/sync.handler.mjs";
import { ALARM_NAME, DEFAULT_LOCK_SECONDS, LOCK_AT_KEY, LOCK_CHOICES, RECHECK_MS, SETTING_KEY, createLock } from "../../src/background/lock.mjs";
import { createRouter } from "../../src/background/router.mjs";
import { UI_PORT, UI_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createFakeTimers, createPort, createSessionStorage } from "./backgroundHelpers.mjs";
import { contentScriptSender, createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";

const SECOND = 1000;
const turn = () => new Promise((resolve) => setTimeout(resolve, 0));

const probes = Object.freeze({
  unlock_probe: {
    vault: false,
    worker: /** @type {"none"} */ ("none"),
    run: async (/** @type {any} */ _client, /** @type {any} */ _args, /** @type {any} */ ctx) => {
      ctx.setUnlocked();
      return { ok: true };
    },
  },
  // An operation that needs the vault worker: it reaches the fake client, which records it.
  vault_probe: {
    vault: true,
    worker: /** @type {"vault"} */ ("vault"),
    run: async (/** @type {any} */ client) => ({ ok: true, aaguid: (await client.vault.ferret_aaguid()).length }),
  },
});

/**
 * The background's lock wiring over fakes. `stored` is what `storage.local` already holds (the setting of an earlier run).
 * @param {{ unlocked?: boolean, stored?: Record<string, unknown> }} [options]
 */
async function setup({ unlocked = true, stored = {} } = {}) {
  const fake = createFakeBrowser();
  const clock = createClock();
  const timers = createFakeTimers(clock);
  const client = createFakeClient({ vault: { ferret_aaguid: () => new Uint8Array(16) } });
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops: probes, names: [...CORE_OPS, "unlock_probe", "vault_probe"] });
  const storage = createSessionStorage();
  const local = createSessionStorage();
  for (const [key, value] of Object.entries(stored)) local.data.set(key, value);
  const events = createAlarmsAndIdle();
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: storage, storageLocal: local, timers, now: clock.now, coreHost });
  /** What reached a handler. @type {string[]} */
  const reached = [];
  const record = (/** @type {string} */ type, /** @type {any} */ reply, /** @type {(ctx: any) => unknown} */ after = () => {}) => ({
    types: [type],
    channel: /** @type {"ui" | "content"} */ (type in UI_TYPES ? "ui" : "content"),
    async handle(/** @type {any} */ _body, /** @type {any} */ ctx) {
      reached.push(type);
      await after(ctx);
      return reply;
    },
  });
  const handlers = [
    lockHandler,
    settingsHandler,
    record("state", { state: "locked" }),
    record("sync_state", { running: false, live: "offline", warnings: [] }),
    record("unlock", { ok: true }, async (ctx) => {
      await ctx.call("unlock_probe");
    }),
    record("candidates", { insecure: false, items: [], grant: [] }, (ctx) => ctx.call("vault_probe")),
    record("frame_report", undefined),
    record("fill_result", undefined),
  ];
  // As in the background (main.mjs): the deadline is also checked before every use of the vault outside the messages.
  coreHost.setGuard(() => lock.isDue());
  const router = createRouter({ runtime: fake.runtime, lock, coreHost, handlers });
  if (unlocked) {
    await coreHost.call("unlock_probe");
    await turn();
  }
  const page = createPort(UI_PORT, extensionPageSender(fake, "pages/popup.html"));
  router.onConnect(page);
  const content = contentScriptSender(fake);
  /** @param {string} type @param {any} [body] */
  const ask = async (type, body = {}) => {
    const before = page.sent.length;
    await page.send(encode(type, body));
    return decode(page.sent[before], UI_TYPES, { reply: true });
  };
  /** A message from a content script in a web page. @param {string} type @param {any} body */
  const fromPage = async (type, body) => {
    await new Promise((resolve) => {
      const answer = router.onMessage(encode(type, body, { id: "c1" }), content);
      Promise.resolve(answer).then(resolve, resolve);
    });
  };
  const deadline = async () => {
    await turn();
    return /** @type {number | undefined} */ ((await storage.get(LOCK_AT_KEY))[LOCK_AT_KEY]);
  };
  return { fake, clock, timers, client, coreHost, storage, local, events, lock, router, reached, page, ask, fromPage, deadline };
}

const FRAME_REPORT = { request_id: "r1", self_origin: "https://example.com", fields: [] };
const FILL_RESULT = { request_id: "r1", ok: true };

test("auto_lock_after_the_setting_with_a_fake_clock", async () => {
  for (const seconds of LOCK_CHOICES) {
    const { clock, client, coreHost, ask, deadline } = await setup({ unlocked: false });
    assert.deepEqual((await ask("settings", { lock_seconds: seconds })).body, { lock_seconds: seconds });
    await ask("unlock", { mp: "typed" });
    assert.equal(coreHost.state(), "unlocked", String(seconds));
    assert.equal(await deadline(), clock.now() + seconds * SECOND, `${seconds}: the deadline starts when the vault opens`);
    // One millisecond short of the setting: still open, and an action in Ferret's UI starts the time again.
    clock.advance(seconds * SECOND - 1);
    assert.equal((await ask("candidates", { tab_id: 1, frame_id: 0 })).type, "candidates", String(seconds));
    assert.equal(coreHost.state(), "unlocked", String(seconds));
    assert.equal(await deadline(), clock.now() + seconds * SECOND, `${seconds}: an action moves it`);
    // The full time with no action: the next message locks and is refused.
    clock.advance(seconds * SECOND);
    const refused = await ask("candidates", { tab_id: 1, frame_id: 0 });
    assert.deepEqual([refused.type, refused.body], ["refused", { reason: "vault_locked" }], String(seconds));
    assert.equal(coreHost.state(), "locked", String(seconds));
    assert.equal(client.locks, 1, `${seconds}: the worker was ended`);
  }
});

test("fifteen_seconds_locks_after_fifteen_seconds_without_activity_in_ferrets_ui", async () => {
  const { clock, client, coreHost, timers, events, ask, deadline } = await setup({ unlocked: false });
  await ask("settings", { lock_seconds: 15 });
  await ask("unlock", { mp: "typed" });
  const opened = clock.now();
  assert.equal(await deadline(), opened + 15 * SECOND);
  // The alarm is armed for it too, and so is a timer of the page (the alarm may only fire at the browser's own granularity).
  assert.equal(events.alarmList.get(ALARM_NAME)?.when, opened + 15 * SECOND);
  assert.equal(timers.pending.size, 1);

  // Fourteen seconds: nothing is due, and the vault stays open.
  clock.advance(14 * SECOND);
  await timers.runDue();
  assert.equal(coreHost.state(), "unlocked");
  // An action in Ferret's UI moves the deadline and the timer with it.
  assert.equal((await ask("candidates", { tab_id: 1, frame_id: 0 })).type, "candidates");
  assert.equal(await deadline(), clock.now() + 15 * SECOND);
  assert.equal(timers.pending.size, 1, "one timer, moved");
  clock.advance(14 * SECOND + 999);
  await timers.runDue();
  assert.equal(coreHost.state(), "unlocked", "14.999 s after the last action");

  // 15 s after the last action and no message at all: the page's timer locks it.
  clock.advance(1);
  await timers.runDue();
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
  assert.equal(timers.pending.size, 0, "the lock takes the timer and the alarm away");
  assert.equal(events.alarmList.has(ALARM_NAME), false);
  assert.equal(await deadline(), undefined);
});

test("the_alarm_of_a_longer_choice_is_set_for_its_own_deadline_and_the_timer_looks_again_every_15_seconds", async () => {
  const { clock, timers, events, ask } = await setup({ unlocked: false });
  await ask("settings", { lock_seconds: 86_400 });
  await ask("unlock", { mp: "typed" });
  const [only] = [...timers.pending.values()];
  assert.equal(only.at, clock.now() + RECHECK_MS, "the timer never waits longer than 15 s");
  assert.equal(events.alarmList.get(ALARM_NAME)?.when, clock.now() + 86_400 * SECOND);
  // A short choice: the timer waits for the deadline itself.
  const short = await setup({ unlocked: false });
  await short.ask("settings", { lock_seconds: 15 });
  await short.ask("unlock", { mp: "typed" });
  assert.equal([...short.timers.pending.values()][0].at, short.clock.now() + 15 * SECOND);
});

test("activity_in_a_web_page_does_not_move_lock_at", async () => {
  const { clock, coreHost, events, ask, fromPage, deadline, reached } = await setup();
  const first = await deadline();
  clock.advance(5 * 60 * SECOND);
  // Reports of a content script, the polls of a page and the browser saying the user is active: none is activity in Ferret's UI.
  await fromPage("frame_report", FRAME_REPORT);
  await fromPage("fill_result", FILL_RESULT);
  await ask("state");
  await ask("sync_state");
  events.fireIdle("active");
  await turn();
  assert.deepEqual(reached.slice(-4), ["frame_report", "fill_result", "state", "sync_state"], "the messages did reach their handlers");
  assert.equal(await deadline(), first, "lock_at is where it was");
  assert.equal(coreHost.state(), "unlocked");
  // An action in Ferret's UI does move it.
  await ask("candidates", { tab_id: 1, frame_id: 0 });
  assert.equal(await deadline(), clock.now() + DEFAULT_LOCK_SECONDS * SECOND);
});

test("idle_locked_locks_when_supported", async () => {
  // Where the browser reports the screen lock, that locks. (Firefox does not report it: the next test is what runs there.)
  const { client, coreHost, events } = await setup();
  events.fireIdle("locked");
  await turn();
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
});

test("idle_for_as_long_as_the_setting_locks_where_the_browser_does_not_report_locked", async () => {
  const { coreHost, events, ask } = await setup({ unlocked: false });
  await turn();
  assert.deepEqual(events.idleIntervals, [900], "the browser is asked to report idle after the default");
  await ask("settings", { lock_seconds: 60 });
  assert.deepEqual(events.idleIntervals, [900, 60], "and after the new setting from then on");
  await ask("unlock", { mp: "typed" });
  events.fireIdle("idle");
  await turn();
  assert.equal(coreHost.state(), "locked");
});

test("sleep_longer_than_the_setting_locks_on_wake", async () => {
  // The machine sleeps for eight hours with the vault open: no timer or alarm ran meanwhile.
  for (const wake of ["the browser says the user is active", "the late alarm", "the late timer", "the first message"]) {
    const { clock, client, coreHost, events, timers, ask } = await setup();
    clock.advance(8 * 60 * 60 * SECOND);
    assert.equal(coreHost.state(), "unlocked", "nothing has run yet");
    if (wake === "the browser says the user is active") events.fireIdle("active");
    else if (wake === "the late alarm") await events.fireAlarm(ALARM_NAME);
    else if (wake === "the late timer") await timers.runDue();
    else assert.equal((await ask("candidates", { tab_id: 1, frame_id: 0 })).type, "refused");
    await turn();
    assert.equal(coreHost.state(), "locked", wake);
    assert.equal(client.locks, 1, wake);
  }
  // Waking before the deadline does not lock.
  const { clock, coreHost, events } = await setup();
  clock.advance(14 * 60 * SECOND);
  events.fireIdle("active");
  await turn();
  assert.equal(coreHost.state(), "unlocked");
});

test("a_sleep_does_not_stretch_the_time_the_vault_stays_open", async () => {
  // The machine sleeps for eight hours with the vault open. The timers are delays on a clock that did not run, so
  // none is due when it wakes. The page's timer is never set for longer than RECHECK_MS, so the first one fires
  // within 15 s of the wake and finds the deadline passed.
  const { clock, client, coreHost, timers, events } = await setup();
  const [first] = [...timers.pending.values()];
  assert.ok(first.at <= clock.now() + RECHECK_MS, "the timer waits 15 s at most, not the 15 minutes of the setting");
  clock.jump(8 * 60 * 60 * SECOND);
  await timers.runDue();
  assert.equal(coreHost.state(), "unlocked", "nothing is due the moment the machine wakes");
  clock.advance(RECHECK_MS);
  await timers.runDue();
  assert.equal(coreHost.state(), "locked", "locked within 15 s of the wake, with no message");
  assert.equal(client.locks, 1);
  assert.equal(events.alarmList.has(ALARM_NAME), false);
  assert.equal(timers.pending.size, 0);
  // And while the deadline is still ahead the timer only looks again: it does not touch it.
  const again = await setup();
  const before = await again.deadline();
  for (let i = 0; i < 10; i += 1) {
    again.clock.advance(RECHECK_MS);
    await again.timers.runDue();
  }
  assert.equal(again.coreHost.state(), "unlocked");
  assert.equal(await again.deadline(), before);
  assert.equal(again.timers.pending.size, 1, "one timer, set again each time");
});

test("a_call_of_the_sync_after_the_deadline_never_reaches_the_worker", async () => {
  const { clock, client, coreHost } = await setup();
  const live = coreHost.liveClient({ open: true });
  assert.equal((await live.vault.ferret_aaguid()).length, 16, "while the vault is open it reaches the worker");
  const calls = client.calls.length;
  // The machine slept past the deadline: no timer, alarm or message has run yet.
  clock.jump(8 * 60 * 60 * SECOND);
  assert.equal(coreHost.state(), "unlocked");
  await assert.rejects(live.vault.ferret_aaguid(), { code: "vault_locked" });
  assert.equal(client.calls.length, calls, "the call never reached the worker");
  assert.equal(coreHost.state(), "locked", "the guard locked the host");
  assert.equal(client.locks, 1);
  await assert.rejects(live.vault.ferret_aaguid(), { code: "vault_locked" });
  // A client of the account session (not `open`) is not held by the deadline: it runs while the host is locked.
  const session = coreHost.liveClient();
  assert.equal((await session.vault.ferret_aaguid()).length, 16);
  assert.equal(coreHost.state(), "locked");
});

test("a_value_written_outside_the_list_by_another_context_reads_as_fifteen_minutes", async () => {
  // storage.local can be written by a content-script context too: the value is checked against the list on every read.
  const first = await setup({ unlocked: false });
  await first.ask("settings", { lock_seconds: 300 });
  for (const bad of [86_401, 7777, 1, "300", null]) {
    first.local.data.set(SETTING_KEY, bad);
    const next = await setup({ unlocked: false, stored: { [SETTING_KEY]: first.local.data.get(SETTING_KEY) } });
    assert.deepEqual((await next.ask("settings", {})).body, { lock_seconds: 900 }, String(bad));
  }
});

test("the_setting_is_used_only_once_it_is_saved", async () => {
  const { local, lock } = await setup({ unlocked: false });
  /** @type {() => void} */
  let release = () => {};
  const held = new Promise((resolve) => { release = () => resolve(undefined); });
  const realSet = local.set.bind(local);
  local.set = async (items) => { await held; return realSet(items); };
  const saving = lock.setSeconds(86_400);
  await turn();
  assert.equal(await lock.getSeconds(), 900, "while the save is pending the old value is still the one in use");
  release();
  await saving;
  assert.equal(await lock.getSeconds(), 86_400);
  local.set = async () => { throw new Error("full"); };
  await assert.rejects(lock.setSeconds(60), /full/);
  assert.equal(await lock.getSeconds(), 86_400, "a failed save leaves the value alone");
});

test("a_call_after_lock_at_never_reaches_the_worker", async () => {
  const { clock, client, coreHost, ask } = await setup();
  assert.equal((await ask("candidates", { tab_id: 1, frame_id: 0 })).type, "candidates");
  const calls = client.calls.length;
  assert.ok(calls > 0, "while it is open the call reaches the worker");
  clock.advance(DEFAULT_LOCK_SECONDS * SECOND);
  for (let i = 0; i < 3; i += 1) {
    const reply = await ask("candidates", { tab_id: 1, frame_id: 0 });
    assert.deepEqual([reply.type, reply.body], ["refused", { reason: "vault_locked" }]);
  }
  assert.equal(client.calls.length, calls, "no call reached the worker after the deadline");
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1);
});

test("every_listed_value_round_trips_and_survives_a_restart", async () => {
  assert.deepEqual([...LOCK_CHOICES], [15, 30, 60, 300, 900, 1800, 3600, 14_400, 28_800, 86_400], "the choices of the setting");
  for (const seconds of LOCK_CHOICES) {
    const first = await setup({ unlocked: false });
    assert.deepEqual((await first.ask("settings", { lock_seconds: seconds })).body, { lock_seconds: seconds });
    assert.deepEqual((await first.ask("settings", {})).body, { lock_seconds: seconds });
    assert.equal(first.local.data.get(SETTING_KEY), seconds, "kept in storage.local, in seconds");
    // The next run of the background reads it back.
    const second = await setup({ unlocked: false, stored: { [SETTING_KEY]: first.local.data.get(SETTING_KEY) } });
    assert.deepEqual((await second.ask("settings", {})).body, { lock_seconds: seconds });
    await turn();
    assert.deepEqual(second.events.idleIntervals, [seconds]);
  }
});

test("an_unknown_stored_value_gives_fifteen_minutes", async () => {
  for (const bad of [0, 1, 14, 16, 45, 61, 899, 900.5, 1200, 86_401, 172_800, -900, NaN, Infinity, "900", "15", null, true, {}, [900]]) {
    const { clock, ask, deadline, events } = await setup({ unlocked: false, stored: { [SETTING_KEY]: bad } });
    assert.deepEqual((await ask("settings", {})).body, { lock_seconds: 900 }, String(bad));
    await ask("unlock", { mp: "typed" });
    assert.equal(await deadline(), clock.now() + 900 * SECOND, String(bad));
    assert.deepEqual(events.idleIntervals, [900], String(bad));
  }
  // The setting of the earlier version (minutes) is not read as seconds, and a storage that cannot be read leaves the default.
  const old = await setup({ unlocked: false, stored: { lock_minutes: 1 } });
  assert.deepEqual((await old.ask("settings", {})).body, { lock_seconds: 900 });
  const broken = await setup({ unlocked: false });
  broken.local.broken = true;
  const lock = createLock({ alarms: broken.events.alarms, idle: broken.events.idle, storageSession: broken.storage, storageLocal: broken.local, now: broken.clock.now, coreHost: broken.coreHost });
  assert.equal(await lock.getSeconds(), 900);
});

test("settings_refuse_values_that_are_not_one_of_the_choices", async () => {
  const { local, lock, page, ask } = await setup({ unlocked: false });
  await ask("settings", { lock_seconds: 300 });
  // A page cannot even encode what is outside the bounds of the list.
  for (const bad of [0, 14, 86_401, 1.5, -15, NaN, Infinity, "300", null]) {
    assert.throws(() => encode("settings", { lock_seconds: bad }), `${String(bad)} is refused by the protocol`);
  }
  // Inside the bounds but not a choice: the page may send it, the background refuses it and changes nothing.
  for (const bad of [16, 29, 45, 90, 600, 1000, 3601, 86_399]) {
    const reply = await ask("settings", { lock_seconds: bad });
    assert.deepEqual([reply.type, reply.body], ["refused", { reason: "invalid_input" }], String(bad));
    await assert.rejects(lock.setSeconds(bad), RangeError, String(bad));
  }
  assert.equal(local.data.get(SETTING_KEY), 300);
  assert.deepEqual((await ask("settings", {})).body, { lock_seconds: 300 });
  // A raw message that the protocol refuses ends the connection and writes nothing.
  const bad = JSON.stringify({ v: 1, id: "x", type: "settings", body: { lock_seconds: 5 } });
  await page.send(bad);
  assert.equal(page.disconnected, true);
  assert.equal(local.data.get(SETTING_KEY), 300);
  // There is no "never": nothing but a number reads.
  for (const bad2 of [null, "never", 0, Infinity]) await assert.rejects(lock.setSeconds(/** @type {any} */ (bad2)), RangeError);
});

test("a_setting_that_cannot_be_saved_leaves_the_old_one_and_says_so", async () => {
  const { local, ask } = await setup({ unlocked: false });
  await ask("settings", { lock_seconds: 300 });
  local.broken = true;
  const reply = await ask("settings", { lock_seconds: 3600 });
  assert.deepEqual([reply.type, reply.body], ["refused", { reason: "internal_error" }]);
  local.broken = false;
  assert.deepEqual((await ask("settings", {})).body, { lock_seconds: 300 }, "the setting that is shown is the one that holds");
});

test("a_shorter_setting_shortens_the_deadline_of_an_open_vault_and_a_longer_one_waits_for_the_next_action", async () => {
  const { clock, coreHost, ask, deadline } = await setup();
  assert.equal(await deadline(), clock.now() + 900 * SECOND);
  await ask("settings", { lock_seconds: 60 });
  assert.equal(await deadline(), clock.now() + 60 * SECOND, "shortened at once");
  await ask("settings", { lock_seconds: 14_400 });
  assert.equal(await deadline(), clock.now() + 60 * SECOND, "not made longer by a change of the setting");
  await ask("candidates", { tab_id: 1, frame_id: 0 });
  assert.equal(await deadline(), clock.now() + 14_400 * SECOND, "longer from the next action");
  assert.equal(coreHost.state(), "unlocked");
  // The settings page is not activity in Ferret's UI that keeps a vault open.
  clock.advance(60 * SECOND);
  await ask("settings", {});
  assert.equal(await deadline(), clock.now() + 14_340 * SECOND);
});

test("settings_work_on_a_locked_device_and_change_nothing_about_the_lock", async () => {
  const { coreHost, client, ask } = await setup({ unlocked: false });
  assert.equal(coreHost.state(), "locked");
  assert.deepEqual((await ask("settings", { lock_seconds: 1800 })).body, { lock_seconds: 1800 });
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.calls.length, 0, "no worker was started for a setting");
});

test("the_lock_message_has_one_handler_and_ends_the_worker", async () => {
  const everyone = [lockHandler, sessionHandler, settingsHandler, syncHandler];
  assert.deepEqual(everyone.filter((h) => h.types.includes("lock")), [lockHandler], "one handler claims `lock`");
  // The real handlers together make a router: two handlers for one type would throw at start-up.
  const fake = createFakeBrowser();
  const clock = createClock();
  const client = createFakeClient();
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops: probes, names: [...CORE_OPS, "unlock_probe", "vault_probe"] });
  const events = createAlarmsAndIdle();
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: createSessionStorage(), now: clock.now, coreHost });
  const router = createRouter({ runtime: fake.runtime, lock, coreHost, handlers: everyone });
  await coreHost.call("unlock_probe");
  const page = createPort(UI_PORT, extensionPageSender(fake, "pages/popup.html"));
  router.onConnect(page);
  await page.send(encode("lock", {}, { id: "l1" }));
  assert.deepEqual(decode(page.sent[0], UI_TYPES, { reply: true }), { id: "l1", type: "lock", body: { ok: true } });
  assert.equal(coreHost.state(), "locked");
  assert.equal(client.locks, 1, "the worker was ended");
  // Locking again is never refused.
  await page.send(encode("lock", {}, { id: "l2" }));
  assert.deepEqual(decode(page.sent[1], UI_TYPES, { reply: true }).body, { ok: true });
  // Two handlers for the type are an error at start-up.
  assert.throws(() => createRouter({ runtime: fake.runtime, lock, coreHost, handlers: [lockHandler, { ...lockHandler }] }), /two handlers for ui:lock/);
});
