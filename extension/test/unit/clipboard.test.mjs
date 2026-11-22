// The clipboard of a copy from the popup: the background writes it, a mark in
// `storage.session` and an alarm clear it 30 seconds later, also when the
// background page was unloaded in between and also while the vault is locked,
// and only while the copy is still Ferret's last.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ALARM_PREFIX, CLEAR_AFTER_MS, MARK_KEY, createClipboard } from "../../src/background/clipboard.mjs";
import { actionErrorKey } from "../../src/pages/popupFlow.mjs";
import { createAlarmsAndIdle, createClock, createSessionStorage } from "./backgroundHelpers.mjs";
import { PASSWORD, TOTP_CODE, itemWorld } from "./itemHelpers.mjs";

/** A background page's clipboard over storage that outlives the page. */
function page(/** @type {{ storage: ReturnType<typeof createSessionStorage>, clock: ReturnType<typeof createClock>, written: string[] }} */ shared) {
  const events = createAlarmsAndIdle();
  let n = 0;
  const clipboard = createClipboard({
    writeText: async (text) => {
      shared.written.push(text);
    },
    storageSession: shared.storage,
    alarms: events.alarms,
    now: shared.clock.now,
    random: (bytes) => bytes.fill((n += 1)),
  });
  return { clipboard, events };
}

test("copy_clears_the_clipboard_after_30_seconds_also_after_the_background_was_unloaded_and_while_locked", async () => {
  const shared = { storage: createSessionStorage(), clock: createClock(), written: /** @type {string[]} */ ([]) };
  const first = page(shared);
  await first.clipboard.copy("hunter2-value");
  assert.deepEqual(shared.written, ["hunter2-value"]);
  const mark = shared.storage.data.get(MARK_KEY);
  assert.match(String(mark), /^[0-9a-f]{32}$/);
  const [[name, info]] = [...first.events.alarmList];
  assert.equal(name, `${ALARM_PREFIX}${mark}`);
  assert.equal(info.when, shared.clock.now() + CLEAR_AFTER_MS);
  assert.equal(CLEAR_AFTER_MS, 30_000);

  // The background page is unloaded; a new one starts when the alarm fires. Its listener clears the clipboard.
  const second = page(shared);
  shared.clock.advance(CLEAR_AFTER_MS);
  await second.events.fireAlarm(name);
  assert.deepEqual(shared.written, ["hunter2-value", ""]);
  assert.equal(shared.storage.data.has(MARK_KEY), false);
  // The alarm again (the browser may fire twice): nothing more.
  await second.events.fireAlarm(name);
  assert.deepEqual(shared.written, ["hunter2-value", ""]);
  // Another alarm name, or a forged mark, does nothing.
  await second.events.fireAlarm("ferret-lock");
  await second.events.fireAlarm(`${ALARM_PREFIX}../x`);
  assert.deepEqual(shared.written, ["hunter2-value", ""]);

  // In the background with a vault: copy, lock, and the alarm still clears.
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = (await popup.list.search({ query: "Example" })).rows;
  assert.deepEqual(await popup.list.copy(row.ref, "password"), { ok: true });
  assert.deepEqual(world.written, [PASSWORD]);
  await world.coreHost.lock("manual");
  assert.equal(world.coreHost.state(), "locked");
  const alarm = [...world.events.alarmList.keys()].find((n) => n.startsWith(ALARM_PREFIX));
  assert.ok(alarm);
  world.clock.advance(CLEAR_AFTER_MS);
  await world.events.fireAlarm(/** @type {string} */ (alarm));
  assert.deepEqual(world.written, [PASSWORD, ""]);
  // The popup never got the value.
  assert.equal(popup.received().join("\n").includes(PASSWORD), false);
});

test("a_second_ferret_copy_moves_the_mark_and_the_first_alarm_does_nothing", async () => {
  const shared = { storage: createSessionStorage(), clock: createClock(), written: /** @type {string[]} */ ([]) };
  const { clipboard, events } = page(shared);
  await clipboard.copy("first");
  const firstAlarm = [...events.alarmList.keys()][0];
  shared.clock.advance(10_000);
  await clipboard.copy("second");
  const alarms = [...events.alarmList.keys()];
  // The first alarm is cleared, and only the second is armed.
  assert.equal(alarms.length, 1);
  assert.notEqual(alarms[0], firstAlarm);
  assert.equal(events.alarmList.get(alarms[0])?.when, shared.clock.now() + CLEAR_AFTER_MS);
  // Should the first fire anyway (it was due already), it finds another mark and leaves the clipboard alone.
  shared.clock.advance(20_000);
  await events.fireAlarm(firstAlarm);
  assert.deepEqual(shared.written, ["first", "second"]);
  shared.clock.advance(10_000);
  await events.fireAlarm(alarms[0]);
  assert.deepEqual(shared.written, ["first", "second", ""]);
});

test("a_copy_that_cannot_write_leaves_the_mark_of_the_last_one_and_nothing_empty_is_copied", async () => {
  const storage = createSessionStorage();
  const events = createAlarmsAndIdle();
  const written = /** @type {string[]} */ ([]);
  let fail = false;
  const clipboard = createClipboard({
    writeText: async (text) => {
      if (fail) throw new Error("denied");
      written.push(text);
    },
    storageSession: storage,
    alarms: events.alarms,
    now: () => 1,
  });
  await clipboard.copy("one");
  const mark = storage.data.get(MARK_KEY);
  fail = true;
  await assert.rejects(clipboard.copy("two"), { code: "clipboard" });
  assert.equal(storage.data.get(MARK_KEY), mark, "the mark of the copy that is on the clipboard stays");
  await assert.rejects(clipboard.copy(""), { code: "nothing_to_copy" });
  assert.deepEqual(written, ["one"]);
});

test("copy_of_a_one_time_code_and_a_user_name_writes_what_the_core_made", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = (await popup.list.search({ query: "example" })).rows;
  assert.deepEqual(await popup.list.copy(row.ref, "totp"), { ok: true });
  assert.deepEqual(await popup.list.copy(row.ref, "username"), { ok: true });
  assert.deepEqual(world.written, [TOTP_CODE, "ola@example.net"]);
  // An item without such a value, and a clipboard that refuses.
  const [note] = (await popup.list.search({ query: "recipe" })).rows;
  assert.deepEqual(await popup.list.copy(note.ref, "password"), { ok: false, reason: "no_value" });
  world.clipboardState.fails = true;
  assert.deepEqual(await popup.list.copy(row.ref, "password"), { ok: false, reason: "clipboard" });
  assert.equal(world.handles.size, 0, "every item was closed again");
});

test("the_totp_code_is_made_in_the_core_from_the_device_clock", async () => {
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = (await popup.list.search({ query: "example" })).rows;
  world.clock.advance(12_345);
  const seconds = Math.floor(world.clock.now() / 1000);
  assert.deepEqual(await popup.list.copy(row.ref, "totp"), { ok: true });
  // One call of the core, with the item's handle and the device's clock in whole seconds; the code is the core's.
  const calls = world.client.calls.filter((/** @type {any} */ c) => c.method === "totp_code");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].args[1], seconds);
  assert.equal(Number.isInteger(seconds) && seconds > 1_700_000_000, true, "unix seconds, not milliseconds");
  assert.equal(typeof calls[0].args[0], "number");
  assert.deepEqual(world.written, [TOTP_CODE]);
  // The popup was told that it worked, and nothing else.
  assert.equal(popup.received().join("\n").includes(TOTP_CODE), false);
  // The item view says a code can be copied; it never holds one.
  const view = await popup.list.item(row.ref);
  assert.deepEqual(view.copyable, ["username", "password", "totp"]);
  assert.equal(JSON.stringify(view).includes(TOTP_CODE), false);
});

/**
 * A clipboard whose alarm cannot be made (`alarms.create` throws, or rejects), with a timer the test runs itself.
 * @param {"throws" | "rejects"} how @param {{ timerFails?: boolean }} [options]
 */
function withoutAlarms(how, { timerFails = false } = {}) {
  const storage = createSessionStorage();
  const events = createAlarmsAndIdle();
  const clock = createClock();
  const written = /** @type {string[]} */ ([]);
  /** @type {Array<{ fn: () => unknown, ms: number }>} */
  const timers = [];
  const clipboard = createClipboard({
    writeText: async (text) => {
      written.push(text);
    },
    storageSession: storage,
    alarms: {
      ...events.alarms,
      create: how === "throws"
        ? () => {
            throw new Error("alarms are not available");
          }
        : async () => {
            throw new Error("alarms are not available");
          },
    },
    now: clock.now,
    setTimer: (fn, ms) => {
      if (timerFails) throw new Error("no timer");
      timers.push({ fn, ms });
    },
  });
  return { clipboard, storage, events, written, timers };
}

/** The world's clipboard alarms cannot be made (the lock's alarms still can). @param {any} world */
function noClipboardAlarm(world) {
  const create = world.events.alarms.create;
  world.events.alarms.create = (/** @type {string} */ name, /** @type {{ when: number }} */ info) => {
    if (name.startsWith(ALARM_PREFIX)) throw new Error("alarms are not available");
    return create(name, info);
  };
}

test("clipboard_falls_back_to_a_timer_when_the_alarm_cannot_be_made", async () => {
  for (const how of /** @type {const} */ (["throws", "rejects"])) {
    const { clipboard, storage, written, timers } = withoutAlarms(how);
    await clipboard.copy("hunter2-value");
    // No alarm, so a timer of the background page clears it 30 seconds later.
    assert.equal(timers.length, 1, how);
    assert.equal(timers[0].ms, CLEAR_AFTER_MS, how);
    await timers[0].fn();
    assert.deepEqual(written, ["hunter2-value", ""], how);
    assert.equal(storage.data.has(MARK_KEY), false, how);

    // The timer keeps the alarm's rule: a later copy of Ferret's moves the mark, and the earlier timer leaves it alone.
    await clipboard.copy("first");
    await clipboard.copy("second");
    assert.equal(timers.length, 3, how);
    await timers[1].fn();
    assert.deepEqual(written, ["hunter2-value", "", "first", "second"], how);
    await timers[2].fn();
    assert.deepEqual(written, ["hunter2-value", "", "first", "second", ""], how);
  }

  // In the background: the copy works as before, and the popup hears nothing but that it worked.
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = (await popup.list.search({ query: "Example" })).rows;
  noClipboardAlarm(world);
  assert.deepEqual(await popup.list.copy(row.ref, "password"), { ok: true });
  assert.equal(world.clipboardState.timers.length, 1);
  assert.equal(world.clipboardState.timers[0].ms, CLEAR_AFTER_MS);
  await world.clipboardState.timers[0].fn();
  assert.deepEqual(world.written, [PASSWORD, ""]);
});

test("clipboard_says_so_when_neither_alarm_nor_timer_works", async () => {
  const { clipboard, storage, written } = withoutAlarms("throws", { timerFails: true });
  // The value is on the clipboard (the copy itself worked), and nothing will clear it: the copy says so.
  await assert.rejects(clipboard.copy("hunter2-value"), { code: "not_cleared" });
  assert.deepEqual(written, ["hunter2-value"]);
  assert.match(String(storage.data.get(MARK_KEY)), /^[0-9a-f]{32}$/);

  // In the background the popup gets the reason, and a text for it in both languages.
  const world = await itemWorld();
  await world.open();
  const popup = world.popup();
  const [row] = (await popup.list.search({ query: "Example" })).rows;
  noClipboardAlarm(world);
  world.clipboardState.timerFails = true;
  assert.deepEqual(await popup.list.copy(row.ref, "password"), { ok: false, reason: "not_cleared" });
  assert.deepEqual(world.written, [PASSWORD]);
  assert.equal(popup.received().join("\n").includes(PASSWORD), false, "the popup never got the value");
  assert.equal(actionErrorKey("not_cleared"), "popup.error.not_cleared");
  for (const lang of ["en", "nb"]) {
    const texts = JSON.parse(readFileSync(new URL(`../../src/locales/${lang}/popup.json`, import.meta.url), "utf8"));
    assert.ok(typeof texts["popup.error.not_cleared"] === "string" && texts["popup.error.not_cleared"] !== "", lang);
  }
  assert.match(JSON.parse(readFileSync(new URL("../../src/locales/en/popup.json", import.meta.url), "utf8"))["popup.error.not_cleared"], /could not set the timer that clears the clipboard/);
});
