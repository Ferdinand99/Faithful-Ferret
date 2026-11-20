// The reminder to take a new encrypted export (spec Fase 1 § 6.4: every 30 days): the date store, "forget this server", and
// the notice in the vault frame.
import assert from "node:assert/strict";
import { test } from "node:test";
import { forgetServer } from "../../src/store/forget.mjs";
import {
  EXPORT_REMINDER_MS, EXPORT_SNOOZE_MS, deleteReminder, exportReminderKey, markExported, reminderStatus, snoozeReminder,
} from "../../src/store/exportReminder.mjs";
import { getSetting, setSetting } from "../../src/store/settings.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { ACCOUNT, SERVER, freshStore } from "./idbHelpers.mjs";
import { all, fakeEngine, find, click, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const DAY = 24 * 60 * 60 * 1000;
const T0 = 1_800_000_000_000;

test("the_reminder_shows_after_30_days_and_goes_after_an_export", async () => {
  const { store } = await freshStore();
  // The first look starts the count: nothing is due on that day.
  assert.deepEqual(await reminderStatus(store, SERVER, ACCOUNT, T0), { due: false, lastExportAt: null });
  assert.deepEqual(await reminderStatus(store, SERVER, ACCOUNT, T0 + 29 * DAY), { due: false, lastExportAt: null });
  assert.equal(EXPORT_REMINDER_MS, 30 * DAY);
  // After 30 days without an export it is due, and stays due.
  assert.deepEqual(await reminderStatus(store, SERVER, ACCOUNT, T0 + 30 * DAY), { due: true, lastExportAt: null });
  assert.equal((await reminderStatus(store, SERVER, ACCOUNT, T0 + 90 * DAY)).due, true);

  // An export clears it, and the next one is 30 days after that export.
  const exportedAt = T0 + 40 * DAY;
  await markExported(store, SERVER, ACCOUNT, exportedAt);
  assert.deepEqual(await reminderStatus(store, SERVER, ACCOUNT, exportedAt + 1), { due: false, lastExportAt: exportedAt });
  assert.equal((await reminderStatus(store, SERVER, ACCOUNT, exportedAt + 30 * DAY - 1)).due, false);
  assert.deepEqual(await reminderStatus(store, SERVER, ACCOUNT, exportedAt + 30 * DAY), { due: true, lastExportAt: exportedAt });

  // One record per server and account.
  const other = "ab".repeat(16);
  assert.deepEqual(await reminderStatus(store, SERVER, other, exportedAt + 30 * DAY), { due: false, lastExportAt: null });
  assert.deepEqual(await reminderStatus(store, "https://other.example", ACCOUNT, exportedAt + 30 * DAY), { due: false, lastExportAt: null });
  assert.notEqual(exportReminderKey(SERVER, ACCOUNT), exportReminderKey(SERVER, other));
});

test("remind_me_later_keeps_the_reminder_away_for_a_week", async () => {
  const { store } = await freshStore();
  await markExported(store, SERVER, ACCOUNT, T0);
  const due = T0 + 31 * DAY;
  assert.equal((await reminderStatus(store, SERVER, ACCOUNT, due)).due, true);
  await snoozeReminder(store, SERVER, ACCOUNT, due);
  const snoozed = await reminderStatus(store, SERVER, ACCOUNT, due + 1);
  assert.deepEqual(snoozed, { due: false, lastExportAt: T0 }, "the date of the last export stays");
  assert.equal(EXPORT_SNOOZE_MS, 7 * DAY);
  assert.equal((await reminderStatus(store, SERVER, ACCOUNT, due + 7 * DAY - 1)).due, false);
  assert.equal((await reminderStatus(store, SERVER, ACCOUNT, due + 7 * DAY)).due, true);
});

test("a_date_that_is_not_to_be_trusted_never_hides_the_reminder", async () => {
  const { store } = await freshStore();
  // The clock went back: the last export is "in the future". Not trusted, so it counts as due.
  await markExported(store, SERVER, ACCOUNT, T0 + 400 * DAY);
  assert.equal((await reminderStatus(store, SERVER, ACCOUNT, T0)).due, true);
  // A snooze that reaches further than a week is not trusted either.
  await markExported(store, SERVER, ACCOUNT, T0 - 60 * DAY);
  await setSetting(store, exportReminderKey(SERVER, ACCOUNT), { exportedAt: T0 - 60 * DAY, since: T0 - 60 * DAY, snoozedUntil: T0 + 365 * DAY });
  assert.equal((await reminderStatus(store, SERVER, ACCOUNT, T0)).due, true);
  // Anything stored that is not a record starts the count again, and is replaced.
  for (const junk of ["x", 5, null, [], { exportedAt: 1 }, { exportedAt: "a", since: 1, snoozedUntil: null }, { exportedAt: null, since: 0, snoozedUntil: null }, { exportedAt: null, since: 1, snoozedUntil: null, extra: 1 }]) {
    await setSetting(store, exportReminderKey(SERVER, ACCOUNT), junk);
    assert.deepEqual(await reminderStatus(store, SERVER, ACCOUNT, T0), { due: false, lastExportAt: null });
  }
  // The values are checked on the way in as well.
  await assert.rejects(markExported(store, SERVER, ACCOUNT, 0), TypeError);
  await assert.rejects(markExported(store, SERVER, "not-an-id", T0), TypeError);
});

test("the_reminder_holds_dates_and_nothing_else_and_goes_with_forget_this_server", async () => {
  const { store } = await freshStore();
  await markExported(store, SERVER, ACCOUNT, T0);
  const kept = await getSetting(store, exportReminderKey(SERVER, ACCOUNT));
  assert.deepEqual(Object.keys(kept).sort(), ["exportedAt", "since", "snoozedUntil"]);
  const other = "cd".repeat(16);
  await markExported(store, SERVER, other, T0);
  await markExported(store, "https://other.example", ACCOUNT, T0);
  const gone = await forgetServer(store, SERVER, ACCOUNT);
  assert.equal(gone.removed.settings, 1, "the date of this server and account is removed");
  assert.equal(await getSetting(store, exportReminderKey(SERVER, ACCOUNT)), undefined);
  assert.notEqual(await getSetting(store, exportReminderKey(SERVER, other)), undefined, "another account keeps its date");
  assert.notEqual(await getSetting(store, exportReminderKey("https://other.example", ACCOUNT)), undefined, "another server keeps its date");
  await deleteReminder(store, SERVER, other);
  assert.equal(await getSetting(store, exportReminderKey(SERVER, other)), undefined);
});

// ------------------------------------------------------------------- the frame

const frame = (reminder, { hash = "#/items" } = {}) => {
  const scope = createWipeScope();
  const root = shellView({
    t, engine: fakeEngine(), session: { onLock() {} }, content: globalThis.document.createElement("div"), lock: async () => {}, touch: () => true,
    scope, onLocked: () => globalThis.document.createElement("div"), win: { location: { hash } }, reminder,
  });
  return { root, scope };
};

test("the_frame_shows_the_reminder_with_a_link_and_a_way_to_postpone_it", async () => {
  await withDom(async () => {
    const calls = [];
    const reminder = {
      check: async () => ({ due: true, lastExportAt: T0 }),
      snooze: async () => void calls.push("snooze"),
    };
    const { root } = frame(reminder);
    await settle();
    const notice = find(root, "export-reminder");
    assert.ok(notice, "the reminder is in the frame");
    assert.match(textOf(notice), /export\.reminder\.text/);
    assert.equal(find(notice, "export-reminder-link").getAttribute("href"), "#/export");
    await click(find(notice, "export-reminder-later"));
    await settle();
    assert.deepEqual(calls, ["snooze"]);
    assert.equal(find(root, "export-reminder"), null, "it is gone for now");
  });

  await withDom(async () => {
    // Never exported: another text; the page itself and a reminder that is not due have none.
    const never = frame({ check: async () => ({ due: true, lastExportAt: null }), snooze: async () => {} });
    await settle();
    assert.match(textOf(find(never.root, "export-reminder")), /export\.reminder\.never/);
    const quiet = frame({ check: async () => ({ due: false, lastExportAt: T0 }), snooze: async () => {} });
    await settle();
    assert.equal(find(quiet.root, "export-reminder"), null);
    const onPage = frame({ check: async () => ({ due: true, lastExportAt: T0 }), snooze: async () => {} }, { hash: "#/export" });
    await settle();
    assert.equal(find(onPage.root, "export-reminder"), null, "the export page needs no reminder to go to itself");
    // A store that fails shows nothing, and the frame builds.
    const broken = frame({ check: async () => Promise.reject(new Error("storage")), snooze: async () => {} });
    await settle();
    assert.equal(find(broken.root, "export-reminder"), null);
    assert.equal(all(broken.root, "banner").length, 0);
    // A lock before the answer comes: nothing is added to a frame that was wiped.
    let release;
    const late = frame({ check: () => new Promise((resolve) => (release = resolve)), snooze: async () => {} });
    late.scope.run();
    release({ due: true, lastExportAt: T0 });
    await settle();
    assert.equal(find(late.root, "export-reminder"), null);
  });
});
