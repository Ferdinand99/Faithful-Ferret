// The reminder to take a new encrypted export (spec Fase 1 § 6.4: every 30 days). It is a
// date and nothing else: when the last encrypted export was made on this device, when the
// reminder started counting for a vault that has not been exported yet, and until when the
// user asked to be left alone. No key, password, item or name is in it. It lives in the
// settings under `export.reminder.<server>.<account>`, and "forget this server" removes it
// (see `forget.mjs`).
//
// The reminder is a help, not a guarantee: a cleared browser starts the count again, and a
// file made on another device is not seen here. A date that lies in the future (the clock
// went back) is not trusted, and counts as due: an extra reminder costs a click, a missing
// one can cost the backup.
import { hex16 } from "../b64.mjs";
import { serverKey } from "./idb.mjs";
import { deleteSetting, getSetting, setSetting } from "./settings.mjs";

/** How long after an export the reminder comes: 30 days, in milliseconds. */
export const EXPORT_REMINDER_MS = 30 * 24 * 60 * 60 * 1000;

/** "Remind me later" keeps the reminder away for 7 days. */
export const EXPORT_SNOOZE_MS = 7 * 24 * 60 * 60 * 1000;

/** A date further ahead than this is a clock that went wrong, and is not trusted. */
const CLOCK_SLACK_MS = 24 * 60 * 60 * 1000;

/**
 * @typedef {object} ReminderRecord
 * @property {number | null} exportedAt when the last encrypted export was made (ms since 1970), or null
 * @property {number} since when the count started for a vault that was never exported (ms since 1970)
 * @property {number | null} snoozedUntil no reminder before this (ms since 1970), or null
 */

/**
 * The settings key of the record.
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {string}
 */
export function exportReminderKey(serverUrl, accountId) {
  if (!hex16.is(accountId)) throw new TypeError("an account id is 32 lower-case hex characters");
  return `export.reminder.${serverKey(serverUrl)}.${accountId}`;
}

/** @param {unknown} value @returns {value is number} */
const whole = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/**
 * The record as it is stored, or null when it is not one: exactly the three fields, of the right types.
 * @param {unknown} value
 * @returns {ReminderRecord | null}
 */
function clean(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (Object.keys(value).sort().join() !== "exportedAt,since,snoozedUntil") return null;
  const { exportedAt, since, snoozedUntil } = /** @type {Record<string, unknown>} */ (value);
  if (!whole(since) || since === 0) return null;
  if (exportedAt !== null && (!whole(exportedAt) || exportedAt === 0)) return null;
  if (snoozedUntil !== null && (!whole(snoozedUntil) || snoozedUntil === 0)) return null;
  return { exportedAt, since, snoozedUntil };
}

/** @param {unknown} now */
function checkNow(now) {
  if (!whole(now) || now === 0) throw new TypeError("now is ms since the epoch");
}

/**
 * Notes that an encrypted export was made now: the next reminder is 30 days away.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {number} now ms since the epoch
 * @returns {Promise<void>}
 */
export async function markExported(store, serverUrl, accountId, now) {
  const key = exportReminderKey(serverUrl, accountId);
  checkNow(now);
  await setSetting(store, key, { exportedAt: now, since: now, snoozedUntil: null });
}

/**
 * Whether the reminder is due now, and when the last export was made. The first call for a vault
 * starts the count (nothing is due on that day); a stored value that is not a record starts it again.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {number} now ms since the epoch
 * @returns {Promise<{ due: boolean, lastExportAt: number | null }>}
 */
export async function reminderStatus(store, serverUrl, accountId, now) {
  const key = exportReminderKey(serverUrl, accountId);
  checkNow(now);
  let record = clean(await getSetting(store, key));
  if (record === null) {
    record = { exportedAt: null, since: now, snoozedUntil: null };
    await setSetting(store, key, record);
  }
  const lastExportAt = record.exportedAt;
  const from = lastExportAt ?? record.since;
  const lying = from > now + CLOCK_SLACK_MS;
  const snoozed = record.snoozedUntil !== null && record.snoozedUntil > now && record.snoozedUntil <= now + EXPORT_SNOOZE_MS + CLOCK_SLACK_MS;
  const due = (lying || now - from >= EXPORT_REMINDER_MS) && !snoozed;
  return { due, lastExportAt };
}

/**
 * "Remind me later": no reminder for 7 days. The date of the last export stays.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @param {number} now ms since the epoch
 * @returns {Promise<void>}
 */
export async function snoozeReminder(store, serverUrl, accountId, now) {
  const key = exportReminderKey(serverUrl, accountId);
  checkNow(now);
  const record = clean(await getSetting(store, key)) ?? { exportedAt: null, since: now, snoozedUntil: null };
  await setSetting(store, key, { ...record, snoozedUntil: now + EXPORT_SNOOZE_MS });
}

/**
 * Removes the record of an account on a server, if there is one.
 * @param {import("./idb.mjs").Store} store
 * @param {string} serverUrl
 * @param {string} accountId
 * @returns {Promise<void>}
 */
export async function deleteReminder(store, serverUrl, accountId) {
  await deleteSetting(store, exportReminderKey(serverUrl, accountId));
}

/** The three calls as the store service hands them out. */
export const exportReminder = Object.freeze({ mark: markExported, status: reminderStatus, snooze: snoozeReminder, delete: deleteReminder });
