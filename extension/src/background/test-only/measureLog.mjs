// The lifetime log of the background page (test build only).
//
// To find out how long the background page lives, the page writes what happens
// to it into `storage.local`, and nobody has to look at it while it happens:
//
//   startup      the page was loaded (a first start, or a start after it was ended)
//   suspend      the browser says it is about to end the page (`runtime.onSuspend`). The page
//                may be gone before a storage write finishes, so the listener also leaves a
//                marker in `localStorage` (a synchronous write) and the next start turns the
//                marker into the entry, marked `late`
//   suspend_canceled   the browser changed its mind
//   heartbeat    an alarm that fires every minute
//
// The measurement runs with every page of the extension closed and with
// about:debugging closed, because a page that is open can keep the background
// alive and give a wrong answer. The log is read afterwards, from the measure
// page, straight from `storage.local` (reading it does not wake the background).
//
// Nothing here keeps the page alive: it only listens and writes.

import { LOG_KEY } from "../../shared/test-only/measureSummary.mjs";

export { LOG_KEY, SCENARIO_KEY, summarize } from "../../shared/test-only/measureSummary.mjs";

export const HEARTBEAT_ALARM = "ferret-measure-heartbeat";
const SUSPEND_MARKER = "measure_suspend";
/** The log is a ring: the oldest entries go first. A 3 h run writes about 400. */
export const MAX_ENTRIES = 5000;

/**
 * @typedef {import("../../shared/test-only/measureSummary.mjs").LogEntry} LogEntry
 * @typedef {{
 *   get: (key: string) => Promise<Record<string, any>>,
 *   set: (items: Record<string, unknown>) => Promise<void>,
 *   remove: (key: string) => Promise<void>,
 * }} Area
 */

/**
 * The log and its writer. Writes are queued, so two entries made in one turn
 * keep their order and neither is lost.
 *
 * @param {{ storageLocal: Area, now: () => number, boot: string, core: () => string }} options
 */
export function createMeasureLog({ storageLocal, now, boot, core }) {
  /** @type {Promise<unknown>} */
  let writes = Promise.resolve();

  /** @returns {Promise<LogEntry[]>} */
  const read = async () => {
    const stored = (await storageLocal.get(LOG_KEY))?.[LOG_KEY];
    return Array.isArray(stored) ? stored : [];
  };

  /**
   * Adds an entry. The returned promise settles when it is written.
   * @param {string} kind
   * @param {Record<string, unknown>} [details]
   * @returns {Promise<unknown>}
   */
  const append = (kind, details = {}) => {
    const entry = { kind, at: now(), boot, core: core(), ...details };
    writes = writes
      .then(async () => {
        const log = await read();
        log.push(/** @type {LogEntry} */ (entry));
        await storageLocal.set({ [LOG_KEY]: log.slice(-MAX_ENTRIES) });
      })
      .catch(() => {});
    return writes;
  };

  return {
    append,
    /** @returns {Promise<LogEntry[]>} */
    read: async () => {
      await writes;
      return read();
    },
    /** Empties the log (a new measurement starts clean). */
    clear: () => {
      writes = writes.then(() => storageLocal.remove(LOG_KEY)).catch(() => {});
      return writes;
    },
  };
}

/**
 * Starts the log for this page: a `startup` entry now, and listeners for the
 * suspend events and the heartbeat. Call it while the page loads, so an alarm
 * that woke the page reaches the listener.
 *
 * @param {{
 *   runtime: { onSuspend: { addListener: (fn: () => void) => void }, onSuspendCanceled?: { addListener: (fn: () => void) => void } },
 *   alarms: {
 *     get: (name: string) => Promise<unknown>,
 *     create: (name: string, info: { periodInMinutes: number, delayInMinutes?: number }) => unknown,
 *     onAlarm: { addListener: (fn: (alarm: { name: string }) => unknown) => void },
 *   },
 *   storageLocal: Area,
 *   now: () => number,
 *   core: () => string,
 *   boot?: string,
 *   marker?: { getItem: (key: string) => string | null, setItem: (key: string, value: string) => void, removeItem: (key: string) => void } | null,
 * }} options
 */
export function startMeasureLog({ runtime, alarms, storageLocal, now, core, boot = newBoot(), marker = null }) {
  const log = createMeasureLog({ storageLocal, now, boot, core });
  runtime.onSuspend.addListener(() => {
    // A synchronous write first: it is done before the page can go.
    try {
      marker?.setItem(SUSPEND_MARKER, JSON.stringify({ at: now(), boot }));
    } catch {
      // No marker: the entry below may still make it.
    }
    log.append("suspend");
  });
  runtime.onSuspendCanceled?.addListener(() => {
    log.append("suspend_canceled");
  });
  alarms.onAlarm.addListener((alarm) => {
    if (alarm?.name === HEARTBEAT_ALARM) log.append("heartbeat");
    return undefined;
  });
  const started = log.append("startup");
  // The marker that an earlier page left when it was told to end: an entry for it, unless that page logged it itself.
  /** @type {{ at: number, boot: string } | null} */
  let left = null;
  try {
    left = JSON.parse(marker?.getItem(SUSPEND_MARKER) ?? "null");
    marker?.removeItem(SUSPEND_MARKER);
  } catch {
    left = null;
  }
  if (left && typeof left.at === "number" && typeof left.boot === "string") {
    const earlier = left;
    started
      .then(() => log.read())
      .then((entries) => (entries.some((e) => e.kind === "suspend" && e.boot === earlier.boot) ? undefined : log.append("suspend", { at: earlier.at, boot: earlier.boot, late: true })))
      .catch(() => {});
  }
  // An alarm is kept by the browser over the end of the page. Only make it when
  // it is missing: making it again would restart its minute and move the beat.
  Promise.resolve(alarms.get(HEARTBEAT_ALARM))
    .then((existing) => {
      if (!existing) alarms.create(HEARTBEAT_ALARM, { delayInMinutes: 1, periodInMinutes: 1 });
    })
    .catch(() => {});
  return { log, boot };
}

/** @returns {string} a random id for this start of the page */
function newBoot() {
  const bytes = new Uint8Array(6);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
