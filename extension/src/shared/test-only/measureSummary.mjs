// What the lifetime measurement makes of its log: the keys it is stored under
// and a pure function that turns the entries into the numbers that matter. The
// background page writes the log (measureLog.mjs, next to the test hooks) and the
// measure page reads and shows it, so the reading lives here, where both may
// import it (test build only).

export const LOG_KEY = "measure_log";
export const SCENARIO_KEY = "measure_scenario";

/** @typedef {{ kind: string, at: number, boot: string, [key: string]: unknown }} LogEntry */

/**
 * Reads the log into the numbers the measurement is about. Pure: the tests and
 * the measure page use it on the same entries.
 *
 * `lifetimes` is one row per start of the page: when it started, how long it
 * was seen alive (until its `suspend` entry, or else its last entry) and whether
 * the browser announced the end with `suspend`. The times that matter are
 * counted from the `scenario_start` entry (or the first entry, when there is
 * none): `firstSuspendAfterMs` is when the browser first announced the end of the
 * page (`runtime.onSuspend`), `restartAfterMs` when the first new page started after
 * the scenario began (the page of the scenario had ended, announced or not).
 *
 * @param {LogEntry[]} entries in the order they were written
 * @returns {{
 *   boots: number,
 *   heartbeats: number,
 *   suspends: number,
 *   lifetimes: { boot: string, startedAt: number, aliveMs: number, ended: "suspend" | "last_seen" }[],
 *   firstSuspendAfterMs: number | null,
 *   restartAfterMs: number | null,
 *   lastEntryAfterMs: number,
 * }}
 */
export function summarize(entries) {
  const valid = entries.filter((e) => typeof e?.boot === "string" && typeof e.at === "number" && typeof e.kind === "string");
  /** @type {Map<string, { startedAt: number, last: number, suspendAt: number | null }>} */
  const boots = new Map();
  let heartbeats = 0;
  let suspends = 0;
  for (const entry of valid) {
    let boot = boots.get(entry.boot);
    if (!boot) {
      boot = { startedAt: entry.at, last: entry.at, suspendAt: null };
      boots.set(entry.boot, boot);
    }
    boot.last = Math.max(boot.last, entry.at);
    if (entry.kind === "heartbeat") heartbeats += 1;
    if (entry.kind === "suspend") {
      suspends += 1;
      boot.suspendAt = entry.at;
    }
  }
  const origin = valid.find((e) => e.kind === "scenario_start") ?? valid[0];
  const from = origin?.at ?? 0;
  const suspend = valid.find((e) => e.kind === "suspend" && e.at >= from);
  // A new page after the scenario began: some page of the scenario ended, announced or not.
  const scenarioBoot = origin?.boot;
  const restart = valid.find((e) => e.kind === "startup" && e.at > from && e.boot !== scenarioBoot);
  return {
    boots: boots.size,
    heartbeats,
    suspends,
    lifetimes: [...boots].map(([boot, b]) => ({
      boot,
      startedAt: b.startedAt,
      aliveMs: (b.suspendAt ?? b.last) - b.startedAt,
      ended: /** @type {"suspend" | "last_seen"} */ (b.suspendAt === null ? "last_seen" : "suspend"),
    })),
    firstSuspendAfterMs: suspend ? suspend.at - from : null,
    restartAfterMs: restart ? restart.at - from : null,
    lastEntryAfterMs: valid.length > 0 ? Math.max(...valid.map((e) => e.at)) - from : 0,
  };
}
