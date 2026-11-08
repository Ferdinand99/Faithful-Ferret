// Helpers of the lifetime measurement (02-lifetime specs): starting a scenario from
// the measure page, closing the page, watching the background from the browser's
// side, and reading the log back. Not a spec file.
//
// What a cell is: one channel, one manifest version, one scenario. Firefox starts
// with the test build, the measure page starts the scenario, the page is closed,
// and nothing touches the extension for the length of the window. The log that
// the background page wrote about itself (startup, onSuspend, a heartbeat every
// minute) and the state of the background as the browser reports it (read in the
// chrome context every few seconds, which does not wake or touch it) are the two
// witnesses.
import { summarize } from "../../src/shared/test-only/measureSummary.mjs";
import { EXTENSION_ORIGIN, fixtures, launch, TEST_ADDON_ID } from "./harness.mjs";

export const MEASURE_URL = `${EXTENSION_ORIGIN}/pages/test-only/measure.html`;
export const POPUP_URL = `${EXTENSION_ORIGIN}/pages/about.html`;
/** The scenarios of the matrix, in the order they run. "terminate" is a quick row of its own. */
export const SCENARIOS = Object.freeze(["idle", "sse", "popup", "argon", "terminate"]);
/** The auto-lock of the extension. A background that ends before this has lost the vault in a normal use. */
export const AUTO_LOCK_MS = 15 * 60_000;

/** @param {number} ms */
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** @typedef {import("./driver.mjs").Session} Session */

/** @param {Session} session */
export async function openMeasurePage(session) {
  await session.navigate(MEASURE_URL);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 30_000, "the measure page");
}

/**
 * Sends one command on the measure port of the background page, from the page in
 * the selected tab, and closes the port.
 * @param {Session} session
 * @param {Record<string, unknown>} command
 * @returns {Promise<any>} the value of the reply; a refusal throws
 */
export async function portCommand(session, command) {
  const reply = await session.content(
    (/** @type {Record<string, unknown>} */ message) =>
      new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-test-measure" });
        const timer = setTimeout(() => reject(new Error("no answer from the background")), 90_000);
        port.onMessage.addListener((answer) => {
          clearTimeout(timer);
          port.disconnect();
          resolve(answer);
        });
        port.onDisconnect.addListener(() => {
          clearTimeout(timer);
          reject(new Error("the background closed the port"));
        });
        port.postMessage({ id: "1", ...message });
      }),
    command,
  );
  if (!reply?.ok) throw new Error(`command ${String(command.cmd)} was refused: ${reply?.code}`);
  return reply.value;
}

/**
 * Starts a scenario with the buttons of the measure page (a real click), as a
 * person would. Leaves the measure page open.
 * @param {Session} session
 * @param {"idle" | "sse" | "popup" | "argon"} scenario
 * @param {string} [url] the stream, for "sse"
 */
export async function startScenario(session, scenario, url) {
  await openMeasurePage(session);
  await session.content(
    (/** @type {string} */ name, /** @type {string} */ stream) => {
      const select = /** @type {HTMLSelectElement} */ (document.getElementById("scenario"));
      select.value = name;
      /** @type {HTMLInputElement} */ (document.getElementById("url")).value = stream;
    },
    scenario,
    url ?? "",
  );
  const [start] = await session.findAll("#start");
  if (!start) throw new Error("the measure page has no start button");
  await session.click(start);
  await session.waitFor(
    () => session.content(() => document.documentElement.dataset.started === "1" || (document.documentElement.dataset.status ?? "").startsWith("failed")),
    90_000,
    "the scenario to start",
  );
  const status = await session.content(() => document.documentElement.dataset.status);
  if (!String(status).startsWith("started")) throw new Error(`the scenario did not start: ${status}`);
}

/**
 * Reads the log and the scenario from the measure page in a tab of its own (the
 * page reads `storage.local` itself; the background is not asked).
 * @param {Session} session
 * @returns {Promise<{ scenario: any, entries: any[] }>}
 */
export async function readLog(session) {
  const tab = await session.newTab();
  await session.switchTo(tab);
  try {
    await openMeasurePage(session);
    const text = await session.waitFor(() => session.content(() => document.getElementById("log")?.textContent), 30_000, "the log on the measure page");
    return JSON.parse(text);
  } finally {
    await session.closeTab();
  }
}

/**
 * Waits `ms` and writes down the state of the background every `everyMs`.
 * @param {Session} session
 * @param {number} ms
 * @param {number} [everyMs]
 * @returns {Promise<{ at: number, state: string | null }[]>} the first state and every change
 */
export async function watchBackground(session, ms, everyMs = 5000) {
  /** @type {{ at: number, state: string | null }[]} */
  const timeline = [];
  const end = Date.now() + ms;
  for (;;) {
    const state = await session.backgroundState(TEST_ADDON_ID);
    if (timeline.length === 0 || timeline[timeline.length - 1].state !== state) timeline.push({ at: Date.now(), state });
    const left = end - Date.now();
    if (left <= 0) break;
    await sleep(Math.min(everyMs, left));
  }
  return timeline;
}

/**
 * One cell of the matrix (not the "terminate" row).
 * @param {{ channel: "release" | "esr", manifest: "mv3" | "mv2", scenario: "idle" | "sse" | "popup" | "argon", windowMs: number, pollMs?: number }} options
 */
export async function runLifetimeCell({ channel, manifest, scenario, windowMs, pollMs = Number(process.env.FERRET_MEASURE_POLL_MS || 5000) }) {
  const server = await fixtures();
  const session = await launch({ channel, manifest });
  try {
    await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active, 30_000, "the add-on");
    await session.waitFor(async () => (await session.backgroundState(TEST_ADDON_ID)) === "running", 30_000, "a running background");
    const home = await session.windowHandle();
    const tab = await session.newTab();
    await session.switchTo(tab);
    await startScenario(session, scenario, scenario === "sse" ? server.url(server.hosts[0], "/sse") : undefined);
    if (scenario === "popup") {
      // The measure page is closed by going to the popup page; the popup page stays open as a tab.
      await session.navigate(POPUP_URL);
      await session.waitFor(() => session.content(() => document.querySelector("h1")?.textContent), 15_000, "the popup page");
    } else {
      await session.closeTab();
    }
    await session.switchTo(home);

    const startedAt = Date.now();
    const timeline = await watchBackground(session, windowMs, pollMs);
    const endedAt = Date.now();
    const { scenario: stored, entries: all } = await readLog(session);
    // What happened after the window (the read itself) is not part of the measurement.
    const entries = all.filter((/** @type {{ at: number }} */ e) => e.at <= endedAt);
    const summary = summarize(entries);
    const origin = entries.find((/** @type {{ kind: string }} */ e) => e.kind === "scenario_start")?.at ?? startedAt;
    const firstGone = timeline.find((t) => t.state !== null && t.state !== "running" && t.state !== "starting");
    return {
      channel,
      firefox: session.browserVersion,
      manifest,
      scenario,
      windowMs,
      startedAt,
      endedAt,
      stored,
      timeline: timeline.map((t) => ({ afterMs: t.at - origin, state: t.state })),
      entries: entries.map((/** @type {Record<string, unknown> & { at: number }} */ e) => ({ ...e, afterMs: e.at - origin })),
      summary,
      jobsMs: entries.filter((/** @type {{ kind: string }} */ e) => e.kind === "job_done").map((/** @type {{ ms: number }} */ e) => e.ms),
      outcome: {
        lived_whole_window: summary.suspends === 0 && !firstGone,
        first_suspend_after_ms: summary.firstSuspendAfterMs,
        restart_after_ms: summary.restartAfterMs,
        browser_stopped_it_after_ms: firstGone ? firstGone.at - origin : null,
        ended_before_auto_lock: (summary.firstSuspendAfterMs !== null && summary.firstSuspendAfterMs < AUTO_LOCK_MS) || (firstGone !== undefined && firstGone.at - origin < AUTO_LOCK_MS),
        window_covers_auto_lock: windowMs >= AUTO_LOCK_MS,
      },
    };
  } finally {
    await session.quit();
  }
}

/**
 * The "terminate" row: the browser ends the background (as the Terminate button of
 * about:debugging does), and the next start has to be locked with no deadline left.
 * @param {{ channel: "release" | "esr", manifest: "mv3" | "mv2" }} options
 */
export async function runTerminateCell({ channel, manifest }) {
  const session = await launch({ channel, manifest });
  try {
    await session.waitFor(async () => (await session.backgroundState(TEST_ADDON_ID)) === "running", 30_000, "a running background");
    const tab = await session.newTab();
    await session.switchTo(tab);
    await startScenario(session, "idle");
    /** @returns {Promise<{ lockAt: number | null }>} what the page itself reads from session storage */
    const readLockAt = () => session.content(async () => ({ lockAt: (await browser.storage.session.get("lock_at")).lock_at ?? null }));
    const before = { ...(await portCommand(session, { cmd: "state" })), ...(await readLockAt()) };
    const stateBefore = await session.backgroundState(TEST_ADDON_ID);
    let terminate;
    try {
      terminate = { ok: true, state: await session.terminateBackground(TEST_ADDON_ID) };
    } catch (error) {
      terminate = { ok: false, error: String(/** @type {Error} */ (error).message).slice(0, 300) };
    }
    const stateAfter = await session.backgroundState(TEST_ADDON_ID);
    // The next message wakes it, if it can be woken: it has to answer locked.
    const after = { ...(await portCommand(session, { cmd: "state" })), ...(await readLockAt()) };
    const stateWoken = await session.backgroundState(TEST_ADDON_ID);
    const entries = (await portCommand(session, { cmd: "summary" }));
    return {
      channel, firefox: session.browserVersion, manifest, scenario: "terminate",
      before, stateBefore, terminate, stateAfter, after, stateWoken, summary: entries,
      outcome: {
        was_open_with_deadline: before.core === "unlocked" && typeof before.lockAt === "number",
        terminated: terminate.ok && stateAfter !== "running",
        came_back_locked: after.core === "locked",
        lock_at_gone: after.lockAt === null,
      },
    };
  } finally {
    await session.quit();
  }
}
