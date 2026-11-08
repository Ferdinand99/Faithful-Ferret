// What only the test build has. It is in a folder named test-only: the release
// build leaves the folder out and the release check refuses it.
//
//  * the core operations `argon2_bench` and `measure_open`;
//  * a port for the test pages to call core operations by name;
//  * the lifetime log of the background page and the scenarios of the lifetime
//    measurement (measureLog.mjs, measureScenario.mjs), with a port to start
//    them from the measure page;
//  * a port that tells a test page what the router would see of it, and a
//    listener that tells a content script the same.
//
// None of the ports is the UI protocol and none carries a secret: a test page
// sends `{ id, op, args }` (or `{ id, cmd, ... }`) and gets `{ id, ok: true, value }`
// or `{ id, ok: false, code }` back. The call and measure ports are accepted from
// top-level extension pages only, like the UI port. The test build is never a
// release: it has its own add-on id and the release check refuses it.

import { contentSender, isTopLevelExtensionPage, isUiPort } from "../../shared/origin.mjs";
import * as fillProbe from "./fillProbe.mjs";
import { LOG_KEY, SCENARIO_KEY, startMeasureLog, summarize } from "./measureLog.mjs";
import { createScenarios } from "./measureScenario.mjs";

export const TEST_CORE_PORT = "ferret-test-core";
export const TEST_MEASURE_PORT = "ferret-test-measure";
export const TEST_WHOAMI_PORT = "ferret-test-whoami";

const FIXED_PASSWORD = "ferret-bench-password";

/** @param {unknown} n @param {number} min @param {number} max */
function whole(n, min, max) {
  return typeof n === "number" && Number.isInteger(n) && n >= min && n <= max;
}

/**
 * Runs Argon2id once in the job worker and reports how long it took. The key
 * that comes out is wiped here and never returned.
 *
 * @type {import("../coreHost.mjs").CoreOp}
 */
const argon2Bench = {
  vault: false,
  worker: "job",
  async run(client, args, { now }) {
    const { m_kib: mKib, t, p } = args ?? {};
    if (!whole(mKib, 1, 524_288) || !whole(t, 1, 16) || !whole(p, 1, 4)) {
      throw Object.assign(new Error("invalid_input"), { code: "invalid_input" });
    }
    const salt = new Uint8Array(16).fill(9);
    const started = now();
    const key = await client.job.argon2_export_key(FIXED_PASSWORD, salt, { m_kib: mKib, t, p }, "open", null);
    const ms = now() - started;
    const length = key.length;
    key.fill(0);
    return { ok: true, ms, key_length: length };
  },
};

/**
 * Opens the vault without a password, for the lifetime measurement: the vault
 * worker starts and holds a WASM instance (the stateless call proves it is
 * there), and the host says "unlocked", so the auto-lock's deadline starts. No
 * key exists.
 *
 * @type {import("../coreHost.mjs").CoreOp}
 */
const measureOpen = {
  vault: false,
  worker: "vault",
  async run(client, _args, { setUnlocked }) {
    const bytes = await client.vault.ferret_aaguid();
    if (!(bytes instanceof Uint8Array) || bytes.length !== 16) throw Object.assign(new Error("internal"), { code: "internal" });
    setUnlocked();
    return { ok: true };
  },
};

/** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
export const ops = Object.freeze({ argon2_bench: argon2Bench, measure_open: measureOpen });

/** What the browser says about a sender, as plain data. @param {any} sender */
function describeSender(sender) {
  return {
    id: sender?.id ?? null,
    url: sender?.url ?? null,
    origin: sender?.origin ?? null,
    frameId: sender?.frameId ?? null,
    documentId: sender?.documentId ?? null,
    tabId: sender?.tab?.id ?? null,
    tabUrl: sender?.tab?.url ?? null,
    envType: sender?.envType ?? null,
  };
}

/** @param {unknown} error @returns {string} */
const codeOf = (error) => {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "internal";
};

/** @param {any} port */
function hangUp(port) {
  try {
    port.disconnect();
  } catch {
    // Already gone.
  }
}

/**
 * The port that calls core operations by name.
 * @param {any} port a port from `runtime.onConnect`
 * @param {{ runtime: { id?: string, getURL: (path: string) => string }, coreHost: { call: (op: string, args?: unknown) => Promise<unknown> } }} deps
 */
export function onConnect(port, { runtime, coreHost }) {
  if (port?.name === fillProbe.FILL_PROBE_PORT) {
    fillProbe.onConnect(port, { runtime });
    return;
  }
  if (port?.name !== TEST_CORE_PORT) return;
  if (!isUiPort(port, runtime, TEST_CORE_PORT)) {
    hangUp(port);
    return;
  }
  port.onMessage.addListener(async (/** @type {any} */ message) => {
    const id = message?.id;
    try {
      const value = await coreHost.call(message?.op, message?.args);
      port.postMessage({ id, ok: true, value });
    } catch (error) {
      port.postMessage({ id, ok: false, code: codeOf(error) });
    }
  });
}

// The content script's reports are kept for the fill probe (the unit tests load
// this module without a `browser`).
if (typeof browser !== "undefined") fillProbe.listen({ runtime: browser.runtime });

/**
 * Sets the test build's hooks up. Call it while the background page loads, so the
 * listeners are there for the event that woke the page.
 *
 * @param {{
 *   browser: any,
 *   runtime: { id?: string, getURL: (path: string) => string },
 *   coreHost: { call: (op: string, args?: unknown) => Promise<unknown>, addOps: (ops: any) => void, state: () => string },
 *   now: () => number,
 * }} deps
 */
export function install({ browser, runtime, coreHost, now }) {
  coreHost.addOps(ops);
  const storageLocal = browser.storage.local;
  const { log } = startMeasureLog({
    runtime: browser.runtime,
    alarms: browser.alarms,
    storageLocal,
    now,
    core: () => coreHost.state(),
    // A synchronous place for the suspend marker (the page may be gone before a storage write finishes).
    marker: globalThis.localStorage ?? null,
  });
  const scenarios = createScenarios({ coreHost, log, storageLocal, scenarioKey: SCENARIO_KEY, now });

  /** The commands of the measure port. @type {Record<string, (args: any) => Promise<unknown> | unknown>} */
  const commands = {
    start: (args) => scenarios.start(args),
    stop: () => scenarios.stop(),
    clear: async () => {
      await log.clear();
      return { ok: true };
    },
    state: async () => ({
      core: coreHost.state(),
      scenario: scenarios.current(),
      lockAt: (await browser.storage.session.get("lock_at")).lock_at ?? null,
    }),
    summary: async () => summarize(await log.read()),
    // What the background page itself can do (it is not the same as an extension page for every API).
    probe: () => ({
      // The control for the CSP of the extension pages: no eval, so this has to throw.
      evalBlocked: (() => {
        try {
          return new Function("return 1")() !== 1;
        } catch (error) {
          return /** @type {Error} */ (error).name;
        }
      })(),
      storageSession: typeof browser.storage.session,
      setAccessLevel: typeof browser.storage.session?.setAccessLevel,
      locks: typeof navigator.locks,
      trustedTypes: typeof (/** @type {any} */ (globalThis).trustedTypes),
      clipboardWriteText: typeof navigator.clipboard?.writeText,
      idleOnStateChanged: typeof browser.idle?.onStateChanged?.addListener,
      scriptingExecuteScript: typeof browser.scripting?.executeScript,
      menusGetTargetElement: typeof browser.menus?.getTargetElement,
    }),
    clipboard: async (args) => {
      if (typeof args?.text !== "string" || args.text.length > 100) throw Object.assign(new Error("bad_text"), { code: "bad_text" });
      try {
        await navigator.clipboard.writeText(args.text);
        return { ok: true };
      } catch (error) {
        // A fact for the document, not a secret: which error the browser gave.
        return { ok: false, error: `${/** @type {Error} */ (error)?.name}: ${String(/** @type {Error} */ (error)?.message).slice(0, 160)}` };
      }
    },
    locks: () => navigator.locks.request("ferret-test-probe", async () => ({ ok: true })),
  };

  browser.runtime.onConnect.addListener((/** @type {any} */ port) => {
    if (port?.name === TEST_CORE_PORT || port?.name === fillProbe.FILL_PROBE_PORT) {
      onConnect(port, { runtime, coreHost });
      return;
    }
    if (port?.name === TEST_WHOAMI_PORT) {
      // Tells a page what the router would see of it. It grants nothing: the answer is a
      // verdict and the sender's own facts, so a page that the router would turn away (a
      // framed page, a page of another extension) still gets an answer to show.
      try {
        port.postMessage({
          sender: describeSender(port.sender),
          isUiPort: isUiPort({ name: TEST_WHOAMI_PORT, sender: port.sender }, runtime, TEST_WHOAMI_PORT),
          isTopLevel: isTopLevelExtensionPage(port.sender, runtime),
        });
      } catch {
        // The page is gone.
      }
      return;
    }
    if (port?.name !== TEST_MEASURE_PORT) return;
    if (!isUiPort(port, runtime, TEST_MEASURE_PORT)) {
      hangUp(port);
      return;
    }
    port.onMessage.addListener(async (/** @type {any} */ message) => {
      const id = message?.id;
      try {
        const run = typeof message?.cmd === "string" && Object.hasOwn(commands, message.cmd) ? commands[message.cmd] : null;
        if (!run) throw Object.assign(new Error("unknown_command"), { code: "unknown_command" });
        port.postMessage({ id, ok: true, value: await run(message) });
      } catch (error) {
        port.postMessage({ id, ok: false, code: codeOf(error) });
      }
    });
  });

  // What a content script's message looks like to the background (the browser's
  // facts about the sender). Anything but this one probe is left to the router.
  browser.runtime.onMessage.addListener((/** @type {any} */ message, /** @type {any} */ sender) => {
    if (message?.ferretProbe !== "sender") return undefined;
    return Promise.resolve({ sender: describeSender(sender), contentSender: contentSender(sender, runtime) });
  });
}

export { LOG_KEY, SCENARIO_KEY };
