// What only the test build has: the `argon2_bench` core operation and a port for
// the test pages to call core operations by name. It is in a folder named
// test-only: the release build leaves the folder out and the release check
// refuses it.
//
// The port is not the UI protocol and carries no secret: a test page sends
// `{ id, op, args }` and gets `{ id, ok: true, value }` or `{ id, ok: false, code }`
// back. It is accepted from top-level extension pages only, like the UI port.

import { isUiPort } from "../../shared/origin.mjs";
import * as fillProbe from "./fillProbe.mjs";

export const TEST_CORE_PORT = "ferret-test-core";

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

/** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
export const ops = Object.freeze({ argon2_bench: argon2Bench });

/**
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
    try {
      port.disconnect();
    } catch {
      // Already gone.
    }
    return;
  }
  port.onMessage.addListener(async (/** @type {any} */ message) => {
    const id = message?.id;
    try {
      const value = await coreHost.call(message?.op, message?.args);
      port.postMessage({ id, ok: true, value });
    } catch (error) {
      const code = /** @type {{ code?: unknown }} */ (error)?.code;
      port.postMessage({ id, ok: false, code: typeof code === "string" ? code : "internal" });
    }
  });
}

// The content script's reports are kept for the fill probe (the unit tests load
// this module without a `browser`).
if (typeof browser !== "undefined") fillProbe.listen({ runtime: browser.runtime });
