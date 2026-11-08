// What the Firefox test of the fill engine needs from the background, in the
// test build only: a port the test bridge page uses to inject the fill script
// into a tab (through the real `injectFill`), to send one `fill_field`, and to
// read what the content script reported. The page that is filled never sees
// this. It is in a folder named test-only: a release leaves it out.
//
// The port is not the UI protocol. It is accepted from top-level extension
// pages only, like the UI port, and it carries the one value a test fills.

import { contentSender, isUiPort } from "../../shared/origin.mjs";
import { CONTENT_TYPES, decode, encode } from "../../shared/protocol.mjs";
import { injectFill } from "../inject.mjs";

export const FILL_PROBE_PORT = "ferret-test-fill";

/** What content scripts reported, in order. @type {Array<Record<string, unknown>>} */
const reports = [];
const MAX_REPORTS = 200;

/**
 * Listens for the content script's reports. Called once, when the hooks load.
 * @param {{ runtime: any }} deps
 */
export function listen({ runtime }) {
  runtime.onMessage.addListener((/** @type {unknown} */ raw, /** @type {any} */ sender) => {
    const from = contentSender(sender, runtime);
    if (from === null) return;
    try {
      const { type, body } = decode(raw, CONTENT_TYPES);
      if (reports.length < MAX_REPORTS) {
        reports.push({ type, body, tabId: from.tabId, frameId: from.frameId, documentId: from.documentId ?? null, url: from.url, senderOrigin: sender.origin ?? null });
      }
    } catch {
      reports.push({ type: "undecodable" });
    }
  });
}

/** @param {unknown} n */
const index = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * @param {any} port a port from `runtime.onConnect`
 * @param {{ runtime: any }} deps
 */
export function onConnect(port, { runtime }) {
  if (!isUiPort(port, runtime, FILL_PROBE_PORT)) {
    try {
      port.disconnect();
    } catch {
      // Already gone.
    }
    return;
  }
  port.onMessage.addListener(async (/** @type {any} */ message) => {
    const id = message?.id;
    const a = message?.args ?? {};
    try {
      if (message?.op === "inject") {
        if (!index(a.tabId) || !index(a.frameId)) throw new Error("bad_target");
        await injectFill({ scripting: browser.scripting, tabId: a.tabId, frameId: a.frameId, requestId: a.requestId, documentId: a.documentId });
        port.postMessage({ id, ok: true });
      } else if (message?.op === "fill") {
        if (!index(a.tabId) || !index(a.frameId)) throw new Error("bad_target");
        const raw = encode("fill_field", {
          request_id: a.requestId,
          field: a.field,
          value: a.value,
          expect: { origin: a.origin, frameUrl: a.frameUrl },
        });
        // Nobody listens in a page that has no engine yet: the browser says so.
        const delivered = await browser.tabs.sendMessage(a.tabId, raw, { frameId: a.frameId }).then(() => true, () => false);
        port.postMessage({ id, ok: true, value: { delivered } });
      } else if (message?.op === "reports") {
        port.postMessage({ id, ok: true, value: reports });
      } else if (message?.op === "clear") {
        reports.length = 0;
        port.postMessage({ id, ok: true });
      } else {
        port.postMessage({ id, ok: false, error: "unknown_op" });
      }
    } catch (error) {
      port.postMessage({ id, ok: false, error: String(/** @type {Error} */ (error)?.message ?? error) });
    }
  });
}
