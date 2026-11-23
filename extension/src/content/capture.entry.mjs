// The start of the capture script. The build joins this file and what it imports into one classic script
// (content/capture.inject.js, see scripts/lib/classic.mjs), which the extension registers for https pages. It
// starts on an https page only (it needs no messaging until a message goes), hands the detection module of the fill engine to the capture, and sends what the
// capture reports to the extension as a message of the protocol (shared/protocol.mjs: form_capture, form_gone and
// page_ready). It builds the envelope itself, because the capture script has no dependencies and the extension checks
// every message against its schema when it arrives. A message that is over the size limit is not sent.
import { createCapture } from "./capture.mjs";
import { SUBMIT, TEXT_TYPES, controlText, findGroups, flatParent, isInside, isSubmitControl, isToggle } from "./forms.mjs";

/** The protocol version and the size limit of a capture message, as shared/protocol.mjs and the extension have them. */
const VERSION = 1;
const MAX_BYTES = 4096;

/** @param {string} text */
const size = (text) => (typeof TextEncoder === "function" ? new TextEncoder().encode(text).length : text.length * 3);

/**
 * The extension's messaging is looked up when the first message goes, not at the start: the first access to it costs
 * more than the rest of the script's start, and most pages never get a message.
 */
function send(/** @type {string} */ type, /** @type {Record<string, unknown>} */ body) {
  const bytes = new Uint8Array(12);
  window.crypto.getRandomValues(bytes);
  const id = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const raw = JSON.stringify({ v: VERSION, id, type, body });
  if (size(raw) > MAX_BYTES) return;
  const runtime = /** @type {any} */ (globalThis).browser?.runtime;
  if (runtime) Promise.resolve(runtime.sendMessage(raw)).catch(() => {});
}

if (/^https:/.test(window.location.href) && window.origin !== "null") {
  createCapture({
    window,
    document,
    send,
    clock: {
      now: () => Date.now(),
      setTimeout: (fn, ms) => window.setTimeout(fn, ms),
      clearTimeout: (id) => window.clearTimeout(id),
    },
    forms: { findGroups, isInside, isSubmitControl, isToggle, controlText, flatParent, SUBMIT, TEXT_TYPES },
  });
}
