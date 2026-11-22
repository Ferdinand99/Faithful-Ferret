// What the extension's own pages share: the UI port to the background
// (design document, section 10.1) and the reading of the background's answers.
// Plain ESM with no DOM, so the tests run it as it is.
//
// A page opens one port (`runtime.connect({ name: UI_PORT })`) and asks over it
// with a type of the UI table. The background answers on the same port with the
// same id: the reply of that type, or the typed refusal. A page never sends a
// message to a content script and never gets a value from one.

import { UI_PORT, UI_TYPES, decode, encode } from "../shared/protocol.mjs";

/** The error of a request that got no answer of its type. Its `code` is a refusal reason, or `disconnected`. */
export class UiError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "UiError";
    this.code = code;
  }
}

/**
 * @typedef {(type: string, body: Record<string, unknown>) => Promise<any>} Request
 * @typedef {{
 *   postMessage(message: string): void,
 *   disconnect(): void,
 *   onMessage: { addListener(fn: (raw: unknown) => void): void },
 *   onDisconnect: { addListener(fn: () => void): void },
 * }} Port
 */

/**
 * Opens the UI port and returns the way to ask over it. A port the background
 * ended (it was unloaded, or it refused a message) fails what waited on it; the
 * next request opens a new port, which starts the background again.
 * @param {{ connect(info: { name: string }): Port }} runtime
 * @returns {{ request: Request, close(): void }}
 */
export function connectUi(runtime) {
  /** @type {Map<string, { type: string, resolve: (body: any) => void, reject: (error: Error) => void }>} */
  const waiting = new Map();
  let closed = false;
  let counter = 0;
  /** @type {Port | null} */
  let port = null;

  const fail = () => {
    for (const entry of waiting.values()) entry.reject(new UiError("disconnected"));
    waiting.clear();
  };

  /** @returns {Port} */
  const open = () => {
    if (port !== null) return port;
    const next = runtime.connect({ name: UI_PORT });
    next.onMessage.addListener((raw) => {
      if (port !== next) return;
      /** @type {{ id: string, type: string, body: any }} */
      let message;
      try {
        message = decode(raw, UI_TYPES, { reply: true });
      } catch {
        return;
      }
      const entry = waiting.get(message.id);
      if (!entry) return;
      waiting.delete(message.id);
      if (message.type === "refused") entry.reject(new UiError(message.body.reason));
      else if (message.type !== entry.type) entry.reject(new UiError("internal_error"));
      else entry.resolve(message.body);
    });
    next.onDisconnect.addListener(() => {
      if (port !== next) return;
      port = null;
      fail();
    });
    port = next;
    return next;
  };

  return {
    request(type, body) {
      if (closed) return Promise.reject(new UiError("disconnected"));
      counter += 1;
      const id = `ui${counter}`;
      // `encode` checks the body against the type's schema before anything is sent.
      const raw = encode(type, body, { id });
      return new Promise((resolve, reject) => {
        waiting.set(id, { type, resolve, reject });
        try {
          open().postMessage(raw);
        } catch {
          waiting.delete(id);
          port = null;
          reject(new UiError("disconnected"));
        }
      });
    },
    close() {
      closed = true;
      try {
        port?.disconnect();
      } catch {
        // Already gone.
      }
      port = null;
      fail();
    },
  };
}

/**
 * The host of a server the way the pages show it: the Unicode form, and the
 * A-label next to it when the two differ (design document, section 10.4).
 * @param {{ host?: string, host_a_label?: string, server?: string }} info
 * @returns {string}
 */
export function shownHost(info) {
  const unicode = typeof info.host === "string" ? info.host : "";
  const aLabel = typeof info.host_a_label === "string" ? info.host_a_label : "";
  if (unicode === "") return aLabel !== "" ? aLabel : typeof info.server === "string" ? info.server : "";
  return aLabel !== "" && aLabel !== unicode ? `${unicode} (${aLabel})` : unicode;
}

/**
 * The initials of an account for the avatar: the first letter of the e-mail's
 * name, and of its second part when it has one ("ola.nordmann@…" is "ON").
 * @param {string | undefined} email
 * @returns {string}
 */
export function initialsOf(email) {
  if (typeof email !== "string" || email === "") return "";
  const name = email.slice(0, Math.max(email.indexOf("@"), 0) || email.length);
  const parts = name.split(/[._+-]+/).filter(Boolean);
  const letters = (parts.length > 1 ? [parts[0], parts[1]] : [name]).map((part) => [...part][0] ?? "");
  return letters.join("").toUpperCase();
}

/** The i18n key of the text for a reason the background gave (`session.error.<reason>`). @param {unknown} reason */
export function reasonKey(reason) {
  return `session.error.${typeof reason === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(reason) ? reason : "unknown"}`;
}
