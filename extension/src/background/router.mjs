// The message router. It holds no keys and has no way to get one: it reaches the
// core host only through `call(op, args)` with a name from the core host's fixed
// list, and it calls the lock before every message that needs the vault.
//
// Two channels (design document, section 10.1):
//
//   UI port       An extension page opens `runtime.connect({ name: UI_PORT })`.
//                 The port is accepted only through `isUiPort`: the extension's
//                 own id and URL, a top-level page (`frameId` 0), never an
//                 extension page that a web page frames and never a content
//                 script. Every message on it is decoded with UI_TYPES.
//   Content       A content script sends `runtime.sendMessage`. The sender must
//                 be a content script (`contentSender`), and the message is
//                 decoded with CONTENT_TYPES only. A content script can report;
//                 it can never ask for a value.
//
// A message is decoded and its sender checked before anything else happens. The
// origin of a sender comes from the browser, never from the message. A handler
// answers with a body; a refusal is the protocol's typed `refused` reply with a
// reason from a fixed short list, never a message text and never anything that
// was in the request. A domain outcome (a wrong password) is the handler's own
// reply, not a refusal.
//
// Handlers come from `background/handlers/<feature>.handler.mjs`, collected by
// the build into `handlers.gen.mjs`; see handlers/README.

import { contentSender, isUiPort } from "../shared/origin.mjs";
import {
  CONTENT_TYPES,
  REFUSAL_REASONS,
  UI_PORT,
  UI_TYPES,
  decode,
  encode,
  encodeRefusal,
} from "../shared/protocol.mjs";
import { LOCK_EXEMPT } from "./lock.mjs";

/**
 * @typedef {"ui" | "content"} Channel
 * @typedef {{
 *   channel: Channel,
 *   sender: any,
 *   lock?: (reason: import("./coreHost.mjs").LockReason) => Promise<void>,
 *   state: () => "locked" | "unlocked",
 *   call?: (op: string, args?: unknown) => Promise<unknown>,
 *   touch?: () => void,
 *   setMinutes?: (n: number) => void,
 * }} HandlerContext
 * @typedef {{ types: readonly string[], channel: Channel, handle: (body: any, ctx: HandlerContext) => unknown }} Handler
 */

/** @param {unknown} error @returns {string} */
function reasonOf(error) {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  return typeof code === "string" && REFUSAL_REASONS.includes(code) ? code : "internal_error";
}

/**
 * Checks the handlers and indexes them by channel and type. A type that the
 * channel does not have, a type with two handlers and a malformed handler are
 * errors at start-up, not surprises later.
 *
 * @param {readonly Handler[]} handlers
 * @returns {Map<string, Handler>}
 */
function indexHandlers(handlers) {
  /** @type {Map<string, Handler>} */
  const table = new Map();
  const tables = { ui: UI_TYPES, content: CONTENT_TYPES };
  for (const handler of handlers) {
    if (
      typeof handler !== "object" ||
      handler === null ||
      !Object.hasOwn(tables, handler.channel) ||
      !Array.isArray(handler.types) ||
      handler.types.length === 0 ||
      typeof handler.handle !== "function"
    ) {
      throw new TypeError("router: a handler needs channel, types and handle");
    }
    for (const type of handler.types) {
      if (typeof type !== "string" || !Object.hasOwn(tables[handler.channel], type)) {
        throw new TypeError(`router: ${handler.channel} has no type ${String(type).slice(0, 32)}`);
      }
      const key = `${handler.channel}:${type}`;
      if (table.has(key)) throw new TypeError(`router: two handlers for ${key}`);
      table.set(key, handler);
    }
  }
  return table;
}

/**
 * @param {{
 *   runtime: { id?: string, getURL: (path: string) => string },
 *   lock: { checkOrLock: (type: string) => Promise<boolean>, touch: () => void, setMinutes: (n: number) => void },
 *   coreHost: { call: (op: string, args?: unknown) => Promise<unknown>, lock: (reason: import("./coreHost.mjs").LockReason) => Promise<void>, state: () => "locked" | "unlocked" },
 *   handlers?: readonly Handler[],
 * }} options
 */
export function createRouter({ runtime, lock, coreHost, handlers = [] }) {
  const table = indexHandlers(handlers);
  const call = (/** @type {string} */ op, /** @type {unknown} */ args) => coreHost.call(op, args);
  const lockHost = (/** @type {import("./coreHost.mjs").LockReason} */ reason) => coreHost.lock(reason);
  const state = () => coreHost.state();

  /**
   * True when the call may go on. Anything that goes wrong in the check is a
   * refusal.
   *
   * @param {string} type
   */
  async function allowed(type) {
    try {
      return await lock.checkOrLock(type);
    } catch {
      return false;
    }
  }

  /** @param {{ postMessage: (message: string) => void }} port @param {string} text */
  function post(port, text) {
    try {
      port.postMessage(text);
    } catch {
      // The page is gone.
    }
  }

  /**
   * One message on the UI port.
   *
   * @param {any} port
   * @param {unknown} raw
   */
  async function onUiMessage(port, raw) {
    /** @type {{ id: string, type: string, body: any }} */
    let message;
    try {
      message = decode(raw, UI_TYPES);
    } catch {
      // Our own pages encode with the same tables, so this is not a mistake of
      // a page: end the connection.
      try {
        port.disconnect();
      } catch {
        // Already gone.
      }
      return;
    }
    const { id, type, body } = message;
    const handler = table.get(`ui:${type}`);
    if (!handler) return post(port, encodeRefusal(id, "not_available"));
    const may = await allowed(type);
    // A request to lock is never refused: it runs whatever the check says.
    if (!may && type !== "lock") return post(port, encodeRefusal(id, "vault_locked"));
    // Activity in Ferret's own UI moves the deadline. The messages that need no
    // key (a state poll, an unlock attempt) do not.
    if (!LOCK_EXEMPT.includes(type)) lock.touch();
    /** @type {HandlerContext} */
    const ctx = Object.freeze({
      channel: "ui",
      sender: port.sender,
      call,
      lock: lockHost,
      state,
      touch: () => lock.touch(),
      setMinutes: (/** @type {number} */ n) => lock.setMinutes(n),
    });
    /** @type {unknown} */
    let result;
    try {
      result = await handler.handle(body, ctx);
    } catch (error) {
      return post(port, encodeRefusal(id, reasonOf(error)));
    }
    // A handler that answers with the wrong shape is a bug of ours; the page
    // learns nothing from it.
    try {
      post(port, encode(type, result, { reply: true, id }));
    } catch {
      post(port, encodeRefusal(id, "internal_error"));
    }
  }

  /**
   * A new port from `runtime.onConnect`.
   *
   * @param {any} port
   */
  function onConnect(port) {
    if (port?.name !== UI_PORT) return;
    if (!isUiPort(port, runtime, UI_PORT)) {
      try {
        port.disconnect();
      } catch {
        // Already gone.
      }
      return;
    }
    port.onMessage.addListener((/** @type {unknown} */ raw) => {
      onUiMessage(port, raw).catch(() => {});
    });
  }

  /**
   * A message from `runtime.onMessage`. Only a content script's message with a
   * type of the content table is handled; the answer is always empty.
   *
   * @param {unknown} raw
   * @param {any} sender
   * @returns {Promise<undefined> | undefined}
   */
  function onMessage(raw, sender) {
    const from = contentSender(sender, runtime);
    if (!from) return undefined;
    /** @type {{ id: string, type: string, body: any }} */
    let message;
    try {
      message = decode(raw, CONTENT_TYPES);
    } catch {
      return undefined;
    }
    const handler = table.get(`content:${message.type}`);
    if (!handler) return undefined;
    return (async () => {
      if (!(await allowed(message.type))) return undefined;
      /** @type {HandlerContext} */
      // A report handler can read the state and nothing else: no call, no lock.
      const ctx = Object.freeze({ channel: "content", sender: from, state });
      try {
        await handler.handle(message.body, ctx);
      } catch {
        // A report that fails has no one to answer.
      }
      return undefined;
    })();
  }

  return { onConnect, onMessage };
}
