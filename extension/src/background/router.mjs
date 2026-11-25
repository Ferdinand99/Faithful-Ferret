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
//                 it can never ask for a value. The one answer a content script
//                 gets is the passkey bridge's "taken" (`passkey_request`).
//
// A message is decoded and its sender checked before anything else happens. The
// origin of a sender comes from the browser, never from the message. A handler
// answers with a body; a refusal is the protocol's typed `refused` reply with a
// reason from a fixed short list, never a message text and never anything that
// was in the request. A domain outcome (a wrong password) is the handler's own
// reply, not a refusal.
//
// Handlers come from `background/handlers/<feature>.handler.mjs`, collected by
// the build into `handlers.gen.mjs`; see handlers/README. A handler of several
// types reads which one it got from `ctx.type`.

import { contentSender, isUiPort, withBrowserOrigin } from "../shared/origin.mjs";
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
 * The one core operation a content script's report may reach: it hands the
 * report to the pending fill request it names and answers nothing. A report
 * can never ask for a value.
 */
export const REPORT_OP = "fill_report";

/**
 * The one core operation a content script's capture of a submitted form (and its two small reports) may reach. The
 * router names the type and the sender it checked, so a handler can hand on only the body of the message it got.
 */
export const CAPTURE_OP = "capture_event";

/**
 * The one core operation the passkey bridge's reports may reach (the `passkeys` feature): like the capture's, the router
 * names the type and the sender it checked, and the handler hands on only the body.
 */
export const PASSKEY_OP = "passkey_event";

/**
 * @typedef {"ui" | "content"} Channel
 * @typedef {{
 *   channel: Channel,
 *   type: string,
 *   sender: any,
 *   runtime?: { id?: string, getURL: (path: string) => string },
 *   session?: string,
 *   lock?: (reason: import("./coreHost.mjs").LockReason) => Promise<void>,
 *   state: () => "locked" | "unlocked",
 *   call?: (op: string, args?: unknown) => Promise<unknown>,
 *   report?: (args: unknown) => Promise<void>,
 *   capture?: (body: unknown) => Promise<void>,
 *   passkey?: (body: unknown) => Promise<void>,
 *   touch?: () => void,
 *   setSeconds?: (n: number) => Promise<void>,
 *   getSeconds?: () => Promise<number>,
 * }} HandlerContext
 *   `session` (UI only) names the page's port: it is new for every port, so a
 *   reference the background gave one page is worth nothing on another.
 *   `runtime` (UI only) is the extension's id and address of its own pages, for a handler that checks the sender again
 *   (`isTopLevelExtensionPage`).
 *   `report` (content only) hands a report to `REPORT_OP`. `capture` (content only) hands the body of a capture message to
 *   `CAPTURE_OP`, with the type and the sender the router has checked. `passkey` (content only) does the same for
 *   `PASSKEY_OP`.
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
 *   lock: { checkOrLock: (type: string) => Promise<boolean>, touch: () => void, setSeconds: (n: number) => Promise<void>, getSeconds: () => Promise<number> },
 *   coreHost: { call: (op: string, args?: unknown) => Promise<unknown>, lock: (reason: import("./coreHost.mjs").LockReason) => Promise<void>, state: () => "locked" | "unlocked" },
 *   handlers?: readonly Handler[],
 *   onSessionEnd?: (session: string) => void,
 *   random?: (bytes: Uint8Array) => Uint8Array,
 * }} options
 *   `onSessionEnd` is called with the session of a UI port once the page has
 *   gone (the port was disconnected); `random` fills the bytes of a new session
 *   name (the tests pass their own).
 */
export function createRouter({
  runtime,
  lock,
  coreHost,
  handlers = [],
  onSessionEnd = () => {},
  random = (bytes) => {
    globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes));
    return bytes;
  },
}) {
  const table = indexHandlers(handlers);
  const call = (/** @type {string} */ op, /** @type {unknown} */ args) => coreHost.call(op, args);
  const report = async (/** @type {unknown} */ args) => {
    await coreHost.call(REPORT_OP, args);
  };
  /** A new session name: 16 random bytes as hex. */
  const newSession = () => Array.from(random(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
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
   * @param {string} session the port's session
   * @param {unknown} raw
   */
  async function onUiMessage(port, session, raw) {
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
    // key (a state poll, an unlock attempt) do not, and neither does a read a page
    // made by itself (`automatic`): it is still checked against the deadline above.
    if (!LOCK_EXEMPT.includes(type) && body?.automatic !== true) lock.touch();
    /** @type {HandlerContext} */
    const ctx = Object.freeze({
      channel: "ui",
      type,
      sender: port.sender,
      runtime: Object.freeze({ id: runtime.id, getURL: (/** @type {string} */ path) => runtime.getURL(path) }),
      session,
      call,
      lock: lockHost,
      state,
      touch: () => lock.touch(),
      setSeconds: (/** @type {number} */ n) => lock.setSeconds(n),
      getSeconds: () => lock.getSeconds(),
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
    const session = newSession();
    port.onMessage.addListener((/** @type {unknown} */ raw) => {
      onUiMessage(port, session, raw).catch(() => {});
    });
    // What the background gave this page (references to items) ends with it.
    port.onDisconnect?.addListener(() => {
      try {
        onSessionEnd(session);
      } catch {
        // Nothing to undo.
      }
    });
  }

  /**
   * A message from `runtime.onMessage`. Only a content script's message with a
   * type of the content table is handled; the answer is empty, except the reply of a type that has one (`passkey_request`).
   *
   * @param {unknown} raw
   * @param {any} sender
   * @returns {Promise<string | undefined> | undefined}
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
      // A report handler can read the state and hand the report on to the one report operation, and nothing else: no
      // other call, no lock. A capture handler can hand the body of its own message to the one capture operation; the
      // type and the sender are the router's.
      const ctx = Object.freeze({
        channel: "content",
        type: message.type,
        sender: from,
        state,
        report,
        capture: async (/** @type {unknown} */ body) => {
          await call(CAPTURE_OP, { type: message.type, sender: from, body });
        },
        // The passkey broker also gets the browser's origin of the frame (and whether the tab is private), from the sender.
        passkey: async (/** @type {unknown} */ body) => {
          await call(PASSKEY_OP, { type: message.type, sender: withBrowserOrigin(from, sender), body });
        },
      });
      /** @type {unknown} */
      let result;
      try {
        result = await handler.handle(message.body, ctx);
      } catch {
        // A report that fails has no one to answer.
        return undefined;
      }
      // A content type with a reply (only `passkey_request`: "taken", so that a bridge whose request was not taken hands the
      // page's call back to the browser) gets the handler's answer; every other report gets nothing.
      const def = /** @type {any} */ (CONTENT_TYPES)[message.type];
      if (!def.reply) return undefined;
      try {
        return encode(message.type, result, { reply: true, id: message.id });
      } catch {
        return undefined;
      }
    })();
  }

  return { onConnect, onMessage };
}
