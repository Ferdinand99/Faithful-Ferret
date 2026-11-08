// Background of the passkey spike. Test-only code.
//
// Answers requests that arrive over runtime ports from the relay content script,
// with the software authenticator in authenticator.mjs, and offers a small control
// surface to the control page (control.html) so the browser tests can steer it.
//
// Rules this file keeps, because the real provider must (design document 9.2):
//  - the origin comes from port.sender, never from the message;
//  - a request from a frame other than the top frame is answered only when the
//    frame's origin equals the top frame's origin (webNavigation.getFrame);
//  - the private keys never leave authenticator.mjs.
import { Authenticator, DomError } from "./authenticator.mjs";

const auth = new Authenticator();
const state = {
  /** What isConditionalMediationAvailable answers. */
  conditionalAvailable: true,
  /** Whether the (simulated) user verification succeeded for the next requests. */
  uv: true,
  /** @type {Record<string, unknown>[]} */
  events: [],
  /** @type {Map<number, { port: browser.runtime.Port, id: number, request: any, origin: string }>} */
  conditional: new Map(),
  nextKey: 1,
};

const CONTROL_URL = browser.runtime.getURL("control.html");

/**
 * What the browser says about the sender of a port. Throws a DomError when it is not
 * a content script of this extension in a tab, or when its origin is opaque.
 * @param {browser.runtime.MessageSender} sender
 */
async function senderFacts(sender) {
  if (sender.id !== browser.runtime.id) throw new DomError("NotAllowedError", "foreign sender");
  if (!sender.tab || typeof sender.tab.id !== "number" || typeof sender.frameId !== "number") throw new DomError("NotAllowedError", "not a tab frame");
  const origin = sender.origin ?? (sender.url ? new URL(sender.url).origin : undefined);
  if (!origin || origin === "null") throw new DomError("SecurityError", "opaque origin");
  const tabId = sender.tab.id;
  const frameId = sender.frameId;
  const documentId = /** @type {any} */ (sender).documentId ?? null;
  /** @type {Record<string, unknown>} */
  const facts = { origin, tabId, frameId, documentId, senderUrl: sender.url ?? null, hasOriginField: sender.origin !== undefined };
  if (frameId !== 0) {
    // Cross-origin frames are denied in v1: the frame's origin must equal the top frame's.
    const top = await browser.webNavigation.getFrame({ tabId, frameId: 0 });
    const topOrigin = top ? new URL(top.url).origin : null;
    facts.topOrigin = topOrigin;
    if (topOrigin !== origin) throw new DomError("NotAllowedError", "cross-origin frame");
  }
  try {
    const frame = await browser.webNavigation.getFrame(/** @type {any} */ ({ tabId, frameId, documentId: documentId ?? undefined }));
    facts.frameUrl = frame ? frame.url : null;
    facts.frameDocumentId = frame ? /** @type {any} */ (frame).documentId ?? null : null;
  } catch (error) {
    facts.frameLookup = String(error);
  }
  return facts;
}

/** @param {unknown} error */
function describeError(error) {
  const known = error instanceof DomError;
  return { name: known ? error.name : "NotAllowedError", message: known ? error.message : "internal error" };
}

/**
 * @param {browser.runtime.Port} port
 * @param {Record<string, unknown>} facts
 * @param {{ id: number, kind: string, payload: any }} msg
 */
async function answer(port, facts, msg) {
  const origin = /** @type {string} */ (facts.origin);
  const log = (/** @type {Record<string, unknown>} */ extra) => state.events.push({ kind: msg.kind, ...facts, ...extra });
  try {
    switch (msg.kind) {
      case "cma":
        log({ available: state.conditionalAvailable });
        port.postMessage({ id: msg.id, available: state.conditionalAvailable });
        return;
      case "create": {
        const res = await auth.create({ ...msg.payload, origin, uv: state.uv });
        log({ rpId: msg.payload.rpId ?? null, outcome: "result" in res ? "ok" : "native" });
        port.postMessage({ id: msg.id, ...res });
        return;
      }
      case "get": {
        if (msg.payload.conditional) {
          // Held until the control page "selects a credential" (the autofill surface of the real provider).
          resolveRpIdOrThrow(origin, msg.payload.rpId);
          const key = state.nextKey++;
          state.conditional.set(msg.id, { port, id: msg.id, request: { ...msg.payload, origin }, origin });
          log({ outcome: "held", key });
          return;
        }
        const res = await auth.get({ ...msg.payload, origin, uv: state.uv });
        log({ rpId: msg.payload.rpId ?? null, outcome: "result" in res ? "ok" : "native" });
        port.postMessage({ id: msg.id, ...res });
        return;
      }
      default:
        throw new DomError("NotSupportedError", "unknown request");
    }
  } catch (error) {
    log({ outcome: "refused", error: describeError(error).name });
    port.postMessage({ id: msg.id, error: describeError(error) });
  }
}

/** @param {string} origin @param {string | null} rpId */
function resolveRpIdOrThrow(origin, rpId) {
  auth.candidates({ origin, rpId });
}

browser.runtime.onConnect.addListener((port) => {
  if (port.name !== "passkey") {
    port.disconnect();
    return;
  }
  /** @type {Promise<Record<string, unknown> | null>} */
  const factsPromise = senderFacts(port.sender ?? {}).catch((error) => {
    state.events.push({ kind: "connect-refused", error: describeError(error).name, senderUrl: port.sender?.url ?? null });
    return null;
  });
  void factsPromise.then((facts) => { if (facts) state.events.push({ kind: "connect", ...facts }); });
  port.onMessage.addListener(async (msg) => {
    const facts = await factsPromise;
    if (!facts) {
      port.disconnect();
      return;
    }
    if (!msg || typeof msg.id !== "number" || typeof msg.kind !== "string") return;
    if (msg.kind === "cancel") {
      state.conditional.delete(msg.payload && msg.payload.target);
      state.events.push({ kind: "cancel", ...facts });
      return;
    }
    await answer(port, facts, msg);
  });
  port.onDisconnect.addListener(() => {
    for (const [key, held] of state.conditional) if (held.port === port) state.conditional.delete(key);
  });
});

// ------------------------------------------------------------------ dynamic registration
/** @param {string[]} matches @param {boolean} persist */
async function registerDynamic(matches, persist) {
  await browser.scripting.registerContentScripts([
    { id: "spike-main", matches, js: ["main-world.js"], runAt: "document_start", world: "MAIN", allFrames: true, persistAcrossSessions: persist },
    { id: "spike-relay", matches, js: ["relay.js"], runAt: "document_start", allFrames: true, persistAcrossSessions: persist },
  ]);
}

// ------------------------------------------------------------------ control surface
/** Calls the control page may make. @type {Record<string, (args: any) => Promise<unknown> | unknown>} */
const CONTROL = {
  setConditionalAvailable: (v) => { state.conditionalAvailable = Boolean(v); },
  setUv: (v) => { state.uv = Boolean(v); },
  events: () => state.events,
  clearEvents: () => { state.events.length = 0; },
  count: () => auth.count(),
  keyFlags: () => auth.keyFlags(),
  tryExportPrivate: () => auth.tryExportPrivate(),
  heldConditional: () => state.conditional.size,
  /** The user picks a credential in the (simulated) autofill surface. */
  async resolveConditional() {
    const [key, held] = [...state.conditional][0] ?? [];
    if (!held) throw new Error("no held conditional request");
    state.conditional.delete(key);
    const res = await auth.get({ ...held.request, uv: state.uv });
    held.port.postMessage({ id: held.id, ...res });
    return "resolved";
  },
  /** "ok", or the error text (without a host permission the call may refuse). */
  async registerDynamic(a) {
    try {
      await registerDynamic(a.matches, a.persist);
      return "ok";
    } catch (error) {
      return `error: ${/** @type {Error} */ (error).message}`;
    }
  },
  unregisterDynamic: () => browser.scripting.unregisterContentScripts(),
  registered: () => browser.scripting.getRegisteredContentScripts(),
  permissions: () => browser.permissions.getAll(),
  requestOrigins: (origins) => browser.permissions.request({ origins }),
  manifest: () => browser.runtime.getManifest(),
};

browser.runtime.onMessage.addListener((message, sender) => {
  if (sender.id !== browser.runtime.id || sender.url !== CONTROL_URL || sender.tab === undefined) return undefined;
  const fn = Object.hasOwn(CONTROL, message?.ctl) ? CONTROL[message.ctl] : null;
  if (!fn) return Promise.reject(new Error(`unknown control call ${String(message?.ctl)}`));
  return Promise.resolve(fn(message.args)).then((value) => JSON.stringify(value ?? null));
});
