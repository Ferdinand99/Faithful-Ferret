// The passkey bridge in the isolated world (the `passkeys` feature, design document § 9 and § 10.8). The build joins this
// file and what it imports into content/passkey.bridge.inject.js, a classic script that the background registers next to
// the script of the page's own world (content/passkey.main.entry.mjs), for `https` pages and their frames, at
// `document_start`.
//
// - The handshake: a cancelable document event of a fixed type that carries a MessagePort, synchronous, no
//   `window.postMessage`. Either script may run first (after a restored session the bridge ran first in the probe): each
//   listens and each sends, and the listener of the one that runs second takes the port and says so with
//   `preventDefault`. Each listener takes one handshake and removes itself.
// - A request from the port is trusted for nothing beyond its schema: the options must fit the wire form and its limits
//   (shared/webauthnWire.mjs) and the message the protocol's limits; anything else goes back as "the browser answers",
//   so the page's call reaches the browser untouched. What the bridge adds it reads here, in the isolated world, where the
//   page cannot change it: whether the page has transient user activation, and what `document.featurePolicy` says (where
//   the browser has it; Firefox has none). It never sends an origin, a frame or an address: the background has those from
//   the browser.
// - Each request gets an id of the bridge's own, 16 random bytes. The background answers by a push of that id to this
//   frame and document only (`tabs.sendMessage` with `frameId` and `documentId`); the bridge passes on an answer only for an
//   id it issued and still waits for, once, and drops everything else.
// - While a request waits it pings the background every 20 seconds (a Manifest V3 event page is suspended after 30
//   seconds otherwise), and never when nothing waits. If the extension cannot be reached, the browser answers.

import { PUSH_TYPES, decode, encode } from "../shared/protocol.mjs";
import { optionsToWire, responseFromWire } from "../shared/webauthnWire.mjs";

/** The type of the handshake event, as the page's own world has it. Not a secret. */
const HANDSHAKE = "ferret.passkeys.handshake";
/** The ping of the background while a request waits. */
const PING_MS = 20_000;
/** The most requests of one document that wait at once; one more ends with NotAllowedError. */
const MAX_WAITING = 64;

/** @param {any} runtime the extension's `runtime` (the isolated world's own) */
function startBridge(runtime) {
  /** @type {MessagePort | null} */
  let port = null;
  /** The requests that wait, by the bridge's id: the number the page's script gave, and the kind. @type {Map<string, { n: number, kind: "create" | "get" }>} */
  const waiting = new Map();
  /** The bridge's id of a request, by the page script's number. @type {Map<number, string>} */
  const idOf = new Map();
  /** @type {ReturnType<typeof setInterval> | null} */
  let pinger = null;
  let foreignSent = false;

  const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

  /** @param {Record<string, unknown>} message */
  const toPage = (message) => {
    try {
      port?.postMessage(message);
    } catch {
      // The page is gone.
    }
  };

  /** Sends a message of the protocol; false when it could not be built or sent. @param {string} type @param {unknown} body */
  const toBackground = async (type, body) => {
    /** @type {string} */
    let raw;
    try {
      raw = encode(type, body);
    } catch {
      return false;
    }
    try {
      await runtime.sendMessage(raw);
      return true;
    } catch {
      return false;
    }
  };

  const keepAlive = () => {
    if (waiting.size === 0) {
      if (pinger !== null) clearInterval(pinger);
      pinger = null;
      return;
    }
    if (pinger !== null) return;
    pinger = setInterval(() => {
      if (waiting.size === 0) {
        keepAlive();
        return;
      }
      void toBackground("passkey_ping", { request_ids: [...waiting.keys()].slice(0, 64) });
    }, PING_MS);
  };

  /** Ends a request here and returns its number, or null when it does not wait. @param {string} id */
  const settle = (id) => {
    const entry = waiting.get(id);
    if (entry === undefined) return null;
    waiting.delete(id);
    idOf.delete(entry.n);
    keepAlive();
    return entry;
  };

  /** What the bridge reads of the page in the isolated world. @param {"create" | "get"} kind */
  const policyFor = (kind) => {
    try {
      const policy = /** @type {any} */ (document).featurePolicy;
      if (!policy || typeof policy.allowsFeature !== "function") return null;
      return policy.allowsFeature(kind === "create" ? "publickey-credentials-create" : "publickey-credentials-get") === true;
    } catch {
      return null;
    }
  };

  /** @param {unknown} data a request of the page's script, as the port delivered it */
  const onRequest = async (data) => {
    const d = /** @type {Record<string, unknown>} */ (data);
    const n = d.n;
    const kind = d.kind;
    const mediation = d.mediation;
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1 || idOf.has(n)) return;
    if (kind !== "create" && kind !== "get") return;
    const handover = () => toPage({ n, outcome: "handover", once: false });
    if (mediation !== "optional" && mediation !== "required" && mediation !== "conditional") return handover();
    if (waiting.size >= MAX_WAITING) return toPage({ n, outcome: "error", name: "NotAllowedError" });
    const options = optionsToWire(kind, d.options);
    if (options === null) return handover();
    const id = newId();
    const body = {
      request_id: id,
      kind,
      mediation,
      [kind]: options,
      activation: navigator.userActivation?.isActive === true,
      policy: policyFor(kind),
    };
    waiting.set(id, { n, kind });
    idOf.set(n, id);
    keepAlive();
    if (!(await toBackground("passkey_request", body))) {
      // Too large for a message, or the extension cannot be reached: the browser answers.
      if (settle(id) !== null) handover();
    }
  };

  /** @param {MessageEvent} event */
  const onPortMessage = (event) => {
    const data = event.data;
    if (typeof data !== "object" || data === null) return;
    const t = /** @type {Record<string, unknown>} */ (data).t;
    if (t === "request") {
      void onRequest(data);
    } else if (t === "abort") {
      const n = /** @type {Record<string, unknown>} */ (data).n;
      const id = typeof n === "number" ? idOf.get(n) : undefined;
      if (id !== undefined && settle(id) !== null) void toBackground("passkey_abort", { request_id: id });
    } else if (t === "foreign") {
      if (foreignSent) return;
      foreignSent = true;
      void toBackground("passkey_foreign", {});
    }
  };

  /** @param {MessagePort} given */
  const connect = (given) => {
    port = given;
    document.removeEventListener(HANDSHAKE, onHandshake, true);
    given.addEventListener("message", onPortMessage);
    given.start();
  };

  /** The handshake of the page's script, when it runs after this one. @param {Event} event */
  function onHandshake(event) {
    if (port !== null) return;
    /** @type {any} */
    const e = event;
    try {
      if (e.data !== "main" || !e.ports || e.ports.length !== 1) return;
    } catch {
      return;
    }
    e.preventDefault();
    connect(e.ports[0]);
  }

  /** An answer of the background, pushed to this frame and document. @param {unknown} raw @param {any} sender */
  const onPush = (raw, sender) => {
    if (sender?.id !== runtime.id) return;
    /** @type {{ type: string, body: any }} */
    let message;
    try {
      message = decode(raw, PUSH_TYPES);
    } catch {
      return;
    }
    const { type, body } = message;
    if (type !== "passkey_result" && type !== "passkey_handover" && type !== "passkey_error") return;
    // Only an id this bridge issued and still waits for, and only once.
    const entry = settle(body.request_id);
    if (entry === null) return;
    if (type === "passkey_handover") {
      toPage({ n: entry.n, outcome: "handover", once: body.once === true });
    } else if (type === "passkey_error") {
      toPage({ n: entry.n, outcome: "error", name: body.name });
    } else {
      const response = responseFromWire(entry.kind, body.response);
      toPage(response === null ? { n: entry.n, outcome: "error", name: "NotAllowedError" } : { n: entry.n, outcome: "result", response });
    }
  };

  runtime.onMessage.addListener((/** @type {unknown} */ raw, /** @type {any} */ sender) => {
    onPush(raw, sender);
    // Never an answer: other scripts of the extension listen on the same channel.
    return undefined;
  });

  document.addEventListener(HANDSHAKE, onHandshake, true);
  try {
    const channel = new MessageChannel();
    const taken = !document.dispatchEvent(new MessageEvent(HANDSHAKE, { data: "bridge", ports: [channel.port2], cancelable: true }));
    if (taken && port === null) connect(channel.port1);
  } catch {
    // No channel: the page's script sends every call to the browser.
  }
}

const runtime = /** @type {any} */ (globalThis).browser?.runtime;
if (runtime && /^https:/.test(location.href)) startBridge(runtime);
