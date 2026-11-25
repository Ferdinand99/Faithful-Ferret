// Two worlds of one page, for the unit tests of the passkey scripts: the page's own world (where the page and
// content/passkey.main.inject.js run) and the isolated world of the bridge (content/passkey.bridge.inject.js), each a realm
// of its own (node:vm), with a small DOM whose state lives outside both, the way Firefox keeps the DOM outside the
// worlds and gives the isolated world its own, untouched view of it (Xray). A page that changes a prototype in its world
// changes nothing the bridge sees, as in the browser. Not a test file (the runner picks up *.test.mjs only).
//
// What it has: EventTarget, Event, MessageEvent (data, ports), MessagePort and MessageChannel (messages cloned into the
// receiver's world, delivered in a microtask once the port is started), AbortController and AbortSignal, DOMException,
// DataView and the typed arrays of the realm, `document`, `navigator.credentials` with the browser's own create and get
// (each records its calls and answers "browser"; they read as native code), `navigator.userActivation`, and, in the
// bridge's world, `browser.runtime` (sendMessage is recorded, onMessage takes a push) and timers that run when told to.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import {
  classicScript, PASSKEY_BRIDGE_BUNDLE, PASSKEY_BRIDGE_ENTRY, PASSKEY_MAIN_BUNDLE, PASSKEY_MAIN_ENTRY, passkeyBridgeMayInclude, passkeyMainMayInclude,
} from "../../scripts/lib/classic.mjs";

const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

/** The real sources, by package path. @returns {Map<string, Buffer>} */
export function readSources() {
  /** @type {Map<string, Buffer>} */
  const out = new Map();
  const walk = (/** @type {string} */ dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else out.set(path.slice(src.length + 1).split("\\").join("/"), readFileSync(path));
    }
  };
  walk(src);
  return out;
}

/** The two joined scripts, as the build writes them. @returns {{ main: string, bridge: string }} */
export function passkeyScripts() {
  const files = readSources();
  return {
    main: classicScript(PASSKEY_MAIN_ENTRY, files, passkeyMainMayInclude, { slim: true, name: PASSKEY_MAIN_BUNDLE }),
    bridge: classicScript(PASSKEY_BRIDGE_ENTRY, files, passkeyBridgeMayInclude, { slim: true, name: PASSKEY_BRIDGE_BUNDLE }),
  };
}

export const RUNTIME_ID = "ferret-test@hedgerow.tools";

// The DOM of the realm: each class keeps its state in the host (outside every world) and finds it through a slot.
const REALM_DOM = String.raw`
(function (host) {
  "use strict";
  const slot = new WeakMap();
  const coreOf = (x) => { const c = slot.get(x); if (c === undefined) throw new TypeError("Illegal invocation"); return c; };
  const captureOf = (o) => o === true || (typeof o === "object" && o !== null && o.capture === true);
  class EventTarget {
    addEventListener(type, fn, options) { host.add(coreOf(this), String(type), fn, captureOf(options), this); }
    removeEventListener(type, fn, options) { host.remove(coreOf(this), String(type), fn, captureOf(options)); }
    dispatchEvent(event) { return host.dispatch(coreOf(this), coreOf(event)); }
  }
  class Event {
    constructor(type, init) { slot.set(this, host.newEvent(String(type), !!(init && init.cancelable), undefined, [])); }
    get type() { return coreOf(this).type; }
    get defaultPrevented() { return coreOf(this).prevented; }
    preventDefault() { const c = coreOf(this); if (c.cancelable) c.prevented = true; }
  }
  class MessageEvent extends Event {
    constructor(type, init) {
      super(type, init);
      const c = coreOf(this);
      c.data = init ? init.data : undefined;
      c.ports = init && init.ports ? Array.from(init.ports, coreOf) : [];
    }
    get data() { return coreOf(this).data; }
    get ports() { return Object.freeze(coreOf(this).ports.map((p) => wrap("port", p))); }
  }
  class MessagePort extends EventTarget {
    postMessage(data) { host.post(coreOf(this), data); }
    start() { host.start(coreOf(this)); }
    close() {}
  }
  class MessageChannel {
    constructor() { const [a, b] = host.channel(); this.port1 = wrap("port", a); this.port2 = wrap("port", b); }
  }
  class AbortSignal extends EventTarget {
    get aborted() { return coreOf(this).aborted; }
    get reason() { return coreOf(this).reason; }
  }
  class AbortController {
    constructor() { this.signal = wrap("signal", host.newTarget({ aborted: false, reason: undefined })); }
    abort(reason) {
      const c = coreOf(this.signal);
      if (c.aborted) return;
      c.aborted = true;
      c.reason = reason === undefined ? new DOMException("The operation was aborted. ", "AbortError") : reason;
      this.signal.dispatchEvent(new Event("abort"));
    }
  }
  class DOMException extends Error {
    constructor(message = "", name = "Error") { super(message); this.name = name; }
  }
  class CredentialsContainer {}
  for (const kind of ["create", "get"]) {
    const target = function () {};
    const native = new Proxy(target, { apply: (_t, self, args) => host.native(kind, self, args, globalThis) });
    Object.defineProperty(CredentialsContainer.prototype, kind, { value: native, writable: true, enumerable: true, configurable: true });
  }
  const wrappers = new WeakMap();
  const PROTOS = { port: MessagePort.prototype, signal: AbortSignal.prototype, target: EventTarget.prototype, event: MessageEvent.prototype };
  function wrap(kind, core) {
    let w = wrappers.get(core);
    if (w === undefined) {
      w = Object.create(PROTOS[kind]);
      slot.set(w, core);
      wrappers.set(core, w);
    }
    return w;
  }
  Object.assign(globalThis, { EventTarget, Event, MessageEvent, MessagePort, MessageChannel, AbortSignal, AbortController, DOMException, CredentialsContainer });
  globalThis.window = globalThis;
  globalThis.self = globalThis;
  globalThis.document = wrap("target", host.document);
  const credentials = Object.create(CredentialsContainer.prototype);
  globalThis.navigator = {
    credentials,
    get userActivation() { return { isActive: host.activation(), hasBeenActive: host.activation() }; },
  };
  globalThis.location = { href: host.href };
  host.register({
    wrap,
    event: (core) => wrap("event", core),
    ArrayBuffer, ObjectProto: Object.prototype, ArrayCtor: Array,
  });
})
`;

/**
 * A page with the two worlds. `foreign` makes the browser's create and get look like another extension's (not native)
 * before the scripts install. `order` is the order the two scripts run in at `document_start`.
 * @param {{ order?: "main-first" | "bridge-first", foreign?: boolean, activation?: boolean, mainScript?: boolean, bridgeScript?: boolean }} [o]
 */
export function createPasskeyPage({ order = "main-first", foreign = false, activation = true, mainScript = true, bridgeScript = true } = {}) {
  const scripts = passkeyScripts();
  /** @type {Map<object, Array<{ type: string, fn: any, capture: boolean, self: any, realm: any }>>} */
  const listeners = new Map();
  const document = {};
  /** Calls of the browser's own create and get. @type {Array<{ kind: string, self: unknown, args: unknown[], world: unknown }>} */
  const nativeCalls = [];
  /** What the bridge sent the background, decoded. @type {Array<{ type: string, body: any }>} */
  const sent = [];
  /** The bridge's push listeners. @type {Array<(raw: unknown, sender: unknown) => unknown>} */
  const pushListeners = [];
  /** @type {Array<{ id: number, fn: () => void, every: number }>} */
  let intervals = [];
  let intervalId = 0;
  let active = activation;
  let sendFails = false;

  /** @type {any} */
  let currentRealm = null;
  const isBuffer = (/** @type {unknown} */ x) => Object.prototype.toString.call(x) === "[object ArrayBuffer]";

  /** A structured clone into `realm`: built with the realm's own constructors, as the browser does it. @param {any} realm @param {unknown} v @returns {unknown} */
  const cloneInto = (realm, v) => {
    if (v === null || typeof v !== "object") {
      if (typeof v === "function" || typeof v === "symbol") throw new Error("DataCloneError");
      return v;
    }
    if (isBuffer(v)) {
      const from = new Uint8Array(/** @type {ArrayBuffer} */ (v));
      const out = new realm.ArrayBuffer(from.length);
      new Uint8Array(out).set(from);
      return out;
    }
    if (Array.isArray(v)) {
      const out = new realm.ArrayCtor();
      for (let i = 0; i < v.length; i += 1) Reflect.defineProperty(out, i, { value: cloneInto(realm, v[i]), writable: true, enumerable: true, configurable: true });
      return out;
    }
    const out = Object.create(realm.ObjectProto);
    for (const key of Object.keys(v)) Reflect.defineProperty(out, key, { value: cloneInto(realm, Reflect.get(v, key)), writable: true, enumerable: true, configurable: true });
    return out;
  };

  /** @type {WeakMap<object, any>} */
  const portRealm = new WeakMap();
  const host = (/** @type {string} */ name) => ({
    document,
    href: "https://rp.example/login",
    activation: () => active,
    register: (/** @type {any} */ r) => {
      currentRealm = r;
      currentRealm.name = name;
    },
    newTarget: (/** @type {object} */ init) => ({ ...init }),
    newEvent: (/** @type {string} */ type, /** @type {boolean} */ cancelable, /** @type {unknown} */ data, /** @type {object[]} */ ports) => ({ type, cancelable, prevented: false, data, ports }),
    add: (/** @type {object} */ core, /** @type {string} */ type, /** @type {any} */ fn, /** @type {boolean} */ capture, /** @type {any} */ self) => {
      const list = listeners.get(core) ?? [];
      if (!list.some((l) => l.type === type && l.fn === fn && l.capture === capture)) list.push({ type, fn, capture, self, realm: realms[name] });
      listeners.set(core, list);
    },
    remove: (/** @type {object} */ core, /** @type {string} */ type, /** @type {any} */ fn, /** @type {boolean} */ capture) => {
      listeners.set(core, (listeners.get(core) ?? []).filter((l) => !(l.type === type && l.fn === fn && l.capture === capture)));
    },
    dispatch: (/** @type {object} */ core, /** @type {any} */ event) => dispatchCore(core, event),
    channel: () => {
      const a = { other: /** @type {any} */ (null), started: false, queue: /** @type {unknown[]} */ ([]) };
      const b = { other: a, started: false, queue: /** @type {unknown[]} */ ([]) };
      a.other = b;
      return [a, b];
    },
    post: (/** @type {any} */ core, /** @type {unknown} */ data) => {
      const other = core.other;
      // The value is copied when it is sent (a later change by the sender is not seen), into the receiver's world on delivery.
      const copy = structuredClone(data);
      queueMicrotask(() => {
        if (other.started) deliver(other, copy);
        else other.queue.push(copy);
      });
    },
    start: (/** @type {any} */ core) => {
      core.started = true;
      for (const copy of core.queue.splice(0)) queueMicrotask(() => deliver(core, copy));
    },
    native: (/** @type {string} */ kind, /** @type {unknown} */ self, /** @type {unknown[]} */ args, /** @type {any} */ world) => {
      nativeCalls.push({ kind, self, args, world });
      return world.Promise.resolve("browser");
    },
  });

  /** @param {any} core @param {unknown} copy */
  function deliver(core, copy) {
    // The listener's world receives the clone; a port has listeners of one world here.
    const list = listeners.get(core) ?? [];
    for (const l of list.filter((x) => x.type === "message")) {
      const realm = l.realm;
      const event = { type: "message", cancelable: false, prevented: false, data: cloneInto(realm, copy), ports: [] };
      Reflect.apply(l.fn, l.self, [realm.event(event)]);
    }
  }

  /** @param {object} core @param {any} event */
  function dispatchCore(core, event) {
    for (const l of [...(listeners.get(core) ?? [])].sort((x, y) => Number(y.capture) - Number(x.capture))) {
      if (l.type !== event.type) continue;
      if (!(listeners.get(core) ?? []).includes(l)) continue;
      Reflect.apply(l.fn, l.self, [l.realm.event(event)]);
    }
    return !event.prevented;
  }

  /** @type {Record<string, any>} */
  const realms = {};
  /** @type {Record<string, vm.Context>} */
  const contexts = {};
  for (const name of ["page", "bridge"]) {
    const context = vm.createContext({});
    contexts[name] = context;
    vm.runInContext(REALM_DOM, context)(host(name));
    realms[name] = currentRealm;
  }
  // The bridge's world has the extension's API, its own crypto and timers.
  const bridgeWorld = /** @type {any} */ (contexts.bridge);
  bridgeWorld.crypto = globalThis.crypto;
  bridgeWorld.TextEncoder = TextEncoder;
  bridgeWorld.setInterval = (/** @type {() => void} */ fn, /** @type {number} */ every) => {
    intervalId += 1;
    intervals.push({ id: intervalId, fn, every });
    return intervalId;
  };
  bridgeWorld.clearInterval = (/** @type {number} */ id) => {
    intervals = intervals.filter((t) => t.id !== id);
  };
  bridgeWorld.browser = {
    runtime: {
      id: RUNTIME_ID,
      sendMessage: async (/** @type {string} */ raw) => {
        if (sendFails) throw new Error("Could not establish connection. Receiving end does not exist.");
        const message = JSON.parse(raw);
        sent.push({ type: message.type, body: message.body });
        return undefined;
      },
      onMessage: { addListener: (/** @type {any} */ fn) => pushListeners.push(fn) },
    },
  };
  if (foreign) {
    // Another extension came first: its create and get are plain functions of the page's world.
    vm.runInContext(`(() => {
      const c = CredentialsContainer.prototype;
      const browserCreate = c.create, browserGet = c.get;
      Object.defineProperty(c, "create", { value: function create(o) { return browserCreate.call(this, o); }, writable: true, enumerable: true, configurable: true });
      Object.defineProperty(c, "get", { value: function get(o) { return browserGet.call(this, o); }, writable: true, enumerable: true, configurable: true });
    })()`, contexts.page);
  }
  const runMain = () => {
    if (mainScript) vm.runInContext(scripts.main, contexts.page);
  };
  const runBridge = () => {
    if (bridgeScript) vm.runInContext(scripts.bridge, contexts.bridge);
  };
  if (order === "main-first") {
    runMain();
    runBridge();
  } else {
    runBridge();
    runMain();
  }

  const flush = async () => {
    for (let i = 0; i < 20; i += 1) await new Promise((r) => setImmediate(r));
  };

  return {
    scripts,
    /** Runs code in the page's world. @param {string} code */
    page: (code) => vm.runInContext(code, contexts.page),
    nativeCalls,
    sent,
    flush,
    /** @param {boolean} on */
    setActivation: (on) => {
      active = on;
    },
    /** @param {boolean} fails */
    setSendFails: (fails) => {
      sendFails = fails;
    },
    /** A push of the background to the bridge, the way tabs.sendMessage delivers it. @param {string} type @param {unknown} body @param {{ id?: string }} [sender] */
    push: async (type, body, sender = { id: RUNTIME_ID }) => {
      const raw = JSON.stringify({ v: 1, id: "p1", type, body });
      for (const fn of pushListeners) fn(raw, sender);
      await flush();
    },
    /** The timers the bridge has set. */
    intervals: () => intervals.map((t) => ({ every: t.every })),
    /** Runs every interval of the bridge once. */
    tick: async () => {
      for (const t of [...intervals]) t.fn();
      await flush();
    },
    /** The listeners on the document, by type. @param {string} type */
    documentListeners: (type) => (listeners.get(document) ?? []).filter((l) => l.type === type).length,
  };
}
