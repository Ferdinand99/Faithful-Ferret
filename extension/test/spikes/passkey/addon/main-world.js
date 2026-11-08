// MAIN-world script of the passkey spike (content script with "world": "MAIN",
// run_at document_start). Test-only code, written to find out what Firefox allows.
//
// It replaces navigator.credentials.create/get and the two availability checks. A
// request goes to the extension over a private MessageChannel: the isolated-world
// relay (relay.js) makes the channel and sends this script one port in a single
// window message. This script claims that message in a capture listener that was
// registered before any page script could run, and stops it there, so a page
// listener never sees it. No request and no answer ever goes through
// window.postMessage. Nothing here has keys or crypto: the background answers.
(() => {
  "use strict";
  if (Object.prototype.hasOwnProperty.call(window, "__ferretSpikeProbe")) return; // static and dynamic registration both match
  if (!window.PublicKeyCredential || !window.CredentialsContainer) return;

  const CC = CredentialsContainer.prototype;
  const nativeCreate = CC.create;
  const nativeGet = CC.get;
  const nativeIsUvpaa = PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
  const nativeIsCma = PublicKeyCredential.isConditionalMediationAvailable;
  const nativeToString = Function.prototype.toString;
  const apply = Reflect.apply;
  const defineProperty = Object.defineProperty;
  const createObject = Object.create;
  const PortProto = MessagePort.prototype;
  const portPostMessage = PortProto.postMessage;
  const portStart = PortProto.start;
  const portOnMessage = Object.getOwnPropertyDescriptor(PortProto, "onmessage").set;
  const eventData = Object.getOwnPropertyDescriptor(MessageEvent.prototype, "data").get;
  const eventPorts = Object.getOwnPropertyDescriptor(MessageEvent.prototype, "ports").get;
  const stopImmediate = Event.prototype.stopImmediatePropagation;
  const addListener = EventTarget.prototype.addEventListener;
  const nativeSetTimeout = window.setTimeout.bind(window);
  const nativeClearTimeout = window.clearTimeout.bind(window);
  const NativePromise = Promise;

  // ---------------------------------------------------------------- the private channel
  /** @type {MessagePort | null} */
  let port = null;
  let claimed = false;
  /** @type {(p: MessagePort) => void} */
  let resolvePort = () => {};
  const portReady = new NativePromise((resolve) => { resolvePort = resolve; });
  /** @type {Map<number, (body: any) => void>} */
  const pending = new Map();
  let nextId = 1;

  const claim = (event) => {
    if (claimed) return;
    const data = apply(eventData, event, []);
    if (!data || typeof data !== "object" || data.ferretSpike !== "offer" || data.v !== 1) return;
    const ports = apply(eventPorts, event, []);
    if (ports.length !== 1) return;
    claimed = true;
    apply(stopImmediate, event, []); // no page listener registered after this one gets the message
    port = ports[0];
    apply(portOnMessage, port, [(answer) => {
      const body = apply(eventData, answer, []);
      if (!body || typeof body.id !== "number") return;
      const done = pending.get(body.id);
      if (done) {
        pending.delete(body.id);
        done(body);
      }
    }]);
    apply(portStart, port, []);
    resolvePort(port);
  };
  // Capture phase on window: before every other listener of the window, page or not.
  apply(addListener, window, ["message", claim, true]);

  /**
   * One request over the port. Resolves with the answer, or with an
   * "unreachable" error after the timeout (never rejects).
   * @param {string} kind
   * @param {unknown} payload
   * @param {{ timeoutMs?: number | null, onId?: (id: number) => void }} [options] timeoutMs null: wait for ever (a conditional request)
   */
  const rpc = (kind, payload, { timeoutMs = 10_000, onId } = {}) => new NativePromise((resolve) => {
    const portWait = new NativePromise((ok) => nativeSetTimeout(() => ok(null), 2000));
    NativePromise.race([portReady, portWait]).then((p) => {
      if (!p) return resolve({ error: { name: "Unreachable", message: "no channel" } });
      const id = nextId++;
      onId?.(id);
      const timer = timeoutMs === null ? 0 : nativeSetTimeout(() => {
        pending.delete(id);
        resolve({ error: { name: "Unreachable", message: "timeout" } });
      }, timeoutMs);
      pending.set(id, (body) => {
        if (timer) nativeClearTimeout(timer);
        resolve(body);
      });
      apply(portPostMessage, p, [{ id, kind, payload }]);
    });
  });

  // ---------------------------------------------------------------- helpers
  /** @param {ArrayBuffer | ArrayBufferView} v */
  const b64u = (v) => {
    const bytes = ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : new Uint8Array(v);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  /** @param {string} s */
  const buf = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)).buffer;
  const domError = (e) => new DOMException(e.message || "error", e.name || "NotAllowedError");
  const define = (obj, props) => {
    for (const [k, v] of Object.entries(props)) defineProperty(obj, k, { value: v, enumerable: true, configurable: true, writable: false });
    return obj;
  };
  const abortIfNeeded = (signal) => {
    if (signal && signal.aborted) throw signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
  };

  // ---------------------------------------------------------------- response objects
  // Own data properties shadow the brand-checked accessors of the real prototypes,
  // so `instanceof` works and nothing throws "illegal invocation".
  const makeAttestation = (r) => {
    const response = define(createObject(AuthenticatorAttestationResponse.prototype), {
      clientDataJSON: buf(r.clientDataJSON),
      attestationObject: buf(r.attestationObject),
      getTransports: () => r.transports.slice(),
      getAuthenticatorData: () => buf(r.authenticatorData),
      getPublicKey: () => buf(r.publicKey),
      getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
    });
    return define(createObject(PublicKeyCredential.prototype), {
      id: r.id, rawId: buf(r.id), type: "public-key", authenticatorAttachment: "platform", response,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({ id: r.id, rawId: r.id, type: "public-key", authenticatorAttachment: "platform", clientExtensionResults: {}, response: { clientDataJSON: r.clientDataJSON, attestationObject: r.attestationObject, authenticatorData: r.authenticatorData, publicKey: r.publicKey, publicKeyAlgorithm: r.publicKeyAlgorithm, transports: r.transports } }),
    });
  };
  const makeAssertion = (r) => {
    const response = define(createObject(AuthenticatorAssertionResponse.prototype), {
      clientDataJSON: buf(r.clientDataJSON),
      authenticatorData: buf(r.authenticatorData),
      signature: buf(r.signature),
      userHandle: buf(r.userHandle),
    });
    return define(createObject(PublicKeyCredential.prototype), {
      id: r.id, rawId: buf(r.id), type: "public-key", authenticatorAttachment: "platform", response,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({ id: r.id, rawId: r.id, type: "public-key", authenticatorAttachment: "platform", clientExtensionResults: {}, response: { clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData, signature: r.signature, userHandle: r.userHandle } }),
    });
  };

  // ---------------------------------------------------------------- the replacements
  const wrappedCreate = {
    create(options) {
      const args = arguments;
      const pk = options && options.publicKey;
      if (!pk || !pk.user || !pk.challenge) return apply(nativeCreate, this, args);
      return (async () => {
        abortIfNeeded(options.signal);
        const res = await rpc("create", {
          rpId: pk.rp && pk.rp.id ? pk.rp.id : null,
          challenge: b64u(pk.challenge),
          user: { id: b64u(pk.user.id), name: pk.user.name },
          pubKeyCredParams: (pk.pubKeyCredParams || []).map((p) => ({ alg: p.alg })),
          excludeCredentials: (pk.excludeCredentials || []).map((c) => b64u(c.id)),
          userVerification: pk.authenticatorSelection && pk.authenticatorSelection.userVerification,
        });
        if (res.error && res.error.name === "Unreachable") return apply(nativeCreate, this, args);
        if (res.error) throw domError(res.error);
        if (res.use === "native") return apply(nativeCreate, this, args);
        abortIfNeeded(options.signal);
        return makeAttestation(res.result);
      })();
    },
  }.create;

  const wrappedGet = {
    get(options) {
      const args = arguments;
      const pk = options && options.publicKey;
      if (!pk || !pk.challenge) return apply(nativeGet, this, args);
      const conditional = options.mediation === "conditional";
      return (async () => {
        abortIfNeeded(options.signal);
        /** @type {number | null} */
        let id = null;
        const signal = options.signal;
        const onAbort = () => {
          if (id === null) return;
          apply(portPostMessage, port, [{ id: nextId++, kind: "cancel", payload: { target: id } }]);
          // The page's promise settles at once, whatever the extension does with the cancel.
          const done = pending.get(id);
          pending.delete(id);
          if (done) done({ id, error: { name: "AbortError", message: "The operation was aborted." } });
        };
        if (signal) apply(addListener, signal, ["abort", onAbort, { once: true }]);
        const res = await rpc("get", {
          rpId: pk.rpId || null,
          challenge: b64u(pk.challenge),
          allowCredentials: (pk.allowCredentials || []).map((c) => b64u(c.id)),
          userVerification: pk.userVerification,
          conditional,
        }, { timeoutMs: conditional ? null : 10_000, onId: (n) => { id = n; } });
        if (signal && signal.aborted) throw signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
        if (res.error && res.error.name === "Unreachable") return apply(nativeGet, this, args);
        if (res.error) throw domError(res.error);
        if (res.use === "native") return apply(nativeGet, this, args);
        return makeAssertion(res.result);
      })();
    },
  }.get;
  defineProperty(wrappedCreate, "length", { value: 0 });
  defineProperty(wrappedGet, "length", { value: 0 });

  const wrappedUvpaa = {
    async isUserVerifyingPlatformAuthenticatorAvailable() {
      return apply(nativeIsUvpaa, this, arguments);
    },
  }.isUserVerifyingPlatformAuthenticatorAvailable;

  // The extension decides, the browser's own answer is only the fallback.
  const wrappedCma = {
    async isConditionalMediationAvailable() {
      const res = await rpc("cma", {}, { timeoutMs: 3000 });
      if (res.error || typeof res.available !== "boolean") return typeof nativeIsCma === "function" ? apply(nativeIsCma, this, arguments) : false;
      return res.available;
    },
  }.isConditionalMediationAvailable;

  // Print as native code (some sites look at Function.prototype.toString).
  const nativeSrc = new Map([
    [wrappedCreate, "function create() {\n    [native code]\n}"],
    [wrappedGet, "function get() {\n    [native code]\n}"],
    [wrappedUvpaa, "function isUserVerifyingPlatformAuthenticatorAvailable() {\n    [native code]\n}"],
    [wrappedCma, "function isConditionalMediationAvailable() {\n    [native code]\n}"],
  ]);
  const patchedToString = {
    toString() { return nativeSrc.has(this) ? nativeSrc.get(this) : apply(nativeToString, this, arguments); },
  }.toString;
  nativeSrc.set(patchedToString, "function toString() {\n    [native code]\n}");

  const redefine = (target, name, value) => {
    const d = Object.getOwnPropertyDescriptor(target, name);
    defineProperty(target, name, { ...d, value });
  };
  redefine(CC, "create", wrappedCreate);
  redefine(CC, "get", wrappedGet);
  if (typeof nativeIsCma === "function") redefine(PublicKeyCredential, "isConditionalMediationAvailable", wrappedCma);
  else defineProperty(PublicKeyCredential, "isConditionalMediationAvailable", { value: wrappedCma, writable: true, configurable: true, enumerable: false });
  redefine(PublicKeyCredential, "isUserVerifyingPlatformAuthenticatorAvailable", wrappedUvpaa);
  redefine(Function.prototype, "toString", patchedToString);

  // Test hook only: lets a test page ask whether a function is the override.
  const ours = new Set([wrappedCreate, wrappedGet, wrappedUvpaa, wrappedCma]);
  defineProperty(window, "__ferretSpikeProbe", {
    value: Object.freeze({
      isOurs: (f) => ours.has(f),
      claimed: () => claimed,
      nativeCmaType: typeof nativeIsCma,
      nativeCma: () => (typeof nativeIsCma === "function" ? apply(nativeIsCma, PublicKeyCredential, []) : NativePromise.resolve(null)),
    }),
  });
})();
