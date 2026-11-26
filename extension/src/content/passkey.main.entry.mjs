// The passkey script in the page's own world (the `passkeys` feature, design document § 9 and § 10.8). The build joins
// this file into content/passkey.main.inject.js, a classic script that the background registers for `https` pages and
// their frames at `document_start` (the passkey registry of the background), before the page's own scripts run.
//
// It is untrusted and dumb: the page can read, change and imitate everything in this world. It holds no secret and no
// key, decides nothing, reaches no network, changes nothing in the DOM and leaves no global behind. What it does:
//
// - It keeps the browser's `CredentialsContainer.prototype.create` and `get` and every built-in it uses later, at
//   install, so a page that changes them afterwards only breaks its own calls.
// - It makes a private channel to the bridge script of the isolated world with a synchronous handshake (a cancelable
//   document event that carries a MessagePort; no `window.postMessage` at all). Either script may run first: each
//   listens and each sends, and the one that finds the other takes its port.
// - It replaces `create` and `get`. A call that is not Ferret's to look at (no `publicKey`: password, federated,
//   identity, one-time code; `mediation: "silent"`; a conditional `create`; a `this` that is not the page's own
//   container; an AbortSignal that has already fired; options it cannot copy; no channel) goes to the browser's own
//   function at once with the page's own arguments. Anything else is copied (bytes into fresh ArrayBuffers) and sent to
//   the bridge, which asks the background. The answer is the browser (the page's own arguments, untouched), an error, or
//   the bytes of Ferret's credential.
// - It fails closed: anything unexpected sends the call to the browser's own function, never a malformed request. That
//   includes a bridge that died (the extension was updated, disabled or reloaded while the page was open: its isolated
//   world goes, this world stays): a request the bridge does not say "taken" for (it does as soon as it has the request)
//   within TAKEN_MS goes to the browser, and
//   a taken one that hears no "alive" from the bridge for ALIVE_MS ends as one the user left (NotAllowedError; a
//   conditional one goes to the browser, whose own list then works as before).
// - Beside a conditional `get` that Ferret takes (its list is in Ferret's popup), it makes a conditional call of its own to
//   the original, with its own AbortController, so the browser's own autofill list still offers the platform's passkeys.
//   Only a credential from it wins (Ferret's request is then aborted); an error from it is swallowed while Ferret's part
//   waits, and the call is made once more if the browser aborted it. It is aborted whenever the page's request ends
//   otherwise, before the original gets the page's own arguments.
// - It tells the bridge when create or get were not the browser's own at install (another extension came first), or
//   when Ferret's own were replaced later.
// - It builds the answer objects of Ferret's credentials (content/passkeyResponse.mjs) and answers the three static
//   methods of PublicKeyCredential that sites read for their choice to offer a passkey: isUserVerifyingPlatformAuthenticatorAvailable
//   (true where Ferret answers), isConditionalMediationAvailable (true where Ferret answers) and getClientCapabilities
//   (the browser's answer with Ferret's entries on top). Where the bridge is not connected (Ferret does not answer on the
//   page) all three give the browser's own answer. parseCreationOptionsFromJSON, parseRequestOptionsFromJSON and the signal
//   methods are not touched.
//
// Nothing this script receives is resolved into one of its own promises as an object: a page that defines
// `Object.prototype.then` would step into it. The page's promise is settled directly from the port's answer.
// Objects it builds have no prototype (or are made by literals), and property descriptors have no prototype, so a
// setter or a getter the page puts on `Object.prototype` or `Array.prototype` never runs with our values.

import { credentialFrom } from "./passkeyResponse.mjs";

/** How long a request waits for the bridge's "taken" before the browser gets it. */
const TAKEN_MS = 3_000;
/** How long a taken request waits without the bridge's "alive" (sent every 20 seconds while a request waits). */
const ALIVE_MS = 50_000;
/** The type of the handshake event. Not a secret: the package is public (design § 10.8). */
const HANDSHAKE = "ferret.passkeys.handshake";
/** The two functions it replaces, by name (read by index: a list of its own, which the page cannot reach). */
const KINDS = /** @type {const} */ (["create", "get"]);
/** The most entries the script copies out of one list of the page's options (the bridge checks the real limits). */
const MAX_LIST = 200;
/** The most bytes it copies out of one buffer of the page (the bridge checks the real limits). */
const MAX_BYTES = 65_536;
/** What Firefox says with a NotAllowedError of WebAuthn. */
const NOT_ALLOWED_TEXT = "The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.";

function install() {
  const W = window;
  if (typeof W.CredentialsContainer !== "function" || typeof W.MessageChannel !== "function") return;
  // Not in a frame with an opaque origin (a sandbox): the bridge does not start there, and a lone listener is no use.
  if (W.origin === "null") return;
  const container = W.navigator.credentials;
  if (!container) return;

  // ---- the built-ins, kept now (the page has not run yet)
  const R = Reflect.apply;
  const ODP = Object.defineProperty;
  const OGOPD = Object.getOwnPropertyDescriptor;
  const OK = Object.keys;
  const hasOwn = Object.hasOwn;
  const isArray = Array.isArray;
  const P = Promise;
  const DOMEx = W.DOMException;
  const TypeErr = TypeError;
  const AB = ArrayBuffer;
  const U8 = Uint8Array;
  const getterOf = (/** @type {object} */ proto, /** @type {string} */ name) => /** @type {Function} */ (/** @type {PropertyDescriptor} */ (OGOPD(proto, name)).get);
  const abLength = getterOf(AB.prototype, "byteLength");
  const TA = Object.getPrototypeOf(U8.prototype);
  const taBuffer = getterOf(TA, "buffer");
  const taOffset = getterOf(TA, "byteOffset");
  const taLength = getterOf(TA, "byteLength");
  const taSet = TA.set;
  const DV = W.DataView.prototype;
  const dvBuffer = getterOf(DV, "buffer");
  const dvOffset = getterOf(DV, "byteOffset");
  const dvLength = getterOf(DV, "byteLength");
  const MC = W.MessageChannel;
  const ME = W.MessageEvent;
  const meData = getterOf(ME.prototype, "data");
  const mePorts = getterOf(ME.prototype, "ports");
  const postToPort = W.MessagePort.prototype.postMessage;
  const startPort = W.MessagePort.prototype.start;
  const ET = W.EventTarget.prototype;
  const listen = ET.addEventListener;
  const unlisten = ET.removeEventListener;
  const dispatch = ET.dispatchEvent;
  const preventDefault = W.Event.prototype.preventDefault;
  const AS = W.AbortSignal.prototype;
  const signalAborted = getterOf(AS, "aborted");
  const signalReason = getterOf(AS, "reason");
  // The AbortController of the conditional call beside Ferret's part; without it (a browser that has none) there is no such call.
  const AC = typeof W.AbortController === "function" ? W.AbortController : null;
  const acAbort = AC === null ? null : AC.prototype.abort;
  const acSignalHeld = AC === null ? undefined : OGOPD(AC.prototype, "signal");
  const acSignal = acSignalHeld !== undefined && typeof acSignalHeld.get === "function" ? acSignalHeld.get : null;
  const pThen = P.prototype.then;
  const setTimer = W.setTimeout;
  const clearTimer = W.clearTimeout;
  const fnText = Function.prototype.toString;
  const reTest = RegExp.prototype.test;
  const NATIVE = /\{\s*\[native code\]\s*\}\s*$/;
  const doc = W.document;
  const CCP = W.CredentialsContainer.prototype;
  /** The functions that were there at install: the browser's own, or another provider's that came first. @type {any} */
  const originals = { __proto__: null };
  for (const kind of KINDS) originals[kind] = CCP[kind];

  // ---- small helpers that call nothing of the page's (beyond reading its own options)
  /** A record with no prototype: a write to it never meets a setter of the page. @returns {any} */
  const rec = () => ({ __proto__: null });
  /** Defines an own data property, with a descriptor that has no prototype. @param {object} o @param {PropertyKey} key @param {unknown} value */
  const put = (o, key, value) => {
    const d = rec();
    d.value = value;
    d.writable = true;
    d.enumerable = true;
    d.configurable = true;
    ODP(o, key, d);
  };
  /** An own property of something that came over the port, or undefined. @param {any} o @param {string} key */
  const own = (o, key) => (typeof o === "object" && o !== null && R(hasOwn, null, [o, key]) ? o[key] : undefined);
  const fail = () => {
    throw new TypeErr("passkey options");
  };
  /** @param {unknown} f */
  const isNative = (f) => {
    try {
      return typeof f === "function" && R(reTest, NATIVE, [R(fnText, f, [])]) === true;
    } catch {
      return false;
    }
  };
  /** @param {() => void} fn @param {number} ms */
  const later = (fn, ms) => R(setTimer, W, [fn, ms]);
  /** @param {unknown} id */
  const cancelTimer = (id) => {
    if (id !== undefined) R(clearTimer, W, [id]);
  };
  const notAllowed = () => new DOMEx(NOT_ALLOWED_TEXT, "NotAllowedError");
  const aborted = () => new DOMEx("The operation was aborted. ", "AbortError");

  // ---- the channel to the bridge
  /** @type {MessagePort | null} */
  let port = null;
  let foreignTold = false;
  let foreignWaits = false;
  /** @param {unknown} message */
  const send = (message) => {
    if (port === null) throw new TypeErr("no channel");
    R(postToPort, port, [message]);
  };
  const tellForeign = () => {
    if (foreignTold) return;
    if (port === null) {
      foreignWaits = true;
      return;
    }
    foreignTold = true;
    try {
      send({ t: "foreign" });
    } catch {
      // Nothing more to say.
    }
  };

  /** The requests that wait for the bridge, by their number. @type {Record<string, any>} */
  const pending = rec();
  /** The key of the conditional request that waits, if any. @type {string | null} */
  let conditionalKey = null;
  let counter = 0;

  /** Ends the conditional call of a request to the original, if one runs; what it answers then counts for nothing. @param {any} entry */
  const stopSide = (entry) => {
    const side = entry.side;
    if (side === null || side === undefined) return;
    entry.side = null;
    try {
      R(/** @type {Function} */ (acAbort), side, []);
    } catch {
      // Ended already.
    }
  };

  /**
   * The conditional call of a request to the original, beside Ferret's part: the page's own `publicKey`, with an AbortController
   * of this script. Only a credential wins; an error is swallowed while Ferret's part waits, and an AbortError of the browser's
   * own (not this script's) starts the call once more.
   * @param {any} entry
   */
  const startSide = (entry) => {
    if (pending[entry.key] !== entry || AC === null || acAbort === null || acSignal === null) return;
    const controller = new AC();
    const options = rec();
    options.mediation = "conditional";
    options.publicKey = entry.publicKey;
    /** @type {unknown} */
    let promise;
    try {
      options.signal = R(acSignal, controller, []);
      promise = R(entry.original, entry.self, [options]);
    } catch {
      return;
    }
    entry.side = controller;
    const mine = () => entry.side === controller;
    try {
      R(pThen, promise, [
        (/** @type {unknown} */ value) => {
          if (!mine()) return;
          entry.side = null;
          if (value === null || value === undefined || !finish(entry)) return;
          // The browser's list answered: Ferret's request of this call ends.
          try {
            send({ t: "abort", n: entry.n });
          } catch {
            // The bridge is gone; the background drops the request with the page.
          }
          entry.resolve(value);
        },
        (/** @type {unknown} */ error) => {
          if (!mine()) return;
          entry.side = null;
          /** @type {unknown} */
          let name;
          try {
            name = typeof error === "object" && error !== null ? /** @type {any} */ (error).name : undefined;
          } catch {
            name = undefined;
          }
          if (name === "AbortError" && !entry.restarted) {
            entry.restarted = true;
            startSide(entry);
          }
        },
      ]);
    } catch {
      stopSide(entry);
    }
  };

  /** @param {any} entry */
  const finish = (entry) => {
    if (pending[entry.key] !== entry) return false;
    delete pending[entry.key];
    stopSide(entry);
    if (conditionalKey === entry.key) conditionalKey = null;
    cancelTimer(entry.timer);
    entry.timer = undefined;
    if (entry.signal !== undefined) {
      try {
        R(unlisten, entry.signal, ["abort", entry.onAbort]);
      } catch {
        // The listener goes with the signal.
      }
    }
    return true;
  };

  /** The browser answers a request, with the page's own arguments. @param {any} entry */
  const toBrowser = (entry) => {
    try {
      entry.resolve(R(entry.original, entry.self, entry.args));
    } catch (error) {
      entry.reject(error);
    }
  };

  /**
   * A taken request waits for the bridge's next "alive". Without it (the bridge died with the extension) a modal request
   * ends as one the user left, and a conditional one goes to the browser.
   * @param {any} entry
   */
  const watch = (entry) => {
    cancelTimer(entry.timer);
    entry.timer = later(() => {
      if (!finish(entry)) return;
      if (entry.conditional) toBrowser(entry);
      else entry.reject(notAllowed());
    }, ALIVE_MS);
  };

  /** One answer of the bridge. @param {Event} event */
  const onPortMessage = (event) => {
    /** @type {any} */
    let data;
    try {
      data = R(meData, event, []);
    } catch {
      return;
    }
    if (own(data, "t") === "alive") {
      // The bridge lives: every taken request may wait another ALIVE_MS.
      const keys = OK(pending);
      for (let i = 0; i < keys.length; i += 1) {
        const waiting = pending[keys[i]];
        if (waiting.taken) watch(waiting);
      }
      return;
    }
    const n = own(data, "n");
    if (typeof n !== "number") return;
    const entry = pending[`r${n}`];
    if (entry === undefined) return;
    const outcome = own(data, "outcome");
    if (outcome === "taken") {
      if (!entry.taken) {
        entry.taken = true;
        watch(entry);
      }
      return;
    }
    if (!finish(entry)) return;
    if (outcome === "handover" && own(data, "once") !== true) {
      // The browser answers, with the page's own arguments.
      toBrowser(entry);
    } else if (outcome === "result") {
      // The credential has a `then` of its own, so a `then` of the page's Object.prototype is not reached by the resolution.
      const credential = credentialFrom(entry.kind, own(data, "response"));
      if (credential === null || credential === undefined) entry.reject(notAllowed());
      else entry.resolve(credential);
    } else if (outcome === "error") {
      const name = own(data, "name");
      if (name === "TypeError") entry.reject(new TypeErr("The options of the request are not valid."));
      else if (name === "AbortError" || name === "InvalidStateError" || name === "SecurityError" || name === "NotSupportedError") entry.reject(new DOMEx("", name));
      else entry.reject(notAllowed());
    } else {
      // `once`: the browser takes the next call of this kind; this one ends as the browser ends one the user left.
      entry.reject(notAllowed());
    }
  };

  /** @param {MessagePort} given */
  const connect = (given) => {
    port = given;
    try {
      R(unlisten, doc, [HANDSHAKE, onHandshake, true]);
    } catch {
      // Removed already.
    }
    R(listen, given, ["message", onPortMessage]);
    R(startPort, given, []);
    if (foreignWaits) tellForeign();
  };

  /** The bridge's handshake, when it runs after this script. @param {Event} event */
  function onHandshake(event) {
    if (port !== null) return;
    /** @type {unknown} */
    let data;
    /** @type {any} */
    let ports;
    try {
      data = R(meData, event, []);
      ports = R(mePorts, event, []);
    } catch {
      return;
    }
    if (data !== "bridge" || !ports || ports.length !== 1) return;
    R(preventDefault, event, []);
    connect(ports[0]);
  }

  // ---- copying the page's options: WebAuthn names, bytes into fresh ArrayBuffers, nothing of the page kept
  /** @param {unknown} x @returns {ArrayBuffer} */
  const bytes = (x) => {
    /** @type {any} */
    let buffer;
    let offset = 0;
    let length = 0;
    try {
      length = R(abLength, x, []);
      buffer = x;
    } catch {
      try {
        buffer = R(taBuffer, x, []);
        offset = R(taOffset, x, []);
        length = R(taLength, x, []);
      } catch {
        buffer = R(dvBuffer, x, []);
        offset = R(dvOffset, x, []);
        length = R(dvLength, x, []);
      }
      // An ArrayBuffer, not a SharedArrayBuffer (which WebAuthn refuses).
      R(abLength, buffer, []);
    }
    if (length > MAX_BYTES) fail();
    const out = new AB(length);
    R(taSet, new U8(out), [new U8(buffer, offset, length)]);
    return out;
  };
  /** @param {unknown} x */
  const str = (x) => (typeof x === "string" ? x : fail());
  /** @param {unknown} x */
  const num = (x) => (typeof x === "number" && x === x && x !== Infinity && x !== -Infinity ? x : fail());
  /**
   * A number as WebIDL reads an `unsigned long` (`timeout`): NaN and the infinities are 0, the rest is truncated and wraps
   * modulo 2^32, as the browser does. Pure arithmetic: no built-in the page could replace. Anything but a number is the
   * browser's to convert.
   * @param {unknown} x
   */
  const u32 = (x) => {
    if (typeof x !== "number") return fail();
    const n = x === x && x !== Infinity && x !== -Infinity ? x : 0;
    const m = (n - (n % 1)) % 4294967296;
    return m < 0 ? m + 4294967296 : m + 0;
  };
  /** A dictionary of the page's: absent (null), or an object. @param {unknown} x @returns {any} */
  const dict = (x) => (x === undefined || x === null ? null : typeof x === "object" || typeof x === "function" ? x : fail());
  /** @param {unknown} x */
  const need = (x) => dict(x) ?? fail();
  /** @template T @param {any} x @param {(item: unknown) => T} each @returns {T[]} */
  const seq = (x, each) => {
    if (!isArray(x)) fail();
    const length = x.length;
    if (typeof length !== "number" || length > MAX_LIST) fail();
    /** @type {T[]} */
    const out = [];
    for (let i = 0; i < length; i += 1) put(out, i, each(x[i]));
    return out;
  };
  /** @param {unknown} x */
  const descriptor = (x) => {
    const d = need(x);
    const out = rec();
    out.type = str(d.type);
    out.id = bytes(d.id);
    const transports = d.transports;
    if (transports !== undefined) out.transports = seq(transports, str);
    return out;
  };
  /** @param {unknown} x */
  const salts = (x) => {
    const s = need(x);
    const out = rec();
    out.first = bytes(s.first);
    const second = s.second;
    if (second !== undefined) out.second = bytes(second);
    return out;
  };
  /** @param {unknown} x */
  const extensions = (x) => {
    const out = rec();
    const e = dict(x);
    if (e === null) return out;
    const credProps = e.credProps;
    if (credProps !== undefined) out.credProps = !!credProps;
    const prf = dict(e.prf);
    if (prf !== null) {
      const p = rec();
      const evaluate = prf.eval;
      if (evaluate !== undefined) p.eval = salts(evaluate);
      const byCredential = dict(prf.evalByCredential);
      if (byCredential !== null) {
        const keys = OK(byCredential);
        if (keys.length > MAX_LIST) fail();
        const map = rec();
        for (let i = 0; i < keys.length; i += 1) map[keys[i]] = salts(byCredential[keys[i]]);
        p.evalByCredential = map;
      }
      out.prf = p;
    }
    const appid = e.appid;
    if (appid !== undefined) out.appid = str(appid);
    const appidExclude = e.appidExclude;
    if (appidExclude !== undefined) out.appidExclude = str(appidExclude);
    // The names of the other extensions the page asked for, for the background to judge; at most 16.
    const names = OK(e);
    /** @type {string[]} */
    const others = [];
    for (let i = 0; i < names.length && others.length < 16; i += 1) {
      const name = names[i];
      const known = name === "credProps" || name === "prf" || name === "appid" || name === "appidExclude";
      if (typeof name === "string" && name.length > 0 && name.length <= 64 && !known) put(others, others.length, name);
    }
    if (others.length > 0) out.others = others;
    return out;
  };
  /** @param {any} o @param {any} pk @param {string} key @param {(x: unknown) => unknown} read */
  const optional = (o, pk, key, read) => {
    const value = pk[key];
    if (value !== undefined) o[key] = read(value);
  };
  /** @param {unknown} x */
  const copyCreate = (x) => {
    const pk = need(x);
    const o = rec();
    o.challenge = bytes(pk.challenge);
    const rp = need(pk.rp);
    const r = rec();
    r.name = str(rp.name);
    const rpId = rp.id;
    if (rpId !== undefined) r.id = str(rpId);
    o.rp = r;
    const user = need(pk.user);
    const u = rec();
    u.id = bytes(user.id);
    u.name = str(user.name);
    u.displayName = str(user.displayName);
    o.user = u;
    o.pubKeyCredParams = seq(pk.pubKeyCredParams, (item) => {
      const p = need(item);
      const out = rec();
      out.type = str(p.type);
      out.alg = num(p.alg);
      return out;
    });
    optional(o, pk, "timeout", u32);
    const exclude = pk.excludeCredentials;
    o.excludeCredentials = exclude === undefined ? [] : seq(exclude, descriptor);
    const selection = dict(pk.authenticatorSelection);
    if (selection !== null) {
      const s = rec();
      optional(s, selection, "authenticatorAttachment", str);
      optional(s, selection, "residentKey", str);
      const requireResidentKey = selection.requireResidentKey;
      if (requireResidentKey !== undefined) s.requireResidentKey = !!requireResidentKey;
      optional(s, selection, "userVerification", str);
      o.authenticatorSelection = s;
    }
    const hints = pk.hints;
    o.hints = hints === undefined ? [] : seq(hints, str);
    optional(o, pk, "attestation", str);
    optional(o, pk, "attestationFormats", (v) => seq(v, str));
    o.extensions = extensions(pk.extensions);
    return o;
  };
  /** @param {unknown} x */
  const copyGet = (x) => {
    const pk = need(x);
    const o = rec();
    o.challenge = bytes(pk.challenge);
    optional(o, pk, "timeout", u32);
    optional(o, pk, "rpId", str);
    const allow = pk.allowCredentials;
    o.allowCredentials = allow === undefined ? [] : seq(allow, descriptor);
    optional(o, pk, "userVerification", str);
    const hints = pk.hints;
    o.hints = hints === undefined ? [] : seq(hints, str);
    optional(o, pk, "attestation", str);
    optional(o, pk, "attestationFormats", (v) => seq(v, str));
    o.extensions = extensions(pk.extensions);
    return o;
  };

  /**
   * What the page asked for, copied, or null when the call is not Ferret's to look at.
   * @param {"create" | "get"} kind @param {unknown} self @param {any[]} args
   */
  const prepare = (kind, self, args) => {
    if (port === null || self !== container) return null;
    const options = dict(args.length > 0 ? args[0] : undefined);
    if (options === null) return null;
    const publicKey = options.publicKey;
    if (publicKey === undefined) return null;
    const given = options.mediation;
    const mediation = given === undefined ? "optional" : given;
    if (mediation !== "optional" && mediation !== "required" && mediation !== "conditional") return null;
    if (kind === "create" && mediation === "conditional") return null;
    const signal = options.signal;
    if (signal !== undefined && R(signalAborted, signal, []) !== false) return null;
    const request = rec();
    request.mediation = mediation;
    request.signal = signal;
    request.publicKey = publicKey;
    request.options = kind === "create" ? copyCreate(publicKey) : copyGet(publicKey);
    // A getter of the page may have fired the signal while the options were copied: then the browser rejects with its reason.
    if (signal !== undefined && R(signalAborted, signal, []) !== false) return null;
    return request;
  };

  /**
   * One call of the page.
   * @param {"create" | "get"} kind @param {unknown} self @param {any[]} args
   */
  const call = (kind, self, args) => {
    const original = originals[kind];
    const held = OGOPD(CCP, kind);
    if (held === undefined || own(held, "value") !== mine[kind]) tellForeign();
    /** @type {any} */
    let request = null;
    try {
      request = prepare(kind, self, args);
    } catch {
      request = null;
    }
    if (request === null) return R(original, self, args);
    return new P((resolve, reject) => {
      counter += 1;
      const n = counter;
      const entry = rec();
      entry.key = `r${n}`;
      entry.kind = kind;
      entry.original = original;
      entry.self = self;
      entry.args = args;
      entry.resolve = resolve;
      entry.reject = reject;
      entry.signal = request.signal;
      entry.conditional = request.mediation === "conditional";
      entry.publicKey = request.publicKey;
      entry.side = null;
      entry.restarted = false;
      entry.taken = false;
      // A modal request replaces a conditional one that waits, which ends as the browser ends it.
      if (request.mediation !== "conditional" && conditionalKey !== null) {
        const replaced = pending[conditionalKey];
        if (replaced !== undefined && finish(replaced)) {
          try {
            send({ t: "abort", n: replaced.n });
          } catch {
            // The bridge is gone; the background drops the request with the page.
          }
          replaced.reject(aborted());
        }
      }
      entry.n = n;
      pending[entry.key] = entry;
      if (request.mediation === "conditional") conditionalKey = entry.key;
      if (entry.signal !== undefined) {
        entry.onAbort = () => {
          if (!finish(entry)) return;
          try {
            send({ t: "abort", n });
          } catch {
            // As above.
          }
          /** @type {unknown} */
          let reason;
          try {
            reason = R(signalReason, entry.signal, []);
          } catch {
            reason = aborted();
          }
          reject(reason);
        };
        R(listen, entry.signal, ["abort", entry.onAbort]);
      }
      try {
        send({ t: "request", n, kind, mediation: request.mediation, options: request.options });
      } catch {
        // No way to the bridge: the browser answers.
        finish(entry);
        toBrowser(entry);
        return;
      }
      // A bridge that does not say "taken" in time is gone (or the background did not take the request): the browser answers.
      entry.timer = later(() => {
        if (entry.taken || !finish(entry)) return;
        try {
          // A bridge that is only slow drops the request with the background.
          send({ t: "abort", n });
        } catch {
          // Gone.
        }
        toBrowser(entry);
      }, TAKEN_MS);
      // A conditional get: the browser's own list keeps the platform's passkeys while Ferret's list is in its popup.
      if (entry.conditional) startSide(entry);
    });
  };

  const mine = {
    /** @param {any[]} args */
    create(...args) {
      return call(KINDS[0], this, args);
    },
    /** @param {any[]} args */
    get(...args) {
      return call(KINDS[1], this, args);
    },
  };

  // ---- install: the handshake first (either order), then the override
  R(listen, doc, [HANDSHAKE, onHandshake, true]);
  try {
    const channel = new MC();
    const taken = !R(dispatch, doc, [new ME(HANDSHAKE, { data: "main", ports: [channel.port2], cancelable: true })]);
    if (taken && port === null) connect(channel.port1);
  } catch {
    // No channel: every call goes to the browser.
  }
  if (!isNative(originals[KINDS[0]]) || !isNative(originals[KINDS[1]])) tellForeign();
  for (const kind of KINDS) {
    const d = rec();
    d.value = mine[kind];
    d.writable = true;
    d.enumerable = true;
    d.configurable = true;
    ODP(CCP, kind, d);
  }
  installStatics();

  // ---- the static methods of PublicKeyCredential: where Ferret answers (the bridge is connected) Ferret's answer, else the browser's
  function installStatics() {
    const PKC = /** @type {any} */ (W).PublicKeyCredential;
    if (typeof PKC !== "function") return;
    /** What Ferret's provider can do, for getClientCapabilities (design § 9.5). */
    const CAPABILITIES = /** @type {const} */ ([
      ["conditionalCreate", false], ["conditionalGet", true], ["passkeyPlatformAuthenticator", true], ["userVerifyingPlatformAuthenticator", true],
      ["extension:prf", true], ["extension:credProps", true],
    ]);
    const original = (/** @type {string} */ name) => (typeof PKC[name] === "function" ? PKC[name] : null);
    const uvpaa = original("isUserVerifyingPlatformAuthenticatorAvailable");
    const conditional = original("isConditionalMediationAvailable");
    const capabilities = original("getClientCapabilities");
    /** @param {string} name @param {Function} value */
    const redefine = (name, value) => {
      const held = OGOPD(PKC, name);
      const d = rec();
      d.value = value;
      d.writable = own(held, "writable") !== false;
      d.enumerable = own(held, "enumerable") !== false;
      d.configurable = own(held, "configurable") !== false;
      ODP(PKC, name, d);
    };
    const answers = {
      /** @param {any[]} args */
      isUserVerifyingPlatformAuthenticatorAvailable(...args) {
        // @ts-ignore the browser's own function, called with the page's `this`
        return port !== null ? new P((resolve) => resolve(true)) : R(/** @type {Function} */ (uvpaa), this, args);
      },
      /** @param {any[]} args */
      isConditionalMediationAvailable(...args) {
        // @ts-ignore as above
        return port !== null ? new P((resolve) => resolve(true)) : R(/** @type {Function} */ (conditional), this, args);
      },
      /** @param {any[]} args */
      getClientCapabilities(...args) {
        // @ts-ignore as above
        const given = R(/** @type {Function} */ (capabilities), this, args);
        if (port === null) return given;
        return new P((resolve, reject) => {
          R(pThen, given, [
            (/** @type {any} */ value) => {
              try {
                const out = {};
                const keys = typeof value === "object" && value !== null ? OK(value) : [];
                for (let i = 0; i < keys.length; i += 1) put(out, keys[i], value[keys[i]]);
                for (let i = 0; i < CAPABILITIES.length; i += 1) put(out, CAPABILITIES[i][0], CAPABILITIES[i][1]);
                // A record of the page's world with a `then` of its own: not in the list of its keys.
                const d = rec();
                d.value = undefined;
                d.writable = false;
                d.enumerable = false;
                d.configurable = true;
                ODP(out, "then", d);
                resolve(out);
              } catch (error) {
                reject(error);
              }
            },
            reject,
          ]);
        });
      },
    };
    if (uvpaa !== null) redefine("isUserVerifyingPlatformAuthenticatorAvailable", answers.isUserVerifyingPlatformAuthenticatorAvailable);
    if (conditional !== null) redefine("isConditionalMediationAvailable", answers.isConditionalMediationAvailable);
    if (capabilities !== null) redefine("getClientCapabilities", answers.getClientCapabilities);
  }
}

try {
  install();
} catch {
  // A page in which the script cannot install keeps the browser's own WebAuthn.
}
