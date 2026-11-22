// A local relying party for the passkey spike (test-only). It verifies registration
// and sign-in on the server side, in Node, with node:crypto, independent of the
// extension code: a pass here means the bytes that the override handed to the page
// are valid WebAuthn and were signed by the key that was registered.
//
// The page it serves also carries two "hostile" scripts that run before anything
// else: a probe that records what the first page script sees, and a spy that
// listens for messages and patches the messaging functions, as a malicious page
// would. The browser test reads their notes from the DOM.
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { AAGUID, FLAGS } from "./addon/authenticator.mjs";

const b64u = (/** @type {Uint8Array} */ b) => Buffer.from(b).toString("base64url");
const sha256 = (/** @type {Uint8Array | string} */ b) => createHash("sha256").update(b).digest();

/** A minimal CBOR decoder: maps become Map, byte strings Buffer, plus ints, text and arrays. @param {Buffer} buf */
export function cborDecode(buf) {
  let o = 0;
  const read = () => {
    const ib = buf[o++];
    const major = ib >> 5;
    let n = ib & 31;
    if (n === 24) n = buf[o++];
    else if (n === 25) { n = buf.readUInt16BE(o); o += 2; }
    else if (n === 26) { n = buf.readUInt32BE(o); o += 4; }
    else if (n > 26) throw new Error("cbor: unsupported length");
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const v = buf.subarray(o, o + n); o += n; return v; }
      case 3: { const v = buf.toString("utf8", o, o + n); o += n; return v; }
      case 4: return Array.from({ length: n }, read);
      case 5: { const m = new Map(); for (let i = 0; i < n; i++) { const k = read(); m.set(k, read()); } return m; }
      default: throw new Error(`cbor: unsupported major ${major}`);
    }
  };
  const value = read();
  return { value, rest: o };
}

/** @param {Buffer} ad */
function parseAuthData(ad) {
  /** @type {{ rpIdHash: Buffer, flags: number, signCount: number, aaguid?: Buffer, credId?: Buffer, cose?: Map<number, any> }} */
  const out = { rpIdHash: ad.subarray(0, 32), flags: ad[32], signCount: ad.readUInt32BE(33) };
  if (out.flags & FLAGS.AT) {
    out.aaguid = ad.subarray(37, 53);
    const idLen = ad.readUInt16BE(53);
    out.credId = ad.subarray(55, 55 + idLen);
    out.cose = cborDecode(ad.subarray(55 + idLen)).value;
  }
  return out;
}

/** @param {string} clientDataJSON @param {string} type @param {string} challenge @param {string} origin */
function checkClientData(clientDataJSON, type, challenge, origin) {
  const cd = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8"));
  const errs = [];
  if (cd.type !== type) errs.push("clientData.type");
  if (cd.challenge !== challenge) errs.push("clientData.challenge");
  if (cd.origin !== origin) errs.push(`clientData.origin (${cd.origin})`);
  return errs;
}

const uuidHex = (/** @type {string} */ uuid) => uuid.replaceAll("-", "");

/**
 * @param {{ origin: string, rpId: string, requireUv: boolean }} rp
 * @param {{ id: string, clientDataJSON: string, attestationObject: string }} body
 * @param {string | null} challenge
 */
export function verifyRegistration(rp, body, challenge) {
  /** @type {string[]} */
  const errs = [];
  if (challenge === null) return { ok: false, errs: ["no challenge issued"] };
  errs.push(...checkClientData(body.clientDataJSON, "webauthn.create", challenge, rp.origin));
  const att = /** @type {Map<string, any>} */ (cborDecode(Buffer.from(body.attestationObject, "base64url")).value);
  if (att.get("fmt") !== "none") errs.push("fmt");
  const ad = parseAuthData(att.get("authData"));
  if (!ad.rpIdHash.equals(sha256(rp.rpId))) errs.push("rpIdHash");
  if (!(ad.flags & FLAGS.UP)) errs.push("UP flag");
  if (rp.requireUv && !(ad.flags & FLAGS.UV)) errs.push("UV flag");
  if (!(ad.flags & FLAGS.AT) || !ad.cose) errs.push("AT flag");
  if ((ad.flags & (FLAGS.BE | FLAGS.BS)) !== (FLAGS.BE | FLAGS.BS)) errs.push("BE/BS flags");
  if (ad.aaguid && ad.aaguid.toString("hex") !== uuidHex(AAGUID)) errs.push("AAGUID");
  if (errs.length || !ad.cose || !ad.credId) return { ok: false, errs };
  if (ad.cose.get(1) !== 2 || ad.cose.get(3) !== -7 || ad.cose.get(-1) !== 1) errs.push("COSE key is not EC2/ES256/P-256");
  const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64u(ad.cose.get(-2)), y: b64u(ad.cose.get(-3)) }, format: "jwk" });
  if (b64u(ad.credId) !== body.id) errs.push("credential id mismatch");
  if (errs.length) return { ok: false, errs };
  return { ok: true, errs, credential: { id: body.id, key } };
}

/**
 * @param {{ origin: string, rpId: string, requireUv: boolean, userHandle: string }} rp
 * @param {{ id: string, clientDataJSON: string, authenticatorData: string, signature: string, userHandle: string | null }} body
 * @param {string | null} challenge
 * @param {{ id: string, key: import("node:crypto").KeyObject }} cred
 */
export function verifyAssertion(rp, body, challenge, cred) {
  /** @type {string[]} */
  const errs = [];
  if (challenge === null) return { ok: false, errs: ["no challenge issued"], signatureValid: false };
  errs.push(...checkClientData(body.clientDataJSON, "webauthn.get", challenge, rp.origin));
  const ad = Buffer.from(body.authenticatorData, "base64url");
  const p = parseAuthData(ad);
  if (!p.rpIdHash.equals(sha256(rp.rpId))) errs.push("rpIdHash");
  if (!(p.flags & FLAGS.UP)) errs.push("UP flag");
  if (rp.requireUv && !(p.flags & FLAGS.UV)) errs.push("UV flag");
  if (body.id !== cred.id) errs.push("credential id");
  if (body.userHandle !== rp.userHandle) errs.push("userHandle");
  const signed = Buffer.concat([ad, sha256(Buffer.from(body.clientDataJSON, "base64url"))]);
  const signatureValid = verify("sha256", signed, cred.key, Buffer.from(body.signature, "base64url"));
  if (!signatureValid) errs.push("signature");
  return { ok: errs.length === 0, errs, signatureValid };
}

// What the first script of the page sees. It runs before any other script of the
// page: if the override is in place by then, the add-on's script ran at document_start.
const FIRST_PROBE = (/** @type {string} */ attribute) => `(function () {
  var p = window.__ferretSpikeProbe;
  var C = CredentialsContainer.prototype;
  var r = {
    probe: !!p,
    createOurs: p ? p.isOurs(C.create) : null,
    getOurs: p ? p.isOurs(C.get) : null,
    cmaOurs: p && PublicKeyCredential.isConditionalMediationAvailable ? p.isOurs(PublicKeyCredential.isConditionalMediationAvailable) : null,
    createSrc: Function.prototype.toString.call(C.create),
    claimedAtFirstScript: p ? p.claimed() : null,
    readyState: document.readyState,
    hasBody: !!document.body
  };
  document.documentElement.setAttribute(${JSON.stringify(attribute)}, JSON.stringify(r));
})();`;

// What a malicious page does at its first script: watch every message, patch the
// messaging functions, and (when asked) offer its own port before the real one.
const SPY = `(function () {
  var seen = { messages: [], windowPostMessage: 0, portPostMessage: 0, channels: 0, dispatched: [], forgedOfferSent: false, forgedPortRequests: 0 };
  var note = function (e) { seen.messages.push({ hasPorts: e.ports ? e.ports.length : 0, dataType: typeof e.data, keys: e.data && typeof e.data === "object" ? Object.keys(e.data).slice(0, 6) : [] }); };
  window.addEventListener("message", note, true);
  window.addEventListener("message", note, false);
  document.addEventListener("message", note, true);
  var wp = window.postMessage;
  window.postMessage = function () { seen.windowPostMessage++; return wp.apply(this, arguments); };
  var pp = MessagePort.prototype.postMessage;
  MessagePort.prototype.postMessage = function () { seen.portPostMessage++; return pp.apply(this, arguments); };
  var MC = window.MessageChannel;
  window.MessageChannel = function () { seen.channels++; return new MC(); };
  var de = EventTarget.prototype.dispatchEvent;
  EventTarget.prototype.dispatchEvent = function (ev) { seen.dispatched.push(ev.type); return de.apply(this, arguments); };
  window.__spy = seen;
  if (location.search.indexOf("hostile=1") >= 0) {
    // The page's own offer, sent as early as a page can: a real answer from the extension must still win.
    var mc = new MC();
    mc.port1.onmessage = function () { seen.forgedPortRequests++; };
    wp.call(window, { ferretSpike: "offer", v: 1 }, "*", [mc.port2]);
    seen.forgedOfferSent = true;
  }
})();`;

const PAGE_SCRIPT = `
var out = document.getElementById("out");
var seq = 0;
function publish(name, value) { out.setAttribute("data-" + name, JSON.stringify(value)); seq++; document.body.setAttribute("data-seq", String(seq)); }
var b64u = function (buf) { var s = ""; new Uint8Array(buf).forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, ""); };
var unb64u = function (s) { return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), function (c) { return c.charCodeAt(0); }); };
var post = function (path, body) { return fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) }).then(function (r) { return r.json(); }); };
var err = function (e) { return { name: e && e.name, message: e && e.message }; };
var uv = new URLSearchParams(location.search).get("uv") || "required";
var controller = null;

document.getElementById("register").onclick = async function () {
  try {
    var o = await post("/reg/options");
    var cred = await navigator.credentials.create({ publicKey: {
      rp: { id: o.rpId, name: "Local RP" },
      user: { id: unb64u(o.user.id), name: "alice", displayName: "Alice" },
      challenge: unb64u(o.challenge),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: uv },
      attestation: "none"
    } });
    var checks = {
      instanceOfPKC: cred instanceof PublicKeyCredential,
      responseInstanceOf: cred.response instanceof AuthenticatorAttestationResponse,
      typeIsPublicKey: cred.type === "public-key",
      rawIdMatchesId: b64u(cred.rawId) === cred.id,
      transports: cred.response.getTransports(),
      publicKeyBytes: cred.response.getPublicKey().byteLength,
      publicKeyAlg: cred.response.getPublicKeyAlgorithm(),
      authDataBytes: cred.response.getAuthenticatorData().byteLength,
      extensions: JSON.stringify(cred.getClientExtensionResults()),
      attachment: cred.authenticatorAttachment,
      json: typeof cred.toJSON === "function" ? Object.keys(cred.toJSON()).sort() : null
    };
    var res = await post("/reg/verify", { id: cred.id, clientDataJSON: b64u(cred.response.clientDataJSON), attestationObject: b64u(cred.response.attestationObject) });
    publish("register", { ok: true, checks: checks, server: res });
  } catch (e) { publish("register", { ok: false, error: err(e) }); }
};

async function signIn(conditional, signal) {
  var o = await post("/auth/options");
  var options = { publicKey: { rpId: o.rpId, challenge: unb64u(o.challenge), userVerification: uv } };
  if (conditional) options.mediation = "conditional";
  if (signal) options.signal = signal;
  var cred = await navigator.credentials.get(options);
  var checks = {
    instanceOfPKC: cred instanceof PublicKeyCredential,
    responseInstanceOf: cred.response instanceof AuthenticatorAssertionResponse,
    userHandlePresent: !!cred.response.userHandle
  };
  var res = await post("/auth/verify", {
    id: cred.id, clientDataJSON: b64u(cred.response.clientDataJSON), authenticatorData: b64u(cred.response.authenticatorData),
    signature: b64u(cred.response.signature), userHandle: cred.response.userHandle ? b64u(cred.response.userHandle) : null
  });
  return { ok: true, checks: checks, server: res };
}

document.getElementById("login").onclick = async function () {
  try { publish("login", await signIn(false)); } catch (e) { publish("login", { ok: false, error: err(e) }); }
};

document.getElementById("conditional").onclick = async function () {
  controller = new AbortController();
  publish("conditional-started", { at: Date.now() });
  try { publish("conditional", await signIn(true, controller.signal)); } catch (e) { publish("conditional", { ok: false, error: err(e) }); }
};
document.getElementById("abort").onclick = function () { if (controller) controller.abort(); };

document.getElementById("cma").onclick = async function () {
  var value = null, error = null;
  try { value = await PublicKeyCredential.isConditionalMediationAvailable(); } catch (e) { error = err(e); }
  var uvpaa = null;
  try { uvpaa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch (e) { uvpaa = err(e); }
  var probe = window.__ferretSpikeProbe;
  var native = null;
  if (probe) { try { native = await probe.nativeCma(); } catch (e) { native = err(e); } }
  publish("cma", { value: value, error: error, uvpaa: uvpaa, nativeCmaType: probe ? probe.nativeCmaType : null, native: native, fnType: typeof PublicKeyCredential.isConditionalMediationAvailable });
};

document.getElementById("native-create").onclick = async function () {
  try {
    var o = await post("/reg/options");
    await navigator.credentials.create({ publicKey: {
      rp: { id: o.rpId, name: "Local RP" }, user: { id: unb64u(o.user.id), name: "alice", displayName: "Alice" },
      challenge: unb64u(o.challenge), pubKeyCredParams: [{ type: "public-key", alg: -7 }], timeout: 1500,
      authenticatorSelection: { userVerification: "discouraged" }
    } });
    publish("native-create", { ok: true });
  } catch (e) { publish("native-create", { ok: false, error: err(e) }); }
};

document.getElementById("forge").onclick = async function () {
  // After the real handshake: a second offer with the page's own port, and answers that no request asked for.
  var spy = window.__spy;
  var mc = new MessageChannel();
  var got = 0;
  mc.port1.onmessage = function () { got++; };
  window.postMessage({ ferretSpike: "offer", v: 1 }, "*", [mc.port2]);
  for (var id = 1; id < 40; id++) window.postMessage({ id: id, error: { name: "NotAllowedError", message: "forged" } }, "*");
  var login;
  try { login = await signIn(false); } catch (e) { login = { ok: false, error: err(e) }; }
  publish("forge", { login: login, forgedPortGotRequests: got, hostileOfferSentAtFirstScript: !!(spy && spy.forgedOfferSent), earlyForgedPortRequests: spy ? spy.forgedPortRequests : null });
};

// Realms the page can make for itself. Each probe reads the new realm at once (what a page would do
// to reach the browser's own function) and again later, and says whether the override is in it.
function snapshot(w) {
  try {
    var C = w.CredentialsContainer && w.CredentialsContainer.prototype;
    var p = w.__ferretSpikeProbe;
    return { href: w.location.href, probe: !!p, createOurs: p && C ? p.isOurs(C.create) : null, createSrc: C ? w.Function.prototype.toString.call(C.create) : null };
  } catch (e) { return { error: err(e) }; }
}
function realmProbe(name, make) {
  document.getElementById(name).onclick = function () {
    var made = make();
    var sync = snapshot(made.win);
    var done = function () { setTimeout(function () { publish(name, { sync: sync, later: snapshot(made.win) }); }, 800); };
    if (made.frame) made.frame.addEventListener("load", done); else done();
  };
}
realmProbe("blank-frame", function () { var f = document.createElement("iframe"); document.body.appendChild(f); return { win: f.contentWindow }; });
realmProbe("srcdoc-frame", function () { var f = document.createElement("iframe"); f.srcdoc = "<!doctype html><p>srcdoc</p>"; document.body.appendChild(f); return { win: f.contentWindow, frame: f }; });
realmProbe("blob-frame", function () {
  var f = document.createElement("iframe");
  f.src = URL.createObjectURL(new Blob(["<!doctype html><p>blob</p>"], { type: "text/html" }));
  document.body.appendChild(f);
  return { win: f.contentWindow, frame: f };
});
realmProbe("open-window", function () { var w = window.open(""); return { win: w }; });

// Native controls: a get the browser itself would have to answer.
document.getElementById("native-get").onclick = async function () {
  try {
    var o = await post("/auth/options");
    await navigator.credentials.get({ publicKey: { rpId: o.rpId, challenge: unb64u(o.challenge), timeout: 1500, userVerification: "discouraged" } });
    publish("native-get", { ok: true });
  } catch (e) { publish("native-get", { ok: false, error: err(e) }); }
};

// More conditional requests than one document may hold: the extra ones must be refused.
document.getElementById("flood").onclick = async function () {
  var count = 6, controllers = [], settled = [];
  for (var i = 0; i < count; i++) {
    var c = new AbortController();
    controllers.push(c);
    (async function (index, signal) {
      var o = await post("/auth/options");
      try {
        await navigator.credentials.get({ mediation: "conditional", signal: signal, publicKey: { rpId: o.rpId, challenge: unb64u(o.challenge) } });
        settled.push({ index: index, ok: true });
      } catch (e) { settled.push({ index: index, name: e && e.name }); }
    })(i, c.signal);
  }
  await new Promise(function (r) { setTimeout(r, 2000); });
  var refused = settled.filter(function (x) { return x.name === "NotAllowedError"; }).length;
  publish("flood", { requested: count, refusedBeforeAbort: refused, other: settled.filter(function (x) { return x.name !== "NotAllowedError"; }) });
  window.__controllers = controllers;
};
document.getElementById("flood-abort").onclick = function () { (window.__controllers || []).forEach(function (c) { c.abort(); }); };

document.getElementById("dump").onclick = function () { publish("spy", window.__spy); };

window.addEventListener("load", function () {
  var frame = document.getElementById("same-origin-frame");
  if (frame) publish("frame-first-inline", frame.contentDocument.documentElement.getAttribute("data-first-inline"));
  publish("loaded", { firstInline: document.documentElement.getAttribute("data-first-inline"), firstExternal: document.documentElement.getAttribute("data-first-external") });
});
`;

/** @param {{ frame: boolean }} options */
function page({ frame }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Local RP (passkey spike)</title>
<script>${FIRST_PROBE("data-first-inline")}</script>
<script>${SPY}</script>
<script src="/first.js"></script>
</head>
<body>
<h1>Local relying party</h1>
<form onsubmit="return false"><input id="username" name="username" autocomplete="username webauthn"></form>
<button id="register">Register passkey</button>
<button id="login">Sign in with passkey</button>
<button id="conditional">Conditional sign-in</button>
<button id="abort">Abort</button>
<button id="cma">Availability</button>
<button id="native-create">Native create</button>
<button id="forge">Forge</button>
<button id="blank-frame">Blank frame</button>
<button id="srcdoc-frame">Srcdoc frame</button>
<button id="blob-frame">Blob frame</button>
<button id="open-window">Open window</button>
<button id="native-get">Native get</button>
<button id="flood">Flood</button>
<button id="flood-abort">Abort flood</button>
<button id="dump">Dump spy</button>
<pre id="out"></pre>
${frame ? '<iframe id="same-origin-frame" src="/frame"></iframe>' : ""}
<script>${PAGE_SCRIPT}</script>
</body>
</html>
`;
}

const FRAME_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><script>${FIRST_PROBE("data-first-inline")}</script></head><body>frame</body></html>
`;

/**
 * Starts the relying party on 127.0.0.1.
 * @param {{ originFor: (port: number) => string, rpId: string, port?: number, tls?: { key: string, cert: string }, requireUv?: boolean }} options
 *   originFor: the page's origin once the port is known
 */
export async function startRp({ originFor, rpId, port = 0, tls, requireUv = true }) {
  const rp = {
    origin: "",
    rpId,
    requireUv,
    userHandle: b64u(randomBytes(16)),
    /** Challenges handed out and not used yet: each can be used once, and two documents can wait at the same time. @type {Set<string>} */
    challenges: new Set(),
    /** @type {{ id: string, key: import("node:crypto").KeyObject } | null} */
    credential: null,
    verified: { registration: false, authentication: 0 },
    /** @type {{ path: string, ok: boolean, errs: string[] }[]} */
    log: [],
  };
  const send = (/** @type {import("node:http").ServerResponse} */ res, /** @type {number} */ code, /** @type {unknown} */ body, type = "application/json") => {
    res.writeHead(code, { "content-type": type, "cache-control": "no-store" });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  /** @param {import("node:http").IncomingMessage} req @returns {Promise<any>} */
  const readJson = (req) => new Promise((resolve) => {
    let s = "";
    req.on("data", (c) => { s += c; });
    req.on("end", () => { try { resolve(JSON.parse(s || "{}")); } catch { resolve({}); } });
  });
  /** The challenge in the client data, if it was handed out and unused: it is used up by asking. @param {string} clientDataJSON @returns {string | null} */
  const claim = (clientDataJSON) => {
    try {
      const challenge = JSON.parse(Buffer.from(String(clientDataJSON), "base64url").toString("utf8")).challenge;
      return typeof challenge === "string" && rp.challenges.delete(challenge) ? challenge : null;
    } catch {
      return null;
    }
  };
  /** @type {import("node:http").RequestListener} */
  const handler = async (req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    if (req.method === "GET") {
      if (path === "/") return send(res, 200, page({ frame: url.searchParams.get("frame") === "1" }), "text/html; charset=utf-8");
      if (path === "/frame") return send(res, 200, FRAME_PAGE, "text/html; charset=utf-8");
      if (path === "/first.js") return send(res, 200, FIRST_PROBE("data-first-external"), "text/javascript; charset=utf-8");
      return send(res, 404, {});
    }
    if (req.method !== "POST") return send(res, 404, {});
    const body = await readJson(req);
    if (path === "/reg/options") {
      const challenge = b64u(randomBytes(32));
      rp.challenges.add(challenge);
      return send(res, 200, { challenge, rpId: rp.rpId, user: { id: rp.userHandle } });
    }
    if (path === "/reg/verify") {
      const r = verifyRegistration(rp, body, claim(body.clientDataJSON));
      if (r.ok && r.credential) {
        rp.credential = r.credential;
        rp.verified.registration = true;
      }
      rp.log.push({ path, ok: r.ok, errs: r.errs });
      return send(res, 200, { ok: r.ok, errs: r.errs });
    }
    if (path === "/auth/options") {
      const challenge = b64u(randomBytes(32));
      rp.challenges.add(challenge);
      return send(res, 200, { challenge, rpId: rp.rpId });
    }
    if (path === "/auth/verify") {
      const challenge = claim(body.clientDataJSON);
      if (!rp.credential) return send(res, 200, { ok: false, errs: ["no credential registered"] });
      const r = verifyAssertion(rp, body, challenge, rp.credential);
      if (r.ok) rp.verified.authentication++;
      rp.log.push({ path, ok: r.ok, errs: r.errs });
      return send(res, 200, { ok: r.ok, errs: r.errs, signatureValid: r.signatureValid });
    }
    return send(res, 404, {});
  };
  const server = tls ? createHttpsServer(tls, handler) : createHttpServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(undefined));
  });
  const bound = /** @type {import("node:net").AddressInfo} */ (server.address()).port;
  rp.origin = originFor(bound);
  return {
    rp,
    port: bound,
    close: () => new Promise((done) => {
      server.close(() => done(undefined));
      server.closeAllConnections();
    }),
  };
}
