// The client side of the passkey fixtures: one ceremony (create, get, or both) against one of the two
// relying parties (rs: webauthn-rs, swa: SimpleWebAuthn), driven by the client code that sites use:
//   swa     @simplewebauthn/browser (startRegistration, startAuthentication: the toJSON path)
//   manual  a hand-written conversion in the style of webauthn-json
//   pubkey  the manual conversion, and it also reads response.getPublicKey(), getPublicKeyAlgorithm(),
//           getAuthenticatorData() and getTransports() of the new credential
// Nothing here signs anything: the browser (or Ferret) does. The result of every step is left on
// window.__result, in the DOM and at /api/report for the run.

/** @param {string} text */
export const fromB64u = (text) => {
  const pad = "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};
/** @param {ArrayBuffer | Uint8Array} buf */
export const toB64u = (buf) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** The options JSON of a server turned into what navigator.credentials.create takes (webauthn-json style). @param {any} o */
export function creationFromJson(o) {
  return {
    ...o,
    challenge: fromB64u(o.challenge),
    user: { ...o.user, id: fromB64u(o.user.id) },
    excludeCredentials: (o.excludeCredentials ?? []).map((/** @type {any} */ c) => ({ ...c, id: fromB64u(c.id) })),
    extensions: o.extensions ? extensionsFromJson(o.extensions) : undefined,
  };
}
/** @param {any} o */
export function requestFromJson(o) {
  return {
    ...o,
    challenge: fromB64u(o.challenge),
    allowCredentials: (o.allowCredentials ?? []).map((/** @type {any} */ c) => ({ ...c, id: fromB64u(c.id) })),
    extensions: o.extensions ? extensionsFromJson(o.extensions) : undefined,
  };
}
/** Binary members of the extension inputs (prf eval) come as base64url text in the JSON. @param {any} ext */
function extensionsFromJson(ext) {
  const out = { ...ext };
  if (ext.prf) {
    const conv = (/** @type {any} */ v) => (v ? { first: fromB64u(v.first), ...(v.second ? { second: fromB64u(v.second) } : {}) } : v);
    out.prf = { ...ext.prf, ...(ext.prf.eval ? { eval: conv(ext.prf.eval) } : {}) };
    if (ext.prf.evalByCredential) out.prf.evalByCredential = Object.fromEntries(Object.entries(ext.prf.evalByCredential).map(([k, v]) => [k, conv(v)]));
  }
  return out;
}
/** @param {any} results */
function extensionResultsToJson(results) {
  const out = { ...results };
  if (results?.prf?.results) {
    const r = results.prf.results;
    out.prf = { ...results.prf, results: { first: toB64u(r.first), ...(r.second ? { second: toB64u(r.second) } : {}) } };
  }
  return out;
}

/** @param {PublicKeyCredential} cred */
function attestationToJson(cred) {
  const r = /** @type {AuthenticatorAttestationResponse} */ (cred.response);
  return {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: toB64u(r.clientDataJSON),
      attestationObject: toB64u(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
    },
    clientExtensionResults: extensionResultsToJson(cred.getClientExtensionResults()),
  };
}
/** @param {PublicKeyCredential} cred */
function assertionToJson(cred) {
  const r = /** @type {AuthenticatorAssertionResponse} */ (cred.response);
  return {
    id: cred.id,
    rawId: toB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: toB64u(r.clientDataJSON),
      authenticatorData: toB64u(r.authenticatorData),
      signature: toB64u(r.signature),
      userHandle: r.userHandle ? toB64u(r.userHandle) : undefined,
    },
    clientExtensionResults: extensionResultsToJson(cred.getClientExtensionResults()),
  };
}

/**
 * Named changes to the options before the browser gets them (the adversarial pages' inputs: forged members, huge values,
 * names made to mislead). They are applied to the options of the library, so the relying party stays honest.
 * @type {Record<string, (options: any, step: string) => void>}
 */
export const TAMPER = {
  // Members that no browser reads but a bridge might: an origin, a top origin, a frame id.
  "forged-origin": (o) => {
    Object.assign(o, { origin: "https://github.com", topOrigin: "https://github.com", crossOrigin: false, frameId: 0, tabId: 1, documentId: "00000000000000000000000000000000", userVerified: true, userPresent: true });
    if (o.rp) o.rp.origin = "https://github.com";
  },
  // Names that pretend to be someone else, with a right-to-left override and control characters.
  "strange-names": (o, step) => {
    if (step !== "create") return;
    o.rp = { ...o.rp, name: "GitHub \u202Esdrawkcab" };
    o.user = { ...o.user, name: "admin@github.com\u0000\u0007\u001b[31m", displayName: "\u202E\u2066Sign in to GitHub\u2069\r\nSecurity team" };
  },
  // A page that claims to be another site by name only.
  "lookalike-name": (o) => {
    if (o.rp) o.rp.name = "rp-a.test";
    if (o.user) o.user.displayName = "Log in to https://rp-a.test";
  },
  // Values far past every limit of the protocol.
  huge: (o) => {
    if (o.user) o.user.displayName = "x".repeat(1024 * 1024);
    if (o.rp) o.rp.name = "y".repeat(1024 * 1024);
    o.excludeCredentials = Array.from({ length: 5000 }, (_, i) => ({ type: "public-key", id: toB64u(new Uint8Array(32).fill(i % 255)) }));
    // The real ones stay, so the relying party can still be answered; thousands of others come with them.
    const fakes = Array.from({ length: 5000 }, (_, i) => ({ type: "public-key", id: toB64u(new Uint8Array(32).fill(i % 255)) }));
    if (o.allowCredentials !== undefined) o.allowCredentials = [...o.allowCredentials, ...fakes];
  },
};

/** @param {any} e */
const errorInfo = (e) => ({ name: e?.name ?? typeof e, message: String(e?.message ?? e).slice(0, 300) });

/** @param {string} path @param {any} body @param {string} [query] */
async function post(path, body, query = "") {
  const res = await fetch(path + query, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, json: await res.json() };
}

/** Leaves one result for the runner. @param {string} run @param {any} payload */
export async function report(run, payload) {
  try {
    await fetch("/api/report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ run, ...payload }) });
  } catch {
    // The runner reads window.__result as well.
  }
}

/**
 * One step of a ceremony. Returns {step, ok, stage, error?, server?, extras?, ms}.
 * @param {any} spec @param {"create" | "get"} step
 */
async function runStep(spec, step) {
  const started = performance.now();
  // A case of the hold-out set says its options in the hold-out set's own words (see the end of this file): what the relying party
  // can issue goes to its start, and the rest is laid over the options the page gives the browser.
  const ho = spec.ho ? holdoutStep(spec, step) : null;
  const rpId = ho ? ho.serverRpId : (spec.rpId ?? location.hostname);
  const sid = spec.sid ?? spec.run;
  const base = `/api/${spec.lib}`;
  const opt = ho ? ho.server : (spec[step] ?? {});
  const hold = spec.holdMs ? `?hold=${spec.holdMs}` : "";
  /** @type {any} */
  const result = { step, ok: false, stage: "start", rpId, lib: spec.lib, client: spec.client };
  try {
    const startBody =
      step === "create"
        ? { sid, rpId, user: ho ? ho.user : spec.user, challengeBytes: opt.challengeBytes, userVerification: opt.userVerification, residentKey: opt.residentKey, attestation: opt.attestation, algs: opt.algs, excludeExisting: opt.excludeExisting, authenticatorAttachment: opt.authenticatorAttachment, extensions: opt.extensions }
        : { sid, rpId, userVerification: opt.userVerification, allow: opt.allow ?? "all", extensions: opt.extensions };
    const started1 = await post(`${base}/${step === "create" ? "register" : "auth"}/start`, startBody);
    if (!started1.json.ok) {
      result.stage = "server-start";
      result.error = { name: "ServerError", message: String(started1.json.error) };
      return { ...result, ms: Math.round(performance.now() - started) };
    }
    /** @type {any} */
    const options = started1.json.options;
    if (opt.timeout) options.timeout = opt.timeout;
    // evalByCredential names the credential the earlier create made as "$created".
    const byCred = options.extensions?.prf?.evalByCredential;
    if (byCred && byCred.$created && spec.__createdId) {
      byCred[spec.__createdId] = byCred.$created;
      delete byCred.$created;
    }
    if (opt.hints) options.hints = opt.hints;
    if (spec.tamper) TAMPER[spec.tamper]?.(options, step);
    // A page that sends a user.id the options of a library would never make (0 or 65 bytes): the browser must throw TypeError.
    if (opt.userIdBytes !== undefined && options.user) options.user.id = toB64u(new Uint8Array(opt.userIdBytes).fill(1));
    if (opt.abortConditional && window.__cond) window.__cond.controller.abort();
    result.stage = "client";
    const controller = new AbortController();
    if (opt.abortAfterMs) setTimeout(() => controller.abort(), opt.abortAfterMs);
    window.__abort = () => controller.abort();
    if (spec.ho) holdoutTimers(spec, step, controller);
    const clientStart = performance.now();
    /** @type {any} */
    let credentialJson;
    /** @type {any} */
    const extras = {};
    try {
      if (spec.client === "swa") {
        const swa = /** @type {any} */ (window).SimpleWebAuthnBrowser;
        credentialJson = step === "create" ? await swa.startRegistration({ optionsJSON: options }) : await swa.startAuthentication({ optionsJSON: options, useBrowserAutofill: opt.mediation === "conditional", verifyBrowserAutofillInput: false });
      } else if (step === "create") {
        const publicKey = ho ? ho.client(creationFromJson(options)) : creationFromJson(options);
        const cred = /** @type {PublicKeyCredential} */ (await (ho ? ho.call("create", publicKey, controller.signal) : navigator.credentials.create({ publicKey, signal: controller.signal })));
        credentialJson = attestationToJson(cred);
        if (spec.client === "pubkey") {
          const r = /** @type {AuthenticatorAttestationResponse} */ (cred.response);
          extras.getPublicKey = typeof r.getPublicKey === "function" && r.getPublicKey() ? toB64u(/** @type {ArrayBuffer} */ (r.getPublicKey())) : null;
          extras.getPublicKeyAlgorithm = typeof r.getPublicKeyAlgorithm === "function" ? r.getPublicKeyAlgorithm() : null;
          extras.getAuthenticatorData = typeof r.getAuthenticatorData === "function" ? toB64u(r.getAuthenticatorData()) : null;
          extras.getTransports = typeof r.getTransports === "function" ? r.getTransports() : null;
          extras.toJSON = typeof (/** @type {any} */ (cred).toJSON) === "function";
        }
      } else {
        const publicKey = ho ? ho.client(requestFromJson(options)) : requestFromJson(options);
        const cred = /** @type {PublicKeyCredential | null} */ (await (ho ? ho.call("get", publicKey, controller.signal) : navigator.credentials.get({ publicKey, mediation: opt.mediation, signal: controller.signal })));
        if (!cred) throw new TypeError("credentials.get answered null");
        credentialJson = assertionToJson(cred);
      }
    } catch (e) {
      result.error = errorInfo(e);
      result.clientMs = Math.round(performance.now() - clientStart);
      return { ...result, ms: Math.round(performance.now() - started) };
    }
    result.clientMs = Math.round(performance.now() - clientStart);
    result.credential = { id: credentialJson.id, attachment: credentialJson.authenticatorAttachment ?? null, extensions: credentialJson.clientExtensionResults ?? null, clientData: JSON.parse(atob(credentialJson.response.clientDataJSON.replace(/-/g, "+").replace(/_/g, "/"))) };
    if (spec.client === "pubkey") result.extras = extras;
    result.stage = "server-finish";
    const finished = await post(`${base}/${step === "create" ? "register" : "auth"}/finish`, { sid, credential: credentialJson }, hold);
    result.server = finished.json;
    result.ok = finished.json.ok === true;
    if (!result.ok) result.error = { name: "ServerRefused", message: String(finished.json.error) };
  } catch (e) {
    result.error = errorInfo(e);
  }
  return { ...result, ms: Math.round(performance.now() - started) };
}

/**
 * Starts a conditional get (mediation "conditional") and does not wait for it: the next step (a modal get, which
 * replaces it) is what the case is about. How the conditional one ends is reported as kind "conditional".
 * @param {any} spec
 */
async function startConditional(spec) {
  const rpId = spec.rpId ?? location.hostname;
  const sid = spec.sid ?? spec.run;
  const opt = spec.conditional ?? spec.get ?? {};
  const started = await post(`/api/${spec.lib}/auth/start`, { sid, rpId, userVerification: opt.userVerification, allow: opt.allow ?? "none" });
  const controller = new AbortController();
  const t0 = performance.now();
  const promise = Promise.resolve()
    .then(() => navigator.credentials.get({ publicKey: requestFromJson(started.json.options), mediation: "conditional", signal: controller.signal }))
    .then(
      () => report(spec.run, { kind: "conditional", ok: true, ms: Math.round(performance.now() - t0) }),
      (e) => report(spec.run, { kind: "conditional", ok: false, error: errorInfo(e), ms: Math.round(performance.now() - t0) }),
    );
  window.__cond = { controller, promise };
  await report(spec.run, { kind: "conditional-started" });
}

/**
 * Runs the steps of the spec in order and stops at the first one that fails.
 * @param {any} spec
 */
export async function runCeremony(spec) {
  /** @type {any[]} */
  const steps = [];
  let creates = 0;
  if (spec.ho) holdoutPage(spec);
  for (const step of spec.steps ?? ["create", "get"]) {
    spec.__createIndex = creates;
    if (step === "conditional") {
      await startConditional(spec);
      continue;
    }
    const stepSpec = step === "create" && creates++ > 0 && spec.user2 ? { ...spec, user: spec.user2 } : spec;
    const r = await runStep(stepSpec, step);
    if (step === "create" && r.ok) spec.__createdId = r.credential?.id;
    if (step === "create" && r.ok && spec.__firstCreatedId === undefined) spec.__firstCreatedId = r.credential?.id;
    steps.push(r);
    await report(spec.run, { kind: "step", ...r });
    if (!r.ok) break;
  }
  const out = { run: spec.run, done: true, ok: steps.length > 0 && steps.every((s) => s.ok), steps, origin: location.origin, topLevel: window.top === window };
  window.__result = out;
  await report(spec.run, { kind: "done", ...out });
  return out;
}

/** The spec of the page: window.__spec (set by the runner) or ?spec=<base64url JSON>. */
export function pageSpec() {
  if (window.__spec) return window.__spec;
  const q = new URLSearchParams(location.search).get("spec");
  return q ? JSON.parse(new TextDecoder().decode(fromB64u(q))) : undefined;
}

// ------------------------------------------------------------------------------------------------- the hold-out set's words
//
// The hold-out set (extension/test/fixtures/passkey-holdout) was written without the page's spec in hand. Its spec (spec.ho here,
// passed through by the runner as the case says it) uses its own conventions, mapped here without changing what any case expects:
//   create / get        overrides of the publicKey options the page gives the browser; `create` may be a list, one per create step.
//                       What the relying party can issue goes to its start as well (the RP ID when it is a plain host name, the user,
//                       the algorithms, the selection, the attestation, the extensions), so it can still check the answer.
//   rpId                rp.id and rpId of every step: a plain lower-case host name goes to the relying party; any other text (a port,
//                       a trailing dot, capitals) is given to the browser as it is, while the relying party keeps the page's host
//   "$cred"             the raw id of the credential the first create made (base64url as a key; in a list, {type: "public-key", id})
//   {"$foreign": n}     n random bytes no authenticator knows, as a credential id
//   {"$bytes": n}       n random bytes; with "$view": {bufferBytes, byteOffset} a Uint8Array view into a larger buffer. For the
//                       challenge: the relying party's own challenge (of size n), so it can check it
//   {"$omit": true}     the member is taken out of the options
//   {"$error": name}    an error of that kind (an abort reason)
//   abort               {when: "before"}: the signal is aborted before the call; {step, afterMs, reason}: during the step
//   navigate            {step, afterMs, kind: "hash", to}: the address's fragment changes while the call waits
//   removeFrame         {afterMs}: the frame the ceremony runs in is taken out of its parent while the call waits
//   switch              "abort-conditional-then-get-same-tick": the conditional call is aborted and the modal get made in one task
//   concurrent, report  n modal gets from one click, in one task; "last-settled-ok": the step is ok when exactly one of them answered
//   __page, tamper      illegal-invocation (get called on another object), proto-pollution (members set on Object.prototype first),
//                       getter-flip (rp.id / rpId give another value after the first read), mutate-after-call (the buffers are
//                       zeroed and detached right after the call), synthetic-click (the page clicks its own button; ceremony.mjs)

/** A plain host name as a relying party takes it: lower case, labels of letters, digits and dashes. @param {unknown} v */
const plainHost = (v) => typeof v === "string" && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/.test(v);
/** @param {number} n */
const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(Math.max(0, Math.min(Number(n) || 0, 4096))));
/** @param {unknown} v @param {string} key */
const isMarker = (v, key) => typeof v === "object" && v !== null && !Array.isArray(v) && key in v;

/** Before the first step: what the hold-out page does to itself, and the user of the ceremony. @param {any} spec */
function holdoutPage(spec) {
  const ho = spec.ho;
  if (ho.__page === "proto-pollution" && ho.tamper && typeof ho.tamper === "object") {
    for (const [path, value] of Object.entries(ho.tamper)) {
      const key = path.replace(/^Object\.prototype\./, "");
      /** @type {any} */ (Object.prototype)[key] = value;
    }
  }
  // One user.id for the whole ceremony (the relying party gets it too).
  const user = ho.user ?? {};
  const idSpec = user.id;
  spec.__hoUser = {
    name: typeof user.name === "string" ? user.name : "alice",
    displayName: typeof user.displayName === "string" ? user.displayName : "Alice",
    idBytes: isMarker(idSpec, "$bytes") ? randomBytes(idSpec.$bytes) : null,
    idView: isMarker(idSpec, "$view") ? idSpec.$view : null,
    omit: Object.entries(user).filter(([, v]) => isMarker(v, "$omit")).map(([k]) => k),
  };
}

/**
 * A value of the hold-out spec as JSON for a relying party's start (bytes as base64url; "$cred" as the first credential's id).
 * @param {any} spec @param {any} v @returns {any}
 */
function holdoutJson(spec, v) {
  if (Array.isArray(v)) return v.map((x) => holdoutJson(spec, x));
  if (v === "$cred") return spec.__firstCreatedId;
  if (typeof v !== "object" || v === null) return v;
  if (isMarker(v, "$bytes")) return toB64u(randomBytes(v.$bytes));
  if (isMarker(v, "$foreign")) return toB64u(randomBytes(v.$foreign));
  /** @type {Record<string, any>} */
  const out = {};
  for (const [k, x] of Object.entries(v)) out[k === "$cred" ? spec.__firstCreatedId : k] = holdoutJson(spec, x);
  return out;
}

/** A credential descriptor of the hold-out spec, for the browser. @param {any} spec @param {any} d */
function holdoutDescriptor(spec, d) {
  const idOf = (/** @type {any} */ v) => (v === "$cred" ? fromB64u(spec.__firstCreatedId ?? "") : isMarker(v, "$foreign") ? randomBytes(v.$foreign).buffer : typeof v === "string" ? fromB64u(v) : v);
  if (d === "$cred" || isMarker(d, "$foreign")) return { type: "public-key", id: idOf(d) };
  return { ...d, id: idOf(d.id) };
}

/** Bytes in a view into a larger buffer, at an offset. @param {Uint8Array} bytes @param {{ bufferBytes: number, byteOffset: number } | null} view */
function inView(bytes, view) {
  if (!view) return bytes;
  const offset = Number(view.byteOffset) || 0;
  const buffer = new ArrayBuffer(Math.max(Number(view.bufferBytes) || 0, bytes.length + offset));
  new Uint8Array(buffer).fill(0x5a);
  const out = new Uint8Array(buffer, offset, bytes.length);
  out.set(bytes);
  return out;
}

const UV_VALUES = ["required", "preferred", "discouraged"];
const RK_VALUES = ["required", "preferred", "discouraged"];
const ATTESTATIONS = ["none", "indirect", "direct", "enterprise"];
const ATTACHMENTS = ["platform", "cross-platform"];

/**
 * The step of a hold-out case: the relying party's start inputs, the user, and how the options for the browser are changed.
 * @param {any} spec @param {"create" | "get"} step
 */
function holdoutStep(spec, step) {
  const ho = spec.ho;
  const raw = Array.isArray(ho[step]) ? (ho[step][spec.__createIndex ?? 0] ?? {}) : (ho[step] ?? {});
  // The RP ID: the step's own (create rp.id, get rpId), else the case's.
  const stepRp = step === "create" ? raw.rp?.id : typeof raw.rpId === "string" ? raw.rpId : undefined;
  const wanted = stepRp ?? ho.rpId;
  const serverRpId = plainHost(wanted) ? wanted : location.hostname;
  const u = spec.__hoUser;
  if (u.idBytes === null) u.idBytes = new TextEncoder().encode(`${serverRpId}:${u.name}`);
  /** @type {Record<string, any>} */
  const server = {};
  if (step === "create") {
    const sel = raw.authenticatorSelection ?? {};
    server.userVerification = UV_VALUES.includes(sel.userVerification) ? sel.userVerification : "preferred";
    server.residentKey = RK_VALUES.includes(sel.residentKey) ? sel.residentKey : sel.requireResidentKey === true ? "required" : "preferred";
    if (ATTACHMENTS.includes(sel.authenticatorAttachment)) server.authenticatorAttachment = sel.authenticatorAttachment;
    server.attestation = ATTESTATIONS.includes(raw.attestation) ? raw.attestation : "none";
    if (Array.isArray(raw.pubKeyCredParams)) {
      const algs = raw.pubKeyCredParams.filter((/** @type {any} */ p) => p?.type === "public-key" && Number.isInteger(p.alg)).map((/** @type {any} */ p) => p.alg);
      if (algs.length > 0) server.algs = [...new Set(algs)];
    }
    if (isMarker(raw.challenge, "$bytes")) server.challengeBytes = raw.challenge.$bytes;
  } else {
    server.userVerification = UV_VALUES.includes(raw.userVerification) ? raw.userVerification : "preferred";
    server.allow = Array.isArray(raw.allowCredentials) && raw.allowCredentials.length === 0 ? "none" : "all";
    if (ho.switch === "abort-conditional-then-get-same-tick") server.abortConditional = true;
  }
  if (raw.extensions) server.extensions = holdoutJson(spec, raw.extensions);
  const user = { name: u.name, displayName: u.displayName, id: toB64u(u.idBytes) };

  /** The options the browser gets: the page's, with the case's overrides laid over them. @param {any} pk */
  const client = (pk) => {
    const out = { ...pk };
    const literalRp = typeof wanted === "string" && wanted !== serverRpId ? wanted : null;
    if (step === "create") {
      out.rp = { ...out.rp };
      if (literalRp !== null) out.rp.id = literalRp;
      if (raw.rp) for (const [k, v] of Object.entries(raw.rp)) if (k !== "id") out.rp[k] = v;
      out.user = { ...out.user, id: inView(u.idBytes, u.idView) };
      for (const k of u.omit) delete out.user[k];
      if (Array.isArray(raw.pubKeyCredParams)) out.pubKeyCredParams = raw.pubKeyCredParams;
      if (raw.authenticatorSelection) out.authenticatorSelection = { ...out.authenticatorSelection, ...raw.authenticatorSelection };
      if ("attestation" in raw) out.attestation = raw.attestation;
      if ("attestationFormats" in raw) out.attestationFormats = raw.attestationFormats;
      if (Array.isArray(raw.excludeCredentials)) out.excludeCredentials = raw.excludeCredentials.map((/** @type {any} */ d) => holdoutDescriptor(spec, d));
    } else {
      if (literalRp !== null) out.rpId = literalRp;
      if (isMarker(raw.rpId, "$omit")) delete out.rpId;
      if (Array.isArray(raw.allowCredentials)) out.allowCredentials = raw.allowCredentials.map((/** @type {any} */ d) => holdoutDescriptor(spec, d));
      if ("userVerification" in raw) out.userVerification = raw.userVerification;
    }
    if ("hints" in raw) out.hints = raw.hints;
    if ("timeout" in raw) out.timeout = raw.timeout;
    if (isMarker(raw.challenge, "$view")) out.challenge = inView(new Uint8Array(out.challenge), raw.challenge.$view);
    // getter-flip: the RP ID reads as one host the first time and as another every time after.
    const flip = ho.__page === "getter-flip" && ho.tamper?.flip ? ho.tamper.flip : null;
    if (flip && flip[step]) {
      let reads = 0;
      const target = step === "create" ? out.rp : out;
      Object.defineProperty(target, step === "create" ? "id" : "rpId", { enumerable: true, configurable: true, get: () => (reads++ === 0 ? flip.first : flip.later) });
    }
    return out;
  };

  /**
   * The call itself, as the case makes it: on another receiver (illegal invocation), several at once (concurrent), or with the
   * buffers changed right after it (mutate-after-call).
   * @param {"create" | "get"} kind @param {any} publicKey @param {AbortSignal} signal
   */
  const call = async (kind, publicKey, signal) => {
    const fn = kind === "create" ? navigator.credentials.create : navigator.credentials.get;
    if (ho.__page === "illegal-invocation" && kind === "get") return fn.call({}, { publicKey, signal });
    if (Number.isInteger(ho.concurrent) && ho.concurrent > 1 && kind === "get") {
      const calls = Array.from({ length: ho.concurrent }, () => fn.call(navigator.credentials, { publicKey, signal }));
      const settled = await Promise.allSettled(calls);
      const answered = settled.filter((x) => x.status === "fulfilled");
      if (answered.length !== 1) {
        const names = settled.map((x) => (x.status === "fulfilled" ? "answered" : /** @type {any} */ (x).reason?.name)).join(", ");
        throw Object.assign(new Error(`${answered.length} of ${ho.concurrent} calls answered: ${names}`), { name: "ConcurrentOutcome" });
      }
      return /** @type {PromiseFulfilledResult<any>} */ (answered[0]).value;
    }
    const pending = fn.call(navigator.credentials, { publicKey, signal });
    if (ho.__page === "mutate-after-call") {
      for (const what of ho.tamper?.afterCall ?? []) {
        try {
          const challenge = publicKey.challenge instanceof ArrayBuffer ? publicKey.challenge : publicKey.challenge.buffer;
          if (what === "challenge.fill(0)") new Uint8Array(challenge).fill(0);
          if (what === "challenge.buffer.transfer()") challenge.transfer?.();
          if (what === "user.id.fill(0)" && publicKey.user) new Uint8Array(publicKey.user.id instanceof ArrayBuffer ? publicKey.user.id : publicKey.user.id.buffer).fill(0);
        } catch {
          // A buffer that is gone already.
        }
      }
    }
    return pending;
  };
  return { serverRpId, server, user, client, call };
}

/** The timers of a hold-out step: an abort, a change of the address's fragment, the frame taken out. @param {any} spec @param {string} step @param {AbortController} controller */
function holdoutTimers(spec, step, controller) {
  const ho = spec.ho;
  const reasonOf = (/** @type {any} */ r) => (isMarker(r, "$error") ? new (/** @type {any} */ (globalThis)[r.$error] ?? Error)(r.message ?? "aborted by the page") : r);
  const abort = () => (ho.abort.reason !== undefined ? controller.abort(reasonOf(ho.abort.reason)) : controller.abort());
  if (ho.abort?.when === "before") abort();
  else if (ho.abort && ho.abort.step === step) setTimeout(abort, Number(ho.abort.afterMs) || 0);
  if (ho.navigate && ho.navigate.step === step && ho.navigate.kind === "hash") {
    setTimeout(() => {
      location.hash = String(ho.navigate.to ?? "#moved").replace(/^#/, "");
    }, Number(ho.navigate.afterMs) || 0);
  }
  if (ho.removeFrame) setTimeout(() => window.frameElement?.remove(), Number(ho.removeFrame.afterMs) || 0);
}
