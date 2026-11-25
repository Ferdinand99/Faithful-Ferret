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
  const rpId = spec.rpId ?? location.hostname;
  const sid = spec.sid ?? spec.run;
  const base = `/api/${spec.lib}`;
  const opt = spec[step] ?? {};
  const hold = spec.holdMs ? `?hold=${spec.holdMs}` : "";
  /** @type {any} */
  const result = { step, ok: false, stage: "start", rpId, lib: spec.lib, client: spec.client };
  try {
    const startBody =
      step === "create"
        ? { sid, rpId, user: spec.user, userVerification: opt.userVerification, residentKey: opt.residentKey, attestation: opt.attestation, algs: opt.algs, excludeExisting: opt.excludeExisting, authenticatorAttachment: opt.authenticatorAttachment, extensions: opt.extensions }
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
    result.stage = "client";
    const controller = new AbortController();
    if (opt.abortAfterMs) setTimeout(() => controller.abort(), opt.abortAfterMs);
    window.__abort = () => controller.abort();
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
        const cred = /** @type {PublicKeyCredential} */ (await navigator.credentials.create({ publicKey: creationFromJson(options), signal: controller.signal }));
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
        const cred = /** @type {PublicKeyCredential | null} */ (await navigator.credentials.get({ publicKey: requestFromJson(options), mediation: opt.mediation, signal: controller.signal }));
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
 * Runs the steps of the spec in order and stops at the first one that fails.
 * @param {any} spec
 */
export async function runCeremony(spec) {
  /** @type {any[]} */
  const steps = [];
  for (const step of spec.steps ?? ["create", "get"]) {
    const r = await runStep(spec, step);
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
