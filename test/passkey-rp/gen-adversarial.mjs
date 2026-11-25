// Generates the adversarial pages from small descriptions: `node gen-adversarial.mjs` writes pages/adversarial/<name>.html. The pages are
// committed; this file is what they are made from (every page has the same shell and its own head script and body).
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

const shell = ({ name, head = "", body }) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Adversarial: ${name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
${head ? `<script>\n${head}\n</script>\n` : ""}</head>
<body>
<h1>Adversarial page: ${name}</h1>
<form id="login" onsubmit="return false">
  <label>User name <input id="username" name="username" type="text" autocomplete="username webauthn"></label>
  <button id="go" type="button">Run the case</button>
</form>
<pre id="result" data-state="idle">idle</pre>
<script type="module">
import { adversarial } from "/adversarial/adv.mjs";
import { report, runCeremony } from "/lib.mjs";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
void report; void sleep;
${body}
</script>
</body>
</html>
`;

const pages = {
  // The page talks to the bridge as if it were the content script: forged requests as messages, events and ports.
  "bridge-direct": {
    body: `
adversarial({ name: "bridge-direct", run: async (spec, note) => {
  const replies = [];
  const raw = [];
  window.addEventListener("message", (e) => raw.push({ type: e.data?.type ?? typeof e.data, hasPorts: e.ports?.length > 0 }));
  const names = ["passkey_request", "passkey-request", "ferret_passkey", "FERRET_PASSKEY", "passkey_result", "passkey_handover", "passkey_error"];
  const forged = (t) => ({ type: t, kind: t, id: "1", op: "get", origin: "https://github.com", rpId: "github.com", frameId: 0, publicKey: { challenge: "AAAA", rpId: "github.com" } });
  for (const t of names) {
    try { window.postMessage(forged(t), "*"); } catch {}
    try { const ch = new MessageChannel(); ch.port1.onmessage = (e) => replies.push(JSON.stringify(e.data).slice(0, 200)); document.dispatchEvent(new MessageEvent(t, { data: forged(t), ports: [ch.port2] })); } catch {}
    try { window.dispatchEvent(new CustomEvent(t, { detail: forged(t) })); } catch {}
  }
  await sleep(300);
  note("repliesToForgedMessages", replies);
  note("windowMessagesSeen", raw.length);
  return runCeremony(spec);
} });`,
  },
  // A script in the head that listens in the capture phase before anything else and tries to keep any port it sees.
  "head-listener": {
    head: `(function () {
  var seen = [], ports = [];
  window.__seen = seen;
  window.__ports = ports;
  function rec(kind, e) {
    seen.push({ kind: kind, type: e && e.type, hasPorts: !!(e && e.ports && e.ports.length) });
    if (e && e.ports && e.ports.length) ports.push(e.ports[0]);
  }
  window.addEventListener("message", function (e) { rec("window-capture", e); }, true);
  document.addEventListener("message", function (e) { rec("document-capture", e); }, true);
  var dispatch = EventTarget.prototype.dispatchEvent;
  EventTarget.prototype.dispatchEvent = function (e) { rec("dispatchEvent", e); return Reflect.apply(dispatch, this, arguments); };
  var add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (t) { seen.push({ kind: "addEventListener", type: t }); return Reflect.apply(add, this, arguments); };
})();`,
    body: `
adversarial({ name: "head-listener", run: async (spec, note) => {
  const out = await runCeremony(spec);
  const replies = [];
  for (const p of window.__ports) { p.onmessage = (e) => replies.push(JSON.stringify(e.data).slice(0, 200)); try { p.postMessage({ type: "passkey_request", id: "x", rpId: "github.com" }); } catch {} }
  await sleep(300);
  note("eventsSeenByHeadScript", window.__seen.length);
  note("portsStolen", window.__ports.length);
  note("repliesOnStolenPorts", replies);
  return out;
} });`,
  },
  // The built-ins a bridge may rely on are replaced before the first request, and Object.prototype.then is defined.
  "patched-builtins": {
    head: `(function () {
  var log = { portPost: 0, call: 0, apply: 0, dispatch: 0, then: 0 };
  window.__patched = log;
  var post = MessagePort.prototype.postMessage;
  MessagePort.prototype.postMessage = function () { log.portPost++; return Reflect.apply(post, this, arguments); };
  var call = Function.prototype.call, apply = Function.prototype.apply;
  Function.prototype.call = function () { log.call++; return Reflect.apply(call, this, arguments); };
  Function.prototype.apply = function () { log.apply++; return Reflect.apply(apply, this, arguments); };
  var dispatch = EventTarget.prototype.dispatchEvent;
  EventTarget.prototype.dispatchEvent = function () { log.dispatch++; return Reflect.apply(dispatch, this, arguments); };
  Object.defineProperty(Object.prototype, "then", { configurable: true, get: function () { log.then++; return undefined; }, set: function () {} });
})();`,
    body: `
adversarial({ name: "patched-builtins", run: async (spec, note) => {
  const out = await runCeremony(spec);
  note("patchedCalls", { ...window.__patched });
  return out;
} });`,
  },
  // Members in the options that no browser reads but a bridge might trust: an origin, a top origin, a user verification claim.
  "forged-origin": {
    body: `
adversarial({ name: "forged-origin", run: (spec) => runCeremony({ tamper: "forged-origin", ...spec }) });`,
  },
  // Values far past every limit, and a thousand requests at once.
  "huge-options": {
    body: `
adversarial({ name: "huge-options", run: async (spec, note) => {
  const flood = async () => {
    const outcomes = {};
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 3000);
    const make = (i) => navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32).fill(i % 255), rpId: spec.rpId ?? location.hostname, timeout: 2000, userVerification: "preferred" }, signal: controller.signal });
    const results = await Promise.allSettled(Array.from({ length: 1000 }, (_, i) => make(i)));
    for (const r of results) { const k = r.status === "fulfilled" ? "fulfilled" : r.reason?.name ?? "error"; outcomes[k] = (outcomes[k] ?? 0) + 1; }
    return outcomes;
  };
  note("flood", await flood());
  return runCeremony({ tamper: "huge", ...spec });
} });`,
  },
  // Names made to mislead: GitHub, a right-to-left override, control characters.
  "strange-names": {
    body: `
adversarial({ name: "strange-names", run: (spec) => runCeremony({ tamper: "strange-names", ...spec }) });`,
  },
  // A page that claims to be another site by name only (the real host is an IDN look-alike).
  "lookalike-name": {
    body: `
adversarial({ name: "lookalike-name", run: (spec) => runCeremony({ tamper: "lookalike-name", ...spec }) });`,
  },
  // No click: the page asks at once (the runner loads it with ?auto=1). It says whether the page had user activation.
  "no-gesture": {
    body: `
adversarial({ name: "no-gesture", run: async (spec, note) => {
  note("activationWhenAsking", navigator.userActivation ? { isActive: navigator.userActivation.isActive, hasBeenActive: navigator.userActivation.hasBeenActive } : null);
  return runCeremony(spec);
} });`,
  },
  // Eight requests, each cancelled at once, then the real one: Ferret must never show more than one window, and a calm period follows.
  "window-storm": {
    body: `
adversarial({ name: "window-storm", run: async (spec, note) => {
  const rows = [];
  for (let i = 0; i < 8; i++) {
    const c = new AbortController();
    const t0 = performance.now();
    const p = navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32).fill(i + 1), rpId: spec.rpId ?? location.hostname, timeout: 4000 }, signal: c.signal }).then(() => "fulfilled", (e) => e?.name ?? "error");
    setTimeout(() => c.abort(), 100);
    rows.push({ name: await p, ms: Math.round(performance.now() - t0) });
  }
  note("storm", rows);
  return runCeremony(spec);
} });`,
  },
  // The pointer goes down on the button and the page leaves for another origin before the click arrives.
  "nav-before-click": {
    body: `
document.getElementById("go").addEventListener("pointerdown", () => { location.assign("https://rp-b.test/ceremony.html?left=1"); });
adversarial({ name: "nav-before-click", run: (spec) => runCeremony(spec) });`,
  },
  // "No match" against "cancelled": the error type and the time of both, three times each.
  timing: {
    body: `
adversarial({ name: "timing", run: async (spec, note) => {
  const one = async (abortAfter) => {
    const c = new AbortController();
    const t0 = performance.now();
    if (abortAfter) setTimeout(() => c.abort(), abortAfter);
    const unknown = new Uint8Array(32).fill(0xa5);
    const name = await navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32).fill(3), rpId: spec.rpId ?? location.hostname, timeout: 1500, allowCredentials: [{ type: "public-key", id: unknown }] }, signal: c.signal }).then(() => "fulfilled", (e) => e?.name ?? "error");
    return { name, ms: Math.round(performance.now() - t0) };
  };
  const noMatch = [], aborted = [];
  for (let i = 0; i < 3; i++) { noMatch.push(await one(0)); aborted.push(await one(300)); }
  note("noMatch", noMatch);
  note("abortedByPage", aborted);
  await report(spec.run, { kind: "done", ok: true, steps: [] });
  return { ok: true };
} });`,
  },
  // The page replaces navigator.credentials and CredentialsContainer.prototype.create after load and calls through its own wrapper.
  "overwrite-credentials": {
    body: `
adversarial({ name: "overwrite-credentials", run: async (spec, note) => {
  const real = navigator.credentials;
  const realCreate = CredentialsContainer.prototype.create;
  const realGet = CredentialsContainer.prototype.get;
  let wrapped = 0;
  CredentialsContainer.prototype.create = function (...a) { wrapped++; return realCreate.apply(this, a); };
  CredentialsContainer.prototype.get = function (...a) { wrapped++; return realGet.apply(this, a); };
  const fake = new Proxy(real, { get(t, k) { const v = t[k]; return typeof v === "function" ? v.bind(t) : v; } });
  Object.defineProperty(navigator, "credentials", { value: fake, configurable: true });
  const out = await runCeremony(spec);
  note("callsThroughTheWrapper", wrapped);
  return out;
} });`,
  },
  // The page asks, and while the answer is awaited it reaches for any window it can get at.
  "opener-reach": {
    body: `
adversarial({ name: "opener-reach", run: async (spec, note) => {
  const p = runCeremony(spec);
  await sleep(500);
  const reached = [];
  const probe = (label, w) => { if (!w || w === window) return; try { w.postMessage({ type: "passkey_choose", id: "1", forged: true }, "*"); reached.push({ label, closed: w.closed }); } catch (e) { reached.push({ label, error: e?.name }); } };
  note("hasOpener", !!window.opener);
  note("frames", window.length);
  for (const name of ["ferret-passkey", "ferret", "passkey"]) probe("open:" + name, window.open("", name));
  probe("opener", window.opener);
  note("reached", reached);
  return await Promise.race([p, sleep(4000).then(() => ({ ok: false, timeout: true }))]);
} });`,
  },
  // The signal methods are the browser's own and are left alone.
  signals: {
    body: `
adversarial({ name: "signals", run: async (spec, note) => {
  const names = ["signalUnknownCredential", "signalAllAcceptedCredentials", "signalCurrentUserDetails", "isUserVerifyingPlatformAuthenticatorAvailable", "isConditionalMediationAvailable", "getClientCapabilities", "parseCreationOptionsFromJSON", "parseRequestOptionsFromJSON"];
  const info = {};
  for (const n of names) {
    const f = PublicKeyCredential[n];
    info[n] = f === undefined ? "absent" : /\\[native code\\]/.test(Function.prototype.toString.call(f)) ? "native" : "replaced";
  }
  note("methods", info);
  for (const n of ["signalUnknownCredential", "signalAllAcceptedCredentials", "signalCurrentUserDetails"]) {
    if (typeof PublicKeyCredential[n] !== "function") continue;
    try { await PublicKeyCredential[n]({ rpId: spec.rpId ?? location.hostname, credentialId: "AAAA", allAcceptedCredentialIds: [], userId: "AAAA", name: "x", displayName: "x" }); note(n, "resolved"); } catch (e) { note(n, e?.name ?? "error"); }
  }
  await report(spec.run, { kind: "done", ok: true, steps: [] });
  return { ok: true };
} });`,
  },
};

for (const [name, p] of Object.entries(pages)) writeFileSync(join(here, "pages", "adversarial", `${name}.html`), shell({ name, ...p }));
console.log(Object.keys(pages).join(" "));
