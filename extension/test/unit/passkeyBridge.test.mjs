// The passkey scripts in a page (the `passkeys` feature, design document § 9.2 and § 10.8): the script of the page's own
// world and the bridge of the isolated world, as the build joins them, run in two worlds of a fake page (passkeyWorld.mjs),
// and the wire form of the options and the answer. The same rules are checked in real Firefox by
// test/firefox/74-passkey-bridge.spec.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";
import { CONTENT_TYPES, PASSKEY_LIMITS, PUSH_TYPES } from "../../src/shared/protocol.mjs";
import { walk } from "../../src/shared/schema.mjs";
import { fromB64u, optionsToWire, responseFromWire, responseToWire, toB64u } from "../../src/shared/webauthnWire.mjs";
import { PASSKEY_BRIDGE_MAX_BYTES, PASSKEY_MAIN_MAX_BYTES } from "../../scripts/lib/classic.mjs";
import { createPasskeyPage, passkeyScripts } from "./passkeyWorld.mjs";

/** A create call of the page, as page code (the result lands in `globalThis.out`). */
const CREATE = `(() => {
  globalThis.out = { done: false };
  const options = { publicKey: {
    challenge: new Uint8Array(32).fill(7),
    rp: { name: "RP", id: "rp.example" },
    user: { id: new Uint8Array([1, 2, 3]), name: "alice", displayName: "Alice" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    extensions: { credProps: true, prf: { eval: { first: new Uint8Array(32) } } },
  } };
  globalThis.lastOptions = options;
  navigator.credentials.create(options).then((v) => { out.done = true; out.value = v; }, (e) => { out.done = true; out.error = e.name; out.reason = e; });
})()`;
const GET = (/** @type {string} */ extra = "") => `(() => {
  globalThis.out = { done: false };
  const options = { publicKey: { challenge: new Uint8Array(32).fill(9), rpId: "rp.example", userVerification: "required" }${extra} };
  globalThis.lastOptions = options;
  navigator.credentials.get(options).then((v) => { out.done = true; out.value = v; }, (e) => { out.done = true; out.error = e.name; out.reason = e; });
})()`;

/** The last request the bridge sent. @param {ReturnType<typeof createPasskeyPage>} page */
const lastRequest = (page) => [...page.sent].reverse().find((m) => m.type === "passkey_request");

test("both_scripts_join_and_the_main_script_stays_within_its_budget", () => {
  const { main, bridge } = passkeyScripts();
  assert.ok(Buffer.byteLength(main) <= PASSKEY_MAIN_MAX_BYTES, `${Buffer.byteLength(main)} bytes`);
  // The bridge runs in every https frame: it has a budget too (the build refuses a bigger one).
  assert.ok(Buffer.byteLength(bridge) <= PASSKEY_BRIDGE_MAX_BYTES, `${Buffer.byteLength(bridge)} bytes`);
  // The page's script is built from its own file only: no protocol, no shared module.
  assert.match(main, /^\/\/ Files: content\/passkeyResponse\.mjs, content\/passkey\.main\.entry\.mjs$/m);
  assert.match(bridge, /^\/\/ Files: .*shared\/webauthnWire\.mjs.*content\/passkey\.bridge\.entry\.mjs$/m);
});

test("the_handshake_works_in_either_order_and_each_listener_takes_one", async () => {
  for (const order of /** @type {const} */ (["main-first", "bridge-first"])) {
    const page = createPasskeyPage({ order });
    // Both listeners are gone after the handshake: a later event of the page finds no one.
    assert.equal(page.documentListeners("ferret.passkeys.handshake"), 0, order);
    page.page(CREATE);
    await page.flush();
    const request = lastRequest(page);
    assert.ok(request, `${order}: the request reached the bridge`);
    assert.equal(request.body.kind, "create");
    // A page that sends a handshake afterwards gets nothing taken.
    const taken = page.page(`(() => { const c = new MessageChannel(); return !document.dispatchEvent(new MessageEvent("ferret.passkeys.handshake", { data: "bridge", ports: [c.port2], cancelable: true })); })()`);
    assert.equal(taken, false, `${order}: a late handshake of the page is not taken`);
  }
});

test("a_request_carries_the_options_activation_and_policy_and_no_origin", async () => {
  const page = createPasskeyPage();
  page.page(CREATE);
  await page.flush();
  const { body } = /** @type {any} */ (lastRequest(page));
  assert.match(body.request_id, /^[0-9a-f]{32}$/);
  assert.equal(body.mediation, "optional");
  assert.equal(body.activation, true);
  assert.equal(body.policy, null, "Firefox has no document.featurePolicy");
  assert.deepEqual(Object.keys(body).sort(), ["activation", "create", "kind", "mediation", "policy", "request_id"]);
  assert.equal(body.create.challenge, toB64u(new Uint8Array(32).fill(7)));
  assert.deepEqual(body.create.rp, { name: "RP", id: "rp.example" });
  assert.deepEqual(body.create.user, { id: "AQID", name: "alice", display_name: "Alice" });
  assert.deepEqual(body.create.pub_key_cred_params, [{ type: "public-key", alg: -7 }]);
  assert.deepEqual(body.create.authenticator_selection, { resident: "required", user_verification: "preferred" });
  assert.deepEqual(body.create.extensions, { cred_props: true, prf: { eval: { first: toB64u(new Uint8Array(32)) } } });
  // The activation is read in the bridge's world.
  page.setActivation(false);
  page.page(GET());
  await page.flush();
  assert.equal(/** @type {any} */ (lastRequest(page)).body.activation, false);
});

test("passkey_messages_have_no_origin_field", () => {
  const forbidden = /origin|top|frame|url|href|host|document|tab|referr|sender/i;
  for (const [table, types] of /** @type {const} */ ([[CONTENT_TYPES, ["passkey_request", "passkey_abort", "passkey_foreign", "passkey_ping"]], [PUSH_TYPES, ["passkey_result", "passkey_handover", "passkey_error"]]])) {
    for (const type of types) {
      const def = /** @type {any} */ (table)[type];
      assert.ok(def, type);
      /** @type {string[]} */
      const paths = [];
      walk(def.request, (_node, path) => paths.push(path));
      const bad = paths.filter((p) => p.split(".").slice(1).some((key) => forbidden.test(key)));
      assert.deepEqual(bad, [], `${type} has no key for an origin, a top, a frame or an address`);
    }
  }
  // The wire form refuses a key it does not know, so a page cannot add one (the schema denies unknown fields).
  assert.equal(optionsToWire("get", { challenge: new Uint8Array(16).buffer, origin: "https://evil.example", allowCredentials: [], hints: [] })?.origin, undefined);
});

test("calls_that_are_not_ours_go_to_the_original_untouched", async () => {
  const page = createPasskeyPage();
  /** @type {Array<[string, string]>} */
  const cases = [
    ["password", "navigator.credentials.get({ password: true })"],
    ["federated", "navigator.credentials.get({ federated: { providers: ['https://idp.example'] } })"],
    ["identity", "navigator.credentials.get({ identity: { providers: [] } })"],
    ["no options", "navigator.credentials.get()"],
    ["null options", "navigator.credentials.create(null)"],
    ["silent", "navigator.credentials.get({ mediation: 'silent', publicKey: { challenge: new Uint8Array(16) } })"],
    ["unknown mediation", "navigator.credentials.get({ mediation: 'sometimes', publicKey: { challenge: new Uint8Array(16) } })"],
    ["conditional create", "navigator.credentials.create({ mediation: 'conditional', publicKey: { challenge: new Uint8Array(16), rp: { name: 'x' }, user: { id: new Uint8Array(1), name: 'a', displayName: 'a' }, pubKeyCredParams: [] } })"],
    ["another this", "CredentialsContainer.prototype.get.call({}, { publicKey: { challenge: new Uint8Array(16) } })"],
    ["aborted signal", "(() => { const c = new AbortController(); c.abort(); return navigator.credentials.get({ signal: c.signal, publicKey: { challenge: new Uint8Array(16) } }); })()"],
    ["salt as text", "navigator.credentials.get({ publicKey: { challenge: new Uint8Array(16), extensions: { prf: { eval: { first: 'salt' } } } } })"],
    ["challenge as text", "navigator.credentials.get({ publicKey: { challenge: 'abc' } })"],
    ["throwing getter", "navigator.credentials.get({ get publicKey() { throw new Error('page'); } })"],
    ["no rp name", "navigator.credentials.create({ publicKey: { challenge: new Uint8Array(16), rp: {}, user: { id: new Uint8Array(1), name: 'a', displayName: 'a' }, pubKeyCredParams: [] } })"],
    ["shared memory", "navigator.credentials.get({ publicKey: { challenge: new Uint8Array(new SharedArrayBuffer(16)) } })"],
    ["a list too long to copy", "navigator.credentials.get({ publicKey: { challenge: new Uint8Array(16), allowCredentials: Array.from({ length: 201 }, () => ({ type: 'public-key', id: new Uint8Array(16) })) } })"],
  ];
  for (const [name, code] of cases) {
    page.nativeCalls.length = 0;
    page.sent.length = 0;
    const result = page.page(`(() => { globalThis.args = null; const p = ${code}; return p; })()`);
    await page.flush();
    assert.equal(page.nativeCalls.length, 1, `${name}: the browser's own function was called once`);
    assert.deepEqual(page.sent.filter((m) => m.type === "passkey_request"), [], `${name}: nothing went to the background`);
    assert.equal(await result, "browser", `${name}: the page got the browser's answer`);
  }
  // Untouched: the very same options object and the page's own container reach the browser.
  page.nativeCalls.length = 0;
  page.page("globalThis.opts = { password: true }; navigator.credentials.get(globalThis.opts)");
  assert.equal(page.nativeCalls[0].args[0], page.page("globalThis.opts"));
  assert.equal(page.nativeCalls[0].self, page.page("navigator.credentials"));
  // A request Ferret looks at and hands back reaches the browser with the page's own arguments too.
  page.nativeCalls.length = 0;
  page.page(GET());
  await page.flush();
  const request = /** @type {any} */ (lastRequest(page));
  assert.equal(page.nativeCalls.length, 0, "nothing yet: the background decides first");
  await page.push("passkey_handover", { request_id: request.body.request_id, once: false });
  assert.equal(page.nativeCalls.length, 1);
  assert.equal(page.nativeCalls[0].args[0], page.page("globalThis.lastOptions"), "the page's own options object");
  assert.equal(page.page("out.value"), "browser");
});

test("a_lone_script_or_an_unreachable_extension_leaves_the_call_to_the_browser", async () => {
  // The page's script without its partner (a bridge that did not run): every call goes to the browser.
  const lone = createPasskeyPage({ bridgeScript: false });
  lone.page(GET());
  await lone.flush();
  assert.equal(lone.nativeCalls.length, 1);
  // The extension cannot be reached (reloaded, updated): the bridge hands the call back.
  const page = createPasskeyPage();
  page.setSendFails(true);
  page.page(GET());
  await page.flush();
  assert.equal(page.nativeCalls.length, 1);
  assert.equal(page.page("out.value"), "browser");
  // The background does not take the request (a sender it refuses, such as a sandboxed frame): the browser answers at once,
  // and a late push for the id is dropped.
  const refused = createPasskeyPage();
  refused.setTakes(false);
  refused.page(GET());
  await refused.flush();
  assert.equal(refused.nativeCalls.length, 1);
  assert.equal(refused.page("out.value"), "browser");
  const id = /** @type {any} */ (lastRequest(refused)).body.request_id;
  await refused.push("passkey_error", { request_id: id, name: "NotAllowedError" });
  assert.equal(refused.page("out.value"), "browser");
});

test("tampered_intrinsics_after_install_fail_closed_to_the_original", async () => {
  const page = createPasskeyPage();
  // The page changes everything it can reach after the scripts installed, and records whatever it gets hold of.
  page.page(`(() => {
    globalThis.seen = new Set();
    const note = (what, value) => { seen.add(what); if (value && typeof value === "object" && typeof value.postMessage === "function") globalThis.stolenPort = value; };
    const post = MessagePort.prototype.postMessage;
    MessagePort.prototype.postMessage = function (...a) { note("postMessage", this); return post.apply(this, a); };
    const add = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (...a) { note("addEventListener", this); return add.apply(this, a); };
    const dispatch = EventTarget.prototype.dispatchEvent;
    EventTarget.prototype.dispatchEvent = function (...a) { note("dispatchEvent", this); return dispatch.apply(this, a); };
    const call = Function.prototype.call, apply = Function.prototype.apply;
    Function.prototype.call = function (...a) { note("call", a[0]); return Reflect.apply(this, a[0], a.slice(1)); };
    Function.prototype.apply = function (self, a) { note("apply", self); return Reflect.apply(this, self, a ?? []); };
    Object.defineProperty(Object.prototype, "then", { get() { note("then", this); return undefined; }, configurable: true });
    Object.defineProperty(Array.prototype, "0", { set(v) { note("index-setter", v); }, configurable: true });
    Object.defineProperty(MessageEvent.prototype, "data", { get() { note("data", this); return undefined; }, configurable: true });
    Array.prototype.indexOf = function () { note("indexOf", this); return 0; };
    JSON.stringify = () => { note("stringify"); return "{}"; };
    RegExp.prototype.test = function () { note("test", this); return true; };
    Object.keys = (o) => { note("keys", o); return []; };
    const RA = Reflect.apply;
    Promise.prototype.then = new Proxy(Promise.prototype.then, { apply(t, self, a) { note("promise-then", self); return RA(t, self, a); } });
    const remove = EventTarget.prototype.removeEventListener;
    EventTarget.prototype.removeEventListener = function (...a) { note("removeEventListener", this); return RA(remove, this, a); };
    const start = MessagePort.prototype.start;
    MessagePort.prototype.start = function (...a) { note("start", this); return RA(start, this, a); };
    for (const name of ["aborted", "reason"]) Object.defineProperty(AbortSignal.prototype, name, { get() { note("signal-" + name, this); return false; }, configurable: true });
    globalThis.DOMException = function () { note("DOMException"); };
    globalThis.setTimeout = () => { note("setTimeout"); return 0; };
    globalThis.clearTimeout = () => { note("clearTimeout"); };
    Array.isArray = () => { note("isArray"); return false; };
    Object.hasOwn = () => { note("hasOwn"); return false; };
    // Last: from here on a descriptor the page writes without a value of its own inherits this one.
    Object.defineProperty(Object.prototype, "value", { set(v) { note("value-setter", v); }, get() { return undefined; }, configurable: true });
    const ODP = Object.defineProperty;
    Object.defineProperty = (o, k, d) => { note("defineProperty", o); return ODP(o, k, d); };
    Reflect.apply = (f, self, a) => { note("reflect-apply", self); return RA(f, self, a); };
  })()`);
  page.page(GET());
  await page.flush();
  const request = /** @type {any} */ (lastRequest(page));
  assert.ok(request, "the request still reached the bridge");
  assert.equal(request.body.get.challenge, toB64u(new Uint8Array(32).fill(9)), "and it carried the page's own options");
  await page.push("passkey_error", { request_id: request.body.request_id, name: "NotAllowedError" });
  assert.equal(page.page("out.error"), "NotAllowedError", "the answer came back through the port");
  assert.equal(page.page("globalThis.stolenPort === undefined"), true, "no port reached the page");
  const seen = /** @type {string[]} */ (JSON.parse(JSON.stringify([...page.page("seen")])));
  // The page's own calls of its own functions are its business; the script never called one of them.
  for (const what of ["postMessage", "addEventListener", "dispatchEvent", "call", "apply", "then", "value-setter", "index-setter", "data", "indexOf", "stringify", "test", "keys",
    "removeEventListener", "start", "signal-aborted", "signal-reason", "DOMException", "setTimeout", "clearTimeout", "isArray", "hasOwn", "defineProperty", "reflect-apply"]) {
    assert.equal(seen.includes(what), false, `the script never called the page's ${what}`);
  }
});

test("an_object_prototype_then_does_not_reach_the_scripts_own_flow", async () => {
  const page = createPasskeyPage();
  page.page(`Object.defineProperty(Object.prototype, "then", { get() { globalThis.thenRead = (globalThis.thenRead ?? 0) + 1; return undefined; }, configurable: true })`);
  page.page(GET());
  await page.flush();
  const request = /** @type {any} */ (lastRequest(page));
  await page.push("passkey_handover", { request_id: request.body.request_id, once: false });
  assert.equal(page.page("out.value"), "browser");
  // The page's own `.then` on its own promise reads `then` of nothing but promises; the script's answers are never resolved as objects.
  assert.equal(page.page("globalThis.thenRead ?? 0"), 0);
});

test("the_bridge_drops_answers_for_ids_it_did_not_issue", async () => {
  const page = createPasskeyPage();
  page.page(GET());
  await page.flush();
  const request = /** @type {any} */ (lastRequest(page));
  // Another id, a well-formed one: nothing happens.
  await page.push("passkey_handover", { request_id: "0".repeat(32), once: false });
  await page.push("passkey_error", { request_id: "f".repeat(32), name: "AbortError" });
  assert.equal(page.page("out.done"), false);
  assert.equal(page.nativeCalls.length, 0);
  // A push from something that is not the extension: dropped.
  await page.push("passkey_handover", { request_id: request.body.request_id, once: false }, { id: "someone-else" });
  assert.equal(page.page("out.done"), false);
  // A malformed one: dropped.
  await page.push("passkey_handover", { request_id: request.body.request_id, once: "yes" });
  assert.equal(page.page("out.done"), false);
  // Its own id: once.
  await page.push("passkey_error", { request_id: request.body.request_id, name: "AbortError" });
  assert.equal(page.page("out.error"), "AbortError");
  await page.push("passkey_handover", { request_id: request.body.request_id, once: false });
  assert.equal(page.nativeCalls.length, 0, "a second answer to the same id is dropped");
  // An answer of the other kind's shape is not passed on as a credential.
  page.page(GET());
  await page.flush();
  const second = /** @type {any} */ (lastRequest(page));
  const createShaped = responseToWire("create", {
    id: new Uint8Array(16), client_data_json: new Uint8Array(8), authenticator_data: new Uint8Array(37), authenticator_attachment: "platform",
    attestation_object: new Uint8Array(8), spki: new Uint8Array(8), public_key_algorithm: -7, transports: ["hybrid", "internal"],
  });
  await page.push("passkey_result", { request_id: second.body.request_id, response: createShaped });
  assert.equal(page.page("out.error"), "NotAllowedError");
});

test("answers_end_the_call_as_the_browser_would", async () => {
  const page = createPasskeyPage();
  for (const [name, expected] of [["NotAllowedError", "NotAllowedError"], ["InvalidStateError", "InvalidStateError"], ["SecurityError", "SecurityError"], ["TypeError", "TypeError"], ["AbortError", "AbortError"]]) {
    page.page(GET());
    await page.flush();
    await page.push("passkey_error", { request_id: /** @type {any} */ (lastRequest(page)).body.request_id, name });
    assert.equal(page.page("out.error"), expected, name);
    assert.equal(page.page(`out.reason instanceof ${expected === "TypeError" ? "TypeError" : "DOMException"}`), true, name);
  }
  // `once`: this call ends (the user clicks again) and the browser is not called now.
  page.page(GET());
  await page.flush();
  await page.push("passkey_handover", { request_id: /** @type {any} */ (lastRequest(page)).body.request_id, once: true });
  assert.equal(page.page("out.error"), "NotAllowedError");
  assert.equal(page.nativeCalls.length, 0);
  // A result is the credential (passkeyResponse.test.mjs looks at it); the browser is not called for it.
  page.page(GET());
  await page.flush();
  const response = responseToWire("get", {
    id: new Uint8Array(16), client_data_json: new Uint8Array(8), authenticator_data: new Uint8Array(37), authenticator_attachment: "platform",
    signature: new Uint8Array(70), user_handle: new Uint8Array(3),
  });
  await page.push("passkey_result", { request_id: /** @type {any} */ (lastRequest(page)).body.request_id, response });
  assert.equal(page.page("out.error"), undefined);
  assert.equal(page.page("out.value instanceof PublicKeyCredential"), true);
  assert.equal(page.nativeCalls.length, 0);
});

test("the_page_abort_and_a_modal_request_end_a_waiting_one", async () => {
  const page = createPasskeyPage();
  page.page(`(() => {
    globalThis.c = new AbortController();
    globalThis.res = {};
    navigator.credentials.get({ signal: c.signal, publicKey: { challenge: new Uint8Array(16) } }).catch((e) => { res.aborted = e; });
  })()`);
  await page.flush();
  const first = /** @type {any} */ (lastRequest(page));
  page.page("c.abort(new Error('mine'))");
  await page.flush();
  assert.equal(page.page("res.aborted.message"), "mine", "rejected with the signal's own reason");
  assert.deepEqual(page.sent.filter((m) => m.type === "passkey_abort").map((m) => m.body.request_id), [first.body.request_id]);
  // A conditional request waits; a modal one replaces it, with AbortError, as Firefox does.
  page.page(`(() => {
    globalThis.cond = {};
    navigator.credentials.get({ mediation: "conditional", publicKey: { challenge: new Uint8Array(16) } }).catch((e) => { cond.error = e.name; });
  })()`);
  await page.flush();
  const conditional = /** @type {any} */ (lastRequest(page));
  assert.equal(conditional.body.mediation, "conditional");
  page.page(GET());
  await page.flush();
  assert.equal(page.page("cond.error"), "AbortError");
  assert.ok(page.sent.some((m) => m.type === "passkey_abort" && m.body.request_id === conditional.body.request_id));
  // An answer to the replaced one is dropped; the modal one still waits.
  await page.push("passkey_handover", { request_id: conditional.body.request_id, once: false });
  assert.equal(page.page("out.done"), false);
});

test("a_dead_bridge_fails_closed_to_the_original", async () => {
  // The extension went away after the handshake (an update, a disable, a reload): nothing says "taken", so the browser gets
  // the call after TAKEN_MS (3 s), with the page's own options.
  const page = createPasskeyPage();
  page.killBridge();
  page.page(GET());
  await page.flush();
  assert.equal(page.nativeCalls.length, 0);
  await page.advance(2_900);
  assert.equal(page.page("out.done"), false, "it waits for the bridge a moment");
  await page.advance(200);
  assert.equal(page.nativeCalls.length, 1);
  assert.equal(page.nativeCalls[0].args[0], page.page("globalThis.lastOptions"));
  assert.equal(page.page("out.value"), "browser");

  // Taken, then the extension goes: a modal request ends as one the user left after ALIVE_MS (50 s) without "alive".
  const taken = createPasskeyPage();
  taken.page(GET());
  await taken.flush();
  await taken.advance(10_000);
  assert.equal(taken.page("out.done"), false, "taken: no handover after 3 s");
  // "alive" with every ping keeps it waiting (a Ferret window can stay open for minutes).
  await taken.advance(30_000);
  await taken.tick();
  await taken.advance(40_000);
  assert.equal(taken.page("out.done"), false, "the bridge is alive");
  taken.killBridge();
  await taken.advance(9_000);
  assert.equal(taken.page("out.done"), false);
  await taken.advance(2_000);
  assert.equal(taken.page("out.error"), "NotAllowedError");
  assert.equal(taken.nativeCalls.length, 0);

  // A conditional request in the same case goes to the browser, whose own list then works as before.
  const conditional = createPasskeyPage();
  conditional.page(GET(', mediation: "conditional"'));
  await conditional.flush();
  conditional.killBridge();
  await conditional.advance(50_000);
  assert.equal(conditional.nativeCalls.length, 1);
  assert.equal(conditional.page("out.value"), "browser");

  // A background that is slow to answer (an event page starting from cold): the bridge said "taken" when it had the request,
  // so the call waits for Ferret and does not slip to the browser after 3 s.
  const slow = createPasskeyPage();
  slow.setHangs(true);
  slow.page(GET());
  await slow.flush();
  await slow.advance(10_000);
  assert.equal(slow.page("out.done"), false);
  assert.equal(slow.nativeCalls.length, 0);
  // A request the background did not take still goes to the browser at once, after the "taken".
  const refused = createPasskeyPage();
  refused.setTakes(false);
  refused.page(GET());
  await refused.flush();
  assert.equal(refused.page("out.value"), "browser");
});

test("a_signal_fired_while_the_options_are_copied_goes_to_the_original", async () => {
  const page = createPasskeyPage();
  page.page(`(() => {
    const c = new AbortController();
    const publicKey = { get challenge() { c.abort(new Error("during the copy")); return new Uint8Array(16); } };
    globalThis.p = navigator.credentials.get({ signal: c.signal, publicKey });
  })()`);
  await page.flush();
  assert.equal(page.nativeCalls.length, 1, "the browser gets it and rejects with the signal's reason");
  assert.deepEqual(page.sent.filter((m) => m.type === "passkey_request"), []);
});

test("no_listener_waits_without_its_partner_in_opaque_or_insecure_frames", async () => {
  // A sandboxed frame (opaque origin): neither script starts; the browser's own functions stay.
  const sandboxed = createPasskeyPage({ origin: "null" });
  assert.equal(sandboxed.page("/\\[native code\\]/.test(Function.prototype.toString.call(CredentialsContainer.prototype.get))"), true);
  assert.equal(sandboxed.documentListeners("ferret.passkeys.handshake"), 0);
  // An https frame under an http parent (not a secure context): no bridge, so no channel, and every call goes to the browser.
  const insecure = createPasskeyPage({ secure: false });
  insecure.page(GET());
  await insecure.flush();
  assert.equal(insecure.nativeCalls.length, 1);
  assert.deepEqual(insecure.sent, []);
});

test("a_flood_beyond_the_waiting_limit_goes_to_the_browser", async () => {
  const page = createPasskeyPage();
  page.page(`globalThis.flood = []; for (let i = 0; i < 70; i += 1) navigator.credentials.get({ publicKey: { challenge: new Uint8Array(16) } }).then((v) => flood.push(v), (e) => flood.push(e.name));`);
  await page.flush();
  assert.equal(page.sent.filter((m) => m.type === "passkey_request").length, 64, "64 wait for the background");
  assert.equal(page.nativeCalls.length, 6, "the rest go to the browser, untouched");
});

test("the_bridge_pings_only_while_a_request_waits", async () => {
  const page = createPasskeyPage();
  assert.deepEqual(page.intervals(), [], "no timer at rest");
  page.page(GET());
  await page.flush();
  assert.deepEqual(page.intervals(), [{ every: 20_000 }]);
  const id = /** @type {any} */ (lastRequest(page)).body.request_id;
  await page.tick();
  assert.deepEqual(page.sent.filter((m) => m.type === "passkey_ping").map((m) => m.body), [{ request_ids: [id] }]);
  await page.push("passkey_error", { request_id: id, name: "NotAllowedError" });
  assert.deepEqual(page.intervals(), [], "the timer goes with the last request");
});

test("a_foreign_override_is_detected_and_reported", async () => {
  // Another extension's create and get were there before the script.
  const page = createPasskeyPage({ foreign: true });
  await page.flush();
  assert.equal(page.sent.filter((m) => m.type === "passkey_foreign").length, 1);
  // The browser choice goes to what was there first.
  page.page("navigator.credentials.get({ password: true })");
  assert.equal(page.nativeCalls.length, 1, "through the other provider to the browser");
  // A page whose create and get are the browser's: nothing at install; Ferret's replaced later is told at the next call, once.
  const clean = createPasskeyPage();
  await clean.flush();
  assert.equal(clean.sent.filter((m) => m.type === "passkey_foreign").length, 0);
  clean.page(`(() => { const mine = CredentialsContainer.prototype.get; Object.defineProperty(CredentialsContainer.prototype, "get", { value: function get(o) { return mine.call(this, o); }, writable: true, configurable: true, enumerable: true }); })()`);
  clean.page(GET());
  clean.page(GET());
  await clean.flush();
  assert.equal(clean.sent.filter((m) => m.type === "passkey_foreign").length, 1);
});

test("the_main_script_has_no_secret_no_network_and_no_dom_change", () => {
  const { main } = passkeyScripts();
  const code = main.replace(/^\/\/.*$/gm, "");
  for (const [what, pattern] of /** @type {Array<[string, RegExp]>} */ ([
    ["network", /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|RTCPeerConnection|Worker)\b/],
    ["the extension's API", /\b(?:browser|chrome)\s*\./],
    ["a change of the DOM", /\b(?:createElement|appendChild|append|prepend|insertBefore|innerHTML|outerHTML|insertAdjacent\w*|setAttribute|removeAttribute|classList|dataset|textContent|write|writeln)\b/],
    ["storage", /\b(?:localStorage|sessionStorage|indexedDB|cookie|caches)\b/],
    ["window.postMessage", /\b(?:window|self|top|parent|opener|globalThis|frames)\s*\.\s*postMessage\b/],
    ["crypto", /\b(?:crypto|subtle|importKey|sign)\b/],
    ["a global", /\b(?:globalThis|window|self)\s*\.\s*[A-Za-z_$][\w$]*\s*=(?!=)/],
    ["dynamic code", /\beval\s*\(|\bFunction\s*\(|\bsetInterval\b/],
  ])) {
    assert.doesNotMatch(code, pattern, `the page's script has no ${what}`);
  }
  // A timer only through the binding kept at install, and only with a function (never a string of code).
  assert.deepEqual([...code.matchAll(/\b(?:setTimeout|clearTimeout)\b/g)].map((m) => m[0]), ["setTimeout", "clearTimeout"]);
  assert.match(code, /const setTimer = W\.setTimeout;/);
  assert.match(code, /const clearTimer = W\.clearTimeout;/);
  assert.deepEqual([...code.matchAll(/R\(setTimer, W, \[([^\]]*)\]\)/g)].map((m) => m[1]), ["fn, ms"]);
  // At run time: no new global and no change in the document.
  const page = createPasskeyPage({ mainScript: false, bridgeScript: false });
  const before = page.page("Object.getOwnPropertyNames(globalThis).sort().join(',')");
  const withScripts = createPasskeyPage();
  assert.equal(withScripts.page("Object.getOwnPropertyNames(globalThis).sort().join(',')"), before);
});

test("no_window_post_message_is_used", async () => {
  const { main, bridge } = passkeyScripts();
  for (const [name, code] of [["main", main], ["bridge", bridge]]) {
    assert.doesNotMatch(code.replace(/^\/\/.*$/gm, ""), /\b(?:window|self|top|parent|opener|globalThis|frames|location)\s*\.\s*postMessage\b|\bpostMessage\s*\(\s*[^)]*,\s*["'`*]/, name);
  }
  // At run time: a page that wraps window.postMessage and listens for messages sees none.
  const page = createPasskeyPage();
  page.page(`globalThis.messages = 0; globalThis.postMessage = () => { globalThis.messages += 1; };`);
  page.page(GET());
  await page.flush();
  await page.push("passkey_handover", { request_id: /** @type {any} */ (lastRequest(page)).body.request_id, once: false });
  assert.equal(page.page("globalThis.messages"), 0);
});

test("the_wire_form_keeps_the_limits", () => {
  const challenge = (/** @type {number} */ n) => new Uint8Array(n).buffer;
  const get = (/** @type {Record<string, unknown>} */ more = {}) => ({ challenge: challenge(32), allowCredentials: [], hints: [], ...more });
  assert.ok(optionsToWire("get", get()));
  assert.ok(optionsToWire("get", get({ challenge: challenge(PASSKEY_LIMITS.challenge) })));
  assert.equal(optionsToWire("get", get({ challenge: challenge(PASSKEY_LIMITS.challenge + 1) })), null);
  assert.equal(optionsToWire("get", get({ challenge: challenge(0) })), null);
  const ids = (/** @type {number} */ n, /** @type {number} */ size) => Array.from({ length: n }, () => ({ type: "public-key", id: challenge(size) }));
  assert.ok(optionsToWire("get", get({ allowCredentials: ids(3, PASSKEY_LIMITS.credentialId) })));
  assert.equal(optionsToWire("get", get({ allowCredentials: ids(1, PASSKEY_LIMITS.credentialId + 1) })), null);
  assert.equal(optionsToWire("get", get({ allowCredentials: ids(PASSKEY_LIMITS.list + 1, 16) })), null);
  assert.equal(optionsToWire("get", get({ rpId: "x".repeat(PASSKEY_LIMITS.text + 1) })), null);
  assert.equal(optionsToWire("get", get({ rpId: "é".repeat(600) })), null, "texts are measured in UTF-8 bytes");
  assert.equal(optionsToWire("get", get({ challenge: "text" })), null);
  assert.equal(optionsToWire("get", get({ extensions: { prf: { eval: { first: "salt" } } } })), null);
  const create = {
    challenge: challenge(32), rp: { name: "RP" }, user: { id: challenge(0), name: "a", displayName: "A" }, pubKeyCredParams: [], excludeCredentials: [], hints: [], extensions: {},
  };
  // user.id of 0 or 65 bytes is carried: the background gives the browser's TypeError.
  assert.deepEqual(/** @type {any} */ (optionsToWire("create", create))?.user.id, "");
  assert.ok(optionsToWire("create", { ...create, user: { ...create.user, id: challenge(65) } }));
  assert.equal(optionsToWire("create", { ...create, pubKeyCredParams: [{ type: "public-key", alg: 1.5 }] }), null);
  // Bytes round-trip, and there is one text for each byte string.
  for (const n of [0, 1, 2, 3, 31, 32, 33, 1024]) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
    assert.deepEqual(fromB64u(toB64u(bytes)), bytes);
  }
  assert.throws(() => fromB64u("AB"));
  assert.throws(() => fromB64u("A"));
  assert.throws(() => fromB64u("AQ=="));
  assert.throws(() => fromB64u("A+Q"));
  // The answer: the fields of its own kind, as ArrayBuffers.
  const wire = responseToWire("get", {
    id: new Uint8Array([1, 2]), client_data_json: new Uint8Array([3]), authenticator_data: new Uint8Array(37), authenticator_attachment: "platform",
    signature: new Uint8Array([4]), user_handle: null, client_extension_results: { prf: { results: { first: new Uint8Array(32) } } },
  });
  const back = /** @type {any} */ (responseFromWire("get", wire));
  assert.deepEqual([...new Uint8Array(back.id)], [1, 2]);
  assert.equal(back.userHandle, null);
  assert.equal(new Uint8Array(back.clientExtensionResults.prf.results.first).length, 32);
  assert.equal(responseFromWire("create", wire), null, "not an answer to a create");
});
