// The answer objects and the static methods of the passkey script in the page's own world (the `passkeys` feature,
// design document § 9.5 and § 10.8): what a page gets when Ferret answers, compared with the objects the browser has (the
// fake browser of passkeyWorld.mjs has them as Firefox does), and the static methods of PublicKeyCredential. The same objects
// are compared with the real ones, from a virtual authenticator, by test/firefox/78-passkey-response.spec.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";
import { responseToWire, toB64u } from "../../src/shared/webauthnWire.mjs";
import { createPasskeyPage } from "./passkeyWorld.mjs";

const CREATE = `(() => {
  globalThis.out = { done: false };
  navigator.credentials.create({ publicKey: {
    challenge: new Uint8Array(32).fill(7), rp: { name: "RP", id: "rp.example" },
    user: { id: new Uint8Array([1, 2, 3]), name: "alice", displayName: "Alice" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], extensions: { credProps: true },
  } }).then((v) => { out.done = true; out.value = v; }, (e) => { out.done = true; out.error = e.name; });
})()`;
const GET = `(() => {
  globalThis.out = { done: false };
  navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32).fill(9), rpId: "rp.example" } })
    .then((v) => { out.done = true; out.value = v; }, (e) => { out.done = true; out.error = e.name; });
})()`;

const bytes = (/** @type {number} */ n, /** @type {number} */ v) => new Uint8Array(n).fill(v);
const CREATE_FIELDS = {
  id: bytes(16, 1), client_data_json: bytes(40, 2), authenticator_data: bytes(37, 3), authenticator_attachment: "platform", attestation_object: bytes(60, 4),
  spki: bytes(91, 5), public_key_algorithm: -7, transports: ["hybrid", "internal"],
  client_extension_results: { cred_props: { rk: true }, prf: { enabled: true } },
};
const GET_FIELDS = {
  id: bytes(16, 1), client_data_json: bytes(40, 2), authenticator_data: bytes(37, 3), authenticator_attachment: "platform", signature: bytes(70, 6), user_handle: bytes(3, 7),
  client_extension_results: { prf: { results: { first: bytes(32, 8), second: bytes(32, 9) } } },
};
/** The same fields as page code, with WebAuthn names and ArrayBuffers: what the bridge hands to the page's script. */
const PAGE_FIELDS = `
const fill = (n, v) => new Uint8Array(n).fill(v).buffer;
globalThis.createFields = { id: fill(16, 1), clientDataJSON: fill(40, 2), authenticatorData: fill(37, 3), authenticatorAttachment: "platform", attestationObject: fill(60, 4),
  publicKey: fill(91, 5), publicKeyAlgorithm: -7, transports: ["hybrid", "internal"], clientExtensionResults: { credProps: { rk: true }, prf: { enabled: true } } };
globalThis.getFields = { id: fill(16, 1), clientDataJSON: fill(40, 2), authenticatorData: fill(37, 3), authenticatorAttachment: "platform", signature: fill(70, 6), userHandle: fill(3, 7),
  clientExtensionResults: { prf: { results: { first: fill(32, 8), second: fill(32, 9) } } } };
`;
const b64 = (/** @type {number} */ n, /** @type {number} */ v) => toB64u(bytes(n, v));
/** What `toJSON()` must give: Web Authentication level 3, the members in lexicographic order as the browser has them. */
const CREATE_JSON = {
  authenticatorAttachment: "platform", clientExtensionResults: { credProps: { rk: true }, prf: { enabled: true } },
  id: b64(16, 1), rawId: b64(16, 1),
  response: { attestationObject: b64(60, 4), authenticatorData: b64(37, 3), clientDataJSON: b64(40, 2), publicKey: b64(91, 5), publicKeyAlgorithm: -7, transports: ["hybrid", "internal"] },
  type: "public-key",
};
const GET_JSON = {
  authenticatorAttachment: "platform", clientExtensionResults: { prf: { results: { first: b64(32, 8), second: b64(32, 9) } } },
  id: b64(16, 1), rawId: b64(16, 1),
  response: { authenticatorData: b64(37, 3), clientDataJSON: b64(40, 2), signature: b64(70, 6), userHandle: b64(3, 7) },
  type: "public-key",
};

/** The last request the bridge sent. @param {ReturnType<typeof createPasskeyPage>} page */
const lastRequest = (page) => /** @type {any} */ ([...page.sent].reverse().find((m) => m.type === "passkey_request"));

/** A call of the page and the core's answer for it. @param {ReturnType<typeof createPasskeyPage>} page @param {"create" | "get"} kind @param {Record<string, unknown>} [fields] */
async function answered(page, kind, fields = kind === "create" ? CREATE_FIELDS : GET_FIELDS) {
  page.page(kind === "create" ? CREATE : GET);
  await page.flush();
  await page.push("passkey_result", { request_id: lastRequest(page).body.request_id, response: responseToWire(kind, /** @type {any} */ (fields)) });
  assert.equal(page.page("out.done"), true, "the call ended");
  assert.equal(page.page("out.error"), undefined, "with no error");
}

/** Page code that describes one object: what a script can see of its shape. */
const DESCRIBE = `
globalThis.describe = (o) => {
  const forIn = [];
  for (const k in o) forIn.push(k);
  const members = {};
  for (const k of forIn) {
    let p = o;
    while (p !== null && !Object.prototype.hasOwnProperty.call(p, k)) p = Object.getPrototypeOf(p);
    const d = Object.getOwnPropertyDescriptor(p, k);
    members[k] = { enumerable: d.enumerable, configurable: d.configurable, accessor: typeof d.get === "function", setter: d.set !== undefined, writable: d.writable, fn: typeof d.value === "function" };
  }
  return { keys: Object.keys(o), names: Reflect.ownKeys(o).length, forIn, tag: Object.prototype.toString.call(o), members };
};
`;

test("response_objects_pass_instanceof_tojson_and_the_getters", async () => {
  const page = createPasskeyPage();
  page.page(PAGE_FIELDS);
  await answered(page, "create");
  const report = JSON.parse(page.page(`JSON.stringify((() => {
    const c = out.value, r = c.response;
    const hex = (ab) => Array.from(new Uint8Array(ab), (x) => x.toString(16).padStart(2, "0")).join("");
    return {
      instanceOf: [c instanceof PublicKeyCredential, c instanceof Credential, r instanceof AuthenticatorAttestationResponse, r instanceof AuthenticatorResponse, r instanceof AuthenticatorAssertionResponse],
      tags: [Object.prototype.toString.call(c), Object.prototype.toString.call(r)],
      id: c.id, type: c.type, attachment: c.authenticatorAttachment, rawId: hex(c.rawId), sameRaw: c.rawId === c.rawId, sameResponse: c.response === c.response,
      rawIdIsBuffer: c.rawId instanceof ArrayBuffer,
      clientData: hex(r.clientDataJSON), attestation: hex(r.attestationObject),
      transports: r.getTransports(), publicKey: hex(r.getPublicKey()), alg: r.getPublicKeyAlgorithm(), authData: hex(r.getAuthenticatorData()),
      ext: c.getClientExtensionResults(), json: c.toJSON(), jsonText: JSON.stringify(c), jsonOrder: Object.keys(c.toJSON()),
    };
  })())`));
  assert.deepEqual(report.instanceOf, [true, true, true, true, false]);
  assert.deepEqual(report.tags, ["[object PublicKeyCredential]", "[object AuthenticatorAttestationResponse]"]);
  assert.equal(report.id, b64(16, 1));
  assert.equal(report.type, "public-key");
  assert.equal(report.attachment, "platform");
  assert.equal(report.rawId, "01".repeat(16));
  assert.equal(report.rawIdIsBuffer, true);
  assert.equal(report.sameRaw, true);
  assert.equal(report.sameResponse, true);
  assert.equal(report.clientData, "02".repeat(40));
  assert.equal(report.attestation, "04".repeat(60));
  assert.deepEqual(report.transports, ["hybrid", "internal"]);
  assert.equal(report.publicKey, "05".repeat(91));
  assert.equal(report.alg, -7);
  assert.equal(report.authData, "03".repeat(37));
  assert.deepEqual(report.ext, { credProps: { rk: true }, prf: { enabled: true } });
  assert.deepEqual(report.json, CREATE_JSON);
  assert.deepEqual(report.jsonOrder, Object.keys(CREATE_JSON));
  assert.equal(report.jsonText, JSON.stringify(CREATE_JSON), "JSON.stringify gives the same, in the browser's order");

  // The copies are the page's: changing one changes nothing the object holds.
  page.page(`(() => { const r = out.value.response; new Uint8Array(r.getPublicKey()).fill(0); r.getTransports().push("x"); new Uint8Array(r.getAuthenticatorData()).fill(0); out.value.getClientExtensionResults().credProps.rk = false; })()`);
  assert.equal(page.page(`new Uint8Array(out.value.response.getPublicKey())[0]`), 5);
  assert.equal(page.page(`out.value.response.getTransports().length`), 2);
  assert.equal(page.page(`out.value.getClientExtensionResults().credProps.rk`), true);

  // A member of the platform object does not work on another object, and the members are not ours to overwrite on the instance's behalf.
  assert.equal(page.page(`(() => { try { Object.getOwnPropertyDescriptor(Object.getPrototypeOf(out.value), "rawId").get.call({}); return "no"; } catch (e) { return e.name; } })()`), "TypeError");
  assert.equal(page.page(`(() => { try { out.value.toJSON.call({}); return "no"; } catch (e) { return e.name; } })()`), "TypeError");
  assert.equal(page.page(`(() => { try { out.value.response.getTransports.call(Object.create(out.value.response)); return "no"; } catch (e) { return e.name; } })()`), "TypeError");

  // A sign-in.
  await answered(page, "get");
  const get = JSON.parse(page.page(`JSON.stringify((() => {
    const c = out.value, r = c.response;
    const hex = (ab) => ab === null ? null : Array.from(new Uint8Array(ab), (x) => x.toString(16).padStart(2, "0")).join("");
    return {
      instanceOf: [c instanceof PublicKeyCredential, r instanceof AuthenticatorAssertionResponse, r instanceof AuthenticatorResponse, r instanceof AuthenticatorAttestationResponse],
      authData: hex(r.authenticatorData), signature: hex(r.signature), userHandle: hex(r.userHandle), clientData: hex(r.clientDataJSON),
      ext: { first: hex(c.getClientExtensionResults().prf.results.first), second: hex(c.getClientExtensionResults().prf.results.second) },
      json: c.toJSON(), noCreateOnlyMembers: [typeof r.getTransports, typeof r.attestationObject],
    };
  })())`));
  assert.deepEqual(get.instanceOf, [true, true, true, false]);
  assert.equal(get.signature, "06".repeat(70));
  assert.equal(get.userHandle, "07".repeat(3));
  assert.equal(get.ext.first, "08".repeat(32));
  assert.equal(get.ext.second, "09".repeat(32));
  assert.deepEqual(get.json, GET_JSON);
  assert.deepEqual(get.noCreateOnlyMembers, ["undefined", "undefined"]);

  // No user handle: null, and left out of the JSON as the standard has it; no public key: null, left out too.
  await answered(page, "get", { ...GET_FIELDS, user_handle: null, authenticator_attachment: null });
  assert.equal(page.page(`out.value.response.userHandle`), null);
  assert.equal(page.page(`out.value.authenticatorAttachment`), null);
  assert.deepEqual(JSON.parse(page.page(`JSON.stringify(Object.keys(out.value.toJSON()))`)), ["clientExtensionResults", "id", "rawId", "response", "type"]);
  assert.deepEqual(JSON.parse(page.page(`JSON.stringify(Object.keys(out.value.toJSON().response))`)), ["authenticatorData", "clientDataJSON", "signature"]);
  await answered(page, "create", { ...CREATE_FIELDS, spki: null, transports: [], client_extension_results: {} });
  assert.equal(page.page(`out.value.response.getPublicKey()`), null);
  assert.deepEqual(JSON.parse(page.page(`JSON.stringify(out.value.response.getTransports())`)), []);
  assert.equal("publicKey" in JSON.parse(page.page(`JSON.stringify(out.value.toJSON().response)`)), false);
  assert.deepEqual(JSON.parse(page.page(`JSON.stringify(out.value.getClientExtensionResults())`)), {});
});

test("response_objects_have_the_shape_of_the_browsers_own", async () => {
  const page = createPasskeyPage();
  page.page(PAGE_FIELDS + DESCRIBE);
  for (const kind of /** @type {const} */ (["create", "get"])) {
    await answered(page, kind);
    const json = JSON.stringify(kind === "create" ? CREATE_JSON : GET_JSON);
    const fields = kind === "create" ? "createFields" : "getFields";
    const same = JSON.parse(page.page(`JSON.stringify((() => {
      const ours = out.value, theirs = __browserCredential(${JSON.stringify(kind)}, ${fields}, ${JSON.stringify(json)});
      const a = describe(ours), b = describe(theirs);
      const ra = describe(ours.response), rb = describe(theirs.response);
      const chainOf = (o) => { const out = []; for (let p = Object.getPrototypeOf(o); p !== null; p = Object.getPrototypeOf(p)) out.push(p); return out; };
      return {
        credential: [a.keys, a.names, a.forIn, a.tag, a.members, b.keys, b.names, b.forIn, b.tag, b.members],
        response: [ra.keys, ra.names, ra.forIn, ra.tag, ra.members, rb.keys, rb.names, rb.forIn, rb.tag, rb.members],
        // Behind the object's own prototype (which holds the members) the chain is the browser's: the same prototypes.
        credentialChain: chainOf(ours).slice(1).every((p, i) => p === chainOf(theirs)[i]) && chainOf(ours).length === chainOf(theirs).length + 1,
        responseChain: chainOf(ours.response).slice(1).every((p, i) => p === chainOf(theirs.response)[i]) && chainOf(ours.response).length === chainOf(theirs.response).length + 1,
        json: JSON.stringify(ours) === JSON.stringify(theirs) && JSON.stringify(ours.toJSON()) === ${JSON.stringify(json)},
        // The members the browser has, ours has as well, of the same kind.
        hasAll: Object.keys(describe(theirs).members).every((k) => typeof ours[k] === typeof theirs[k]) && Object.keys(describe(theirs.response).members).every((k) => typeof ours.response[k] === typeof theirs.response[k]),
      };
    })())`));
    for (const [name, [ak, an, af, at, am, bk, bn, bf, bt, bm]] of /** @type {Array<[string, any[]]>} */ ([["credential", same.credential], ["response", same.response]])) {
      assert.deepEqual(ak, bk, `${kind} ${name}: Object.keys`);
      assert.equal(an, bn, `${kind} ${name}: own property count`);
      assert.deepEqual(af, bf, `${kind} ${name}: for...in, in the browser's order`);
      assert.equal(at, bt, `${kind} ${name}: toStringTag`);
      assert.deepEqual(am, bm, `${kind} ${name}: kind and flags of each member`);
    }
    assert.equal(same.credentialChain, true, `${kind}: the browser's prototypes follow`);
    assert.equal(same.responseChain, true, `${kind}: the response's prototypes follow`);
    assert.equal(same.json, true, `${kind}: JSON`);
    assert.equal(same.hasAll, true, `${kind}: every member`);
  }
});

test("an_object_prototype_then_does_not_reach_the_resolved_credential", async () => {
  const page = createPasskeyPage();
  page.page(`globalThis.thenRead = 0; Object.defineProperty(Object.prototype, "then", { get() { globalThis.thenRead += 1; return undefined; }, configurable: true });`);
  // The control: a promise resolved with an ordinary object does read it.
  page.page(`Promise.resolve({})`);
  await page.flush();
  assert.equal(page.page("thenRead"), 1, "a plain object is looked at for `then`");
  await answered(page, "create");
  assert.equal(page.page("thenRead"), 1, "the credential was not");
  assert.equal(page.page("out.value instanceof PublicKeyCredential"), true);
  // A page whose Object.prototype.then takes over a resolution would hang or replace the answer: here it is not reached.
  page.page(`delete Object.prototype.then; Object.defineProperty(Object.prototype, "then", { value(resolve) { resolve("HIJACKED"); }, configurable: true, writable: true })`);
  await answered(page, "get");
  assert.equal(page.page("out.value instanceof PublicKeyCredential"), true, "the answer is the credential, not what the page's `then` gives");
  assert.equal(page.page(`Object.keys(out.value).includes("then") || (() => { for (const k in out.value) if (k === "then") return true; return false; })()`), false, "and `then` is not one of its enumerable members");
});

test("the_answer_path_never_calls_what_the_page_can_change", async () => {
  const page = createPasskeyPage();
  page.page(`(() => {
    globalThis.seen = new Set();
    // The own properties the answer is written to (a setter of Object.prototype must not take them).
    globalThis.out = { done: false, value: null, error: undefined };
    const note = (what) => seen.add(what);
    const RA = Reflect.apply;
    Reflect.apply = (f, self, a) => { note("reflect-apply"); return RA(f, self, a); };
    Object.defineProperty(Object.prototype, "then", { get() { note("then"); return undefined; }, configurable: true });
    for (const k of ["0", "1", "2", "3"]) Object.defineProperty(Array.prototype, k, { set() { note("index-setter"); }, configurable: true });
    ArrayBuffer.prototype.slice = function () { note("slice"); return new ArrayBuffer(0); };
    Object.defineProperty(ArrayBuffer, Symbol.species, { get() { note("species"); return ArrayBuffer; }, configurable: true });
    const set = Uint8Array.prototype.set;
    Object.getPrototypeOf(Uint8Array.prototype).set = function (...a) { note("typed-set"); return RA(set, this, a); };
    Object.defineProperty(Object.getPrototypeOf(Uint8Array.prototype), "length", { get() { note("typed-length"); return 0; }, configurable: true });
    Object.defineProperty(ArrayBuffer.prototype, "byteLength", { get() { note("byteLength"); return 0; }, configurable: true });
    Array.isArray = () => { note("isArray"); return false; };
    Object.hasOwn = () => { note("hasOwn"); return false; };
    Object.keys = () => { note("keys"); return []; };
    String.fromCharCode = () => { note("fromCharCode"); return ""; };
    String.prototype.charAt = () => { note("charAt"); return ""; };
    JSON.stringify = () => { note("stringify"); return ""; };
    // Last: from here on a descriptor the page writes without a value of its own inherits one of these.
    const ODP = Object.defineProperty;
    const traps = ["value", "get", "set", "writable", "enumerable", "configurable"].map((k) => [k, { __proto__: null, set() { note("descriptor-setter-" + k); }, get() { return undefined; }, configurable: true }]);
    for (const [k, d] of traps) ODP(Object.prototype, k, d);
  })()`);
  // The call and the answer, with no assignment to a global (the fake page's own globals are made with descriptors).
  page.page(`navigator.credentials.create({ publicKey: {
    challenge: new Uint8Array(32), rp: { name: "RP", id: "rp.example" }, user: { id: new Uint8Array([1]), name: "a", displayName: "A" }, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  } }).then((v) => { out.done = true; out.value = v; }, (e) => { out.done = true; out.error = e.name; })`);
  await page.flush();
  await page.push("passkey_result", { request_id: lastRequest(page).body.request_id, response: responseToWire("create", /** @type {any} */ (CREATE_FIELDS)) });
  assert.equal(page.page("out.error"), undefined);
  assert.equal(page.page("out.value instanceof PublicKeyCredential"), true);
  // Reading the answer, the page's own objects are its business (they are not changed here). It must still be the right answer.
  const seen = /** @type {string[]} */ (JSON.parse(JSON.stringify([...page.page("seen")])));
  for (const what of ["then", "index-setter", "slice", "species", "typed-set", "typed-length", "byteLength", "isArray", "hasOwn", "keys", "fromCharCode", "charAt", "stringify"]) {
    assert.equal(seen.includes(what), false, `the answer path never used the page's ${what}`);
  }
  assert.deepEqual(seen.filter((s) => s.startsWith("descriptor-setter")), [], "no descriptor of the script inherited a setter of the page");
});

test("the_main_script_makes_no_object_with_object_create", async () => {
  const { passkeyScripts } = await import("./passkeyWorld.mjs");
  const code = passkeyScripts().main.replace(/^\/\/.*$/gm, "");
  assert.doesNotMatch(code, /\bObject\s*\.\s*(?:create|setPrototypeOf|assign|fromEntries)\b|\.__proto__\b|\bReflect\s*\.\s*(?:setPrototypeOf|construct)\b/, "objects are made by literals (with __proto__ in the literal) and descriptors");
  assert.doesNotMatch(code, /\bnew\s+Proxy\b/);
});

test("static_methods_answer_as_the_design_has_them", async () => {
  // Where the bridge is connected, Ferret answers.
  const page = createPasskeyPage();
  const answers = JSON.parse(await page.page(`(async () => JSON.stringify({
    uvpaa: await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
    conditional: await PublicKeyCredential.isConditionalMediationAvailable(),
    capabilities: await PublicKeyCredential.getClientCapabilities(),
  }))()`));
  assert.equal(answers.uvpaa, true);
  assert.equal(answers.conditional, true);
  // The browser's answer, with Ferret's entries over it; what the browser says about other things stays.
  assert.deepEqual(answers.capabilities, {
    hybridTransport: true, "extension:prf": true, conditionalGet: true, conditionalCreate: false, passkeyPlatformAuthenticator: true,
    userVerifyingPlatformAuthenticator: true, "extension:credProps": true,
  });
  // The shape of what the page gets: a record of booleans whose keys are those, and no `then` among them.
  assert.deepEqual(JSON.parse(await page.page(`PublicKeyCredential.getClientCapabilities().then((c) => JSON.stringify({ keys: Object.keys(c), then: Object.getOwnPropertyDescriptor(c, "then").enumerable, proto: Object.getPrototypeOf(c) === Object.prototype }))`)), {
    keys: ["hybridTransport", "extension:prf", "conditionalGet", "conditionalCreate", "passkeyPlatformAuthenticator", "userVerifyingPlatformAuthenticator", "extension:credProps"], then: false, proto: true,
  });
  // The methods are the browser's kind of function: own, enumerable and writable as they were, with their names and no argument.
  assert.deepEqual(JSON.parse(page.page(`JSON.stringify(["isUserVerifyingPlatformAuthenticatorAvailable", "isConditionalMediationAvailable", "getClientCapabilities"].map((n) => {
    const d = Object.getOwnPropertyDescriptor(PublicKeyCredential, n);
    return [PublicKeyCredential[n].name, PublicKeyCredential[n].length, d.enumerable, d.writable, d.configurable];
  }))`)), [
    ["isUserVerifyingPlatformAuthenticatorAvailable", 0, true, true, true], ["isConditionalMediationAvailable", 0, true, true, true], ["getClientCapabilities", 0, true, true, true],
  ]);

  // Where it is not (no bridge, no channel), the browser answers with its own words.
  const lone = createPasskeyPage({ bridgeScript: false });
  const own = JSON.parse(await lone.page(`(async () => JSON.stringify({
    uvpaa: await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
    conditional: await PublicKeyCredential.isConditionalMediationAvailable(),
    capabilities: await PublicKeyCredential.getClientCapabilities(),
  }))()`));
  assert.deepEqual(own, { uvpaa: false, conditional: false, capabilities: { hybridTransport: true, "extension:prf": false, conditionalGet: false } });
});

test("signal_methods_pass_through_untouched", async () => {
  const page = createPasskeyPage();
  const report = JSON.parse(await page.page(`(async () => JSON.stringify({
    parse: [PublicKeyCredential.parseCreationOptionsFromJSON.browsers, PublicKeyCredential.parseRequestOptionsFromJSON.browsers],
    parsed: [PublicKeyCredential.parseCreationOptionsFromJSON({}), PublicKeyCredential.parseRequestOptionsFromJSON({})],
    signal: [PublicKeyCredential.signalUnknownCredential.browsers, PublicKeyCredential.signalAllAcceptedCredentials.browsers, PublicKeyCredential.signalCurrentUserDetails.browsers],
    signalled: [await PublicKeyCredential.signalUnknownCredential({}), await PublicKeyCredential.signalAllAcceptedCredentials({}), await PublicKeyCredential.signalCurrentUserDetails({})],
    // And the three that Ferret answers are not the browser's.
    ours: [PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable.browsers, PublicKeyCredential.isConditionalMediationAvailable.browsers, PublicKeyCredential.getClientCapabilities.browsers],
  }))()`));
  assert.deepEqual(report.parse, [true, true], "the browser's own functions");
  assert.deepEqual(report.parsed, ["browser-parse-creation", "browser-parse-request"]);
  assert.deepEqual(report.signal, [true, true, true]);
  assert.deepEqual(report.signalled, ["browser-signal", "browser-signal", "browser-signal"]);
  assert.deepEqual(report.ours, [null, null, null], "the browser's marker is not on the three that Ferret answers");
});
