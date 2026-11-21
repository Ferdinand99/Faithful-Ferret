// The API client with a device's tokens: no cookies, the protocol header on
// every request, a new proof per attempt, one renewal and one clock resync at
// most, and the web vault's requests unchanged without tokens.
// Spec: Fase 1 § 7.6, § 8.2; RFC 9449 § 4.2, § 7.1.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { ApiError, createApi } from "../../src/api.mjs";
import { generateDeviceKey, saveDeviceKey } from "../../src/auth/deviceKey.mjs";
import { createClock } from "../../src/auth/dpop.mjs";
import { createTokenAuth, REFRESH_PATH, REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { freshStore } from "./idbHelpers.mjs";
import {
  ACCOUNT, answer, claimsOf, DEVICE, eventStream, fakeServer, LOCAL_MS, loginRes, refusal, SERVER, signedInDevice, tok, tokenRes,
  verifies,
} from "./tokenHelpers.mjs";

const CHANGES = "/api/sync/changes";
const EVENTS = "/api/sync/events";
const changes = { items: [], next: 0, more: false };
/** The `ath` of a token: base64url of SHA-256 of its ASCII text. */
const ath = (/** @type {string} */ token) => createHash("sha256").update(token, "ascii").digest("base64url");

/** Runs `promise` and returns the ApiError it rejects with. */
async function failure(promise) {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof ApiError, `expected an ApiError, got ${error}`);
    return error;
  }
  return assert.fail("expected an ApiError");
}

/** A request as text: the URL and the RequestInit in the order of their keys, the signal and bytes named. */
const describe = (/** @type {string} */ url, /** @type {RequestInit} */ init) =>
  JSON.stringify([url, init], (_, value) => {
    if (value instanceof AbortSignal) return "[AbortSignal]";
    if (value instanceof Uint8Array) return `[bytes ${Buffer.from(value).toString("hex")}]`;
    return value;
  });

test("web_vault_api_is_unchanged", async () => {
  /** @type {string[]} */
  const sent = [];
  /** @type {typeof fetch} */
  const fetchImpl = async (url, init = {}) => {
    sent.push(describe(String(url), init));
    return String(url).endsWith(EVENTS) ? eventStream() : answer(200, {});
  };
  const api = createApi({ fetchImpl });
  const based = createApi({ base: "https://vault.example", fetchImpl });
  const controller = new AbortController();
  const nonce = new Uint8Array(32).fill(7);
  const proof = new Uint8Array(64).fill(9);

  await api.get("/api/auth/session");
  await based.get("/api/sync/changes?since=3&limit=500");
  await api.post("/api/auth/logout", { a: 1 });
  await api.post("/api/auth/logout");
  await api.put("/api/sync/items/ab", '{ "idem":"00", "base_rev":0 }');
  await api.put("/api/sync/items/ab", new Uint8Array([1, 2, 3]));
  await api.sendSigned("PUT", "/api/vault/manifest", new Uint8Array([4, 5]), { nonce, proof });
  await api.sendSigned("POST", "/api/vault/password", new Uint8Array([6]), { nonce, proof });
  await (await api.stream(EVENTS)).cancel();
  await (await based.stream(EVENTS, { signal: controller.signal })).cancel();

  const n = Buffer.from(nonce).toString("base64url");
  const p = Buffer.from(proof).toString("base64url");
  // What the web vault sent before device tokens existed, byte for byte.
  assert.deepEqual(sent, [
    '["/api/auth/session",{"method":"GET","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json"},"signal":"[AbortSignal]"}]',
    '["https://vault.example/api/sync/changes?since=3&limit=500",{"method":"GET","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json"},"signal":"[AbortSignal]"}]',
    '["/api/auth/logout",{"method":"POST","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json","Ferret-Protocol":"1","Content-Type":"application/json"},"body":"{\\"a\\":1}","signal":"[AbortSignal]"}]',
    '["/api/auth/logout",{"method":"POST","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json","Ferret-Protocol":"1","Content-Type":"application/json"},"signal":"[AbortSignal]"}]',
    '["/api/sync/items/ab",{"method":"PUT","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json","Ferret-Protocol":"1","Content-Type":"application/json"},"body":"{ \\"idem\\":\\"00\\", \\"base_rev\\":0 }","signal":"[AbortSignal]"}]',
    '["/api/sync/items/ab",{"method":"PUT","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json","Ferret-Protocol":"1","Content-Type":"application/json"},"body":"[bytes 010203]","signal":"[AbortSignal]"}]',
    `["/api/vault/manifest",{"method":"PUT","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json","Ferret-Protocol":"1","Content-Type":"application/json","Ferret-Nonce":"${n}","Ferret-Proof":"${p}"},"body":"[bytes 0405]","signal":"[AbortSignal]"}]`,
    `["/api/vault/password",{"method":"POST","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json","Ferret-Protocol":"1","Content-Type":"application/json","Ferret-Nonce":"${n}","Ferret-Proof":"${p}"},"body":"[bytes 06]","signal":"[AbortSignal]"}]`,
    '["/api/sync/events",{"method":"GET","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"text/event-stream","Ferret-Protocol":"1"}}]',
    '["https://vault.example/api/sync/events",{"method":"GET","credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"text/event-stream","Ferret-Protocol":"1"},"signal":"[AbortSignal]"}]',
  ]);
  for (const line of sent) {
    assert.ok(!/authorization|dpop|"omit"/i.test(line), "no token header and no change of credentials");
  }

  // An answer the web vault cannot use is still one try: no renewal, no clock, no second attempt.
  let tries = 0;
  const refusing = createApi({
    fetchImpl: async () => {
      tries += 1;
      return refusal(tries === 1 ? "token_expired" : "dpop_invalid", { date: new Date().toUTCString() });
    },
  });
  assert.equal((await failure(refusing.get(CHANGES))).code, "token_expired");
  assert.equal((await failure(refusing.stream(EVENTS))).code, "dpop_invalid");
  assert.equal(tries, 2);
});

test("api_with_auth_never_sends_cookies", async () => {
  const db = await freshStore();
  const clock = createClock({ now: () => LOCAL_MS });
  // An older device on the same server: the sign-in signs it out first.
  const older = await generateDeviceKey(SERVER);
  await saveDeviceKey(db.store, older, { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: tok(9) });
  const key = await generateDeviceKey(SERVER);
  const server = fakeServer();
  server.handle = (call) => {
    if (call.path === REVOKE_PATH) return answer(204, null);
    if (call.path === REFRESH_PATH) return answer(200, tokenRes(tok(3), tok(4)));
    if (call.path === EVENTS) return eventStream();
    if (call.headers.Authorization === `DPoP ${tok(1)}`) return refusal("token_expired");
    return answer(200, changes);
  };
  const auth = createTokenAuth({ serverUrl: SERVER, store: db.store, key, clock, fetchImpl: server.fetchImpl });
  await auth.accept(loginRes());
  const api = createApi({ base: SERVER, fetchImpl: server.fetchImpl, auth });
  await api.get(CHANGES);
  await api.post("/api/sync/batch", { ops: [] });
  await api.put("/api/sync/items/ab", "{}");
  await (await api.stream(EVENTS)).cancel();
  await auth.revoke();

  assert.deepEqual(server.calls.map((c) => c.path), [REVOKE_PATH, CHANGES, REFRESH_PATH, CHANGES, "/api/sync/batch", "/api/sync/items/ab", EVENTS, REVOKE_PATH]);
  for (const call of server.calls) {
    assert.equal(call.init.credentials, "omit", `${call.init.method} ${call.path}`);
    assert.equal(call.init.cache, "no-store");
    assert.equal(call.init.redirect, "error");
    assert.ok(!Object.keys(call.headers).some((name) => name.toLowerCase() === "cookie"));
  }
});

test("every_token_request_sends_ferret_protocol_also_get_and_stream", async () => {
  const { server, auth, api } = await signedInDevice();
  server.handle = (call) => {
    if (call.path === REFRESH_PATH) return answer(200, tokenRes(tok(3), tok(4)));
    if (call.path === EVENTS) return call.headers.Authorization === `DPoP ${tok(1)}` ? refusal("token_expired") : eventStream();
    if (call.path === REVOKE_PATH) return answer(204, null);
    return answer(200, changes);
  };
  await api.get(CHANGES);
  await api.get("/api/vault/unlock-methods");
  await api.get("/api/sync/checkpoint");
  await api.put("/api/sync/checkpoint", { a: 1 });
  await api.post("/api/sync/batch", { ops: [] });
  await (await api.stream(EVENTS)).cancel();
  await auth.revoke();

  const methods = new Set(server.calls.map((c) => `${c.init.method} ${c.path}`));
  for (const expected of [`GET ${CHANGES}`, `GET ${EVENTS}`, `POST ${REFRESH_PATH}`, `POST ${REVOKE_PATH}`, "PUT /api/sync/checkpoint"]) {
    assert.ok(methods.has(expected), expected);
  }
  for (const call of server.calls) {
    assert.equal(call.headers["Ferret-Protocol"], "1", `${call.init.method} ${call.path}`);
    assert.ok(typeof call.headers.DPoP === "string", "every token request has a proof");
  }
  const reads = server.calls.filter((c) => c.init.method === "GET");
  assert.ok(reads.every((c) => c.headers.Authorization?.startsWith("DPoP ")));
  assert.equal(server.calls.find((c) => c.path === EVENTS)?.headers.Accept, "text/event-stream");
});

test("a_new_proof_per_attempt", async () => {
  const { key, server, api } = await signedInDevice();
  const serverDate = new Date(LOCAL_MS).toUTCString();
  let attempt = 0;
  server.handle = (call) => {
    if (call.path === REFRESH_PATH) return answer(200, tokenRes(tok(3), tok(4)));
    attempt += 1;
    if (attempt === 1) return refusal("dpop_invalid", { date: serverDate });
    if (attempt === 2) return refusal("token_expired");
    return answer(200, changes);
  };
  await api.put("/api/sync/items/ab?x=1#frag", '{"same":"body"}');
  const tries = server.to("/api/sync/items/ab");
  assert.equal(tries.length, 3);
  const proofs = tries.map((c) => c.headers.DPoP);
  assert.equal(new Set(proofs).size, 3, "each attempt has its own proof");
  const claims = proofs.map(claimsOf);
  assert.equal(new Set(claims.map((c) => c.jti)).size, 3, "and its own jti");
  for (const proof of proofs) assert.equal(await verifies(proof, key.publicJwk), true);
  for (const c of claims) {
    assert.equal(c.htm, "PUT");
    assert.equal(c.htu, `${SERVER}/api/sync/items/ab`, "no query and no fragment");
  }
  assert.deepEqual(claims.map((c) => c.ath), [ath(tok(1)), ath(tok(1)), ath(tok(3))], "ath is the hash of the token sent");
  assert.deepEqual(tries.map((c) => c.headers.Authorization), [`DPoP ${tok(1)}`, `DPoP ${tok(1)}`, `DPoP ${tok(3)}`]);
  // A retry sends the body as it was.
  assert.deepEqual(tries.map((c) => c.init.body), ['{"same":"body"}', '{"same":"body"}', '{"same":"body"}']);

  // The event stream too.
  attempt = 0;
  server.handle = () => {
    attempt += 1;
    return attempt === 1 ? refusal("dpop_invalid", { date: serverDate }) : eventStream();
  };
  await (await api.stream(EVENTS)).cancel();
  const streams = server.to(EVENTS);
  assert.equal(streams.length, 2);
  assert.notEqual(claimsOf(streams[0].headers.DPoP).jti, claimsOf(streams[1].headers.DPoP).jti);
});

test("iat_uses_the_server_clock_offset_and_resyncs_once_on_dpop_invalid", async () => {
  const local = LOCAL_MS / 1000;
  let serverSeconds = local + 3600;
  const { server, api } = await signedInDevice();
  const date = () => new Date(serverSeconds * 1000).toUTCString();
  /** Accepts a proof within 60 seconds of the server's time, as the server does. */
  const fair = (call) =>
    Math.abs(claimsOf(call.headers.DPoP).iat - serverSeconds) <= 60 ? answer(200, changes, { date: date() }) : refusal("dpop_invalid", { date: date() });
  server.handle = fair;

  // The first proof uses the local clock; the server's Date of the refusal sets the offset, and the one retry passes.
  assert.deepEqual({ ...(await api.get(CHANGES)) }, changes);
  assert.deepEqual(server.calls.map((c) => claimsOf(c.headers.DPoP).iat), [local, local + 3600]);

  // From now on the offset holds: one attempt.
  server.calls.length = 0;
  await api.get(CHANGES);
  assert.deepEqual(server.calls.map((c) => claimsOf(c.headers.DPoP).iat), [local + 3600]);

  // A success with another Date moves nothing.
  server.calls.length = 0;
  server.handle = () => answer(200, changes, { date: new Date((local + 9000) * 1000).toUTCString() });
  await api.get(CHANGES);
  await api.get(CHANGES);
  assert.deepEqual(server.calls.map((c) => claimsOf(c.headers.DPoP).iat), [local + 3600, local + 3600]);

  // The server's clock jumps: one resync and one retry, never a second one.
  server.calls.length = 0;
  serverSeconds = local + 3600 + 600;
  server.handle = (call) => {
    const answerOf = fair(call);
    serverSeconds += 600; // and keeps running away
    return answerOf;
  };
  const error = await failure(api.get(CHANGES));
  assert.equal(error.code, "dpop_invalid");
  assert.deepEqual(server.calls.map((c) => claimsOf(c.headers.DPoP).iat), [local + 3600, local + 4200]);

  // A dpop_invalid that is not the server's own no-store answer gives its one retry, and the clock stays.
  server.calls.length = 0;
  server.handle = () => refusal("dpop_invalid", { date: new Date((local + 1) * 1000).toUTCString(), headers: { "cache-control": "max-age=600" } });
  await failure(api.get(CHANGES));
  assert.deepEqual(server.calls.map((c) => claimsOf(c.headers.DPoP).iat), [local + 4200, local + 4200]);
});

test("two_parallel_401s_refresh_once", async () => {
  const { server, api } = await signedInDevice();
  /** @type {() => void} */
  let bothIn = () => {};
  const both = new Promise((resolve) => {
    bothIn = () => resolve(undefined);
  });
  let early = 0;
  server.handle = async (call) => {
    if (call.path === REFRESH_PATH) return answer(200, tokenRes(tok(3), tok(4)));
    if (call.headers.Authorization === `DPoP ${tok(1)}`) {
      early += 1;
      if (early === 2) bothIn();
      await both;
      return refusal("token_expired");
    }
    return answer(200, changes);
  };
  const results = await Promise.all([api.get(CHANGES), api.get(CHANGES)]);
  assert.deepEqual(results.map((r) => ({ ...r })), [changes, changes]);
  assert.equal(server.to(REFRESH_PATH).length, 1, "one renewal for both");
  assert.deepEqual(
    server.to(CHANGES).map((c) => c.headers.Authorization),
    [`DPoP ${tok(1)}`, `DPoP ${tok(1)}`, `DPoP ${tok(3)}`, `DPoP ${tok(3)}`],
  );

  // A 401 that comes back after the renewal is over does not renew again: the token has changed since.
  const late = await signedInDevice();
  /** @type {() => void} */
  let retried = () => {};
  const firstRetried = new Promise((resolve) => {
    retried = () => resolve(undefined);
  });
  let count = 0;
  late.server.handle = async (call) => {
    if (call.path === REFRESH_PATH) return answer(200, tokenRes(tok(5), tok(6)));
    if (call.headers.Authorization === `DPoP ${tok(1)}`) {
      count += 1;
      if (count === 2) await firstRetried;
      return refusal("token_expired");
    }
    retried();
    return answer(200, changes);
  };
  await Promise.all([late.api.get(CHANGES), late.api.get(CHANGES)]);
  assert.equal(late.server.to(REFRESH_PATH).length, 1);
});

test("a_signed_call_with_device_auth_is_refused", async () => {
  const { server, api } = await signedInDevice();
  const nonce = new Uint8Array(32);
  const proof = new Uint8Array(64);
  for (const method of ["PUT", "POST"]) {
    await assert.rejects(api.sendSigned(/** @type {"PUT"} */ (method), "/api/vault/manifest", new Uint8Array([1]), { nonce, proof }), TypeError);
  }
  assert.equal(server.calls.length, 0, "nothing was sent");
});

test("an_auth_that_is_not_one_is_refused", () => {
  for (const auth of [{}, "token", { prepare() {}, observe() {}, refresh() {} }]) {
    assert.throws(() => createApi({ auth: /** @type {any} */ (auth) }), TypeError);
  }
});

test("no_token_reaches_url_storage_or_console", async (t) => {
  // Storage that records every call, and a console that records every call.
  const calls = [];
  const storage = (name) =>
    new Proxy({}, {
      get: (_, prop) => {
        calls.push(`${name}.${String(prop)}`);
        return () => undefined;
      },
      set: (_, prop) => {
        calls.push(`${name}.${String(prop)}=`);
        return true;
      },
    });
  for (const name of ["localStorage", "sessionStorage"]) {
    const had = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { value: storage(name), configurable: true, writable: true });
    t.after(() => {
      if (had) Object.defineProperty(globalThis, name, had);
      else delete globalThis[name];
    });
  }
  for (const method of ["log", "info", "warn", "error", "debug", "trace", "dir", "table"]) {
    t.mock.method(console, method, (...args) => calls.push(`console.${method}: ${args.length}`));
  }

  const secrets = [1, 2, 3, 4, 9].map(tok);
  /** @type {unknown[]} */
  const errors = [];
  const keep = async (/** @type {Promise<unknown>} */ promise) => {
    try {
      await promise;
    } catch (error) {
      errors.push(error);
    }
  };
  const { server, auth, api } = await signedInDevice();
  let refreshes = 0;
  let expired = false;
  server.handle = (call) => {
    if (call.path === REFRESH_PATH) {
      refreshes += 1;
      return refreshes === 1 ? answer(200, tokenRes(tok(3), tok(4))) : refusal("token_reused");
    }
    if (call.path === EVENTS) return refusal("dpop_invalid", { date: new Date(LOCAL_MS).toUTCString() });
    if (call.path === REVOKE_PATH) return answer(204, null);
    return call.headers.Authorization === `DPoP ${tok(3)}` && !expired ? answer(200, changes) : refusal("token_expired");
  };
  await api.get(`${CHANGES}?since=0`);
  await keep(api.stream(EVENTS));
  await api.get("/api/sync/checkpoint");
  expired = true;
  await keep(api.get(CHANGES));
  assert.equal(auth.state, "revoked");
  await keep(api.get(CHANGES));
  await keep(auth.revoke());
  await keep(auth.accept({ ...loginRes(), token_type: "Bearer" }));

  assert.deepEqual(calls, [], "no storage and no console");
  assert.deepEqual(
    errors.map((e) => /** @type {any} */ (e).code ?? /** @type {Error} */ (e).name),
    ["dpop_invalid", "token_reused", "device_revoked", "TypeError"],
  );
  for (const call of server.calls) {
    for (const secret of secrets) assert.ok(!call.url.includes(secret), "no token in a URL");
  }
  for (const error of errors) {
    const text = `${String(error)} ${JSON.stringify(error)} ${/** @type {Error} */ (error).stack ?? ""}`;
    for (const secret of secrets) assert.ok(!text.includes(secret), "no token in an error");
  }
});

test("a_device_client_ignores_unknown_answer_fields_and_the_web_vault_refuses_them", async () => {
  const device = await signedInDevice();
  const page = { changes: [], latest_seq: 0, vk_epoch: 1, restore_epoch: 0, restore_seq: 0, has_more: false };
  const later = { ...page, later: { from: "a newer server" }, changes: [] };
  device.server.handle = () => answer(200, later);
  // The extension, released apart from the server, reads what it knows and drops the rest.
  const read = await device.api.get(`${CHANGES}?since=0&limit=1`, { shape: "changes_res" });
  assert.deepEqual(Object.keys(read), Object.keys(page));
  // The web vault comes from its own server: an unknown field is a bad answer there, as before.
  const web = createApi({ fetchImpl: async () => answer(200, later) });
  assert.equal((await failure(web.get(`${CHANGES}?since=0&limit=1`, { shape: "changes_res" }))).code, "bad_response");
  // A known field that is wrong is a bad answer for both.
  device.server.handle = () => answer(200, { ...page, vk_epoch: -1 });
  assert.equal((await failure(device.api.get(`${CHANGES}?since=0&limit=1`, { shape: "changes_res" }))).code, "bad_response");
  // The current row of a conflict is read the same way.
  const row = { current_rev: 2, deleted: true, later: 1 };
  device.server.handle = () => answer(409, row);
  const conflict = await failure(device.api.put("/api/sync/items/ab", "{}"));
  assert.equal(conflict.code, "conflict");
  assert.deepEqual({ ...conflict.body }, { current_rev: 2, deleted: true });
  const webConflict = await failure(createApi({ fetchImpl: async () => answer(409, row) }).put("/api/sync/items/ab", "{}"));
  assert.equal(webConflict.code, "bad_response");
});
