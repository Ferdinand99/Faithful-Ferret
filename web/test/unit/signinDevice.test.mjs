// The sign-in of a device client (the browser extension) through the shared
// sign-in flow, and the web vault's sign-in next to it, unchanged.
// Spec: Fase 1 § 4.2, § 7.6, § 8.2; RFC 9449 § 4.2, § 5.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { loadDeviceKey, sameKey } from "../../src/auth/deviceKey.mjs";
import { LOGIN_FINISH_PATH, LOGIN_START_PATH, REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { createCryptoSession } from "../../src/crypto/session.mjs";
import { createVaultSession } from "../../src/crypto/vaultSession.mjs";
import storeDef from "../../src/services/store.service.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { getSetting } from "../../src/store/settings.mjs";
import { coded, EMAIL, fakeClient, fakeServer as cookieServer, PASSWORD, SK_CODE } from "./accountHelpers.mjs";
import { DEVICE_NAME_FIREFOX, deviceWorld, loginStartRes, METHODS, methodsRes } from "./deviceSessionHelpers.mjs";
import { freshStore } from "./idbHelpers.mjs";
import { ACCOUNT, answer, claimsOf, DEVICE, headerOf, LOCAL_MS, loginRes, refusal, SERVER, tok, VAULT, verifies } from "./tokenHelpers.mjs";

const signIn = (/** @type {any} */ world, extra = {}) =>
  world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE, ...extra });

/** A request as text: the URL and the RequestInit in the order of their keys, the signal named. */
const describe = (/** @type {string} */ url, /** @type {RequestInit} */ init) =>
  JSON.stringify([url, init], (_, value) => (value instanceof AbortSignal ? "[AbortSignal]" : value));

test("cookie_mode_is_byte_for_byte_the_m2_request", async () => {
  /** @type {string[]} */
  const sent = [];
  const server = cookieServer();
  /** @type {typeof fetch} */
  const fetchImpl = async (url, init = {}) => {
    sent.push(describe(String(url), init));
    return server.fetchImpl(url, init);
  };
  const db = await freshStore();
  const store = { ...storeDef.create({}), open: async () => db.store };
  const rand = (/** @type {Uint8Array} */ bytes) => bytes.fill(0xab);
  const options = { api: createApi({ fetchImpl }), store, serverUrl: SERVER, rand };

  // The shared session and the web vault's session send the same, both as the web vault did before device mode.
  for (const create of [createCryptoSession, createVaultSession]) {
    sent.length = 0;
    server.state.signedIn = false;
    const session = create({ ...options, client: fakeClient() });
    assert.equal(session.mode, "cookie");
    await session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE, rememberSk: true });
    await session.lock();
    await session.unlock({ password: PASSWORD });

    const ke1 = "AQEB".repeat(32); // 96 bytes of 1
    const ke3 = `${"AgIC".repeat(21)}Ag`; // 64 bytes of 2
    const json = '"headers":{"Accept":"application/json","Ferret-Protocol":"1","Content-Type":"application/json"}';
    const get = '"credentials":"same-origin","cache":"no-store","redirect":"error","headers":{"Accept":"application/json"}';
    const post = `"credentials":"same-origin","cache":"no-store","redirect":"error",${json}`;
    const finish = (/** @type {string} */ purpose) =>
      `{\\"login_id\\":\\"${"cd".repeat(16)}\\",\\"ke3\\":\\"${ke3}\\",\\"device_id\\":\\"${"ab".repeat(16)}\\",\\"device_name\\":\\"Web vault\\",\\"purpose\\":\\"${purpose}\\"}`;
    assert.deepEqual(sent, [
      `["/api/auth/opaque/login/start",{"method":"POST",${post},"body":"{\\"email\\":\\"${EMAIL}\\",\\"ke1\\":\\"${ke1}\\",\\"purpose\\":\\"login\\"}","signal":"[AbortSignal]"}]`,
      `["/api/auth/opaque/login/finish",{"method":"POST",${post},"body":"${finish("login")}","signal":"[AbortSignal]"}]`,
      `["/api/vault/unlock-methods",{"method":"GET",${get},"signal":"[AbortSignal]"}]`,
      `["/api/auth/session",{"method":"GET",${get},"signal":"[AbortSignal]"}]`,
      `["/api/auth/opaque/login/start",{"method":"POST",${post},"body":"{\\"email\\":\\"${EMAIL}\\",\\"ke1\\":\\"${ke1}\\",\\"purpose\\":\\"reauth\\"}","signal":"[AbortSignal]"}]`,
      `["/api/auth/opaque/login/finish",{"method":"POST",${post},"body":"${finish("reauth")}","signal":"[AbortSignal]"}]`,
      `["/api/vault/unlock-methods",{"method":"GET",${get},"signal":"[AbortSignal]"}]`,
    ]);
    for (const line of sent) assert.ok(!/authorization|dpop|"omit"|"client"|platform/i.test(line), line);

    // A sign-in that does not open the vault ends the new session with the web vault's sign-out, as before.
    sent.length = 0;
    const broken = create({
      ...options,
      client: fakeClient({ handlers: { unlock_password: () => { throw coded("decrypt"); } } }),
    });
    await assert.rejects(broken.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE }), { code: "decrypt" });
    assert.equal(sent.at(-1), `["/api/auth/logout",{"method":"POST",${post},"signal":"[AbortSignal]"}]`);
    // And the web vault's sign-out is the same call.
    sent.length = 0;
    const again = create({ ...options, client: fakeClient() });
    await again.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE });
    sent.length = 0;
    await again.signOut();
    assert.deepEqual(sent, [`["/api/auth/logout",{"method":"POST",${post},"signal":"[AbortSignal]"}]`]);
  }
});

test("device_mode_sends_the_jwk_and_a_proof_and_never_a_cookie", async () => {
  const world = await deviceWorld();
  await signIn(world);
  assert.deepEqual(world.server.calls.map((call) => call.path), [LOGIN_START_PATH, LOGIN_FINISH_PATH, METHODS]);
  for (const call of world.server.calls) {
    // No cookie ever: the browser is told to leave them out, and no request names one.
    assert.equal(call.init.credentials, "omit", call.path);
    assert.ok(!Object.keys(call.headers).some((name) => name.toLowerCase() === "cookie"), call.path);
    assert.equal(call.headers["Ferret-Protocol"], "1", call.path);
    assert.equal(call.init.redirect, "error", call.path);
    assert.equal(call.init.cache, "no-store", call.path);
    assert.ok(call.url.startsWith(`${SERVER}/`), "every request goes to the named server");
  }
  const [start, finish, methods] = world.server.calls;

  // login/start: no token and no proof; the purpose is a sign-in.
  assert.ok(!("Authorization" in start.headers) && !("DPoP" in start.headers));
  assert.deepEqual(Object.keys(start.body), ["email", "ke1", "purpose"]);
  assert.equal(start.body.purpose, "login");

  // login/finish: the device body, and the key in a proof of it (no token, no `ath`).
  assert.ok(!("Authorization" in finish.headers));
  assert.deepEqual(finish.body, {
    login_id: "cd".repeat(16),
    ke3: `${"AgIC".repeat(21)}Ag`,
    client: "device",
    device_name: DEVICE_NAME_FIREFOX,
    platform: "windows",
  });
  const proof = finish.headers.DPoP;
  assert.deepEqual(headerOf(proof), { typ: "dpop+jwt", alg: "ES256", jwk: world.deviceKey.publicJwk });
  const claims = claimsOf(proof);
  assert.equal(claims.htm, "POST");
  assert.equal(claims.htu, `${SERVER}${LOGIN_FINISH_PATH}`);
  assert.ok(!("ath" in claims));
  assert.ok(await verifies(proof, world.deviceKey.publicJwk), "signed by the device key");

  // After the sign-in the device's calls carry its token and a proof with `ath`.
  assert.equal(methods.headers.Authorization, `DPoP ${tok(1)}`);
  assert.ok("ath" in claimsOf(methods.headers.DPoP));
  assert.ok(await verifies(methods.headers.DPoP, world.deviceKey.publicJwk));

  // A device never asks the cookie route of the session, and its unlock sends no re-authentication.
  assert.equal(await world.session.info(), null);
  assert.ok(!world.server.calls.some((call) => call.path === "/api/auth/session" || call.path === "/api/auth/logout"));
});

test("device_mode_signs_in_again_with_a_new_proof_after_its_clock_was_refused", async () => {
  // The server's clock is an hour ahead; its first refusal carries its `Date`, and the sign-in state is still there.
  const serverMs = LOCAL_MS + 3_600_000;
  let refused = false;
  const world = await deviceWorld({
    overrides: {
      [LOGIN_FINISH_PATH]: () => {
        if (refused) return undefined;
        refused = true;
        return refusal("dpop_invalid", { date: new Date(serverMs).toUTCString() });
      },
    },
  });
  await signIn(world);
  const finishes = world.server.to(LOGIN_FINISH_PATH);
  assert.equal(finishes.length, 2);
  const [first, second] = finishes.map((call) => claimsOf(call.headers.DPoP));
  assert.notEqual(first.jti, second.jti, "a new proof");
  assert.equal(first.iat, LOCAL_MS / 1000);
  assert.equal(second.iat, serverMs / 1000, "in the server's time");
  assert.deepEqual(finishes[0].body, finishes[1].body, "the same sign-in");
  assert.equal(world.tokens.state, "ok");
});

test("device_mode_saves_tokens_and_the_server_device_id", async () => {
  const world = await deviceWorld();
  const unlocked = await signIn(world, { rememberSk: true });

  // The record of the key holds the server's device id, the account and the refresh token; the access token is in memory.
  const record = await loadDeviceKey(world.db.store, SERVER);
  assert.ok(record);
  assert.equal(record.deviceId, DEVICE);
  assert.equal(record.accountId, ACCOUNT);
  assert.equal(record.refreshToken, tok(2));
  assert.ok(sameKey(record.publicJwk, world.deviceKey.publicJwk));
  assert.equal(world.tokens.state, "ok");
  assert.equal(world.server.to(METHODS)[0].headers.Authorization, `DPoP ${tok(1)}`);

  // The vault is open and pinned as for the web vault; no browser id was made for a device the server names.
  assert.deepEqual([unlocked.accountId, unlocked.vaultId, unlocked.vkEpoch, unlocked.email], [ACCOUNT, VAULT, 1, EMAIL]);
  assert.equal(world.session.current()?.accountId, ACCOUNT);
  assert.ok(await loadPinned(world.db.store, SERVER, EMAIL));
  assert.equal(await getSetting(world.db.store, "device_id"), undefined);

  // No token reaches what the sign-in gives back.
  const shown = JSON.stringify(unlocked);
  for (const token of [tok(1), tok(2)]) assert.ok(!shown.includes(token));

  // The key signs in once: another sign-in in this session is refused before anything is sent.
  const before = world.server.calls.length;
  await assert.rejects(signIn(world), TypeError);
  assert.equal(world.server.calls.length, before);
});

test("a_failed_device_unlock_revokes_the_new_tokens", async () => {
  // The vault does not open after the server gave the device its tokens (here: the core refuses the wrap).
  const world = await deviceWorld({ handlers: { unlock_password: () => { throw coded("decrypt"); } } });
  await assert.rejects(signIn(world), { code: "decrypt" });

  // The new device is signed out with its own refresh token and a proof of its key; its record and tokens are gone.
  const [revoke] = world.server.to(REVOKE_PATH);
  assert.ok(revoke, "the new device is signed out");
  assert.deepEqual(revoke.body, { refresh_token: tok(2) });
  assert.ok(!("Authorization" in revoke.headers));
  assert.ok(await verifies(revoke.headers.DPoP, world.deviceKey.publicJwk));
  assert.equal(revoke.init.credentials, "omit");
  assert.equal(await loadDeviceKey(world.db.store, SERVER), null);
  assert.equal(world.tokens.state, "signed_out");
  // There is no cookie session to end, the vault is locked and nothing is pinned.
  assert.ok(!world.server.calls.some((call) => call.path === "/api/auth/logout"));
  assert.ok(world.client.locked >= 1);
  assert.equal(world.session.current(), null);
  assert.equal(await loadPinned(world.db.store, SERVER, EMAIL), null);

  // The same for a server whose account key differs from the pin, and even when the sign-out cannot reach the server.
  const other = await deviceWorld({
    overrides: {
      [METHODS]: () => answer(200, { ...methodsRes(), pk_a: Buffer.alloc(32, 7).toString("base64url") }),
      [REVOKE_PATH]: () => {
        throw new TypeError("offline");
      },
    },
  });
  await assert.rejects(signIn(other), { code: "pinned_auth_key" });
  assert.equal(other.server.to(REVOKE_PATH).length, 1);
  assert.equal(await loadDeviceKey(other.db.store, SERVER), null);
  assert.equal(other.tokens.state, "signed_out");
});

test("a_device_sign_in_that_never_reached_the_server_keeps_its_key_for_another_try", async () => {
  // A wrong password is found by the core before KE3: no login/finish is sent, the key is not spent.
  let wrong = true;
  const world = await deviceWorld({
    handlers: {
      login_finish: () => {
        if (wrong) throw coded("decrypt");
        return { ke3: new Uint8Array(64).fill(2), server_public_key: new Uint8Array(32).fill(9) };
      },
    },
  });
  await assert.rejects(signIn(world), { code: "decrypt" });
  assert.deepEqual(world.server.calls.map((call) => call.path), [LOGIN_START_PATH]);
  assert.equal(world.tokens.state, "signed_out");
  wrong = false;
  await signIn(world);
  assert.equal(world.tokens.state, "ok");
  assert.equal(world.server.to(LOGIN_FINISH_PATH).length, 1);
});

test("a_device_answer_with_fields_the_extension_does_not_know_is_read_without_them", async () => {
  // A newer server adds fields to its answers; the extension, released apart from it, reads what it knows.
  const world = await deviceWorld({
    overrides: {
      [LOGIN_START_PATH]: () => answer(200, { ...loginStartRes(), later: 1 }),
      [LOGIN_FINISH_PATH]: () => answer(200, { ...loginRes(), later: { a: 1 } }),
      [METHODS]: () => {
        const methods = /** @type {any} */ (methodsRes());
        methods.methods[0].later = true;
        methods.manifest.later = "x";
        methods.later = [];
        return answer(200, methods);
      },
    },
  });
  await signIn(world);
  assert.equal(world.tokens.state, "ok");
  assert.equal(world.session.current()?.accountId, ACCOUNT);

  // A known field with a wrong value is still refused, and so the device is signed out again.
  const bad = await deviceWorld({ overrides: { [METHODS]: () => answer(200, { ...methodsRes(), vk_epoch: "1" }) } });
  await assert.rejects(signIn(bad), { code: "bad_response" });
  assert.equal(bad.server.to(REVOKE_PATH).length, 1);
});
