// The sign-in of a device client (the browser extension) through the shared
// sign-in flow, and the web vault's sign-in next to it, unchanged.
// Spec: Fase 1 § 4.2, § 7.6, § 8.2; RFC 9449 § 4.2, § 5.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { LOGIN_FINISH_PATH, LOGIN_START_PATH, REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { createCryptoSession } from "../../src/crypto/session.mjs";
import { createVaultSession } from "../../src/crypto/vaultSession.mjs";
import storeDef from "../../src/services/store.service.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { getSetting } from "../../src/store/settings.mjs";
import { coded, EMAIL, fakeClient, fakeServer as cookieServer, PASSWORD, SK_CODE } from "./accountHelpers.mjs";
import { DEVICE_NAME_FIREFOX, deviceAnswers, deviceId, deviceWorld, loginStartRes, METHODS, methodsRes, REFRESH } from "./deviceSessionHelpers.mjs";
import { freshStore } from "./idbHelpers.mjs";
import { ACCOUNT, answer, claimsOf, headerOf, LOCAL_MS, loginRes, refusal, SERVER, tok, VAULT, verifies } from "./tokenHelpers.mjs";

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
  const record = await world.record();
  assert.ok(record);

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
  assert.deepEqual(headerOf(proof), { typ: "dpop+jwt", alg: "ES256", jwk: { ...record.publicJwk } });
  const claims = claimsOf(proof);
  assert.equal(claims.htm, "POST");
  assert.equal(claims.htu, `${SERVER}${LOGIN_FINISH_PATH}`);
  assert.ok(!("ath" in claims));
  assert.ok(await verifies(proof, record.publicJwk), "signed by the device key");

  // After the sign-in the device's calls carry its token and a proof with `ath`.
  assert.equal(methods.headers.Authorization, `DPoP ${tok(1)}`);
  assert.ok("ath" in claimsOf(methods.headers.DPoP));
  assert.ok(await verifies(methods.headers.DPoP, record.publicJwk));

  // A device never asks the cookie route of the session.
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
  assert.equal(await world.session.deviceState(), "ok");
  // The clock the refusal taught stays for the device's later proofs.
  assert.equal(claimsOf(world.server.to(METHODS)[0].headers.DPoP).iat, serverMs / 1000);
});

test("device_mode_saves_tokens_and_the_server_device_id", async () => {
  const world = await deviceWorld();
  assert.equal(await world.session.deviceState(), "signed_out");
  const unlocked = await signIn(world, { rememberSk: true });

  // The record of the key holds the server's device id, the account and the refresh token; the access token is in memory.
  const record = await world.record();
  assert.ok(record);
  assert.equal(record.deviceId, deviceId(0));
  assert.equal(record.accountId, ACCOUNT);
  assert.equal(record.refreshToken, tok(2));
  assert.equal(await world.session.deviceState(), "ok");
  assert.equal(world.server.to(METHODS)[0].headers.Authorization, `DPoP ${tok(1)}`);

  // The vault is open and pinned as for the web vault; no browser id was made for a device the server names.
  assert.deepEqual([unlocked.accountId, unlocked.vaultId, unlocked.vkEpoch, unlocked.email], [ACCOUNT, VAULT, 1, EMAIL]);
  assert.equal(world.session.current()?.accountId, ACCOUNT);
  assert.ok(await loadPinned(world.db.store, SERVER, EMAIL));
  assert.equal(await getSetting(world.db.store, "device_id"), undefined);

  // No token reaches what the sign-in gives back.
  const shown = JSON.stringify(unlocked);
  for (const token of [tok(1), tok(2)]) assert.ok(!shown.includes(token));

  // A later start of the extension (a new session on the same store) finds the device and its tokens.
  const restarted = await deviceWorld({ db: world.db });
  assert.equal(await restarted.session.deviceState(), "ok");
});

test("a_full_sign_in_signs_the_older_device_out_before_the_new_one_is_added", async () => {
  // At the quota a new device fits only once the older one is gone: the older one is signed out before login/finish.
  const world = await deviceWorld();
  await signIn(world);
  const older = await world.record();
  world.server.calls.length = 0;
  await signIn(world);
  const paths = world.server.calls.map((call) => call.path);
  assert.deepEqual(paths, [LOGIN_START_PATH, REVOKE_PATH, LOGIN_FINISH_PATH, METHODS]);
  const [revoke] = world.server.to(REVOKE_PATH);
  assert.deepEqual(revoke.body, { refresh_token: tok(2) });
  assert.ok(older && (await verifies(revoke.headers.DPoP, older.publicJwk)), "signed by the older key");
  // The new device is the session's now: its token, its record.
  assert.equal(world.server.to(METHODS)[0].headers.Authorization, `DPoP ${tok(11)}`);
  assert.equal((await world.record())?.deviceId, deviceId(1));
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
  const [finish] = world.server.to(LOGIN_FINISH_PATH);
  assert.ok(await verifies(revoke.headers.DPoP, headerOf(finish.headers.DPoP).jwk), "signed by the new key");
  assert.equal(revoke.init.credentials, "omit");
  assert.equal(await world.record(), null);
  assert.equal(await world.session.deviceState(), "signed_out");
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
  assert.equal(await other.record(), null);
  assert.equal(await other.session.deviceState(), "signed_out");
});

test("a_device_is_never_offered_the_recovery", async () => {
  // An older password wrap than the pin: the web vault may offer the recovery key; a device is not offered it and
  // asks the server nothing more.
  const world = await deviceWorld({ handlers: { unlock_password: () => { throw coded("pinned_kek_generation"); } } });
  const error = await signIn(world).catch((e) => e);
  assert.equal(error.code, "pinned_kek_generation");
  assert.equal(error.recoveryOffer, undefined);
  assert.ok(!world.server.calls.some((call) => call.path.startsWith("/api/sync/")));
  assert.equal(world.server.to(REVOKE_PATH).length, 1);
});

test("a_device_sign_in_that_never_reached_the_server_keeps_nothing", async () => {
  // A wrong password is found by the core before KE3: no login/finish is sent, no device is made.
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
  assert.equal(await world.session.deviceState(), "signed_out");
  assert.equal(await world.record(), null);
  wrong = false;
  await signIn(world);
  assert.equal(await world.session.deviceState(), "ok");
  assert.equal(world.server.to(LOGIN_FINISH_PATH).length, 1);
});

test("a_device_unlock_after_lock_keeps_its_device_and_posts_no_ke3", async () => {
  const world = await deviceWorld();
  await signIn(world, { rememberSk: true });
  const before = await world.record();
  await world.session.lock();
  assert.equal(world.session.current(), null);
  // A lock revokes nothing.
  assert.equal(world.server.to(REVOKE_PATH).length, 0);
  assert.equal(await world.session.deviceState(), "ok");
  world.server.calls.length = 0;

  // The password alone: the e-mail and the account come from the device's record and pin, the secret key from the device.
  const unlocked = await world.session.unlock({ password: PASSWORD });
  assert.equal(unlocked.purpose, "unlock");
  assert.deepEqual([unlocked.accountId, unlocked.vaultId, unlocked.email], [ACCOUNT, VAULT, EMAIL]);
  assert.equal(world.session.current()?.accountId, ACCOUNT);
  // login/start, then (the password proved on the device) the token; no login/finish (no KE3), no new device, no new
  // tokens, no sign-out.
  assert.deepEqual(world.server.calls.map((call) => call.path), [LOGIN_START_PATH, METHODS]);
  const [start, methods] = world.server.calls;
  assert.equal(methods.headers.Authorization, `DPoP ${tok(1)}`);
  assert.ok(!("Authorization" in start.headers) && !("DPoP" in start.headers));
  assert.equal(start.init.credentials, "omit");
  assert.deepEqual(start.body.email, EMAIL);
  assert.equal(start.body.purpose, "login");
  const after = await world.record();
  assert.equal(after?.deviceId, before?.deviceId);
  assert.equal(after?.refreshToken, before?.refreshToken);
  // The core ran its side of the finish under the pin and opened the wrap of the device's account.
  const early = world.client.called("login_finish").at(-1).snapshot[2];
  assert.equal(early.kind, "pinned");
  assert.equal(world.client.called("unlock_password").at(-1).snapshot[3].kind, "pinned");
  assert.equal(world.client.called("login_start").at(-1).snapshot[1], SK_CODE);
  assert.equal(world.session.freshReauth(), false, "an unlock is no re-authentication");

  // Again, after a restart of the extension: the stored device unlocks the same way (its first request renews the token).
  const restarted = await deviceWorld({ db: world.db });
  restarted.server.handle = deviceAnswers({
    [REFRESH]: () => answer(200, { access_token: tok(5), refresh_token: tok(6), token_type: "DPoP", expires_in: 900 }),
  });
  await restarted.session.unlock({ password: PASSWORD });
  assert.deepEqual(restarted.server.calls.map((call) => call.path), [LOGIN_START_PATH, REFRESH, METHODS]);
  assert.equal(restarted.server.to(METHODS)[0].headers.Authorization, `DPoP ${tok(5)}`);
  assert.equal((await restarted.record())?.deviceId, before?.deviceId);
});

test("a_wrong_master_password_at_unlock_leaves_the_server_state_alone", async () => {
  let wrong = false;
  const world = await deviceWorld({
    handlers: {
      login_finish: () => {
        if (wrong) throw coded("decrypt");
        return { ke3: new Uint8Array(64).fill(2), server_public_key: new Uint8Array(32).fill(9) };
      },
    },
  });
  await signIn(world, { rememberSk: true });
  const before = await world.record();
  await world.session.lock();
  world.server.calls.length = 0;
  wrong = true;
  await assert.rejects(world.session.unlock({ password: "not-the-password" }), { code: "decrypt" });
  // Nothing but login/start (whose state the server drops after a minute): no token read, no KE3, no device, no sign-out.
  assert.deepEqual(world.server.calls.map((call) => call.path), [LOGIN_START_PATH]);
  const kept = await world.record();
  assert.deepEqual([kept?.deviceId, kept?.refreshToken], [before?.deviceId, before?.refreshToken]);
  assert.equal(await world.session.deviceState(), "ok");
  assert.equal(world.session.current(), null);
  assert.ok(world.client.called("clear").length >= 1, "the core drops what it holds");
  // The right password then opens the vault on the same device.
  wrong = false;
  await world.session.unlock({ password: PASSWORD });
  assert.equal(world.server.to(LOGIN_FINISH_PATH).length, 0);
  assert.equal((await world.record())?.deviceId, before?.deviceId);

  // The access token expired during the lock (here: a restart, which keeps none): a wrong password still renews nothing.
  const restarted = await deviceWorld({
    db: world.db,
    handlers: { login_finish: () => { throw coded("decrypt"); } },
    overrides: { [REFRESH]: () => answer(200, { access_token: tok(5), refresh_token: tok(6), token_type: "DPoP", expires_in: 900 }) },
  });
  const stored = await restarted.record();
  await assert.rejects(restarted.session.unlock({ password: "not-the-password" }), { code: "decrypt" });
  assert.deepEqual(restarted.server.calls.map((call) => call.path), [LOGIN_START_PATH], "no token/refresh, no token read");
  const still = await restarted.record();
  assert.deepEqual([still?.deviceId, still?.refreshToken], [stored?.deviceId, stored?.refreshToken]);
  assert.equal(await restarted.session.deviceState(), "ok");
});

test("a_revoked_device_unlock_falls_back_to_a_new_sign_in", async () => {
  const world = await deviceWorld();
  await signIn(world, { rememberSk: true });
  await world.session.lock();
  // The device was revoked in the web vault while the extension was locked.
  const usual = world.server.handle;
  let revoked = true;
  world.server.handle = (call) => {
    if (revoked && call.path === METHODS) {
      revoked = false;
      return refusal("device_revoked");
    }
    return usual(call);
  };
  world.server.calls.length = 0;
  const unlocked = await world.session.unlock({ password: PASSWORD });
  // The refusal ends the old tokens; the same password signs the extension in as a new device.
  assert.equal(unlocked.purpose, "login");
  assert.deepEqual(world.server.calls.map((call) => call.path), [LOGIN_START_PATH, METHODS, LOGIN_START_PATH, LOGIN_FINISH_PATH, METHODS]);
  assert.equal(world.server.to(METHODS)[0].headers.Authorization, `DPoP ${tok(1)}`, "the old device's token");
  assert.equal(world.server.to(METHODS)[1].headers.Authorization, `DPoP ${tok(11)}`, "the new device's first token");
  assert.equal((await world.record())?.deviceId, deviceId(1), "the new device's id");
  assert.equal(await world.session.deviceState(), "ok");
  assert.equal(world.session.current()?.accountId, ACCOUNT);

  // An expired refresh token ends the same way, and so does a device whose record is gone.
  const expired = await deviceWorld();
  await signIn(expired, { rememberSk: true });
  const restarted = await deviceWorld({ db: expired.db, overrides: { [REFRESH]: () => refusal("token_expired") } });
  const again = await restarted.session.unlock({ password: PASSWORD });
  assert.equal(again.purpose, "login");
  assert.equal(restarted.server.to(LOGIN_FINISH_PATH).length, 1);

  // With no device and no e-mail there is nothing to unlock: a sign-in needs the e-mail.
  const none = await deviceWorld();
  await assert.rejects(none.session.unlock({ password: PASSWORD }), { code: "session_ended" });
  assert.equal(none.server.calls.length, 0);
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
  assert.equal(await world.session.deviceState(), "ok");
  assert.equal(world.session.current()?.accountId, ACCOUNT);

  // A known field with a wrong value is still refused, and so the device is signed out again.
  const bad = await deviceWorld({ overrides: { [METHODS]: () => answer(200, { ...methodsRes(), vk_epoch: "1" }) } });
  await assert.rejects(signIn(bad), { code: "bad_response" });
  assert.equal(bad.server.to(REVOKE_PATH).length, 1);
});
