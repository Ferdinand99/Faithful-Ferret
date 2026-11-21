// The session in device mode: what it must be given, and its unlock, sign-out
// and session info for a device client. Spec: Fase 1 § 7.6.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { generateDeviceKey, loadDeviceKey } from "../../src/auth/deviceKey.mjs";
import { LOGIN_START_PATH, REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { createCryptoSession, SESSION_MODES } from "../../src/crypto/session.mjs";
import { createVaultSession } from "../../src/crypto/vaultSession.mjs";
import { EMAIL, fakeClient, PASSWORD, SK_CODE } from "./accountHelpers.mjs";
import { deviceWorld } from "./deviceSessionHelpers.mjs";
import { SERVER, tok } from "./tokenHelpers.mjs";

test("device_mode_without_server_url_throws", async () => {
  const world = await deviceWorld();
  const { serverUrl, ...rest } = world.options;
  assert.equal(serverUrl, SERVER);
  // The page of a device client is no server: without an address nothing is made, also where a page has a location.
  const saved = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "location", { value: { origin: SERVER }, configurable: true });
  try {
    assert.throws(() => createCryptoSession(rest), TypeError);
    assert.throws(() => createCryptoSession({ ...rest, serverUrl: undefined }), TypeError);
  } finally {
    if (saved) Object.defineProperty(globalThis, "location", saved);
    else delete (/** @type {any} */ (globalThis)).location;
  }
  // An address that is not a server's is refused as in the web vault.
  assert.throws(() => createCryptoSession({ ...rest, serverUrl: "ftp://x" }), TypeError);
  assert.equal(world.server.calls.length, 0);
});

test("a_device_session_is_given_its_tokens_its_key_and_a_name_and_platform_the_server_takes", async () => {
  const world = await deviceWorld();
  const { options } = world;
  assert.equal(createCryptoSession(options).mode, "device");
  assert.deepEqual(SESSION_MODES, ["cookie", "device"]);
  const otherServer = await generateDeviceKey("https://other.example");
  /** @type {Array<[string, Record<string, unknown>]>} */
  const bad = [
    ["an unknown mode", { mode: "token" }],
    ["no tokens", { tokens: undefined }],
    ["tokens that are not", { tokens: { revoke() {} } }],
    ["no key", { deviceKey: undefined }],
    ["the key of another server", { deviceKey: otherServer }],
    ["an unknown platform", { platform: "win" }],
    ["an empty name", { deviceName: "" }],
    ["a name of 65 characters", { deviceName: "x".repeat(65) }],
    ["a name with a control character", { deviceName: "Ferret\u0007" }],
    ["a name with an invisible character", { deviceName: "Ferret​" }],
  ];
  for (const [label, change] of bad) assert.throws(() => createCryptoSession({ ...options, ...change }), TypeError, label);
  assert.doesNotThrow(() => createCryptoSession({ ...options, deviceName: "x".repeat(64), platform: "other" }));

  // The web vault's session holds no device key and no tokens, so the two modes cannot be mixed.
  const cookie = { client: fakeClient(), api: createApi(), store: world.store, serverUrl: SERVER };
  assert.equal(createCryptoSession(cookie).mode, "cookie");
  assert.throws(() => createCryptoSession({ ...cookie, tokens: world.tokens }), TypeError);
  assert.throws(() => createCryptoSession({ ...cookie, deviceKey: world.deviceKey }), TypeError);
  assert.throws(() => createVaultSession(/** @type {any} */ ({ ...cookie, tokens: world.tokens })), TypeError);
  assert.equal(createVaultSession(/** @type {any} */ ({ ...cookie, mode: "device" })).mode, "cookie", "the web vault's session is always the cookie one");
  assert.equal(world.server.calls.length, 0, "nothing is sent while a session is made");
});

test("a_device_session_has_no_cookie_session_to_ask_or_re_authenticate", async () => {
  const world = await deviceWorld();
  // No session route: the answer is null, and no request is made.
  assert.equal(await world.session.info(), null);
  // An unlock is a sign-in of the device: without an e-mail it cannot start, and nothing is sent.
  await assert.rejects(world.session.unlock({ password: PASSWORD }), { code: "session_ended" });
  assert.equal(world.server.calls.length, 0);
  // With the e-mail it signs the device in (the purpose is `login`; a device has no re-authentication).
  const unlocked = await world.session.unlock({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE });
  assert.equal(unlocked.purpose, "login");
  assert.equal(world.server.to(LOGIN_START_PATH)[0].body.purpose, "login");
  assert.equal(world.session.freshReauth(), false);
  assert.equal(world.session.reauthUntil(), null);
});

test("a_device_signs_out_with_its_tokens_and_forgets_them", async () => {
  const world = await deviceWorld();
  await world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE });
  await world.session.signOut();
  const [revoke] = world.server.to(REVOKE_PATH);
  assert.deepEqual(revoke.body, { refresh_token: tok(2) });
  assert.ok(!world.server.calls.some((call) => call.path === "/api/auth/logout"));
  assert.equal(world.tokens.state, "signed_out");
  assert.equal(await loadDeviceKey(world.db.store, SERVER), null);
  assert.equal(world.session.current(), null);

  // A server that cannot be reached: the tokens are forgotten all the same, and the error says the sign-out is incomplete.
  const offline = await deviceWorld({
    overrides: {
      [REVOKE_PATH]: () => {
        throw new TypeError("offline");
      },
    },
  });
  await offline.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE });
  await assert.rejects(offline.session.signOut(), { code: "signout_incomplete" });
  assert.equal(offline.tokens.state, "signed_out");
  assert.equal(await loadDeviceKey(offline.db.store, SERVER), null);
});
