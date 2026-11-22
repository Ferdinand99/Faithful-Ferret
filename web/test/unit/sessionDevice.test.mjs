// The session in device mode: what it must be given, and its session info and
// sign-out for a device client. Spec: Fase 1 § 7.6.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { createCryptoSession, SESSION_MODES } from "../../src/crypto/session.mjs";
import { createVaultSession } from "../../src/crypto/vaultSession.mjs";
import { ACCOUNT, EMAIL, fakeClient, PASSWORD, SK_CODE } from "./accountHelpers.mjs";
import { deviceWorld } from "./deviceSessionHelpers.mjs";
import { SERVER, tok } from "./tokenHelpers.mjs";

const signIn = (/** @type {any} */ world) => world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE });

test("device_mode_without_server_url_throws", async () => {
  const world = await deviceWorld();
  const { serverUrl, ...rest } = world.options;
  assert.equal(serverUrl, SERVER);
  // The page of a device client is no server: without an address nothing is made, also where a page has a location.
  const saved = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "location", { value: { origin: SERVER }, configurable: true });
  try {
    assert.throws(() => createCryptoSession(/** @type {any} */ (rest)), TypeError);
    assert.throws(() => createCryptoSession(/** @type {any} */ ({ ...rest, serverUrl: undefined })), TypeError);
  } finally {
    if (saved) Object.defineProperty(globalThis, "location", saved);
    else delete (/** @type {any} */ (globalThis)).location;
  }
  // An address that is not a server's is refused as in the web vault.
  assert.throws(() => createCryptoSession(/** @type {any} */ ({ ...rest, serverUrl: "ftp://x" })), TypeError);
  assert.equal(world.server.calls.length, 0);
});

test("a_device_session_names_its_device_and_makes_its_own_api_client", async () => {
  const world = await deviceWorld();
  const options = /** @type {any} */ (world.options);
  assert.equal(createCryptoSession(options).mode, "device");
  assert.deepEqual(SESSION_MODES, ["cookie", "device"]);
  /** @type {Array<[string, Record<string, unknown>]>} */
  const bad = [
    ["an unknown mode", { mode: "token" }],
    // A device that forgets its name would be listed as the web vault.
    ["no name", { deviceName: undefined }],
    ["an unknown platform", { platform: "win" }],
    ["an empty name", { deviceName: "" }],
    ["a name of 65 characters", { deviceName: "x".repeat(65) }],
    ["a name with a control character", { deviceName: "Ferret\u0007" }],
    ["a name with an invisible character", { deviceName: "Ferret​" }],
    // A device's requests carry its own tokens: an API client from outside is refused.
    ["an API client of the caller", { api: createApi() }],
  ];
  for (const [label, change] of bad) assert.throws(() => createCryptoSession({ ...options, ...change }), TypeError, label);
  assert.doesNotThrow(() => createCryptoSession({ ...options, deviceName: "x".repeat(64), platform: "other" }));

  // The web vault's session takes its API client and stays the cookie one.
  const cookie = { client: fakeClient(), api: createApi(), store: world.store, serverUrl: SERVER };
  const web = createCryptoSession(cookie);
  assert.equal(web.mode, "cookie");
  assert.equal(web.api, cookie.api);
  assert.equal(await web.deviceState(), null);
  assert.throws(() => createCryptoSession({ ...cookie, api: undefined }), TypeError);
  assert.equal(createVaultSession(/** @type {any} */ ({ ...cookie, mode: "device" })).mode, "cookie", "the web vault's session is always the cookie one");
  assert.equal(world.server.calls.length, 0, "nothing is sent while a session is made");

  // The device session's own client carries the device's token; without a device it sends nothing.
  const device = createCryptoSession(options);
  await assert.rejects(device.api.get("/api/sync/changes?since=0&limit=1"), { status: 401, code: "signed_out" });
  assert.equal(world.server.calls.length, 0);
  await signIn({ session: device });
  assert.equal(world.server.calls.at(-1)?.headers.Authorization, `DPoP ${tok(1)}`);
});

test("a_device_session_has_no_cookie_session_to_ask", async () => {
  const world = await deviceWorld();
  // No session route: the answer is null, and no request is made.
  assert.equal(await world.session.info(), null);
  assert.equal(world.server.calls.length, 0);
});

test("a_device_signs_out_with_its_tokens_and_forgets_them", async () => {
  const world = await deviceWorld();
  await signIn(world);
  await world.session.signOut();
  const [revoke] = world.server.to(REVOKE_PATH);
  assert.deepEqual(revoke.body, { refresh_token: tok(2) });
  assert.ok(!world.server.calls.some((call) => call.path === "/api/auth/logout"));
  assert.equal(await world.session.deviceState(), "signed_out");
  assert.equal(await world.record(), null);
  assert.equal(world.session.current(), null);

  // A server that cannot be reached: the tokens are forgotten all the same, and the error says the sign-out is incomplete.
  const offline = await deviceWorld({
    overrides: {
      [REVOKE_PATH]: () => {
        throw new TypeError("offline");
      },
    },
  });
  await signIn(offline);
  await assert.rejects(offline.session.signOut(), { code: "signout_incomplete" });
  assert.equal(await offline.session.deviceState(), "signed_out");
  assert.equal(await offline.record(), null);
});

test("a_device_signed_out_while_locked_clears_the_cached_rows_of_its_account", async () => {
  const world = await deviceWorld();
  await signIn(world);
  await world.session.lock();
  // The extension is locked most of the time: its account comes from the device's record.
  /** @type {string[]} */
  const cleared = [];
  world.store.cache = { ...world.store.cache, clearAccount: async (/** @type {any} */ _db, /** @type {string} */ accountId) => void cleared.push(accountId) };
  await world.session.signOut();
  assert.deepEqual(cleared, [ACCOUNT]);
  assert.equal(world.server.to(REVOKE_PATH).length, 1);

  // A restarted extension that never unlocked does the same.
  const other = await deviceWorld();
  await signIn(other);
  const restarted = await deviceWorld({ db: other.db });
  /** @type {string[]} */
  const also = [];
  restarted.store.cache = { ...restarted.store.cache, clearAccount: async (/** @type {any} */ _db, /** @type {string} */ accountId) => void also.push(accountId) };
  await restarted.session.signOut();
  assert.deepEqual(also, [ACCOUNT]);
  assert.equal(await restarted.record(), null);
});
