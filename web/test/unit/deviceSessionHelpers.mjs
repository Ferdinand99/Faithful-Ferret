// Helpers for the tests of the session in device mode: a device client (the
// extension) with a new device key, its tokens, the API client with them, the
// real local stores, the fake crypto client of the account tests and a fake
// server that answers like the vault server does for a device.
import { createApi } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { generateDeviceKey } from "../../src/auth/deviceKey.mjs";
import { createClock } from "../../src/auth/dpop.mjs";
import { createTokenAuth, LOGIN_FINISH_PATH, LOGIN_START_PATH, REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { createCryptoSession } from "../../src/crypto/session.mjs";
import storeDef from "../../src/services/store.service.mjs";
import { fakeClient, filled } from "./accountHelpers.mjs";
import { freshStore } from "./idbHelpers.mjs";
import { answer, fakeLocks, fakeServer, LOCAL_MS, loginRes, SERVER } from "./tokenHelpers.mjs";

export const DEVICE_NAME_FIREFOX = "Ferret for Firefox (Windows)";
export const METHODS = "/api/vault/unlock-methods";

/** The answer of `GET /api/vault/unlock-methods` that the fake client's account has. */
export const methodsRes = () => ({
  methods: [
    { method_id: "11".repeat(16), method_type: 1, kek_generation: 1, wrap: b64u.encode(filled(104, 5)) },
    { method_id: "22".repeat(16), method_type: 2, kek_generation: 1, wrap: b64u.encode(filled(72, 6)) },
  ],
  pk_a: b64u.encode(filled(32, 3)),
  vk_epoch: 1,
  manifest: { rev: 1, envelope: b64u.encode(filled(80, 4)), tag: b64u.encode(filled(32, 5)) },
});

/** The answer of `login/start`. */
export const loginStartRes = () => ({ login_id: "cd".repeat(16), ke2: b64u.encode(filled(320, 4)), ksf_profile: 1, sk_hint: true });

/**
 * The server's answers to a device, by path. `overrides[path]` may answer a call
 * instead (return a Response), or return nothing to let the default answer.
 * @param {Record<string, (call: any) => Response | undefined>} [overrides]
 */
export function deviceAnswers(overrides = {}) {
  return (/** @type {any} */ call) => {
    const custom = overrides[call.path]?.(call);
    if (custom) return custom;
    switch (call.path) {
      case LOGIN_START_PATH:
        return answer(200, loginStartRes());
      case LOGIN_FINISH_PATH:
        return answer(200, loginRes());
      case METHODS:
        return answer(200, methodsRes());
      case REVOKE_PATH:
        return answer(204, null);
      default:
        return answer(404, { error: "not_found" });
    }
  };
}

/**
 * A device client before its sign-in: a new key, its tokens, the API client
 * with them and a session in device mode.
 * @param {{ handlers?: Record<string, Function>, overrides?: Record<string, Function>, now?: () => number, db?: any, session?: Record<string, unknown> }} [options]
 */
export async function deviceWorld({ handlers = {}, overrides = {}, now = () => LOCAL_MS, db: given, session: extra = {} } = {}) {
  const log = [];
  const db = given ?? (await freshStore());
  const client = fakeClient({ log, handlers });
  const server = fakeServer();
  server.handle = deviceAnswers(overrides);
  const clock = createClock({ now });
  const deviceKey = await generateDeviceKey(SERVER);
  const tokens = createTokenAuth({ serverUrl: SERVER, store: db.store, key: deviceKey, clock, fetchImpl: server.fetchImpl, locks: fakeLocks() });
  const api = createApi({ base: SERVER, fetchImpl: server.fetchImpl, auth: tokens });
  const store = { ...storeDef.create({}), open: async () => db.store };
  const options = {
    client,
    api,
    store,
    serverUrl: SERVER,
    mode: /** @type {const} */ ("device"),
    deviceName: DEVICE_NAME_FIREFOX,
    platform: "windows",
    tokens,
    deviceKey,
    ...extra,
  };
  const session = createCryptoSession(options);
  return { log, db, client, server, clock, deviceKey, tokens, api, store, session, options };
}
