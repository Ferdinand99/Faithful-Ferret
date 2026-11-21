// Helpers for the tests of the session in device mode: a device client (the
// extension) whose session keeps its own device key and tokens, the real local
// stores, the fake crypto client of the account tests and a fake server that
// answers like the vault server does for a device.
import { b64u } from "../../src/b64.mjs";
import { loadDeviceKey } from "../../src/auth/deviceKey.mjs";
import { LOGIN_FINISH_PATH, LOGIN_START_PATH, REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { createCryptoSession } from "../../src/crypto/session.mjs";
import storeDef from "../../src/services/store.service.mjs";
import { fakeClient, filled } from "./accountHelpers.mjs";
import { freshStore } from "./idbHelpers.mjs";
import { answer, DEVICE, fakeLocks, fakeServer, LOCAL_MS, loginRes, SERVER, tok } from "./tokenHelpers.mjs";

export const DEVICE_NAME_FIREFOX = "Ferret for Firefox (Windows)";
export const METHODS = "/api/vault/unlock-methods";
export const REFRESH = "/api/auth/token/refresh";

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

/** The device id the n-th sign-in (from 0) gets. @param {number} n */
export const deviceId = (n) => `${DEVICE.slice(0, -1)}${n}`;

/**
 * The server's answers to a device, by path. `overrides[path]` may answer a call
 * instead (return a Response), or return nothing to let the default answer. Each
 * sign-in gives new tokens: the n-th (from 0) gives `tok(10n + 1)` and
 * `tok(10n + 2)`, and the device id `deviceId(n)`.
 * @param {Record<string, (call: any) => Response | undefined>} [overrides]
 */
export function deviceAnswers(overrides = {}) {
  let signIns = 0;
  return (/** @type {any} */ call) => {
    const custom = overrides[call.path]?.(call);
    if (custom) return custom;
    switch (call.path) {
      case LOGIN_START_PATH:
        return answer(200, loginStartRes());
      case LOGIN_FINISH_PATH: {
        const n = signIns;
        signIns += 1;
        return answer(200, { ...loginRes(tok(10 * n + 1), tok(10 * n + 2)), device_id: deviceId(n) });
      }
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
 * A device client: a session in device mode on a fresh store (or `db`), with the
 * fake client and server. Its key and tokens are the session's own.
 * @param {{ handlers?: Record<string, Function>, overrides?: Record<string, Function>, now?: () => number, db?: any, session?: Record<string, unknown> }} [options]
 */
export async function deviceWorld({ handlers = {}, overrides = {}, now = () => LOCAL_MS, db: given, session: extra = {} } = {}) {
  const log = [];
  const db = given ?? (await freshStore());
  const client = fakeClient({ log, handlers });
  const server = fakeServer();
  server.handle = deviceAnswers(overrides);
  const store = { ...storeDef.create({}), open: async () => db.store };
  const options = {
    client,
    store,
    serverUrl: SERVER,
    mode: /** @type {const} */ ("device"),
    deviceName: DEVICE_NAME_FIREFOX,
    platform: "windows",
    fetchImpl: server.fetchImpl,
    locks: fakeLocks(),
    now,
    ...extra,
  };
  const session = createCryptoSession(/** @type {any} */ (options));
  /** The stored record of the device, or null. */
  const record = () => loadDeviceKey(db.store, SERVER);
  return { log, db, client, server, store, session, options, record };
}
