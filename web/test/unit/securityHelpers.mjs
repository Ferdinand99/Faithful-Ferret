// Helpers for the tests of re-authentication, signed calls and the password change:
// an account that is signed in (so a vault is open and this device holds its pinned
// record), a fake server that also answers the calls these flows make, and a fake
// crypto client that answers the core's calls. Every value here is a test value.
import { b64u } from "../../src/b64.mjs";
import { ACCOUNT, EMAIL, PASSWORD, SK_CODE, filled, pinnedRecord, scenario } from "./accountHelpers.mjs";

export { ACCOUNT, EMAIL, PASSWORD, SK_CODE, filled, pinnedRecord };

export const NEW_PASSWORD = "another-test-password-for-unit-tests";
export const NONCE = filled(32, 7);
export const PROOF = filled(64, 5);
export const GRANT = filled(32, 3);

/** An answer of the fake server. */
export const answer = (status, body, headers = {}) =>
  new Response(body === null ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

/** What the core's `change_password` gives for the fake: generation 2 and a record with the new floor. */
export function changed({ skBit = true } = {}) {
  return {
    wrap: { method_id: filled(16, 0x11), kek_generation: 2, method: { type: "password", ksf_profile: 1 }, wrap: filled(104, 8) },
    manifest: { rev: 2, envelope: filled(80, 9), tag: filled(32, 10) },
    registration_record: filled(192, 11),
    ksf_profile: 1,
    server_public_key: filled(32, 9),
    pinned: pinnedRecord({ skBit, floors: [["password", 2], ["recovery", 1]] }),
  };
}

/**
 * A world in which the account is signed in. The log, the requests and the client calls of the sign-in are
 * dropped, so a test sees only what it did itself. `reauthUntil` (seconds) is what the session answer says.
 * @param {object} [options]
 */
export async function signedInWorld({ skBit = true, forgetKey = false, handlers: extraHandlers = {}, overrides: extraOverrides = {}, reauthUntil = null, putStatus = 200, putBody, createImportWorker } = {}) {
  /** The signed PUTs the fake server received: `{ headers, bytes }`. */
  const puts = [];
  // The test's own handlers and answers are put in after the sign-in, which must go through as the defaults make it.
  const handlers = {
    check_master_password: () => undefined,
    auth_sign: () => PROOF,
    reauth_grant: () => GRANT,
    change_password: () => changed({ skBit }),
  };
  const overrides = {
    "GET /api/auth/session": (_body, state) =>
      state.signedIn
        ? answer(200, { account_id: ACCOUNT, email: EMAIL, scope: "full", origin: "vault", ...(reauthUntil === null ? {} : { reauth_until: reauthUntil }) })
        : answer(401, { error: "unauthorized" }),
    "POST /api/auth/challenge": () => answer(200, { nonce: b64u.encode(NONCE), expires_in: 300 }),
    "POST /api/auth/opaque/reregister/start": () => answer(200, { registration_response: b64u.encode(filled(64, 3)) }),
    "PUT /api/vault/unlock-methods/password": (body, state) => {
      puts.push({ headers: state.requests.at(-1).headers, body });
      return putStatus === 200 ? answer(200, putBody ?? { kek_generation: 2, seq: 12 }) : answer(putStatus, putBody ?? { error: "write_conflict" });
    },
  };
  const world = await scenario({ skBit, handlers, overrides, createImportWorker });
  world.puts = puts;
  await world.session.signIn({ email: EMAIL, password: PASSWORD, skBit, skCode: skBit ? SK_CODE : undefined, rememberSk: skBit });
  if (forgetKey) await world.session.forgetSecretKey(ACCOUNT);
  Object.assign(handlers, extraHandlers);
  Object.assign(overrides, extraOverrides);
  world.log.length = 0;
  world.requests.length = 0;
  world.client.calls.length = 0;
  return world;
}
