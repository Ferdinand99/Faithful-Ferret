// Helpers for the tests of the recovery: a fake server that also answers the one-time code,
// the recovery wrap and the recovery request, a fake core that answers `recover`, and the
// env the flow takes. Every value here is a test value; none is a real key, password or code.
import { b64u, hex16 } from "../../src/b64.mjs";
import { recoverAccount } from "../../src/flows/recover.mjs";
import { ACCOUNT, EMAIL, PASSWORD, RK_CODE, SERVER, SK_CODE, VAULT, coded, filled, pinnedRecord, scenario } from "./accountHelpers.mjs";
import { SERVER_KEY, parseQr, qrText } from "./setupQrHelpers.mjs";

export { ACCOUNT, EMAIL, PASSWORD, RK_CODE, SERVER, SK_CODE, VAULT, coded, filled, pinnedRecord, qrText, SERVER_KEY };

export const CODE = "TESTCODE-0123456789";
export const NEW_PASSWORD = "a-new-test-password-for-recovery";
export const NEW_RK = "FFR1-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK-NEWK";
export const RK_TYPO = "FFR1-TYPO-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST";
export const NONCE = filled(32, 7);
export const PROOF = filled(64, 5);
export const ID_RECOVERY = "22".repeat(16);

const json = (value, status = 200, headers = {}) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });

/** What the core's `recover` gives in the fake: both generations raised to 2, and the record to pin. */
export function recoveredDto({ skBit = true, floors = [["password", 2], ["recovery", 2]] } = {}) {
  return {
    password_wrap: { method_id: filled(16, 0x11), kek_generation: 2, method: { type: "password", ksf_profile: 1 }, wrap: filled(104, 8) },
    recovery_wrap: { method_id: hex16.decode(ID_RECOVERY), kek_generation: 2, method: { type: "recovery" }, wrap: filled(72, 12) },
    manifest: { rev: 2, envelope: filled(80, 9), tag: filled(32, 10) },
    pk_r: filled(32, 13),
    registration_record: filled(192, 11),
    ksf_profile: 1,
    server_public_key: SERVER_KEY,
    sk_bit: skBit,
    pinned: pinnedRecord({ skBit, floors, serverKey: 9 }),
  };
}

/**
 * A world for the recovery: the fake server answers the redeem (`CODE` for `EMAIL`), the recovery wrap and the
 * recovery request; the fake core answers `recover` and friends. `session` is the session the server has at the
 * start: null, "full" or "account_reset". `recovers` holds the signed recovery requests the server received.
 * @param {object} [options]
 */
export async function recoverWorld({
  skBit = true,
  session = null,
  handlers: extraHandlers = {},
  overrides: extraOverrides = {},
  recoverStatus = 200,
  recoverBody,
  redeemStatus = null,
  serverRecoveryGeneration = 1,
  serverPasswordGeneration = 1,
  restoreEpoch = 0,
} = {}) {
  const recovers = [];
  const handlers = {
    check_code: (kind, code) => {
      if (kind !== "recovery_key" && kind !== "secret_key") throw coded("invalid_input");
      if (String(code).includes("TYPO")) throw coded("checksum");
    },
    setup_qr_parse: parseQr,
    setup_qr_build: (url, account, profile, sk, key) =>
      qrText({ url, account: hex16.encode(account), profile, sk, key }),
    recover: () => recoveredDto({ skBit }),
    reveal_recovery_code: () => NEW_RK,
    verify_recovery_setup: (typed) => {
      if (typed !== NEW_RK) throw coded("decrypt");
    },
    recover_sign: () => PROOF,
    // The sign-in after the recovery: the core gives back the record it was handed (its floors stay).
    unlock_password: (_server, _ctx, _wrap, pin) => ({ pinned: pin.kind === "pinned" ? pin.record : pinnedRecord({ skBit }) }),
    ...extraHandlers,
  };
  const methods = () =>
    json({
      methods: [
        { method_id: "11".repeat(16), method_type: 1, kek_generation: serverPasswordGeneration, wrap: b64u.encode(filled(104, 5)) },
        { method_id: ID_RECOVERY, method_type: 2, kek_generation: serverRecoveryGeneration, wrap: b64u.encode(filled(72, 6)) },
      ],
      pk_a: b64u.encode(filled(32, 3)),
      vk_epoch: 1,
      manifest: { rev: 1, envelope: b64u.encode(filled(80, 4)), tag: b64u.encode(filled(32, 5)) },
    });
  const overrides = {
    "GET /api/auth/session": (_body, state) => {
      if (state.signedIn) return json({ account_id: ACCOUNT, email: EMAIL, scope: "full", origin: "vault" });
      if (state.reset) return json({ email: EMAIL, scope: "account_reset", origin: "vault" });
      return json({ error: "unauthorized" }, 401);
    },
    "POST /api/auth/redeem": (body, state) => {
      if (redeemStatus === 429) return json({ error: "throttled" }, 429, { "retry-after": "60" });
      if (redeemStatus !== null || body.code !== CODE || body.email !== EMAIL) return json({ error: "denied" }, 401);
      state.reset = true;
      return json({ scope: "account_reset" });
    },
    "GET /api/vault/recovery": (_body, state) =>
      state.reset || state.signedIn
        ? json({
            account_id: ACCOUNT,
            vault_id: VAULT,
            vk_epoch: 1,
            ksf_profile: 1,
            wrap: { method_id: ID_RECOVERY, method_type: 2, kek_generation: serverRecoveryGeneration, wrap: b64u.encode(filled(72, 6)) },
            manifest: { rev: 1, envelope: b64u.encode(filled(80, 4)), tag: b64u.encode(filled(32, 5)) },
          })
        : json({ error: "unauthorized" }, 401),
    "POST /api/auth/challenge": () => json({ nonce: b64u.encode(NONCE), expires_in: 300 }),
    "POST /api/auth/opaque/reregister/start": () => json({ registration_response: b64u.encode(filled(64, 3)) }),
    "POST /api/vault/recover": (body, state) => {
      recovers.push({ body, headers: state.requests.at(-1).headers });
      if (recoverStatus !== 200) return json(recoverBody ?? { error: "denied" }, recoverStatus);
      const ended = !state.signedIn;
      state.reset = false;
      return json(recoverBody ?? { session_ended: ended, seq: 2 });
    },
    "GET /api/vault/unlock-methods": () => methods(),
    [`GET /api/sync/changes?since=${Number.MAX_SAFE_INTEGER}&limit=1`]: () =>
      json({ changes: [], latest_seq: 9, vk_epoch: 1, restore_epoch: restoreEpoch, restore_seq: 0, has_more: false }),
    ...extraOverrides,
  };
  const world = await scenario({ skBit, handlers, overrides });
  world.server.state.reset = session === "account_reset";
  world.server.state.signedIn = session === "full";
  world.recovers = recovers;
  world.env = {
    client: world.client,
    api: world.api,
    store: world.store,
    server: SERVER,
    lock: () => world.session.lock(),
    now: Date.now,
    rand: (bytes) => globalThis.crypto.getRandomValues(bytes),
  };
  return world;
}

/** Pins the account on this device, as a sign-in on it once did. */
export async function pinHere(world, { skBit = true, floors = [["password", 1], ["recovery", 1]], keepSk = false } = {}) {
  const db = await world.store.open();
  await world.store.savePinned(db, SERVER, ACCOUNT, EMAIL, pinnedRecord({ skBit, floors, serverKey: 9 }));
  if (keepSk) {
    const { saveSecretKey } = await import("../../src/flows/deviceSecret.mjs");
    await saveSecretKey(db, SERVER, ACCOUNT, SK_CODE);
  }
  return db;
}

/** A confirmation that types the new key back right away (and records that it was asked). */
export function typeBack(asked = [], typed = NEW_RK) {
  return async ({ sheet, check }) => {
    asked.push(sheet);
    await check(typed);
  };
}

/**
 * Runs the flow in a world, with the session's own sign-in after it.
 * @param {any} world
 * @param {Record<string, any>} args
 */
export function recoverIn(world, args) {
  return recoverAccount(
    world.env,
    {
      email: EMAIL,
      code: CODE,
      qrText: qrText(),
      skCode: SK_CODE,
      rkCode: RK_CODE,
      newPassword: NEW_PASSWORD,
      newPasswordAgain: NEW_PASSWORD,
      confirmNewRk: typeBack(),
      ...args,
    },
    { signIn: (a) => world.session.unlock(a) },
  );
}

/** The password a call of the fake core was given, as text (from the snapshot taken at the call). */
export const passwordOf = (call) => new TextDecoder().decode(call.snapshot[0]);
