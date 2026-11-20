// A new OPAQUE registration for the account that is signed in (spec Fase 1 § 6.3,
// step 3: "The client runs a new OPAQUE registration"; the server side is
// `POST /api/auth/opaque/reregister/start`, which a full session may call for its own
// account only). It is the first half of a master password change; the keys and the
// wrap that go with it come from the core's `change_password`, which takes the state
// this function leaves in the core.
//
//   register_start          core: the first message from the new password (and the secret key code)
//   POST reregister/start   the server's answer
//   register_finish         core: runs Argon2id, makes the record; the export key stays in the core
//
// The account's secret key does not change (spec Fase 1 § 6.2): an account that has
// one is registered with its own code, an account that has none without. The code
// comes from the page or from this device, never from a guess; with a secret key on
// the account and no code, nothing is sent (`sk_required`), because a registration
// without it would lock the account out at the next sign-in.
import { b64u } from "../b64.mjs";
import { withPassword } from "../crypto/convert.mjs";
import { encodeWire } from "../wire.mjs";
import { accountContext } from "./reauth.mjs";
import { decideSecretKey } from "./signin.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */

/**
 * Registers the new password with the server and in the core.
 *
 * `profile` is the key stretching profile to register with; without it, the profile
 * this device has pinned (never lower). `context` is the account the caller has
 * already looked up (`accountContext`).
 * @param {Env} env
 * @param {{ password: string, skCode?: string, profile?: number, context?: Awaited<ReturnType<typeof accountContext>> }} args
 * @returns {Promise<{ profile: number }>}
 */
export async function registerForSession(env, { password, skCode, profile, context }) {
  const { client, api } = env;
  const { db, record } = context ?? (await accountContext(env));
  const { skBit, skCode: code } = await decideSecretKey(env, db, record, { skCode });
  const registerWith = Math.max(Number.isSafeInteger(profile) ? /** @type {number} */ (profile) : 1, record.ksf_profile);
  try {
    const request = await withPassword(password, (mp) =>
      client.vault.register_start(mp, skBit ? { kind: "code", code } : { kind: "none" }),
    );
    const answer = await api.post(
      "/api/auth/opaque/reregister/start",
      encodeWire("reregister_start_req", { registration_request: b64u.encode(request) }),
      { shape: "reregister_start_res" },
    );
    await client.vault.register_finish(b64u.decode(answer.registration_response), registerWith);
  } catch (error) {
    // The core drops the half-made registration.
    await Promise.resolve(client.vault.clear()).catch(() => undefined);
    throw error;
  }
  return { profile: registerWith };
}
