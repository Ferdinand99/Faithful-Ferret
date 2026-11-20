// Changing the master password (spec Fase 1 § 4.6 and § 6.3, the password
// wrap; J9, J10). The order of the calls:
//
//   (the two typed passwords are compared, the floor is checked, nothing is sent)
//   check_master_password   core: the creation floor (12 characters with a secret key, 15 without)
//   login_start ... POST login/finish   a fresh re-authentication with the current password (`reauth.mjs`)
//   GET unlock-methods      the password wrap, the manifest row and `pk_a` the server holds
//   seed_pinned             core: adds the generation floors from that manifest to this device's record
//   check_server_methods    core: the server's list against the manifest
//   register_start ... register_finish  the new OPAQUE registration (`opaqueRegister.mjs`)
//   change_password         core: the new password wrap, the new manifest, the registration record
//   POST challenge, auth_sign, PUT unlock-methods/password   the signed write (`signedCall.mjs`)
//   savePinned              only after the server answered 200
//
// This device's record is replaced only after the server has accepted the change. A
// refusal at any step leaves the record, the session and the open vault as they were,
// and says why (the error's `code`). The server ends every other session of the
// account when it accepts the change (J10); this one goes on. Old exports and server
// backups still open with the old password: the page says so.
//
// The three passwords are strings from the page (JavaScript strings cannot be wiped);
// each is encoded to a byte array for the core, and the core's copy is wiped after the
// call. No password, key or code is logged, stored or put in an address.
import { b64u } from "../b64.mjs";
import { num, rowToCore, rowToWire, serverMethods, withPassword, wrapToCore } from "../crypto/convert.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { registerForSession } from "./opaqueRegister.mjs";
import { accountContext, reauthenticate } from "./reauth.mjs";
import { decideSecretKey } from "./signin.mjs";
import { signedCall } from "./signedCall.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * Changes the master password.
 *
 * `skCode` is only needed when the account has a secret key and this device does
 * not hold it (`sk_required` says so); the secret key itself does not change.
 * @param {Env} env
 * @param {{ current: string, next: string, nextAgain: string, skCode?: string }} args
 * @returns {Promise<{ kekGeneration: number, until: number }>}
 */
export async function changePassword(env, { current, next, nextAgain, skCode }) {
  const { client, api, store, server } = env;
  if (typeof current !== "string" || current === "" || typeof next !== "string" || next === "") {
    throw new AccountError("password_required");
  }
  if (next !== nextAgain) throw new AccountError("password_mismatch");
  if (next === current) throw new AccountError("password_unchanged");

  // The floor of the new password depends on the secret key bit, which this device pinned.
  const context = await accountContext(env);
  const { info, db, record } = context;
  const { skBit, skCode: code } = await decideSecretKey(env, db, record, { skCode });
  await withPassword(next, (mp) => client.vault.check_master_password(mp, skBit ? "with_secret_key" : "without_secret_key"));

  const fresh = await reauthenticate(env, { password: current, skCode: code ?? undefined, context });
  try {
    const methods = await api.get("/api/vault/unlock-methods", { shape: "methods_res" });
    const passwordWraps = methods.methods.filter((/** @type {{ method_type: number }} */ m) => m.method_type === 1);
    if (passwordWraps.length !== 1) throw new AccountError("methods_invalid");
    const manifest = rowToCore(methods.manifest);

    // What the server shows must agree with what this device has pinned, as at every unlock. A disagreement closes the vault.
    /** @type {Record<string, any>} */
    let seeded;
    try {
      seeded = await client.vault.seed_pinned(record, manifest);
      await client.vault.check_server_methods(manifest, serverMethods(methods.methods));
      if (!sameBytes(seeded.pk_a, b64u.decode(methods.pk_a))) throw new AccountError("pinned_auth_key");
    } catch (error) {
      await Promise.resolve(env.lock()).catch(() => undefined);
      throw error;
    }

    await registerForSession(env, { password: next, skCode: code ?? undefined, profile: fresh.ksfProfile, context });
    const change = await client.vault.change_password(seeded, wrapToCore(passwordWraps[0], fresh.ksfProfile), manifest);

    const answer = await signedCall(env, {
      op: "unlock-method.password.put",
      method: "PUT",
      path: "/api/vault/unlock-methods/password",
      shape: "password_put_req",
      body: {
        registration_record: b64u.encode(change.registration_record),
        ksf_profile: num(change.ksf_profile),
        wrap: b64u.encode(change.wrap.wrap),
        kek_generation: num(change.wrap.kek_generation),
        manifest: rowToWire(change.manifest),
      },
    });

    // The server has accepted the change. Only now does this device pin the new generation.
    if (answer.kek_generation !== num(change.wrap.kek_generation)) throw new AccountError("bad_response");
    try {
      await store.savePinned(db, server, info.accountId, info.email, change.pinned);
    } catch (error) {
      throw new AccountError("pin_save_failed", { cause: /** @type {any} */ (error)?.code ?? null });
    }
    return { kekGeneration: answer.kek_generation, until: fresh.until };
  } catch (error) {
    // The core drops what it held of the registration; nothing was pinned.
    await Promise.resolve(client.vault.clear()).catch(() => undefined);
    throw error;
  }
}
