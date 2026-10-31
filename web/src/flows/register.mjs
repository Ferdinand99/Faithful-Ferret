// Registration of the first administrator (spec Fase 1 § 4.2 "Registration",
// § 6.1 "Confirmation at setup"). The order of the calls:
//
//   check_master_password    core: the creation floor (12 characters with a secret key, 15 without)
//   register_start           core: the first OPAQUE message, with a new secret key
//   POST register/start      the server's answer and the new account and vault ids
//   register_finish          core: runs Argon2id, the record
//   create_account           core: vault key, recovery key, wraps, manifest, first checkpoint
//   reveal_emergency_sheet   the sheet is shown
//   verify_recovery_setup    the user types the recovery key back; the recovery wrap is opened with it
//   verify_secret_key_entry  the same for the secret key
//   POST register/finish     only now; nothing was uploaded before both were typed back
//   savePinned, saveSecretKey, clear_setup_secrets
//
// A failed confirmation leaves the flow open for another try and uploads
// nothing; `abort()` ends it and drops the keys the core holds.
import { b64u, hex16 } from "../b64.mjs";
import { checkpointToWire, num, rowToWire, withPassword, wrapToWire } from "../crypto/convert.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { encodeWire } from "../wire.mjs";
import { saveSecretKey } from "./deviceSecret.mjs";
import { DEVICE_NAME } from "./signin.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */

/**
 * 16 random bytes that are not all zero.
 * @param {Env} env
 * @param {Uint8Array[]} [avoid]
 */
function randomId(env, avoid = []) {
  for (;;) {
    const id = env.rand(new Uint8Array(16));
    if (id.some((n) => n !== 0) && !avoid.some((other) => other.every((n, i) => n === id[i]))) return id;
  }
}

/**
 * @typedef {object} Registration
 * @property {{ access: Record<string, any>, recoveryKeyCode: string }} sheet what to show; the user writes it down
 * @property {(rkTyped: string, skTyped?: string) => Promise<void>} confirm opens the recovery wrap with what was typed and compares the secret key
 * @property {() => Promise<{ accountId: string, vaultId: string, vkEpoch: number, pinned: Record<string, any>, secretKey: "saved" | "unavailable" | "unchanged" }>} finish
 * @property {() => Promise<void>} abort
 */

/**
 * Registers the first administrator up to the point where the sheet is shown.
 * @param {Env} env
 * @param {{ email: string, password: string, setupToken?: string | null, useSecretKey?: boolean, rememberSk?: boolean }} args
 * @returns {Promise<Registration>}
 */
export async function register(env, args) {
  const { client, api, store, server } = env;
  const email = typeof args.email === "string" ? args.email.trim() : "";
  if (email === "") throw new AccountError("email_required");
  const useSecretKey = args.useSecretKey !== false;
  const rememberSk = useSecretKey && args.rememberSk !== false;
  const db = await store.open();

  /** @type {Record<string, any>} */
  let start;
  /** @type {Record<string, any>} */
  let account;
  /** @type {Record<string, any>} */
  let sheetCore;
  try {
    await withPassword(args.password, (mp) =>
      client.vault.check_master_password(mp, useSecretKey ? "with_secret_key" : "without_secret_key"),
    );
    const request = await withPassword(args.password, (mp) =>
      client.vault.register_start(mp, useSecretKey ? { kind: "generate" } : { kind: "none" }),
    );
    const token = typeof args.setupToken === "string" && args.setupToken !== "" ? args.setupToken : null;
    start = await api.post(
      "/api/auth/opaque/register/start",
      encodeWire("register_start_req", {
        ...(token === null ? {} : { setup_token: token }),
        email,
        request: b64u.encode(request),
      }),
      { shape: "register_start_res" },
    );
    await client.vault.register_finish(b64u.decode(start.response), start.ksf_profile);
    const passwordId = randomId(env);
    const ids = {
      account_id: hex16.decode(start.account_id),
      vault_id: hex16.decode(start.vault_id),
      password_method_id: passwordId,
      recovery_method_id: randomId(env, [passwordId]),
    };
    account = await client.vault.create_account(server, ids);
    sheetCore = await client.vault.reveal_emergency_sheet(server, email);
  } catch (error) {
    // Nothing was uploaded; the job and any vault it made are dropped.
    await Promise.resolve(env.lock()).catch(() => undefined);
    throw error;
  }

  const recoveryWrap = account.wraps.find((/** @type {any} */ w) => w?.method?.type === "recovery");
  if (!recoveryWrap) {
    await Promise.resolve(env.lock()).catch(() => undefined);
    throw new AccountError("methods_invalid");
  }
  // The secret key is read now: the core drops it once both keys are typed back.
  /** @type {string | null} */
  let skCode = typeof sheetCore.access?.secret_key_code === "string" ? sheetCore.access.secret_key_code : null;
  if (useSecretKey && skCode === null) {
    await Promise.resolve(env.lock()).catch(() => undefined);
    throw new AccountError("methods_invalid");
  }

  /** @type {"open" | "confirmed" | "finishing" | "done" | "aborted"} */
  let phase = "open";
  const closed = () => phase === "done" || phase === "aborted";

  return {
    sheet: { access: sheetCore.access, recoveryKeyCode: sheetCore.recovery_key_code },

    async confirm(rkTyped, skTyped) {
      if (closed()) throw new AccountError("not_confirmed");
      if (phase !== "open") return;
      await client.vault.verify_recovery_setup(rkTyped, recoveryWrap);
      if (useSecretKey) await client.vault.verify_secret_key_entry(skTyped ?? "");
      phase = "confirmed";
    },

    async finish() {
      if (phase !== "confirmed") throw new AccountError("not_confirmed");
      phase = "finishing";
      try {
        const deviceId = await store.deviceId(db, env.rand);
        const res = await api.post(
          "/api/auth/opaque/register/finish",
          encodeWire("register_finish_req", {
            registration_id: start.registration_id,
            device_id: deviceId,
            device_name: DEVICE_NAME,
            record: b64u.encode(account.registration_record),
            ksf_profile: num(account.ksf_profile),
            sk_bit: useSecretKey,
            wraps: account.wraps.map(wrapToWire),
            manifest: rowToWire(account.manifest),
            checkpoint: checkpointToWire(account.checkpoint),
            pk_a: b64u.encode(account.pk_a),
            pk_r: b64u.encode(account.pk_r),
          }),
          { shape: "register_finish_res" },
        );
        if (res.account_id !== start.account_id || res.vault_id !== start.vault_id) {
          throw new AccountError("ids_changed");
        }
        try {
          await store.savePinned(db, server, res.account_id, email, account.pinned);
        } catch (error) {
          // The account exists on the server now; this device could not keep its record.
          await Promise.resolve(env.lock()).catch(() => undefined);
          phase = "done";
          skCode = null;
          throw new AccountError("pin_save_failed", { accountId: res.account_id, cause: /** @type {any} */ (error)?.code ?? null });
        }
        /** @type {"saved" | "unavailable" | "unchanged"} */
        let secretKey = "unchanged";
        if (rememberSk && skCode !== null) secretKey = await saveSecretKey(db, server, res.account_id, skCode, env.secrets);
        skCode = null;
        await client.vault.clear_setup_secrets();
        phase = "done";
        return {
          accountId: res.account_id,
          vaultId: res.vault_id,
          vkEpoch: num(account.pinned.vk_epoch_max),
          pinned: account.pinned,
          secretKey,
        };
      } catch (error) {
        if (phase === "finishing") phase = "confirmed";
        throw error;
      }
    },

    async abort() {
      if (closed()) return;
      phase = "aborted";
      skCode = null;
      await Promise.resolve(client.vault.clear_setup_secrets()).catch(() => undefined);
      await Promise.resolve(env.lock()).catch(() => undefined);
    },
  };
}
