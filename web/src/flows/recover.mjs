// Recovering the account with the recovery key, on a new browser or after a forgotten
// master password (spec Fase 1 § 6.3, § 6.1 and § 4.2). The order of the calls:
//
//   (local checks, nothing is sent: the two new passwords agree, the recovery key and the
//    secret key read without a typo (`check_code`), the new password meets the floor, and on
//    a new device the sheet's QR text was read and its address is this server's)
//   GET  session            a full session needs no code; a reset session for the
//                           same e-mail is used again instead of a second code
//   POST redeem             the one-time code: a reset session (`account_reset`)
//   GET  recovery           the recovery wrap, the manifest row and the account's ids
//   (the sheet names this account; a new device makes a pin only when no other server holds it)
//   register_start ... register_finish   the new OPAQUE registration (`opaqueRegister.mjs`),
//                           with the account's own secret key from page 1 of the sheet
//   recover                 core: opens the recovery wrap with the recovery key, checks every pin
//                           (or, on a new device, the sheet), makes the new wraps and a new recovery key
//   (the new recovery key is shown alone, as page 2, and must be typed back before anything is sent)
//   POST challenge, recover_sign, POST recover   the request, signed with the OLD recovery key
//   recover_done            the old recovery key is wiped
//   savePinned              only after the server answered 200
//   (lock, then the ordinary sign-in with the new password)
//
// No step asks for the old master password: the recovery key stands in for it.
//
// A new device needs both pages of the emergency sheet: the QR text and the secret key
// from page 1, the recovery key from page 2. The QR text pins the server's identity, so the
// first answer of the server is not trusted. A device that holds a record of the account may
// leave the QR text out; its record is the pin. Recovery never lowers a pinned floor: the core
// refuses a recovery wrap below the record's floor, and the store refuses a record that would
// lower one.
//
// The sheet's address (`u=`) is compared as an origin, as at sign-in (`setupQr.mjs`): the
// scheme, the host in lower case and the port. The core compares the address in the text it
// is given with the page's address as an exact string, so when the sheet wrote the same origin
// in another spelling, the core is given the same text rebuilt with this page's canonical
// origin (`setup_qr_build`, from the values the core itself read). Every other value is the
// sheet's.
//
// The passwords, the recovery keys, the secret key, the one-time code and the QR text are
// strings from the page; JavaScript strings cannot be wiped. They are never logged, stored,
// put in an address or in an error. The code goes to the server in the body of the redeem
// request and nowhere else; the keys and the passwords reach the core only.
import { ApiError } from "../api.mjs";
import { b64u, hex16 } from "../b64.mjs";
import { num, rowToCore, rowToWire, withPassword, wrapToCore } from "../crypto/convert.mjs";
import { AccountError, codeOf } from "../crypto/errors.mjs";
import { encodeWire } from "../wire.mjs";
import { hasSecretKey } from "./deviceSecret.mjs";
import { pageTwoOnly } from "./emergencySheet.mjs";
import { registerForSession } from "./opaqueRegister.mjs";
import { checkQrAfterLogin, checkQrBeforeKe3, readSetupQr, SetupQrError } from "./setupQr.mjs";
import { signedCall } from "./signedCall.mjs";
import { unlock } from "./signin.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */

/**
 * The page's part in step 7: show `sheet` (page 2 only, the new recovery key) and resolve once
 * `check(typed)` has passed for what the user typed back. Reject to stop the recovery.
 * @typedef {(step: { sheet: import("./emergencySheet.mjs").Sheet, check: (typed: string) => Promise<void> }) => Promise<void>} ConfirmNewRk
 */

/**
 * @typedef {object} RecoverArgs
 * @property {string | null} [qrText] the text of the sheet's QR code (page 1); required on a device without a record of the account
 * @property {string} [email] required unless the session is a full one
 * @property {string} [code] the one-time code; not needed with a full session or a reset session already open for the e-mail
 * @property {string} rkCode the recovery key as typed (page 2)
 * @property {string} newPassword
 * @property {string} newPasswordAgain
 * @property {string} [skCode] the secret key (page 1), when the account has one and this device does not hold it
 * @property {ConfirmNewRk} confirmNewRk
 */

/** @param {unknown} value @returns {string} */
function trimmed(value) {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Whether a failure of the signed request leaves it unknown if the server applied it: it was sent, and the answer is
 * no answer, a server error or not an answer this page understands. A refusal with the server's code is not.
 * @param {unknown} error
 */
function outcomeUnknown(error) {
  const e = /** @type {any} */ (error);
  if (e?.afterSend !== true && e?.details?.afterSend !== true) return false;
  if (e instanceof ApiError) return e.status === 0 || e.status >= 500 || e.code === "bad_response" || e.code === "network";
  return e?.code === "bad_response";
}

/**
 * The session this browser has at the server, as far as recovery cares: a full one (the account and e-mail), a reset
 * one (its e-mail), or none.
 * @param {Env} env
 * @returns {Promise<{ scope: "full", accountId: string, email: string } | { scope: "account_reset", email: string } | null>}
 */
export async function recoverySession(env) {
  try {
    const res = await env.api.get("/api/auth/session", { shape: "session_res" });
    if (res.origin !== "vault") return null;
    if (res.scope === "full" && hex16.is(res.account_id)) return { scope: "full", accountId: res.account_id, email: res.email };
    if (res.scope === "account_reset") return { scope: "account_reset", email: res.email };
    return null;
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

/**
 * The text the core is given for the sheet: the sheet's own when it names this page's origin exactly, else the same
 * values with the canonical origin. The caller has checked that the two are the same origin.
 * @param {Env} env
 * @param {string} text the text as typed (trimmed)
 * @param {import("./setupQr.mjs").SetupQr} qr what the core read from it
 * @returns {Promise<string>}
 */
export async function canonicalQrText(env, text, qr) {
  if (qr.serverUrl === env.server) return text;
  return env.client.vault.setup_qr_build(env.server, hex16.decode(qr.accountId), qr.ksfProfile, qr.skBit, qr.serverPublicKey.slice());
}

/**
 * Recovers the account (see the top of this file) and signs in with the new password. `signIn` is the sign-in that
 * follows; the session passes its own (`session.unlock`), so the vault opens as after any sign-in.
 * @param {Env} env
 * @param {RecoverArgs} args
 * @param {{ signIn?: (args: { email: string, password: string, skCode?: string }) => Promise<unknown> }} [hooks]
 * @returns {Promise<"recovered">}
 */
export async function recoverAccount(env, args, hooks = {}) {
  const { client, api, store, server } = env;
  const { newPassword, newPasswordAgain, confirmNewRk } = args;
  if (typeof confirmNewRk !== "function") throw new TypeError("recoverAccount needs confirmNewRk");

  // ------------------------------------------------ local checks; nothing is sent
  if (typeof newPassword !== "string" || newPassword === "") throw new AccountError("password_required");
  if (newPassword !== newPasswordAgain) throw new AccountError("password_mismatch");
  const rkCode = trimmed(args.rkCode);
  if (rkCode === "") throw new AccountError("rk_required");
  // A typo in the recovery key is caught here, before any key is derived and before the code is spent.
  await client.vault.check_code("recovery_key", rkCode);
  const typedSk = trimmed(args.skCode);
  if (typedSk !== "") await client.vault.check_code("secret_key", typedSk);

  const session = await recoverySession(env);
  const full = session?.scope === "full" ? session : null;
  const email = full ? full.email : trimmed(args.email);
  if (email === "") throw new AccountError("email_required");
  const reuseReset = session?.scope === "account_reset" && session.email.trim().toLowerCase() === email.toLowerCase();
  const code = trimmed(args.code);
  if (!full && !reuseReset && code === "") throw new AccountError("code_required");

  const db = await store.open();
  /** @type {Record<string, any> | null} */
  const early = full ? await store.pinnedForSignIn(db, server, full.email, full.accountId) : await store.pinHintForEmail(db, server, email);
  const qrTyped = trimmed(args.qrText);
  const qr = qrTyped === "" ? null : await readSetupQr(client, qrTyped);
  // The sheet is for this server, or nothing is sent.
  if (qr !== null) checkQrBeforeKe3(qr, { serverUrl: server });
  // A new device needs page 1: without a record of the account, the sheet is the only pin of the server.
  if (qr === null && !early) throw new AccountError("qr_required");
  if (qr !== null && early && hex16.encode(early.account_id) !== qr.accountId) throw new SetupQrError("qr_account");
  if (qr !== null && full && full.accountId !== qr.accountId) throw new SetupQrError("qr_account");
  if (qr !== null && early && (early.sk_bit === true) !== qr.skBit) throw new SetupQrError("qr_sk_bit");
  const skBit = qr !== null ? qr.skBit : early?.sk_bit === true;
  // The secret key stays the account's own: typed from page 1, or the one this device holds.
  if (skBit && typedSk === "" && !(early && (await hasSecretKey(db, server, hex16.encode(early.account_id))))) {
    throw new AccountError("sk_required");
  }
  await withPassword(newPassword, (mp) => client.vault.check_master_password(mp, skBit ? "with_secret_key" : "without_secret_key"));
  // A new pin: the account must not be pinned under another address of this browser (one pin per account id). The
  // sheet names the account, so this is asked before the code is spent, and again once the server has named it.
  if (!early && qr !== null) {
    const other = await store.pinnedElsewhere(db, server, qr.accountId);
    if (other !== null) throw new AccountError("pinned_elsewhere", { server: other, accountId: qr.accountId });
  }

  // ------------------------------------------------ 1. the reset session
  if (!full && !reuseReset) {
    try {
      await api.post("/api/auth/redeem", encodeWire("redeem_req", { email, code }), { shape: "redeem_res" });
    } catch (error) {
      // Every refusal of the code reads the same: a wrong, used or old code, an unknown e-mail, or too many tries.
      if (error instanceof ApiError && (error.status === 401 || error.status === 429)) throw new AccountError("code_refused");
      throw error;
    }
  }

  // ------------------------------------------------ 2. what the server holds
  const held = await api.get("/api/vault/recovery", { shape: "recovery_res" });
  if (full && held.account_id !== full.accountId) throw new AccountError("pinned_account_mismatch");
  if (qr !== null) checkQrAfterLogin(qr, { accountId: held.account_id });
  /** @type {Record<string, any> | null} */
  const record = full ? early : await store.pinnedForSignIn(db, server, email, held.account_id);
  if (record === null && qr === null) throw new AccountError("qr_required");
  if (record !== null && qr !== null && (record.sk_bit === true) !== qr.skBit) throw new SetupQrError("qr_sk_bit");
  if (record === null) {
    // A new pin: the account must not be pinned under another address of this browser (one pin per account id).
    const other = await store.pinnedElsewhere(db, server, held.account_id);
    if (other !== null) throw new AccountError("pinned_elsewhere", { server: other, accountId: held.account_id });
  }

  // ------------------------------------------------ 3. the new password and the recovery in the core
  const profile = Math.max(held.ksf_profile, qr?.ksfProfile ?? 1);
  // On a new device the sheet stands in for the record: it states the account, the secret key bit and the profile.
  const pinFor = record ?? { account_id: hex16.decode(held.account_id), sk_bit: skBit, ksf_profile: qr?.ksfProfile ?? 1 };
  let recovered = /** @type {Record<string, any> | null} */ (null);
  let succeeded = false;
  try {
    await registerForSession(env, {
      password: newPassword,
      skCode: typedSk === "" ? undefined : typedSk,
      profile,
      context: { info: { accountId: held.account_id, email }, db, record: pinFor },
    });
    const ctx = { account_id: hex16.decode(held.account_id), vault_id: hex16.decode(held.vault_id), vk_epoch: held.vk_epoch };
    const pin = record ? { kind: "pinned", record } : { kind: "first_use", sk_bit: skBit };
    const qrForCore = qr === null ? undefined : await canonicalQrText(env, qrTyped, qr);
    recovered = await client.vault.recover(server, ctx, rkCode, wrapToCore(held.wrap, held.ksf_profile), rowToCore(held.manifest), pin, qrForCore);
    const made = /** @type {Record<string, any>} */ (recovered);

    // ---------------------------------------------- 4. the new recovery key is typed back before anything is sent
    let confirmed = false;
    const sheet = pageTwoOnly(await client.vault.reveal_recovery_code());
    await confirmNewRk({
      sheet,
      check: async (typed) => {
        await client.vault.verify_recovery_setup(typed, made.recovery_wrap);
        confirmed = true;
      },
    });
    if (!confirmed) throw new AccountError("not_confirmed");
    await Promise.resolve(client.vault.clear_setup_secrets()).catch(() => undefined);

    // ---------------------------------------------- 5. the request, signed with the old recovery key
    /** @type {Record<string, any>} */
    let answer;
    try {
      answer = await signedCall(env, {
        op: "recover",
        method: "POST",
        path: "/api/vault/recover",
        shape: "recover_req",
        body: {
          registration_record: b64u.encode(made.registration_record),
          ksf_profile: num(made.ksf_profile),
          pw_wrap: b64u.encode(made.password_wrap.wrap),
          rk_wrap: b64u.encode(made.recovery_wrap.wrap),
          pw_kek_generation: num(made.password_wrap.kek_generation),
          rk_kek_generation: num(made.recovery_wrap.kek_generation),
          pk_r_new: b64u.encode(made.pk_r),
          manifest: rowToWire(made.manifest),
        },
        sign: (nonce, bytes) => client.vault.recover_sign(nonce, bytes),
      });
    } catch (error) {
      if (outcomeUnknown(error)) throw new AccountError("recover_unconfirmed");
      throw error;
    } finally {
      // The old recovery key is wiped whatever the answer was.
      await Promise.resolve(client.vault.recover_done()).catch(() => undefined);
    }
    if (typeof answer?.session_ended !== "boolean") throw new AccountError("recover_unconfirmed");

    // ---------------------------------------------- 6. the server holds the new password and recovery key
    try {
      await store.savePinned(db, server, held.account_id, email, made.pinned);
    } catch (error) {
      throw new AccountError("pin_save_failed", { cause: codeOf(error) });
    }
    succeeded = true;
  } finally {
    recovered = null;
    if (!succeeded) {
      // The core drops the registration and the old recovery key; the worker that holds the recovered vault ends.
      await Promise.resolve(client.vault.recover_done()).catch(() => undefined);
      await Promise.resolve(client.vault.clear()).catch(() => undefined);
    }
    await Promise.resolve(env.lock()).catch(() => undefined);
  }

  // ------------------------------------------------ 7. the ordinary sign-in with the new password
  const signIn = hooks.signIn ?? ((/** @type {any} */ a) => unlock(env, a));
  try {
    await signIn({ email, password: newPassword, ...(typedSk === "" ? {} : { skCode: typedSk }) });
  } catch (error) {
    throw new AccountError("recovered_not_signed_in", { cause: codeOf(error) });
  }
  return "recovered";
}
