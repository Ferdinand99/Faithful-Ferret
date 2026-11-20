// Sign-in and unlock (spec Fase 1 § 4.2, "Sign-in" and "Pinning and the SK
// bit"). The order of the calls:
//
//   (the sheet's QR text, when there is one: its address is checked first)
//   login_start           core: KE1 from the password (and the secret key code)
//   POST login/start      the server's KE2, the profile number and `sk_hint`
//   (the sheet's profile is checked before the password is stretched)
//   login_finish          core: checks the profile and the pins, runs Argon2id, KE3
//   (the sheet's server key is checked before KE3 is posted)
//   POST login/finish     the session cookie; the account, vault and epoch
//   (the sheet's account id and `pinnedElsewhere`, before anything is pinned)
//   GET unlock-methods    the wraps, the manifest row and `pk_a`
//   unlock_password       core: opens the password wrap under the pin state
//   seed_pinned           core: adds the generation floors from the manifest
//   check_server_methods  core: the server's list against the manifest
//   savePinned            the record, kept on this device
//
// The core's `login_finish` runs before the server has named the account, so
// it gets the record the typed e-mail maps to on this device (if any) as an
// early guard. The pin state that opens the vault is looked up after
// `login/finish`, only through `pinnedForSignIn`, which also covers an e-mail
// that was changed on another device. A first use is only ever the case when
// both lookups found nothing, and the secret key bit is the user's answer: the
// server's `sk_hint` is shown as a preselection and changes nothing that is
// sent.
//
// The text of the emergency sheet's QR code (`args.qr`) is the way to a new
// device that does not rest on the first answer of the server (spec Fase 1
// § 4.2, F-01 point 6). It states the address, the server's OPAQUE key, the KSF
// profile, the account id and the secret key bit. The bit answers the question
// about the secret key, and everything else is checked against what the server
// says; a difference ends the sign-in with a hard error and nothing is pinned.
// An account id is pinned under one server address only: `pinnedElsewhere` runs
// right after `login/finish`, for a sign-in and for any re-authentication that
// would make a new pin (this server holds no record of the account yet). Such a
// pin is refused (`pinned_elsewhere`). A refused sign-in locks the vault and asks
// the server to end the new session (best effort); a refused re-authentication
// keeps the session it was made for, because nothing was pinned.
import { ApiError } from "../api.mjs";
import { b64u, hex16 } from "../b64.mjs";
import { rowToCore, serverMethods, withPassword, wrapToCore } from "../crypto/convert.mjs";
import { AccountError, withSkHint } from "../crypto/errors.mjs";
import { encodeWire } from "../wire.mjs";
import { forgetSecretKey, hasSecretKey, loadSecretKey, saveSecretKey } from "./deviceSecret.mjs";
import { checkQrAfterLogin, checkQrBeforeKe3, readSetupQr, SetupQrError } from "./setupQr.mjs";

/** What the server calls this browser when it lists the devices. */
export const DEVICE_NAME = "Web vault";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {import("../crypto/env.mjs").Unlocked} Unlocked */

/** @param {unknown} value @returns {string | null} */
function nonEmpty(value) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * What the vault session says, or null when there is none.
 * @param {Env} env
 * @returns {Promise<{ accountId: string, email: string } | null>}
 */
export async function sessionInfo(env) {
  try {
    const res = await env.api.get("/api/auth/session", { shape: "session_res" });
    if (res.origin !== "vault" || !hex16.is(res.account_id)) return null;
    return { accountId: res.account_id, email: res.email };
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

/**
 * What this device knows about the account behind an e-mail, without asking
 * the server: whether it holds a pinned record, the secret key bit in it and
 * whether a sealed secret key is kept. Used to decide which questions to ask.
 * @param {Env} env
 * @param {string} email
 * @returns {Promise<{ pinned: boolean, skBit: boolean | null, skStored: boolean }>}
 */
export async function deviceStatus(env, email) {
  const db = await env.store.open();
  const record = await env.store.pinHintForEmail(db, env.server, email);
  if (!record) return { pinned: false, skBit: null, skStored: false };
  const skStored = record.sk_bit ? await hasSecretKey(db, env.server, hex16.encode(record.account_id)) : false;
  return { pinned: true, skBit: record.sk_bit === true, skStored };
}

/**
 * Decides the secret key bit and the code to use. The bit is the user's
 * answer, else the pinned record's; with neither, the page must ask. The code
 * is the one typed, else the one sealed on this device.
 * @param {Env} env
 * @param {import("../store/idb.mjs").Store} db
 * @param {Record<string, any> | null} record the pinned record found so far
 * @param {{ skBit?: boolean, skCode?: string }} args
 * @param {import("./setupQr.mjs").SetupQr | null} [qr] the sheet's text, when there is one: its bit is the answer
 * @returns {Promise<{ skBit: boolean, skCode: string | null }>}
 */
export async function decideSecretKey(env, db, record, args, qr = null) {
  // The sheet answers the question. An answer or a record that differs from it is no wrong password: nothing is
  // sent, and the refusal says that the sheet and the device disagree.
  if (qr !== null && ((typeof args.skBit === "boolean" && args.skBit !== qr.skBit) || (record && (record.sk_bit === true) !== qr.skBit))) {
    throw new SetupQrError("qr_sk_bit");
  }
  const bit = qr !== null ? qr.skBit : typeof args.skBit === "boolean" ? args.skBit : record ? record.sk_bit === true : undefined;
  if (bit === undefined) throw new AccountError("sk_answer_required");
  if (!bit) return { skBit: false, skCode: null };
  let code = nonEmpty(args.skCode);
  if (code === null && record) code = await loadSecretKey(db, env.server, hex16.encode(record.account_id), env.secrets);
  if (code === null) throw new AccountError("sk_required");
  return { skBit: true, skCode: code };
}

/**
 * The part of both flows that is the same. `early` is the record that guards
 * the core's `login_finish`; the record that opens the vault is looked up
 * after the server has named the account. Any failure after the session exists
 * ends the vault in the worker, and a failed sign-in also ends the session.
 * @param {Env} env
 * @param {{
 *   purpose: "login" | "reauth",
 *   email: string,
 *   password: string,
 *   skBit: boolean,
 *   skCode: string | null,
 *   early: Record<string, any> | null,
 *   rememberSk?: boolean,
 *   qr?: import("./setupQr.mjs").SetupQr | null,
 * }} p
 * @returns {Promise<Unlocked>}
 */
async function open(env, p) {
  const { client, api, store, server } = env;
  const db = await store.open();
  const deviceId = await store.deviceId(db, env.rand);
  const qr = p.qr ?? null;

  /** @type {Record<string, any>} */
  let start;
  /** @type {Uint8Array} */
  let ke3;
  try {
    // The sheet is for this server or the sign-in does not start: nothing is sent to a server the sheet is not for.
    if (qr !== null) checkQrBeforeKe3(qr, { serverUrl: server });
    const ke1 = await withPassword(p.password, (mp) => client.vault.login_start(mp, p.skCode));
    start = await api.post(
      "/api/auth/opaque/login/start",
      encodeWire("login_start_req", { email: p.email, ke1: b64u.encode(ke1), purpose: p.purpose }),
      { shape: "login_start_res" },
    );
    try {
      // The password is not stretched for a profile below the sheet's.
      if (qr !== null) checkQrBeforeKe3(qr, { serverUrl: server, serverProfile: start.ksf_profile });
      const early = p.early ? { kind: "pinned", record: p.early } : { kind: "first_use", sk_bit: p.skBit };
      const finished = await client.vault.login_finish(b64u.decode(start.ke2), start.ksf_profile, early);
      ke3 = finished.ke3;
      // The server has proved its key. It is the sheet's, or KE3 is not posted.
      if (qr !== null) {
        if (!(finished.server_public_key instanceof Uint8Array)) throw new SetupQrError("qr_server_key");
        checkQrBeforeKe3(qr, { serverUrl: server, serverProfile: start.ksf_profile, serverPublicKey: finished.server_public_key });
      }
    } catch (error) {
      throw withSkHint(error, start.sk_hint);
    }
  } catch (error) {
    // No session exists yet: the job drops the password-derived state it holds.
    await Promise.resolve(client.vault.clear()).catch(() => undefined);
    throw error;
  }

  /** @type {Record<string, any>} */
  let done;
  try {
    done = await api.post(
      "/api/auth/opaque/login/finish",
      encodeWire("login_finish_req", {
        login_id: start.login_id,
        ke3: b64u.encode(ke3),
        device_id: deviceId,
        device_name: DEVICE_NAME,
        purpose: p.purpose,
      }),
      { shape: "login_finish_res" },
    );
  } catch (error) {
    // No session was made: the job drops what it holds from the login.
    await Promise.resolve(client.vault.clear()).catch(() => undefined);
    // The account has the kit's two-factor sign-in on; the vault has no second step yet.
    if (error instanceof ApiError && error.code === "forbidden") throw new AccountError("two_factor_unsupported");
    throw error;
  }

  try {
    // The server has named the account. It is the sheet's account, and no other address has it pinned: both
    // are asked before anything is pinned.
    if (qr !== null) checkQrAfterLogin(qr, { accountId: done.account_id });
    const record = await store.pinnedForSignIn(db, server, p.email, done.account_id);
    // A re-authentication in a session that is already pinned here makes no new pin; every other path does.
    if (p.purpose === "login" || !record) {
      const other = await store.pinnedElsewhere(db, server, done.account_id);
      if (other !== null) throw new AccountError("pinned_elsewhere", { server: other, accountId: done.account_id });
    }
    const methods = await api.get("/api/vault/unlock-methods", { shape: "methods_res" });
    if (methods.vk_epoch !== done.vk_epoch) throw new AccountError("epoch_mismatch");
    const passwordWraps = methods.methods.filter((/** @type {{ method_type: number }} */ m) => m.method_type === 1);
    if (passwordWraps.length !== 1) throw new AccountError("methods_invalid");

    // Accepted residual: when the e-mail was changed on another device, the early
    // guard of `login_finish` was `first_use`, so a lower KSF profile than the pinned one
    // is caught only here, after Argon2id has run. `unlock_password` still refuses it
    // (`pinned_profile_downgrade`) and the sign-in ends. M1 has one profile, so none can be lower.
    const pin = record ? { kind: "pinned", record } : { kind: "first_use", sk_bit: p.skBit };
    const ctx = { account_id: hex16.decode(done.account_id), vault_id: hex16.decode(done.vault_id), vk_epoch: done.vk_epoch };
    const opened = await client.vault.unlock_password(server, ctx, wrapToCore(passwordWraps[0], start.ksf_profile), pin);
    const seeded = await client.vault.seed_pinned(opened.pinned, rowToCore(methods.manifest));
    await client.vault.check_server_methods(rowToCore(methods.manifest), serverMethods(methods.methods));
    // The account key the server lists must be the one the vault pins.
    if (!sameBytes(seeded.pk_a, b64u.decode(methods.pk_a))) throw new AccountError("pinned_auth_key");
    await store.savePinned(db, server, done.account_id, p.email, seeded);

    /** @type {Unlocked["secretKey"]} */
    let secretKey = "unchanged";
    if (p.purpose === "login" && p.rememberSk === false) {
      await forgetSecretKey(db, server, done.account_id);
      secretKey = "forgotten";
    } else if (p.purpose === "login" && p.rememberSk === true && p.skBit && p.skCode) {
      secretKey = await saveSecretKey(db, server, done.account_id, p.skCode, env.secrets);
    }
    return {
      accountId: done.account_id,
      vaultId: done.vault_id,
      vkEpoch: done.vk_epoch,
      email: p.email,
      pinned: seeded,
      secretKey,
      purpose: p.purpose,
    };
  } catch (error) {
    await Promise.resolve(env.lock()).catch(() => undefined);
    // A sign-in that did not open the vault leaves no session behind; a
    // re-authentication must not end the session it was made for.
    if (p.purpose === "login") await api.post("/api/auth/logout").catch(() => undefined);
    throw error;
  }
}

/**
 * Sign in with the e-mail and the master password (purpose `login`). On a
 * device with no record for the e-mail the answer to "does the account have a
 * secret key" (`skBit`) is required, and the code if the answer is yes. With the
 * text of the sheet's QR code (`qr`), the sheet's bit is the answer and the
 * sheet is checked against the server (see the top of this file).
 * @param {Env} env
 * @param {{ email: string, password: string, skCode?: string, skBit?: boolean, rememberSk?: boolean, qr?: string | null }} args
 * @returns {Promise<Unlocked>}
 */
export async function signIn(env, args) {
  const email = nonEmpty(args.email);
  if (email === null) throw new AccountError("email_required");
  const db = await env.store.open();
  const early = await env.store.pinHintForEmail(db, env.server, email);
  const qr = args.qr === undefined || args.qr === null ? null : await readSetupQr(env.client, args.qr);
  // A record this device holds for the e-mail names an account: it is the sheet's, or nothing is sent.
  if (qr !== null && early && hex16.encode(early.account_id) !== qr.accountId) throw new SetupQrError("qr_account");
  const { skBit, skCode } = await decideSecretKey(env, db, early, args, qr);
  return open(env, { purpose: "login", email, password: args.password, skBit, skCode, early, rememberSk: args.rememberSk, qr });
}

/**
 * Opens the vault again in a tab where the vault session is still valid
 * (purpose `reauth`): the session names the account, the secret key comes from
 * this device or the page. With no valid session this is a sign-in when an
 * e-mail is given, else `session_ended`.
 * @param {Env} env
 * @param {{ password: string, email?: string, skCode?: string, skBit?: boolean, rememberSk?: boolean }} args
 * @returns {Promise<Unlocked>}
 */
export async function unlock(env, args) {
  const info = await sessionInfo(env);
  if (info === null) {
    if (nonEmpty(args.email) === null) throw new AccountError("session_ended");
    return signIn(env, /** @type {any} */ (args));
  }
  const db = await env.store.open();
  const record = await env.store.pinnedForSignIn(db, env.server, info.email, info.accountId);
  const { skBit, skCode } = await decideSecretKey(env, db, record, args);
  return open(env, { purpose: "reauth", email: info.email, password: args.password, skBit, skCode, early: record });
}
