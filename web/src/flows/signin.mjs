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
//
// One refusal keeps the new session too: the core refuses the server's password wrap as
// older than this device has seen (`pinned_kek_generation`) and the server's restore epoch
// is above the one this device stored. The server was restored from a backup, and the page
// offers the recovery key (`pinnedRefusalAction`); that recovery runs in this session.
//
// Two modes (`env.mode`, spec Fase 1 § 7.6). The web vault's is "cookie": the
// calls above, with the session cookie, byte for byte as they always were. A
// device client (the browser extension) is "device": it signs in as a device
// with its own tokens and no cookie.
//   - A sign-in makes a new device key and its tokens (`env.device.fresh`).
//     `login/start` goes without a cookie, a token or a proof
//     (`startSignIn`), with the purpose `login`.
//   - `login/finish` sends `{ login_id, ke3, client: "device", device_name,
//     platform }` with a DPoP proof of the new device key (`finishSignIn`,
//     which signs the older device of the server out first). The key is the
//     proof's `jwk`; the body carries no key and no id, and the server names
//     the device in its answer. The answer's tokens and device id are stored
//     by the tokens (the refresh token in the key's record, the access token
//     in memory) and never reach this file's result.
//   - Every later call (`unlock-methods`) carries the token.
//   - A sign-in that does not open the vault signs the new device out
//     (`revoke`, best effort), which forgets its tokens; there is no cookie
//     session to end, and nothing is pinned. A device is never offered the
//     recovery: that runs in the web vault's session.
//   - An unlock keeps the device (spec Fase 1 § 7.6): the device's token reads
//     `unlock-methods` first (a device whose tokens have ended signs in again
//     with the same password), then `login/start` and the client's side of the
//     OPAQUE finish give the export key that opens the password wrap. KE3 is
//     not posted, no device is made and no token is issued. The unlock needs
//     the pinned record of the device's account: there is no first use at an
//     unlock. A wrong password ends in the core and changes nothing on the
//     server.
import { ApiError } from "../api.mjs";
import { loadDeviceKey } from "../auth/deviceKey.mjs";
import { b64u, hex16 } from "../b64.mjs";
import { rowToCore, serverMethods, withPassword, wrapToCore } from "../crypto/convert.mjs";
import { AccountError, codeOf, withSkHint } from "../crypto/errors.mjs";
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
 * What the vault session says, or null when there is none. Only a full session is a signed-in one: a reset session
 * (`account_reset`, from a one-time code) can do nothing but recover the account, and one that waits for a second
 * factor can do nothing at all.
 * @param {Env} env
 * @returns {Promise<{ accountId: string, email: string, admin: boolean } | null>} `admin`: the server says the user is
 *   an administrator (only then are the admin pages offered)
 */
export async function sessionInfo(env) {
  // A device has no vault session: the route takes the cookie only, and a token is refused there.
  if (env.mode === "device") return null;
  try {
    const res = await env.api.get("/api/auth/session", { shape: "session_res" });
    if (res.origin !== "vault" || res.scope !== "full" || !hex16.is(res.account_id)) return null;
    return { accountId: res.account_id, email: res.email, admin: res.admin === true };
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
  const device = env.mode === "device";
  if (device && p.purpose !== "login") throw new TypeError("a device has no re-authentication: it unlocks or signs in");
  const db = await store.open();
  /** A device's sign-in has a new key and its own tokens (unused in the web vault). */
  const tokens = /** @type {import("../auth/tokens.mjs").TokenAuth} */ (device ? await deviceSlot(env).fresh() : null);
  // A browser names itself with an id of its own; the server names a device.
  const deviceId = device ? null : await store.deviceId(db, env.rand);
  const qr = p.qr ?? null;

  /** @type {Record<string, any>} */
  let start;
  /** @type {Uint8Array} */
  let ke3;
  try {
    // The sheet is for this server or the sign-in does not start: nothing is sent to a server the sheet is not for.
    if (qr !== null) checkQrBeforeKe3(qr, { serverUrl: server });
    const ke1 = await withPassword(p.password, (mp) => client.vault.login_start(mp, p.skCode));
    const startBody = encodeWire("login_start_req", { email: p.email, ke1: b64u.encode(ke1), purpose: p.purpose });
    start = device
      ? await tokens.startSignIn(startBody)
      : await api.post("/api/auth/opaque/login/start", startBody, { shape: "login_start_res" });
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
    done = device
      ? await tokens.finishSignIn(
        encodeWire("login_finish_req_device", {
          login_id: start.login_id,
          ke3: b64u.encode(ke3),
          client: "device",
          device_name: env.deviceName,
          platform: env.platform,
        }),
      )
      : await api.post(
        "/api/auth/opaque/login/finish",
        encodeWire("login_finish_req", {
          login_id: start.login_id,
          ke3: b64u.encode(ke3),
          device_id: deviceId,
          device_name: env.deviceName ?? DEVICE_NAME,
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
  // The device of this sign-in is the session's device from now on (its API client carries the new token).
  if (device) deviceSlot(env).use(tokens);

  // What the refusal of an older password is weighed against (see `pinnedRefusalAction`).
  /** @type {Record<string, any> | null} */
  let seenRecord = null;
  /** @type {Record<string, any> | null} */
  let seenMethods = null;
  try {
    // The server has named the account. It is the sheet's account, and no other address has it pinned: both
    // are asked before anything is pinned.
    if (qr !== null) checkQrAfterLogin(qr, { accountId: done.account_id });
    const record = await store.pinnedForSignIn(db, server, p.email, done.account_id);
    seenRecord = record;
    // A re-authentication in a session that is already pinned here makes no new pin; every other path does.
    if (p.purpose === "login" || !record) {
      const other = await store.pinnedElsewhere(db, server, done.account_id);
      if (other !== null) throw new AccountError("pinned_elsewhere", { server: other, accountId: done.account_id });
    }
    const methods = await api.get("/api/vault/unlock-methods", { shape: "methods_res" });
    seenMethods = methods;
    if (methods.vk_epoch !== done.vk_epoch) throw new AccountError("epoch_mismatch");
    return await openWith(env, db, {
      methods,
      accountId: done.account_id,
      vaultId: done.vault_id,
      vkEpoch: done.vk_epoch,
      profile: start.ksf_profile,
      record,
      email: p.email,
      skBit: p.skBit,
      skCode: p.skCode,
      rememberSk: p.rememberSk,
      purpose: p.purpose,
    });
  } catch (error) {
    await Promise.resolve(env.lock()).catch(() => undefined);
    // A refusal of an older password after a restore of the server can be answered with the recovery key (in the web
    // vault's session only: a device is not offered it).
    const offer = !device && codeOf(error) === "pinned_kek_generation" && seenRecord && seenMethods
      ? await pinnedRefusalAction(env, db, { accountId: done.account_id, record: seenRecord, methods: seenMethods }).catch(() => null)
      : null;
    if (offer !== null && error !== null && typeof error === "object") /** @type {any} */ (error).recoveryOffer = offer;
    // A sign-in that did not open the vault leaves no session behind; a
    // re-authentication must not end the session it was made for. The one
    // exception is the offer to recover: that recovery runs in this session.
    // A device's new tokens always go.
    if (device) await tokens.revoke().catch(() => undefined);
    else if (p.purpose === "login" && offer !== "recover") await api.post("/api/auth/logout").catch(() => undefined);
    throw error;
  }
}

/**
 * The steps that open the vault once the server's account, wraps and manifest are known: the one password wrap, the
 * core's unlock under the pin state, the generation floors, the server's list against the manifest, the account key,
 * the pin, and what becomes of the remembered secret key. Shared by a sign-in, a re-authentication and a device's unlock.
 * @param {Env} env
 * @param {import("../store/idb.mjs").Store} db
 * @param {{
 *   methods: Record<string, any>,
 *   accountId: string,
 *   vaultId: string,
 *   vkEpoch: number,
 *   profile: number,
 *   record: Record<string, any> | null,
 *   email: string,
 *   skBit: boolean,
 *   skCode: string | null,
 *   rememberSk?: boolean,
 *   purpose: "login" | "reauth" | "unlock",
 * }} o
 * @returns {Promise<Unlocked>}
 */
async function openWith(env, db, o) {
  const { client, store, server } = env;
  const { methods } = o;
  const passwordWraps = methods.methods.filter((/** @type {{ method_type: number }} */ m) => m.method_type === 1);
  if (passwordWraps.length !== 1) throw new AccountError("methods_invalid");

  // Accepted residual: when the e-mail was changed on another device, the early
  // guard of `login_finish` was `first_use`, so a lower KSF profile than the pinned one
  // is caught only here, after Argon2id has run. `unlock_password` still refuses it
  // (`pinned_profile_downgrade`) and the sign-in ends. M1 has one profile, so none can be lower.
  const pin = o.record ? { kind: "pinned", record: o.record } : { kind: "first_use", sk_bit: o.skBit };
  const ctx = { account_id: hex16.decode(o.accountId), vault_id: hex16.decode(o.vaultId), vk_epoch: o.vkEpoch };
  const opened = await client.vault.unlock_password(server, ctx, wrapToCore(passwordWraps[0], o.profile), pin);
  const seeded = await client.vault.seed_pinned(opened.pinned, rowToCore(methods.manifest));
  await client.vault.check_server_methods(rowToCore(methods.manifest), serverMethods(methods.methods));
  // The account key the server lists must be the one the vault pins.
  if (!sameBytes(seeded.pk_a, b64u.decode(methods.pk_a))) throw new AccountError("pinned_auth_key");
  await store.savePinned(db, server, o.accountId, o.email, seeded);

  /** @type {Unlocked["secretKey"]} */
  let secretKey = "unchanged";
  if (o.purpose === "login" && o.rememberSk === false) {
    await forgetSecretKey(db, server, o.accountId);
    secretKey = "forgotten";
  } else if (o.purpose === "login" && o.rememberSk === true && o.skBit && o.skCode) {
    secretKey = await saveSecretKey(db, server, o.accountId, o.skCode, env.secrets);
  }
  return {
    accountId: o.accountId,
    vaultId: o.vaultId,
    vkEpoch: o.vkEpoch,
    email: o.email,
    pinned: seeded,
    secretKey,
    purpose: o.purpose,
  };
}

/**
 * The device of a device session (see `crypto/env.mjs`).
 * @param {Env} env
 * @returns {import("../crypto/env.mjs").DeviceSlot}
 */
function deviceSlot(env) {
  if (env.mode !== "device" || !env.device) throw new TypeError("only a device session has a device");
  return env.device;
}

/**
 * The unlock of a device that keeps its device and tokens (see the top of this file). A device whose tokens have
 * ended, or that has no pinned record for its account, signs in again with the same password.
 * @param {Env} env
 * @param {{ password: string, email?: string, skCode?: string, skBit?: boolean, rememberSk?: boolean }} args
 * @returns {Promise<Unlocked>}
 */
async function unlockDevice(env, args) {
  const { client, api, store, server } = env;
  const tokens = await deviceSlot(env).tokens();
  const db = await store.open();
  /** A new sign-in with the password just typed (a new device key and new tokens). @param {string | null} email */
  const signInAgain = (email) => {
    if (email === null) throw new AccountError("session_ended");
    return signIn(env, { ...args, email });
  };
  const stored = tokens !== null && tokens.state === "ok" ? await loadDeviceKey(db, server).catch(() => null) : null;
  const accountId = stored?.accountId ?? null;
  const known = accountId !== null ? (await store.loadPinnedAccount(db, server, accountId))?.email ?? null : null;
  const email = nonEmpty(args.email) ?? known;
  if (tokens === null || tokens.state !== "ok" || accountId === null || email === null) return signInAgain(email);
  const record = await store.pinnedForSignIn(db, server, email, accountId);
  // No first use at an unlock: the pin of the device's own account, or a sign-in.
  if (!record || !(record.account_id instanceof Uint8Array) || hex16.encode(record.account_id) !== accountId) return signInAgain(email);

  // The device's token first: a device that was signed out, revoked or replaced signs in again, before any password work.
  /** @type {Record<string, any>} */
  let methods;
  try {
    methods = await api.get("/api/vault/unlock-methods", { shape: "methods_res" });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401 && tokens.state !== "ok") return signInAgain(email);
    throw error;
  }

  const { skBit, skCode } = await decideSecretKey(env, db, record, args);
  /** @type {Record<string, any>} */
  let start;
  try {
    const ke1 = await withPassword(args.password, (mp) => client.vault.login_start(mp, skCode));
    start = await tokens.startUnlock(encodeWire("login_start_req", { email, ke1: b64u.encode(ke1), purpose: "login" }));
    try {
      const finished = await client.vault.login_finish(b64u.decode(start.ke2), start.ksf_profile, { kind: "pinned", record });
      // KE3 proves the password to the server; an unlock does not post it, so it is dropped here.
      if (finished?.ke3 instanceof Uint8Array) finished.ke3.fill(0);
    } catch (error) {
      throw withSkHint(error, start.sk_hint);
    }
  } catch (error) {
    // Nothing was opened: the job drops the password-derived state it holds.
    await Promise.resolve(client.vault.clear()).catch(() => undefined);
    throw error;
  }

  try {
    return await openWith(env, db, {
      methods,
      accountId,
      vaultId: hex16.encode(record.vault_id),
      vkEpoch: methods.vk_epoch,
      profile: start.ksf_profile,
      record,
      email,
      skBit,
      skCode,
      purpose: "unlock",
    });
  } catch (error) {
    // The device stays: a refusal of what the server lists is no reason to sign it out.
    await Promise.resolve(env.lock()).catch(() => undefined);
    throw error;
  }
}

/**
 * The floor this device has pinned for an unlock method, or null.
 * @param {Record<string, any>} record
 * @param {"password" | "recovery"} type
 * @returns {number | null}
 */
function floorOf(record, type) {
  const floor = Array.isArray(record?.kek_generation_max) ? record.kek_generation_max.find((/** @type {any} */ f) => f?.type === type) : undefined;
  return Number.isSafeInteger(floor?.generation) ? floor.generation : null;
}

/**
 * The generation of the server's wrap of an unlock method type (1 password, 2 recovery), or null.
 * @param {Record<string, any>} methods the answer of `GET /api/vault/unlock-methods`
 * @param {number} type
 * @returns {number | null}
 */
function serverGeneration(methods, type) {
  const wraps = Array.isArray(methods?.methods) ? methods.methods.filter((/** @type {any} */ m) => m.method_type === type) : [];
  return wraps.length === 1 && Number.isSafeInteger(wraps[0].kek_generation) ? wraps[0].kek_generation : null;
}

/**
 * What a page can offer after the core refused the server's password wrap as older than the one this device has
 * seen (`pinned_kek_generation`, spec Fase 1 § 4.5 and § 8.6, "re-applying the newest unlock methods"):
 *
 *   - `"recover"`: the server's restore epoch is above the one this device has stored, so the server was restored
 *     from a backup. If the restore is the user's own, the recovery key the server holds opens the vault, and a
 *     recovery with the newest master password as the new one puts the password back (in this session);
 *   - `"old_sheet"`: as above, but the server's recovery wrap is below this device's recovery floor too (the recovery
 *     key was renewed after the backup). The newest recovery key does not work on this server, and this device does
 *     not use the older one: the way out is to forget this server here, then use the sheet from before the renewal,
 *     or sign in with the password the server knows;
 *   - `null`: the epoch was not raised (or cannot be read), so the refusal keeps the text that it can be an attack.
 *
 * No answer here lowers a floor or changes a check; it only picks what the page says and offers. The restore epoch
 * the server states is not authenticated, so a server that raises it (with an older wrap) can lead the user on:
 *   - into a recovery: the server then gets a new OPAQUE record for the newest master password (open to guessing
 *     offline by whoever holds the OPRF key when the account has no secret key), the recovery key is rotated, and the
 *     account's other sessions end. The recovery key never leaves the core, the request is signed with the old one,
 *     every pin of this device is checked (the core refuses a recovery wrap below its floor) and the store refuses a
 *     record that would lower one;
 *   - in the `old_sheet` case, towards forgetting this server on this device, which drops its pins. Both texts say
 *     so only "if you restored the server yourself" and name the attack otherwise.
 * These checks protect the honest-code case: the web vault's code comes from the same origin, so a hostile server can
 * serve code that skips them; the extension and the apps keep them.
 * @param {Env} env
 * @param {import("../store/idb.mjs").Store} db
 * @param {{ accountId: string, record: Record<string, any>, methods: Record<string, any> }} seen
 * @returns {Promise<"recover" | "old_sheet" | null>}
 */
export async function pinnedRefusalAction(env, db, { accountId, record, methods }) {
  const passwordFloor = floorOf(record, "password");
  const passwordOnServer = serverGeneration(methods, 1);
  // The refusal is about the password wrap, and that wrap really is below what this device has seen.
  if (passwordFloor === null || passwordOnServer === null || passwordOnServer >= passwordFloor) return null;
  const state = await env.store.loadSyncState(db, env.server, accountId);
  const stored = state?.restoreEpoch;
  if (!Number.isSafeInteger(stored)) return null;
  // A cursor at the top of the feed asks for no rows, only the head (and is never below the floor).
  const feed = await env.api.get(`/api/sync/changes?since=${Number.MAX_SAFE_INTEGER}&limit=1`, { shape: "changes_res" });
  if (!Number.isSafeInteger(feed.restore_epoch) || feed.restore_epoch <= stored) return null;
  const recoveryFloor = floorOf(record, "recovery");
  const recoveryOnServer = serverGeneration(methods, 2);
  if (recoveryOnServer === null) return null;
  return recoveryFloor !== null && recoveryOnServer < recoveryFloor ? "old_sheet" : "recover";
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
  // A device has no session to re-authenticate: it keeps its device and opens the vault with the password.
  if (env.mode === "device") return unlockDevice(env, args);
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
