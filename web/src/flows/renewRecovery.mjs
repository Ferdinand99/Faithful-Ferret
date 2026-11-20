// A new recovery key for the open vault (spec Fase 1 § 4.3, § 4.5, § 4.6 and § 6.1). The order
// of the calls:
//
//   reauth                  the master password again (the page's dialog; skipped while the check is fresh)
//   GET session             who the session is; this device's pinned record of the account
//   GET unlock-methods      the recovery wrap, the manifest row and `pk_a` the server holds
//   seed_pinned             core: adds the generation floors from that manifest to this device's record
//   check_server_methods    core: the server's list against the manifest (a disagreement closes the vault)
//   renew_recovery          core: the new key, a new recovery wrap above every floor, `pk_r` and the manifest
//   reveal_recovery_code    page 2 alone: the new key, shown once (page 1 does not change)
//   (the page)              the new key is written down and typed back; `verify_recovery_setup` checks it
//   POST challenge, auth_sign, PUT unlock-methods/recovery   the signed write (`signedCall.mjs`)
//   savePinned              only after the server answered 200
//
// Nothing is sent before the new key has been typed back and checked (J22). A "no" at the sheet,
// a lock or any refusal discards the new key (`clear_setup_secrets`) and leaves the record and
// the server as they were: the old key still works. The new key also leaves the worker after a
// write that went through. A renewal ends no session; the server asks for a backup after it.
//
// The core makes the full sheet only while it holds the secret key; after a renewal it does not,
// so only page 2 is made here (`pageTwoOnly`) and page 1 is never built from this flow. Page 1 is
// printed again on its own page (`showSecretKey.mjs`, `accessSheet`).
//
// The new key reaches the page as a string, which JavaScript cannot wipe; the page drops it
// with the sheet. No key, code or typed value is logged, stored or put in an address.
//
// The core's other entry, for a server restored from an older backup (`flows/reapplyMethods.mjs`),
// goes through `runRenewal` with its own entry. No other module names that entry.
import { ApiError } from "../api.mjs";
import { b64u } from "../b64.mjs";
import { num, rowToCore, rowToWire, serverMethods, wrapToCore } from "../crypto/convert.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { pageTwoOnly } from "./emergencySheet.mjs";
import { accountContext } from "./reauth.mjs";
import { signedCall } from "./signedCall.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {import("../../js/client.mjs").RenewedRecovery} RenewedRecovery */
/** @typedef {import("./emergencySheet.mjs").Sheet} Sheet */

/** The name of the signed operation (spec Fase 1 § 4.6). */
export const RECOVERY_OP = "unlock-method.recovery.put";

/** The method types of the server's list. */
const PASSWORD_TYPE = 1;
const RECOVERY_TYPE = 2;

/**
 * Asks the page for the master password again; "ok" when it was confirmed (or is still fresh).
 * @typedef {() => Promise<"ok" | "cancelled">} Reauth
 */

/**
 * Shows the new page 2 and waits for the user. `verify(typed)` checks a typed key in the core; it
 * rejects on a typo or another key, and the page lets the user try again. The answer is true once a
 * `verify` has passed, false when the user said no (or left the page, or the vault locked).
 * @typedef {(shown: { sheet: Sheet, verify: (typed: string) => Promise<void> }) => Promise<boolean>} ConfirmNewRk
 */

/**
 * What the server holds and this device has pinned, read and checked as at an unlock.
 * @typedef {object} Methods
 * @property {Record<string, any>} seeded the pinned record with the floors of the manifest
 * @property {Record<string, any>} manifest the manifest row, for the core
 * @property {Record<string, any>} recovery the server's recovery wrap (wire form)
 * @property {Record<string, any>} password the server's password wrap (wire form)
 */

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * The floor this device holds for a method type, or null when it holds none.
 * @param {Record<string, any>} record
 * @param {"password" | "recovery"} type
 * @returns {number | null}
 */
export function floorOf(record, type) {
  const floor = (record?.kek_generation_max ?? []).find((/** @type {any} */ f) => f?.type === type);
  return floor === undefined ? null : num(floor.generation);
}

/**
 * The server-side methods whose generation is below the floor this device holds: an older state of the
 * server (a restore, or a rollback). Never anything the device has not seen go higher.
 * @param {Methods} methods
 * @returns {Array<"password" | "recovery">}
 */
export function belowFloor(methods) {
  /** @type {Array<"password" | "recovery">} */
  const below = [];
  for (const [type, wrap] of /** @type {const} */ ([["password", methods.password], ["recovery", methods.recovery]])) {
    const floor = floorOf(methods.seeded, type);
    if (floor !== null && num(wrap.kek_generation) < floor) below.push(type);
  }
  return below;
}

/**
 * Reads the unlock methods and checks them against this device's record. A disagreement (an unknown or
 * missing method, another `pk_a`) closes the vault, as at an unlock.
 * @param {Env} env
 * @param {Record<string, any>} record this device's pinned record of the account
 * @returns {Promise<Methods>}
 */
export async function readMethods(env, record) {
  const { client, api } = env;
  const methods = await api.get("/api/vault/unlock-methods", { shape: "methods_res" });
  const of = (/** @type {number} */ type) => methods.methods.filter((/** @type {{ method_type: number }} */ m) => m.method_type === type);
  const recovery = of(RECOVERY_TYPE);
  const password = of(PASSWORD_TYPE);
  if (recovery.length !== 1 || password.length !== 1) throw new AccountError("methods_invalid");
  const manifest = rowToCore(methods.manifest);
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
  return { seeded, manifest, recovery: recovery[0], password: password[0] };
}

/**
 * Whether a failure of the signed write leaves it unknown if the server took the new key: it was sent, and
 * the answer is no answer, a server error or not an answer this page understands. An explicit refusal is not.
 * @param {unknown} error
 */
function outcomeUnknown(error) {
  const e = /** @type {any} */ (error);
  if (e?.afterSend !== true && e?.details?.afterSend !== true) return false;
  if (e instanceof ApiError) return e.status === 0 || e.status >= 500 || e.code === "bad_response" || e.code === "network";
  return e?.code === "bad_response";
}

/**
 * The record the core hands back must keep every floor this device had and raise the recovery floor
 * above the old one: a floor is never lowered (spec Fase 1 § 4.3). Checked before anything is sent.
 * @param {Record<string, any>} before
 * @param {Record<string, any>} after
 */
function checkFloorsRise(before, after) {
  const key = (/** @type {any} */ f) => `${f?.type}:${f?.credential_id instanceof Uint8Array ? b64u.encode(f.credential_id) : ""}`;
  const next = new Map((after?.kek_generation_max ?? []).map((/** @type {any} */ f) => [key(f), num(f.generation)]));
  for (const floor of before?.kek_generation_max ?? []) {
    const raised = next.get(key(floor));
    if (raised === undefined || raised < num(floor.generation)) throw new AccountError("pinned_floor_downgrade");
  }
  const old = floorOf(before, "recovery");
  const now = floorOf(after, "recovery");
  if (now === null || (old !== null && now <= old)) throw new AccountError("pinned_floor_downgrade");
}

/**
 * The renewal with a given core entry. `check` runs after the methods are read and before anything is made;
 * it may refuse. Exported for `reapplyMethods.mjs`; everything else calls `renewRecoveryKey`.
 * @param {Env} env
 * @param {{
 *   confirmNewRk: ConfirmNewRk,
 *   reauth: Reauth,
 *   entry: (vault: any, pinned: Record<string, any>, current: Record<string, any>, manifest: Record<string, any>) => Promise<RenewedRecovery>,
 *   check?: (methods: Methods, context: Awaited<ReturnType<typeof accountContext>>) => Promise<void>,
 * }} args
 * @returns {Promise<{ kekGeneration: number }>}
 */
export async function runRenewal(env, { confirmNewRk, reauth, entry, check }) {
  const { client, store, server } = env;
  if (typeof confirmNewRk !== "function" || typeof reauth !== "function") throw new TypeError("renewal: confirmNewRk and reauth are needed");
  if ((await reauth()) !== "ok") throw new AccountError("cancelled");

  const context = await accountContext(env);
  const { info, db, record } = context;
  const methods = await readMethods(env, record);
  if (check) await check(methods, context);

  // A key made earlier in this tab that was never typed back (a page left half way) was never sent: it goes.
  await client.vault.clear_setup_secrets();
  try {
    const renewed = await entry(client.vault, methods.seeded, wrapToCore(methods.recovery, num(record.ksf_profile)), methods.manifest);
    const generation = num(renewed.wrap.kek_generation);
    checkFloorsRise(methods.seeded, renewed.pinned);

    // Page 2 alone. The string is the page's to drop; nothing here keeps it.
    let verified = false;
    const verify = async (/** @type {string} */ typed) => {
      // The core reads what was typed: a typo is `checksum`, another key `decrypt`, nothing at all `malformed_code`.
      await client.vault.verify_recovery_setup(String(typed ?? ""), renewed.wrap);
      verified = true;
    };
    const confirmed = await confirmNewRk({ sheet: pageTwoOnly(await client.vault.reveal_recovery_code()), verify });
    // Only a check that passed here counts, whatever the page answers.
    if (confirmed !== true || !verified) throw new AccountError("cancelled");

    const body = {
      wrap: b64u.encode(renewed.wrap.wrap),
      kek_generation: generation,
      pk_r: b64u.encode(renewed.pk_r),
      manifest: rowToWire(renewed.manifest),
    };
    const send = () => signedCall(env, { op: RECOVERY_OP, method: "PUT", path: "/api/vault/unlock-methods/recovery", shape: "recovery_put_req", body });
    /** @type {Record<string, any>} */
    let answer;
    try {
      try {
        answer = await send();
      } catch (error) {
        // Writing the key down can take longer than the password check lasts. The server refused before it
        // changed anything, so the check is asked for once more and the same signed change is sent again.
        if (!(error instanceof ApiError && error.code === "reauth_required")) throw error;
        if ((await reauth()) !== "ok") throw new AccountError("cancelled");
        answer = await send();
      }
      // An answer for another generation than the one that was signed cannot be trusted either way.
      if (answer.kek_generation !== generation) throw new AccountError("bad_response", { afterSend: true });
    } catch (error) {
      if (outcomeUnknown(error)) throw new AccountError("renew_unconfirmed");
      throw error;
    }

    // The server has the new key. Only now does this device pin the raised floor.
    try {
      await store.savePinned(db, server, info.accountId, info.email, renewed.pinned);
    } catch (error) {
      throw new AccountError("renew_pin_save_failed", { cause: /** @type {any} */ (error)?.code ?? null });
    }
    return { kekGeneration: generation };
  } finally {
    // The new key leaves the worker on every path: typed back and sent, refused, or not wanted.
    await Promise.resolve(client.vault.clear_setup_secrets()).catch(() => undefined);
  }
}

/**
 * Makes a new recovery key and puts it in force. A wrap or manifest entry below this device's floor is
 * refused by the core (`pinned_kek_generation`): the server shows an older recovery key than this device
 * has seen. After an accepted restore, `reapplyMethods` is the way on.
 * @param {Env} env
 * @param {{ confirmNewRk: ConfirmNewRk, reauth: Reauth }} args
 * @returns {Promise<{ kekGeneration: number }>}
 */
export async function renewRecoveryKey(env, { confirmNewRk, reauth }) {
  return runRenewal(env, {
    confirmNewRk,
    reauth,
    entry: (vault, pinned, current, manifest) => vault.renew_recovery(pinned, current, manifest),
  });
}
