// Opening a closed vault with a passkey (spec Fase 1 § 7.3, § 4.3, § 9.4). The web vault and the browser extension share
// this file (extension/shared.json): the page that calls it makes the WebAuthn call itself and hands it in as
// `getAssertion`, so nothing here touches the browser.
//
// A passkey opens the vault only while the vault session on the server is still valid: it is a way to open the vault
// again, not a way to sign in. An ended session asks for the master password, as it always did. The device must also hold
// the pinned record of the account (a passkey, like the password, is never the first unlock of a device).
//
// In two parts, because a browser lets a page make one WebAuthn call for each click and the call has to come from the click:
//
//   preparePasskeyUnlock   when the Unlock page is shown. No passkey is asked for. The session, the server's rule and the list
//                          of the account's passkey methods give the credential ids and salts the call needs. Nothing is
//                          offered (null) unless the session is valid, this device has the pinned record, the server
//                          offers passkeys and the account has at least one passkey method.
//   unlockWithPasskey      from the click. The first thing it does is the WebAuthn call (`allowCredentials` with every
//                          method's credential and `evalByCredential` with its salt, user verification required); the
//                          answer must name one of those credentials, the user must have been verified and the PRF result
//                          must be exactly 32 bytes. Then, with nothing from the earlier read trusted:
//     GET unlock-methods   the list as it is now (a method removed meanwhile is `method_removed`, a changed one `method_changed`)
//     unlock_prf           core: opens the vault with the passkey's wrap under the pinned record only (no first use); the
//                          pins, the generation floors and the key epoch are checked as for the master password
//     seed_pinned, check_server_methods, pk_a, savePinned   the same checks as after the master password (`sealOpened`)
//
// A refusal at any step locks the vault again. The PRF result is a lasting secret of the vault: it goes from the
// browser's answer to the core and nowhere else (not to the page, a log, storage or a request), and the copy this module
// holds is wiped when the core has it. A wrong key, a missing result and one of the wrong size are one answer
// (`passkey_unlock_failed`), so the page cannot say which of them it was.
import { ApiError } from "../api.mjs";
import { b64u, hex16 } from "../b64.mjs";
import { wrapToCore } from "../crypto/convert.mjs";
import { AccountError, codeOf } from "../crypto/errors.mjs";
import { evaluateOneOf, PRF_OUTPUT_LENGTH } from "./passkeyAnswer.mjs";
import { sealOpened, sessionInfo } from "./signin.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {import("../crypto/env.mjs").Unlocked} Unlocked */
/** @typedef {import("./passkeyAnswer.mjs").CeremonyDeps} CeremonyDeps */

/** The path of the list of unlock methods. */
const METHODS_PATH = "/api/vault/unlock-methods";
/** The path of the server's rule for quick unlock. */
const POLICY_PATH = "/api/vault/policy";
/** The method type of a passkey on the wire. */
const PRF_TYPE = 3;
/** The codes of the ceremony that mean the passkey gave no usable key: one answer for all of them. */
const NO_KEY = Object.freeze(["passkey_no_output", "passkey_bad_output"]);

/**
 * What the page holds between showing the offer and the click. Public values only: the account, the host and, for each
 * passkey method, its credential id and salt.
 * @typedef {object} PasskeyOffer
 * @property {string} accountId
 * @property {string} email
 * @property {string} rpId the exact host of the vault
 * @property {Array<{ id: Uint8Array, salt: Uint8Array }>} credentials
 */

/**
 * Whether a passkey can be offered on the Unlock page, and what the click needs. Nothing is offered (null) when the vault
 * session has ended, this device has no pinned record of the account, the server does not offer passkeys or the account
 * has no passkey method. Any failure of a read is "not offered": the master password is always there.
 * @param {Env} env
 * @param {{ rpId: string }} options `rpId` is the exact host of the vault
 * @returns {Promise<PasskeyOffer | null>}
 */
export async function preparePasskeyUnlock(env, { rpId }) {
  try {
    if (typeof rpId !== "string" || rpId === "") return null;
    const info = await sessionInfo(env);
    if (info === null) return null;
    const rule = await env.api.get(POLICY_PATH);
    if (rule?.prf?.enabled !== true) return null;
    const db = await env.store.open();
    const record = await env.store.pinnedForSignIn(db, env.server, info.email, info.accountId);
    if (!record) return null;
    const methods = await env.api.get(METHODS_PATH, { shape: "methods_res" });
    // A row whose salt is not 32 bytes cannot be evaluated: it is left out (the wire refuses such a list already; this keeps
    // one bad row from breaking the button if that ever changes).
    const credentials = passkeyWraps(methods)
      .map((wrap) => ({ id: b64u.decode(wrap.credential_id), salt: b64u.decode(wrap.prf_salt) }))
      .filter(({ salt }) => salt.length === PRF_OUTPUT_LENGTH);
    if (credentials.length === 0) return null;
    return { accountId: info.accountId, email: info.email, rpId, credentials };
  } catch {
    return null;
  }
}

/**
 * The passkey methods of a list, with what an evaluation needs.
 * @param {Record<string, any>} methods the answer of `GET unlock-methods`
 * @returns {Array<Record<string, any>>}
 */
function passkeyWraps(methods) {
  return methods.methods.filter((/** @type {Record<string, any>} */ m) => m.method_type === PRF_TYPE && typeof m.credential_id === "string" && typeof m.prf_salt === "string");
}

/**
 * Opens the vault with a passkey. Call it from the click: the WebAuthn call is the first thing it does.
 * @param {Env} env
 * @param {PasskeyOffer} offer what `preparePasskeyUnlock` gave
 * @param {{ getAssertion: (publicKey: any) => Promise<any>, deps: Omit<CeremonyDeps, "credentials"> }} how `getAssertion` is the page's
 *   WebAuthn call for the page; `deps` are the random source, the clock, SHA-256 and the page's origin
 * @returns {Promise<Unlocked>}
 */
export async function unlockWithPasskey(env, offer, { getAssertion, deps }) {
  /** @type {{ credentialId: Uint8Array, output: Uint8Array }} */
  let answer;
  try {
    answer = await evaluateOneOf({ rpId: offer.rpId, credentials: offer.credentials, getAssertion }, deps);
  } catch (error) {
    // A passkey that gave no key, or one of the wrong size, is the same answer as a key that does not open the vault.
    throw NO_KEY.includes(codeOf(error)) ? new AccountError("passkey_unlock_failed") : error;
  }
  const { credentialId, output } = answer;
  try {
    return await openWith(env, offer, credentialId, output);
  } catch (error) {
    // Whatever refused (the list, the core, a check after it), no vault stays open. The server session stays: the
    // password still works.
    await Promise.resolve(env.lock()).catch(() => undefined);
    throw error;
  } finally {
    output.fill(0);
  }
}

/**
 * The part after the passkey has answered: the list as it is now, the core's unlock and the checks that follow.
 * @param {Env} env
 * @param {PasskeyOffer} offer
 * @param {Uint8Array} credentialId
 * @param {Uint8Array} output
 * @returns {Promise<Unlocked>}
 */
async function openWith(env, offer, credentialId, output) {
  const info = await sessionInfo(env);
  // The session ended, or it is another account's now: the password is asked for, as before.
  if (info === null || info.accountId !== offer.accountId) throw new AccountError("session_ended");
  const db = await env.store.open();
  const record = await env.store.pinnedForSignIn(db, env.server, info.email, info.accountId);
  // No first use: a passkey opens the vault of a device that has opened it before.
  if (!record || !(record.vault_id instanceof Uint8Array)) throw new AccountError("session_ended");
  /** @type {Record<string, any>} */
  let methods;
  try {
    methods = await env.api.get(METHODS_PATH, { shape: "methods_res" });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) throw new AccountError("session_ended");
    throw error;
  }
  const wanted = b64u.encode(credentialId);
  const wrap = passkeyWraps(methods).find((m) => m.credential_id === wanted);
  // The method was removed since the page was shown: nothing is tried with it.
  if (wrap === undefined) throw new AccountError("method_removed");
  const asked = offer.credentials.find(({ id }) => b64u.encode(id) === wanted);
  if (asked === undefined || b64u.encode(asked.salt) !== wrap.prf_salt) throw new AccountError("method_changed");

  const ctx = { account_id: hex16.decode(info.accountId), vault_id: record.vault_id, vk_epoch: methods.vk_epoch };
  /** @type {{ pinned: Record<string, any> }} */
  let opened;
  try {
    // No OPAQUE exchange runs here, so the server shows no key to check. The record's own key is handed back so that the
    // core's server-key pin is neutral (it never pins a new one). What this unlock authenticates is the data, not the
    // server: the wrap opens only under the passkey's key for the pinned account, vault and epoch, and `pk_a`, the floors
    // and the manifest are checked after it. Never take this key from a server response.
    const pinned = { kind: "pinned", record, ...(record.server_public_key instanceof Uint8Array ? { server_public_key: record.server_public_key } : {}) };
    opened = await env.client.vault.unlock_prf(env.server, ctx, output, wrapToCore(wrap, 0), pinned);
  } catch (error) {
    // A key that does not open the wrap has no more to say than a missing one.
    throw codeOf(error) === "decrypt" ? new AccountError("passkey_unlock_failed") : error;
  }
  const seeded = await sealOpened(env, db, { opened, methods, accountId: info.accountId, email: info.email });
  return {
    accountId: info.accountId,
    vaultId: hex16.encode(record.vault_id),
    vkEpoch: methods.vk_epoch,
    email: info.email,
    pinned: seeded,
    secretKey: "unchanged",
    purpose: "unlock",
  };
}
