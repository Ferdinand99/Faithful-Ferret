// The secret key, shown again, and page 1 of the emergency sheet, printed again (spec Fase 1 § 6.1,
// § 6.2 and § 4.6). Both are sensitive operations: the master password is asked for again first (the
// page's dialog; skipped while the check is fresh). Neither sends anything to the server or changes
// anything: the secret key comes from this device, where the user let the browser remember it after a
// sign-in (`deviceSecret.mjs`), and page 1 is made from that key and this device's pinned record.
//
//   showSecretKey   the code `FFS1-...` and a QR code that holds that text and nothing else
//   accessSheet     page 1 alone as a PDF (address, e-mail, account id, profile, secret key, the setup
//                   QR code and its text). Page 2 is never made here: no device keeps the recovery key
//                   after it was typed back; a new page 2 is a new recovery key (`renewRecovery.mjs`).
//
// When this device does not remember the secret key, nothing is shown and no page 1 is made: the
// secret key is on page 1 of the sheet the user already has. A page 1 is never made for an account
// with a secret key without its key (`checkAccessPage`).
//
// The code is a string, which JavaScript cannot wipe; the page drops it when it hides the key, on
// a lock and when it is left. The PDF bytes are the caller's to wipe after the download. No key or
// code is logged, stored or put in an address.
import { hex16 } from "../b64.mjs";
import { num } from "../crypto/convert.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { qrModules } from "../qr.mjs";
import { hasSecretKey, loadSecretKey } from "./deviceSecret.mjs";
import { accessPdf, checkAccessPage } from "./emergencySheet.mjs";
import { accountContext } from "./reauth.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */
/** @typedef {import("./renewRecovery.mjs").Reauth} Reauth */
/** @typedef {(key: string, vars?: Record<string, string | number>) => string} Translate */

/**
 * The account id as the sheet writes it: a UUID in the usual text form (8-4-4-4-12, lower-case hex).
 * @param {Uint8Array} id
 */
export function accountIdText(id) {
  const hex = hex16.encode(id);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * The account, and the secret key this device remembers for it: `"no_secret_key"` for an account without one,
 * `"not_remembered"` when this device keeps none. The key itself is read only after the password check.
 * @param {Env} env
 */
async function remembered(env) {
  const context = await accountContext(env);
  const { info, db, record } = context;
  if (record.sk_bit !== true) return { context, kept: /** @type {const} */ ("no_secret_key") };
  if (!(await hasSecretKey(db, env.server, info.accountId))) return { context, kept: /** @type {const} */ ("not_remembered") };
  return { context, kept: /** @type {const} */ ("kept") };
}

/**
 * The secret key code of the account, read after `reauth`, and checked for form by the core. Null when it
 * cannot be opened any more (the browser lost the sealing key).
 * @param {Env} env
 * @param {string} accountId
 * @param {any} db
 */
async function readKey(env, db, accountId) {
  const code = await loadSecretKey(db, env.server, accountId, env.secrets);
  if (code === null) return null;
  await env.client.vault.check_code("secret_key", code);
  return code;
}

/**
 * Shows the secret key again: its code and a QR code of exactly that text.
 * @param {Env} env
 * @param {{ reauth: Reauth }} args
 * @returns {Promise<{ code: string, qr: { size: number, dark: (x: number, y: number) => boolean } } | "not_remembered" | "no_secret_key">}
 */
export async function showSecretKey(env, { reauth }) {
  if (typeof reauth !== "function") throw new TypeError("showSecretKey: reauth is needed");
  const { context, kept } = await remembered(env);
  if (kept !== "kept") return kept;
  if ((await reauth()) !== "ok") throw new AccountError("cancelled");
  const code = await readKey(env, context.db, context.info.accountId);
  if (code === null) return "not_remembered";
  return { code, qr: qrModules(code) };
}

/**
 * Page 1 of the emergency sheet again, as a PDF of one page.
 * @param {Env} env
 * @param {{ reauth: Reauth, t: Translate }} args
 * @returns {Promise<Uint8Array>}
 */
export async function accessSheet(env, { reauth, t }) {
  if (typeof reauth !== "function") throw new TypeError("accessSheet: reauth is needed");
  const { context, kept } = await remembered(env);
  if (kept === "not_remembered") throw new AccountError("sk_not_remembered");
  const { info, db, record } = context;
  if (!(record.server_public_key instanceof Uint8Array) || record.server_public_key.length !== 32) throw new AccountError("sheet_server_key_missing");
  if ((await reauth()) !== "ok") throw new AccountError("cancelled");

  const skBit = record.sk_bit === true;
  const code = skBit ? await readKey(env, db, info.accountId) : null;
  if (skBit && code === null) throw new AccountError("sk_not_remembered");
  const profile = num(record.ksf_profile);
  const payload = await env.client.vault.setup_qr_build(env.server, record.account_id, profile, skBit, record.server_public_key);
  const access = {
    server_url: env.server,
    email: info.email,
    account_id: accountIdText(record.account_id),
    ksf_profile: profile,
    secret_key_code: code,
    qr_payload: payload,
  };
  // The QR text, the key and the record must agree about the secret key, or no page 1 is made.
  checkAccessPage(access, skBit);
  return accessPdf({ access, t });
}
