// Fresh re-authentication for sensitive operations (spec Fase 1 § 4.6 (a)): the
// master password again, as a new OPAQUE sign-in with `purpose: "reauth"`, even
// though the vault is open. The server marks the session fresh for five minutes
// (`reauth_until` in `GET /api/auth/session`); the mark belongs to that session
// only and is not used up by an operation.
//
// The order of the calls:
//
//   GET session             who the session is (e-mail, account id)
//   login_start             core: KE1 from the password (and the secret key code)
//   POST login/start        the server's KE2 and the profile number
//   login_finish            core: checks the profile and the pins, runs Argon2id, KE3
//   POST login/finish       purpose reauth: the session becomes fresh
//   GET session             `reauth_until`
//   GET unlock-methods      (only with `wantGrant`) the password wrap
//   reauth_grant            (only with `wantGrant`) core: the one-time token of a plain export
//   clear                   the core drops the sign-in it held
//
// The vault that is open is never touched: no `unlock_password` runs here, so the
// open items and the sync engine go on. A failure leaves the vault as it was; it
// only says that the password check did not pass. The password reaches the core as
// a byte array that is wiped after the call, and nothing here keeps it. No secret
// is logged, stored or put in an address.
import { ApiError } from "../api.mjs";
import { b64u } from "../b64.mjs";
import { wrapToCore, withPassword } from "../crypto/convert.mjs";
import { AccountError } from "../crypto/errors.mjs";
import { encodeWire } from "../wire.mjs";
import { DEVICE_NAME, decideSecretKey, sessionInfo } from "./signin.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */

/** How long a re-authentication lasts on the server (spec Fase 1 § 4.6 (a)), in milliseconds. */
export const REAUTH_WINDOW_MS = 300_000;

/** A dialog is skipped when the freshness still covers this many milliseconds (the next operation needs its time). */
export const REAUTH_SKIP_MS = 60_000;

/**
 * Who the open session is and what this device has pinned for the account. A
 * missing record is an error: a vault that was opened here has one.
 * @param {Env} env
 * @returns {Promise<{ info: { accountId: string, email: string }, db: import("../store/idb.mjs").Store, record: Record<string, any> }>}
 */
export async function accountContext(env) {
  const info = await sessionInfo(env);
  if (info === null) throw new AccountError("session_ended");
  const db = await env.store.open();
  const record = await env.store.pinnedForSignIn(db, env.server, info.email, info.accountId);
  if (!record) throw new AccountError("pin_missing");
  return { info, db, record };
}

/**
 * Whether the freshness that ends at `until` still covers the next `needMs`.
 * @param {number | null | undefined} until milliseconds since 1970, or nothing
 * @param {number} now
 * @param {number} [needMs]
 */
export function coversNext(until, now, needMs = REAUTH_SKIP_MS) {
  return typeof until === "number" && Number.isFinite(until) && until - now >= needMs;
}

/**
 * Confirms the master password again for the open session.
 *
 * `skCode` is only needed when the account has a secret key and this device does not
 * hold it (`sk_required` says so). With `wantGrant`, the answer also holds the one-time
 * token that a plain export needs (`reauth_grant`, five minutes, one use).
 *
 * `until` is the end of the freshness in milliseconds since 1970, or null when the server did not say. It is the
 * server's `reauth_until`, never later than five minutes from now on this device's clock.
 * @param {Env} env
 * @param {{ password: string, skCode?: string, wantGrant?: boolean, context?: Awaited<ReturnType<typeof accountContext>> }} args
 * @returns {Promise<{ until: number | null, ksfProfile: number, grant?: Uint8Array }>}
 */
export async function reauthenticate(env, { password, skCode, wantGrant = false, context }) {
  const { client, api, store } = env;
  const { info, db, record } = context ?? (await accountContext(env));
  const { skCode: code } = await decideSecretKey(env, db, record, { skCode });

  /** @type {Record<string, any>} */
  let start;
  try {
    const ke1 = await withPassword(password, (mp) => client.vault.login_start(mp, code));
    start = await api.post(
      "/api/auth/opaque/login/start",
      encodeWire("login_start_req", { email: info.email, ke1: b64u.encode(ke1), purpose: "reauth" }),
      { shape: "login_start_res" },
    );
    const finished = await client.vault.login_finish(b64u.decode(start.ke2), start.ksf_profile, { kind: "pinned", record });
    const deviceId = await store.deviceId(db, env.rand);
    const done = await api.post(
      "/api/auth/opaque/login/finish",
      encodeWire("login_finish_req", {
        login_id: start.login_id,
        ke3: b64u.encode(finished.ke3),
        device_id: deviceId,
        device_name: DEVICE_NAME,
        purpose: "reauth",
      }),
      { shape: "login_finish_res" },
    );
    // The password belongs to the account this session is for, or nothing was confirmed.
    if (done.account_id !== info.accountId) throw new AccountError("pinned_account_mismatch");
  } catch (error) {
    // The core drops the sign-in it held; the vault that is open stays open.
    await Promise.resolve(client.vault.clear()).catch(() => undefined);
    // The account has the kit's two-factor sign-in on; the vault has no second step yet.
    if (error instanceof ApiError && error.code === "forbidden") throw new AccountError("two_factor_unsupported");
    throw error;
  }

  // The freshness is the server's word. Without `reauth_until` (or without the answer) it is not counted, and the next
  // sensitive operation asks for the password again: at most one extra prompt.
  const ceiling = env.now() + REAUTH_WINDOW_MS;
  /** @type {number | null} */
  let until = null;
  try {
    const session = await api.get("/api/auth/session", { shape: "session_res" });
    if (Number.isSafeInteger(session.reauth_until)) until = Math.min(session.reauth_until * 1000, ceiling);
  } catch {
    // No answer: the freshness stays uncounted.
  }

  /** @type {Uint8Array | undefined} */
  let grant;
  try {
    if (wantGrant) {
      const methods = await api.get("/api/vault/unlock-methods", { shape: "methods_res" });
      const wraps = methods.methods.filter((/** @type {{ method_type: number }} */ m) => m.method_type === 1);
      if (wraps.length !== 1) throw new AccountError("methods_invalid");
      grant = await client.vault.reauth_grant(wrapToCore(wraps[0], start.ksf_profile), env.now());
    }
  } finally {
    // The sign-in is used up by `reauth_grant`; without a grant the core still holds it until now.
    await Promise.resolve(client.vault.clear()).catch(() => undefined);
  }
  return grant === undefined ? { until, ksfProfile: start.ksf_profile } : { until, ksfProfile: start.ksf_profile, grant };
}
