// What the account session of the extension does for the PIN (design document, sections 7.2 and 7.6). The shared
// session (`shared/crypto/session.mjs`, the one the web vault uses too) opens the vault with the master password. These
// are the steps around it that only the extension needs, over the same environment (`inner.env`: the crypto client, the
// device's tokens, the local stores):
//
//   verifyPassword   the master password asked again while the vault is open: the OPAQUE steps of an unlock, up to the
//                    client's check of the server's answer. Nothing is opened (the vault that is open is not touched)
//                    and nothing is posted: a device's unlock sends `login/start` only.
//   pinUnlock        the core's `pin_unlock` with the PIN's blob and the record this device has pinned for its account.
//                    There is no first use: a device with no pinned record has no PIN to open. It leaves the vault open
//                    in the vault worker and the session closed: the session is not opened until `finishLocalUnlock`.
//   finishLocalUnlock  the checks that follow every unlock (the server's list of unlock methods against the manifest, the
//                    account key against the pinned one, the generation floors), while the server answers; then the
//                    session is opened. When the server cannot be reached the checks are not made (`checked: false`) and
//                    the session is opened all the same: the PIN works without the server for a window (the caller
//                    bounds it: the PIN store does). A refusal ends in a thrown error, and the caller locks.
//   renewTokens      one renewal of the device's tokens, now: the way to learn that the device is still not revoked.
//
// Neither the PIN nor the master password is kept, logged or put in an error here: the bytes go to the core and the
// client wipes them.

import { ApiError } from "../shared/api.mjs";
import { loadDeviceKey } from "../shared/auth/deviceKey.mjs";
import { b64u, hex16 } from "../shared/b64.mjs";
import { num, rowToCore, serverMethods, withPassword } from "../shared/crypto/convert.mjs";
import { AccountError, withSkHint } from "../shared/crypto/errors.mjs";
import { decideSecretKey } from "../shared/flows/signin.mjs";
import { encodeWire } from "../shared/wire.mjs";

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
}

/**
 * The PIN's steps over the environment of a device session.
 * @param {{
 *   env: import("../shared/crypto/env.mjs").Env,
 *   opened: (unlocked: import("../shared/crypto/env.mjs").Unlocked) => Promise<import("../shared/crypto/env.mjs").Unlocked>,
 *   current: () => import("../shared/crypto/env.mjs").Unlocked | null,
 * }} inner
 */
export function pinSessionMethods(inner) {
  const { env } = inner;
  const device = env.device;
  if (env.mode !== "device" || device === undefined) throw new TypeError("only a device session has a PIN");

  /**
   * The account of this device and the record it has pinned for it.
   * @returns {Promise<{ db: any, accountId: string, email: string, record: Record<string, any> }>}
   */
  async function ownAccount() {
    const db = await env.store.open();
    const key = await loadDeviceKey(db, env.server).catch(() => null);
    const accountId = key?.accountId ?? null;
    if (!hex16.is(accountId)) throw new AccountError("signed_out");
    const email = (await env.store.loadPinnedAccount(db, env.server, accountId))?.email ?? null;
    if (email === null) throw new AccountError("pinned_missing");
    const record = await env.store.pinnedForSignIn(db, env.server, email, accountId);
    if (!record || !(record.account_id instanceof Uint8Array) || hex16.encode(record.account_id) !== accountId) {
      throw new AccountError("pinned_missing");
    }
    return { db, accountId, email, record };
  }

  return {
    /**
     * Confirms the master password (and the secret key, when this device does not keep it) for the open vault: the
     * client's side of the OPAQUE finish succeeds only for the right password, secret key and server. The sign-in
     * state the core held for it is dropped at the end, and the vault that is open stays open.
     * @param {{ password: string, skCode?: string }} args
     * @returns {Promise<{ accountId: string }>}
     */
    async verifyPassword({ password, skCode }) {
      const open = inner.current();
      if (open === null) throw new AccountError("vault_locked");
      const { db, accountId, email, record } = await ownAccount();
      // The vault that is open is this device's account, or the password says nothing about it.
      if (open.accountId !== accountId) throw new AccountError("pinned_account_mismatch");
      const tokens = await device.tokens();
      if (tokens === null || tokens.state !== "ok") throw new AccountError("session_ended");
      const { skCode: code } = await decideSecretKey(env, db, record, { skCode });
      try {
        const ke1 = await withPassword(password, (mp) => env.client.vault.login_start(mp, code));
        const start = await tokens.startUnlock(encodeWire("login_start_req", { email, ke1: b64u.encode(ke1), purpose: "login" }));
        try {
          const finished = await env.client.vault.login_finish(b64u.decode(start.ke2), start.ksf_profile, { kind: "pinned", record });
          // KE3 proves the password to the server; an unlock does not post it, so it is dropped here.
          if (finished?.ke3 instanceof Uint8Array) finished.ke3.fill(0);
        } catch (error) {
          throw withSkHint(error, start.sk_hint);
        }
      } finally {
        await Promise.resolve(env.client.vault.clear()).catch(() => undefined);
      }
      return { accountId };
    },

    /**
     * Opens the vault in the worker with a PIN. `pin` is the PIN's UTF-8 bytes (the client wipes them); `blob` is what
     * the PIN store gives (`methodId`, `wrap`, `deviceSalt`, `pinProfile`, `vkEpoch`); `rule` is the administrator's
     * rule `{ allowed, after_restart, min_length }`. Rejects with the core's code: `decrypt` (a wrong PIN or a changed
     * blob), `pin_stale`, `kdf_out_of_memory`, `pinned_auth_key` (the blob's vault key is not the pinned account's),
     * and the refusals that come before Argon2id (`pin_not_allowed`, `input_too_short`, `kdf_profile_unknown`, ...).
     * @param {{ pin: Uint8Array, blob: { methodId: Uint8Array, wrap: Uint8Array, deviceSalt: Uint8Array, pinProfile: number, vkEpoch: number }, rule: { allowed: boolean, after_restart: boolean, min_length: number } }} args
     * @returns {Promise<{ accountId: string, vaultId: string, vkEpoch: number, email: string, pinned: Record<string, any> }>}
     */
    async pinUnlock({ pin, blob, rule }) {
      const { accountId, email, record } = await ownAccount();
      // A blob made for a later epoch than this record has seen is none this record can open: it is stale (the core would
      // answer `decrypt` and the attempt would count).
      if (num(blob.vkEpoch) > num(record.vk_epoch_max)) throw Object.assign(new Error("pin_stale"), { code: "pin_stale" });
      const wrap = { method_id: blob.methodId, wrap: blob.wrap, device_salt: blob.deviceSalt, profile: blob.pinProfile, vk_epoch: blob.vkEpoch };
      const opened = await env.client.vault.pin_unlock(pin, record, wrap, rule);
      return {
        accountId,
        vaultId: hex16.encode(record.vault_id),
        vkEpoch: num(record.vk_epoch_max),
        email,
        pinned: opened?.pinned ?? record,
      };
    },

    /**
     * The checks that follow an unlock, then the session is opened (see the top of this file). Rejects with the code of
     * a refusal: a `pinned_*` or `method_list_*` code of the core, `epoch_mismatch` (the server's vault key epoch is not
     * the one the PIN's key has), or the `ApiError` of a request the server refused (the device was revoked).
     * @param {{ accountId: string, vaultId: string, vkEpoch: number, email: string, pinned: Record<string, any> }} ready
     * @returns {Promise<{ checked: boolean }>}
     */
    async finishLocalUnlock(ready) {
      let checked = false;
      /** @type {Record<string, any> | null} */
      let methods = null;
      try {
        methods = await env.api.get("/api/vault/unlock-methods", { shape: "methods_res" });
      } catch (error) {
        // No answer (no network, a server that is down): the PIN works without the server for its window.
        if (!(error instanceof ApiError) || !(error.status === 0 || error.status >= 500)) throw error;
      }
      if (methods !== null) {
        if (num(methods.vk_epoch) !== num(ready.vkEpoch)) throw new AccountError("epoch_mismatch");
        const manifest = rowToCore(methods.manifest);
        const seeded = await env.client.vault.seed_pinned(ready.pinned, manifest);
        await env.client.vault.check_server_methods(manifest, serverMethods(methods.methods));
        // The account key the server lists must be the one the vault pins.
        if (!sameBytes(seeded.pk_a, b64u.decode(methods.pk_a))) throw new AccountError("pinned_auth_key");
        await env.store.savePinned(await env.store.open(), env.server, ready.accountId, ready.email, seeded);
        checked = true;
      }
      await inner.opened({
        accountId: ready.accountId,
        vaultId: ready.vaultId,
        vkEpoch: ready.vkEpoch,
        email: ready.email,
        pinned: ready.pinned,
        secretKey: "unchanged",
        purpose: "unlock",
      });
      return { checked };
    },

    /**
     * Renews the device's tokens now, whether or not the access token has run out. Resolves when the server has
     * answered; rejects with the `ApiError` of a refusal (`device_revoked`, `token_reused` and `token_expired` end the
     * tokens) or of a request that got no answer (status 0).
     * @returns {Promise<void>}
     */
    async renewTokens() {
      const tokens = await device.tokens();
      if (tokens === null) throw new ApiError(401, "signed_out");
      await tokens.refresh();
    },

    /** The account of this device from its own records, or null. @returns {Promise<string | null>} */
    async deviceAccount() {
      try {
        const key = await loadDeviceKey(await env.store.open(), env.server);
        return hex16.is(key?.accountId) ? /** @type {string} */ (key?.accountId) : null;
      } catch {
        return null;
      }
    },
  };
}
