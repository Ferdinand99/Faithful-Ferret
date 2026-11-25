// What the account session of the extension does for the PIN (design document, sections 7.2 and 7.6). The shared
// session (`shared/crypto/session.mjs`, the one the web vault uses too) opens the vault with the master password. These
// are the steps around it that only the extension needs, over the same environment (`inner.env`: the crypto client, the
// device's tokens, the local stores):
//
//   verifyPassword   the master password asked again while the vault is open: the OPAQUE steps of an unlock, and then the
//                    core's `confirm_password`: the password wrap the server lists must open to a vault key whose
//                    account key is the pinned one. A server that planted an OPAQUE record for a password of its own
//                    cannot pass that. No second vault is made (the vault that is open is not touched) and nothing is
//                    posted: a device's unlock sends `login/start` only.
//   pinUnlock        the core's `pin_unlock` with the PIN's blob and the record this device has pinned for its account.
//                    There is no first use: a device with no pinned record has no PIN to open. It leaves the vault open
//                    in the vault worker and the session closed: the session is not opened until `finishLocalUnlock`.
//   finishLocalUnlock  the checks that follow every unlock (the server's list of unlock methods against the manifest, the
//                    account key against the pinned one, the generation floors), while the server answers; then the
//                    session is opened. When the server cannot be reached the checks are not made (`checked: false`) and
//                    the session is opened all the same: the PIN works without the server for a window (the caller
//                    bounds it: the PIN store does). A refusal ends in a thrown error, and the caller locks.
//   renewTokens      one renewal of the device's tokens, now: the way to learn that the device is still not revoked.
//   prfOptions       what the unlock window needs for its one WebAuthn call: the vault's exact host and, from the server's list
//                    as it is now, each passkey's credential id and salt. Live tokens and the network; nothing is kept.
//   prfUnlock        the core's `unlock_prf` with the passkey's wrap and the record this device has pinned (no first use), and
//                    then the checks that follow every unlock, which a passkey unlock always makes against the list it just
//                    read (it is only done online). The OPAQUE server key handed to the core is the record's own, as in the
//                    web vault; no response of the server is a source for it.
//
// Neither the PIN nor the master password is kept, logged or put in an error here: the bytes go to the core and the
// client wipes them.

import { ApiError } from "../shared/api.mjs";
import { loadDeviceKey } from "../shared/auth/deviceKey.mjs";
import { b64u, hex16 } from "../shared/b64.mjs";
import { num, rowToCore, serverMethods, withPassword, wrapToCore } from "../shared/crypto/convert.mjs";
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

/** The method type of a passkey on the wire, and the length of the salt of its PRF. */
const PRF_TYPE = 3;
const PRF_SALT_LENGTH = 32;

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

  /**
   * The passkey wraps of the server's list, with what an evaluation needs (a credential id and a 32-byte salt).
   * @param {Record<string, any>} methods
   * @returns {Array<Record<string, any>>}
   */
  function passkeyWraps(methods) {
    return methods.methods.filter(
      (/** @type {Record<string, any>} */ m) =>
        m.method_type === PRF_TYPE && typeof m.credential_id === "string" && typeof m.prf_salt === "string" && b64u.decode(m.prf_salt).length === PRF_SALT_LENGTH,
    );
  }

  /**
   * A device whose tokens are alive (a passkey unlock is only offered and only runs for one). In device mode there is no
   * cookie session to ask; the device's own state is the check.
   */
  async function livingDevice() {
    const tokens = await /** @type {NonNullable<typeof device>} */ (device).tokens();
    if (tokens === null || tokens.state !== "ok") throw new AccountError("signed_out");
  }

  /** @param {{ accountId: string, vaultId: string, vkEpoch: number, email: string, pinned: Record<string, any> }} ready @param {{ known?: Record<string, any> }} [options] */
  async function finish(ready, { known } = {}) {
    let checked = false;
    /** @type {Record<string, any> | null} */
    let methods = known ?? null;
    if (methods === null) {
      try {
        methods = await env.api.get("/api/vault/unlock-methods", { shape: "methods_res" });
      } catch (error) {
        // No answer (no network, a server that is down): the PIN works without the server for its window.
        if (!(error instanceof ApiError) || !(error.status === 0 || error.status >= 500)) throw error;
      }
    }
    if (methods !== null) {
      // Below the epoch this device has pinned is a downgrade (an attack); above it, the vault was rekeyed since.
      if (num(methods.vk_epoch) < num(ready.vkEpoch)) throw new AccountError("pinned_epoch_downgrade");
      if (num(methods.vk_epoch) > num(ready.vkEpoch)) throw new AccountError("epoch_mismatch");
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
  }

  return {
    /**
     * Confirms the master password (and the secret key, when this device does not keep it) for the open vault: the
     * client's side of the OPAQUE finish, then the password wrap opened against the pinned record (the generation
     * floor, the epoch and `pk_a`), without making a vault. The sign-in state the core held for it is dropped at the
     * end, and the vault that is open stays open. Rejects with the core's code (`decrypt`, `pinned_auth_key`, ...).
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
        // The wrap the server lists must open to the vault key of the pinned account (as at an unlock).
        const methods = await env.api.get("/api/vault/unlock-methods", { shape: "methods_res" });
        const wraps = methods.methods.filter((/** @type {{ method_type: number }} */ m) => m.method_type === 1);
        if (wraps.length !== 1) throw new AccountError("methods_invalid");
        // The password is confirmed for the vault that is open, at the epoch it is open at: the server's word that the
        // epoch is another says nothing (and the core takes a vault key of a higher epoch as new, without `pk_a`).
        if (num(methods.vk_epoch) !== num(open.vkEpoch) || num(methods.vk_epoch) !== num(record.vk_epoch_max)) {
          throw new AccountError("pinned_vk_epoch");
        }
        const ctx = { account_id: hex16.decode(accountId), vault_id: record.vault_id, vk_epoch: methods.vk_epoch };
        await env.client.vault.confirm_password(env.server, ctx, wrapToCore(wraps[0], start.ksf_profile), { kind: "pinned", record });
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
     * a refusal: a `pinned_*` or `method_list_*` code of the core, `epoch_mismatch` (the server's vault key epoch is
     * above the one the PIN's key has: the vault was rekeyed), `pinned_epoch_downgrade` (below it), or the `ApiError` of
     * a request the server refused (the device was revoked). The generation floors of the unlock methods are those of
     * `seed_pinned` (from the manifest) and `check_server_methods` (the server's list against the manifest), the same
     * calls as after a master password; the password wrap itself is not opened here, which is what the PIN replaces.
     * `known`: the server's list the caller has just read (a passkey unlock reads it for the wrap); it is used as it is and
     * a missing answer is then impossible, so the checks are always made.
     * @param {{ accountId: string, vaultId: string, vkEpoch: number, email: string, pinned: Record<string, any> }} ready
     * @param {{ known?: Record<string, any> }} [options]
     * @returns {Promise<{ checked: boolean }>}
     */
    async finishLocalUnlock(ready, options) {
      return finish(ready, options);
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

    /**
     * What the unlock window needs for its WebAuthn call. Needs live tokens (a device whose tokens have ended has nothing
     * to unlock) and the network: the list is read now and kept nowhere. Rejects with an `AccountError` of `signed_out`,
     * `pinned_missing` or `prf_unavailable` (no passkey is an unlock method), or the `ApiError` of the read.
     * @returns {Promise<{ rpId: string, credentials: Array<{ id: string, salt: string }> }>}
     */
    async prfOptions() {
      const { accountId } = await ownAccount();
      await livingDevice();
      const methods = await env.api.get("/api/vault/unlock-methods", { shape: "methods_res" });
      const credentials = passkeyWraps(methods).map((wrap) => ({ id: wrap.credential_id, salt: wrap.prf_salt }));
      if (credentials.length === 0) throw new AccountError("prf_unavailable");
      // The relying party id of every passkey is the exact host of the vault, never a parent domain.
      return { rpId: new URL(env.server).hostname, credentials };
    },

    /**
     * Opens the vault in the worker with the 32 bytes a passkey gave for its salt, and makes the checks that follow every
     * unlock against the list read for the wrap. `output` is wiped by the client (and again by the caller). The session is
     * opened here (`finishLocalUnlock`'s last step); a refusal at any step is thrown and the caller locks. There is no first
     * use: the record this device pinned for its account must exist.
     * @param {{ credentialId: string, output: Uint8Array }} args
     * @returns {Promise<{ accountId: string, email: string, checked: boolean }>}
     */
    async prfUnlock({ credentialId, output }) {
      const { accountId, email, record } = await ownAccount();
      await livingDevice();
      if (!(record.vault_id instanceof Uint8Array)) throw new AccountError("pinned_missing");
      /** @type {Record<string, any>} */
      const methods = await env.api.get("/api/vault/unlock-methods", { shape: "methods_res" });
      const wrap = passkeyWraps(methods).find((m) => m.credential_id === credentialId);
      // The passkey was removed since the window asked: nothing is tried with it.
      if (wrap === undefined) throw new AccountError("method_removed");
      const ctx = { account_id: hex16.decode(accountId), vault_id: record.vault_id, vk_epoch: methods.vk_epoch };
      // No OPAQUE exchange runs here, so the server shows no key to check: the record's own key is handed back so that the
      // core's server-key pin is neutral (it never pins a new one). Never a key from a response.
      const pinned = { kind: "pinned", record, ...(record.server_public_key instanceof Uint8Array ? { server_public_key: record.server_public_key } : {}) };
      /** @type {{ pinned: Record<string, any> }} */
      let opened;
      try {
        opened = await env.client.vault.unlock_prf(env.server, ctx, output, wrapToCore(wrap, 0), pinned);
      } catch (error) {
        // A key that does not open the wrap has no more to say than a missing one.
        throw /** @type {{ code?: unknown }} */ (error)?.code === "decrypt" ? new AccountError("prf_failed") : error;
      }
      const ready = { accountId, vaultId: hex16.encode(record.vault_id), vkEpoch: num(methods.vk_epoch), email, pinned: opened.pinned };
      const { checked } = await finish(ready, { known: methods });
      return { accountId, email, checked };
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
