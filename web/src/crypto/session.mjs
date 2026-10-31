// The account session of the web vault: registration, sign-in, unlock, lock
// and sign-out, over the crypto client (the workers hold every key) and the
// API client. No secret lives here: the password goes to the worker as a byte
// array that is wiped after the call, the keys never leave the worker, and
// what this object keeps is the account's ids and its pinned record, neither
// of which is secret.
//
// The sync engine is reached through one small seam (`attachSync`): after an
// unlock the session calls `sync.start({ accountId, vaultId, vkEpoch })`, and
// on lock and sign-out `sync.stop()`. A sync that is not attached, or that
// throws, never stops a sign-in.
import { forgetSecretKey } from "../flows/deviceSecret.mjs";
import { register } from "../flows/register.mjs";
import { deviceStatus, sessionInfo, signIn, unlock } from "../flows/signin.mjs";
import { serverKey } from "../store/idb.mjs";
import { AccountError } from "./errors.mjs";

/** @typedef {import("./env.mjs").Env} Env */
/** @typedef {import("./env.mjs").Unlocked} Unlocked */

/** How long after a re-authentication a hand-over for it may still start. */
export const REAUTH_FRESH_MS = 60_000;

/**
 * The seam to the sync engine: `{ start(scope), stop() }`, attached later.
 * @returns {{ attach(target: any): void, start(scope: { accountId: string, vaultId: string, vkEpoch: number }): Promise<void>, stop(): void }}
 */
function createSyncSeam() {
  /** @type {any} */
  let target = null;
  return {
    attach(next) {
      target = next && typeof next.start === "function" && typeof next.stop === "function" ? next : null;
    },
    async start(scope) {
      try {
        await target?.start(scope);
      } catch {
        // The engine reports its own state; a sign-in does not fail for it.
      }
    },
    stop() {
      try {
        target?.stop();
      } catch {
        // as above
      }
    },
  };
}

/**
 * @param {{
 *   client?: any,
 *   createClient?: () => any,
 *   api: import("../api.mjs").Api,
 *   store: any,
 *   serverUrl?: string,
 *   now?: () => number,
 *   rand?: (bytes: Uint8Array) => Uint8Array,
 *   sync?: any,
 *   secrets?: import("../flows/deviceSecret.mjs").Env,
 * }} options
 */
export function createCryptoSession({
  client: given,
  createClient,
  api,
  store,
  serverUrl = globalThis.location?.origin,
  now = Date.now,
  rand = (bytes) => globalThis.crypto.getRandomValues(bytes),
  sync,
  secrets,
}) {
  const client = given ?? createClient?.();
  if (!client) throw new TypeError("the crypto session needs a client");
  // One form of the address reaches the core and the store.
  const server = serverKey(serverUrl);
  /** @type {Env} */
  const env = { client, api, store, server, now, rand, secrets, lock: () => lock() };

  const seam = createSyncSeam();
  seam.attach(sync);
  /** @type {Unlocked | null} */
  let current = null;
  /** @type {number | null} */
  let reauthAt = null;
  /** @type {Set<() => void>} */
  const lockListeners = new Set();

  /**
   * @param {Unlocked} unlocked
   * @returns {Promise<Unlocked>}
   */
  async function opened(unlocked) {
    current = unlocked;
    await seam.start({ accountId: unlocked.accountId, vaultId: unlocked.vaultId, vkEpoch: unlocked.vkEpoch });
    return unlocked;
  }

  async function lock() {
    seam.stop();
    current = null;
    reauthAt = null;
    try {
      await client.lock();
    } finally {
      for (const listener of [...lockListeners]) {
        try {
          listener();
        } catch {
          // a listener must not keep the others from running
        }
      }
    }
  }

  return {
    client,
    /** The vault's address, as the core and the store see it. */
    serverUrl: server,

    /** Hands the sync engine over (see the top of this file). */
    attachSync(/** @type {any} */ target) {
      seam.attach(target);
    },

    /** The account that is open in this tab, or null when locked. */
    current: () => current,

    /** The vault session the server knows, or null: `{ accountId, email }`. */
    info: () => sessionInfo(env),

    /** What this device knows about an e-mail (no request): `{ pinned, skBit, skStored }`. */
    deviceStatus: (/** @type {string} */ email) => deviceStatus(env, email),

    /**
     * Whether a re-authentication just succeeded, so that a hand-over for it
     * may start now.
     * @param {number} [maxAgeMs]
     */
    freshReauth(maxAgeMs = REAUTH_FRESH_MS) {
      return reauthAt !== null && now() - reauthAt >= 0 && now() - reauthAt <= maxAgeMs;
    },

    /**
     * Registers an account up to the sheet. The returned flow's `finish()`
     * also makes the new account the open one.
     * @param {Parameters<typeof register>[1]} args
     */
    async register(args) {
      if (current !== null) await lock();
      const flow = await register(env, args);
      const email = args.email.trim();
      return {
        ...flow,
        async finish() {
          const done = await flow.finish();
          const unlocked = await opened({ ...done, email });
          return { ...unlocked, accountId: done.accountId, vaultId: done.vaultId };
        },
      };
    },

    async signIn(/** @type {Parameters<typeof signIn>[1]} */ args) {
      // A sign-in never runs on top of an open vault: that one is locked first.
      if (current !== null) await lock();
      return opened(await signIn(env, args));
    },

    async unlock(/** @type {Parameters<typeof unlock>[1]} */ args) {
      if (current !== null) await lock();
      const result = await unlock(env, args);
      // A sign-in that `unlock` fell back to is not a re-authentication.
      if (result.purpose === "reauth") reauthAt = now();
      return opened(result);
    },

    /** Ends the worker; the keys and the open items go with it. */
    lock,

    /**
     * Locks, clears the cached rows of the account and ends the server
     * session. The pinned record and the device id stay. The server is always
     * asked to end the session; if that fails, or it cannot be reached, the device
     * is still wiped and the error is `signout_incomplete`: the server session
     * may still be live.
     */
    async signOut() {
      /** @type {unknown} */
      let failure = null;
      /** @type {string | null} */
      let accountId = current ? current.accountId : null;
      if (accountId === null) accountId = (await sessionInfo(env).catch(() => null))?.accountId ?? null;
      // Whatever else goes wrong, the device is wiped and the server is asked.
      try {
        await lock();
      } catch (error) {
        failure ??= error;
      }
      try {
        if (accountId !== null) await store.cache.clearAccount(await store.open(), accountId);
      } catch (error) {
        failure ??= error;
      }
      try {
        await api.post("/api/auth/logout");
      } catch {
        // The server session may still be live: say so.
        throw new AccountError("signout_incomplete");
      }
      if (failure !== null) throw failure;
    },

    /** Removes the secret key this device remembers for the account. */
    async forgetSecretKey(/** @type {string} */ accountId) {
      await forgetSecretKey(await store.open(), server, accountId);
    },

    /** Calls `fn` when the vault is locked; returns the function that stops it. */
    onLock(/** @type {() => void} */ fn) {
      lockListeners.add(fn);
      return () => void lockListeners.delete(fn);
    },
  };
}
