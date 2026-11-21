// The account session: sign-in, unlock, lock and sign-out, over the crypto
// client (the workers hold every key) and the API client. No secret lives
// here: the password goes to the worker as a byte array that is wiped after
// the call, the keys never leave the worker, and what this object keeps is the
// account's ids and its pinned record, neither of which is secret.
//
// The web vault and the browser extension share this file (extension/shared.json),
// so it imports only what the extension may carry. The web vault's other
// account operations (registration, re-authentication, password change,
// export, import, recovery key, secret key, emergency sheet) are added by
// `vaultSession.mjs`, which only the web vault loads.
//
// Two modes (spec Fase 1 § 7.6):
//   - "cookie" (the default): the web vault. Its server is the page's own
//     origin, and the sign-in ends in the vault session's cookie, as it always did.
//   - "device": a device client, the browser extension. It names its server
//     (`serverUrl` is required: the extension's own origin is no server), its
//     name in the list of devices (`deviceName`, required) and its platform.
//     The session keeps the device itself: the stored device key of the server
//     and its tokens (`auth/deviceKey.mjs`, `auth/tokens.mjs`), read once from
//     the local store, and its own API client over them (`session.api`, the
//     one the sync engine takes; a caller's `api` is refused). A sign-in makes
//     a new key and new tokens and signs the older device out; an unlock keeps
//     the device and its tokens (see `flows/signin.mjs`); a lock revokes
//     nothing; a sign-out signs the device out and forgets its tokens.
//
// The sync engine is reached through one small seam (`attachSync`): after an
// unlock the session calls `sync.start({ accountId, vaultId, vkEpoch })`, and
// on lock and sign-out `sync.stop()`. A sync that is not attached, or that
// throws, never stops a sign-in.
import { ApiError, createApi } from "../api.mjs";
import { generateDeviceKey, loadDeviceKey } from "../auth/deviceKey.mjs";
import { createClock } from "../auth/dpop.mjs";
import { createTokenAuth } from "../auth/tokens.mjs";
import { forgetSecretKey } from "../flows/deviceSecret.mjs";
import { readSetupQr } from "../flows/setupQr.mjs";
import { DEVICE_NAME, deviceStatus, sessionInfo, signIn, unlock } from "../flows/signin.mjs";
import { serverKey } from "../store/idb.mjs";
import { encodeWire, PLATFORMS } from "../wire.mjs";
import { AccountError } from "./errors.mjs";

/** @typedef {import("./env.mjs").Env} Env */
/** @typedef {import("./env.mjs").Unlocked} Unlocked */

/** How long after a re-authentication a hand-over for it may still start. */
export const REAUTH_FRESH_MS = 60_000;

/** The modes of a session. */
export const SESSION_MODES = Object.freeze(["cookie", "device"]);


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
 * Checks what a device session is given, before anything is sent: a name and
 * a platform the sign-in body takes.
 * @param {{ deviceName: unknown, platform: unknown }} device
 */
function checkDevice({ deviceName, platform }) {
  if (deviceName === undefined) throw new TypeError("a device session names its device");
  if (typeof platform !== "string" || !PLATFORMS.includes(platform)) throw new TypeError(`the platform is one of ${PLATFORMS.join(", ")}`);
  try {
    // The name by the rule of the sign-in body: 1 to 64 characters, no control or invisible character.
    encodeWire("login_finish_req_device", { login_id: "0".repeat(32), ke3: "A".repeat(86), client: "device", device_name: deviceName, platform });
  } catch {
    throw new TypeError("a device name has 1 to 64 characters and no control or invisible character");
  }
}

/**
 * The session and what the web vault's own operations build on
 * (`vaultSession.mjs`): the flows' `env`, the lock, `opened`, and the state the
 * lock resets. Only the web vault's session uses `inner`; everything else takes
 * `createCryptoSession`.
 * @param {{
 *   client?: any,
 *   createClient?: () => any,
 *   api?: import("../api.mjs").Api,
 *   store: any,
 *   serverUrl?: string,
 *   now?: () => number,
 *   rand?: (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>,
 *   sync?: any,
 *   secrets?: import("../flows/deviceSecret.mjs").Env,
 *   createImportWorker?: () => any,
 *   mode?: "cookie" | "device",
 *   deviceName?: string,
 *   platform?: string,
 *   fetchImpl?: typeof fetch,
 *   locks?: Pick<LockManager, "request"> | null,
 * }} options `createImportWorker` makes the import worker (the page's own file, started through the Trusted Types
 *   policy). `mode`, `deviceName`, `platform`: see the top of this file; `platform` is one of the wire's platforms. A
 *   device session makes its own API client with `fetchImpl` and renews its tokens under `locks` (the Web Locks; left
 *   out: `navigator.locks`); the web vault's session takes `api`
 */
export function createSessionCore({
  client: given,
  createClient,
  api,
  store,
  serverUrl,
  now = Date.now,
  rand = (bytes) => globalThis.crypto.getRandomValues(bytes),
  sync,
  secrets,
  createImportWorker,
  mode = "cookie",
  deviceName,
  platform = "other",
  fetchImpl,
  locks: webLocks,
}) {
  if (!SESSION_MODES.includes(mode)) throw new TypeError(`the mode of a session is one of ${SESSION_MODES.join(", ")}`);
  const device = mode === "device";
  // A device names its server: the page it runs in is not one.
  if (device && serverUrl === undefined) throw new TypeError("a device session needs the address of its server");
  // A device's requests go through its own client, with its tokens; the web vault's through the one it is given.
  if (device && api !== undefined) throw new TypeError("a device session makes its own API client");
  if (!device && api === undefined) throw new TypeError("the web vault's session needs its API client");
  const client = given ?? createClient?.();
  if (!client) throw new TypeError("the crypto session needs a client");
  // One form of the address reaches the core and the store.
  const server = serverKey(serverUrl === undefined ? globalThis.location?.origin : serverUrl);
  if (device) checkDevice({ deviceName, platform });
  const slot = device ? createDeviceSlot({ server, store, now, fetchImpl: fetchImpl ?? ((input, init) => fetch(input, init)), locks: webLocks }) : null;
  /** @type {Env} */
  const env = {
    client,
    api: slot !== null ? slot.api : /** @type {import("../api.mjs").Api} */ (api),
    store,
    server,
    now,
    rand,
    secrets,
    lock: () => lock(),
    createImportWorker,
    mode,
    deviceName: deviceName ?? DEVICE_NAME,
    platform: device ? platform : undefined,
    device: slot ?? undefined,
  };

  const seam = createSyncSeam();
  seam.attach(sync);
  /** @type {Unlocked | null} */
  let current = null;
  /** @type {number | null} */
  let reauthAt = null;
  /** When the freshness of the last re-authentication ends (ms since 1970); null when there is none. @type {number | null} */
  let freshUntil = null;
  /** Counts the locks, so a call that was running when the vault locked does not write its result back. */
  let locks = 0;
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
    freshUntil = null;
    locks += 1;
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

  const session = {
    client,
    /** The vault's address, as the core and the store see it. */
    serverUrl: server,
    /** "cookie" (the web vault) or "device" (a device client). */
    mode,
    /** The API client of this session: a device's carries its tokens (the sync engine takes it). */
    api: env.api,

    /**
     * Whether a device is signed in at its server: "ok", "signed_out" or "revoked" (null in the web vault). A locked
     * device with live tokens is "ok": its unlock needs only the password.
     * @returns {Promise<"ok" | "signed_out" | "revoked" | null>}
     */
    async deviceState() {
      if (slot === null) return null;
      return (await slot.tokens())?.state ?? "signed_out";
    },

    /** Hands the sync engine over (see the top of this file). */
    attachSync(/** @type {any} */ target) {
      seam.attach(target);
    },

    /** The account that is open in this tab, or null when locked. */
    current: () => current,

    /** The vault session the server knows, or null: `{ accountId, email }`. A device has none: always null. */
    info: () => sessionInfo(env),

    /** What this device knows about an e-mail (no request): `{ pinned, skBit, skStored }`. */
    deviceStatus: (/** @type {string} */ email) => deviceStatus(env, email),

    /**
     * Reads the text of the sheet's QR code (no request): the host and port to show before the sign-in, and the
     * rest of what the sheet states. The sign-in reads the text again itself.
     * @param {string} text
     */
    readSetupQr: (/** @type {string} */ text) => readSetupQr(client, text),

    /**
     * Whether a re-authentication just succeeded, so that a hand-over for it
     * may start now.
     * @param {number} [maxAgeMs]
     */
    freshReauth(maxAgeMs = REAUTH_FRESH_MS) {
      return reauthAt !== null && now() - reauthAt >= 0 && now() - reauthAt <= maxAgeMs;
    },

    /**
     * When the server stops counting this session as freshly re-authenticated (milliseconds since 1970), or
     * null when it is not fresh. A page that asks for the password again skips its dialog while this covers
     * the next minute (`coversNext`).
     */
    reauthUntil() {
      return freshUntil !== null && freshUntil > now() ? freshUntil : null;
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
     * session (a device: signs the device out and forgets its tokens). The
     * pinned record and the device id stay. The server is always asked; if that
     * fails, or it cannot be reached, the device is still wiped and the error is
     * `signout_incomplete`: the server session (or the device) may still be live.
     */
    async signOut() {
      /** @type {unknown} */
      let failure = null;
      /** @type {string | null} */
      let accountId = current ? current.accountId : null;
      if (accountId === null) accountId = (await sessionInfo(env).catch(() => null))?.accountId ?? null;
      // A locked device knows its account from its stored record.
      if (accountId === null && slot !== null) accountId = (await loadDeviceKey(await store.open(), server).catch(() => null))?.accountId ?? null;
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
        // A device's sign-out forgets its tokens whether or not the server answers.
        if (slot !== null) await (await slot.tokens())?.revoke();
        else await env.api.post("/api/auth/logout");
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

  const inner = {
    env,
    lock,
    opened,
    /** The account that is open, or null. */
    current: () => current,
    /** How many locks there were: a call compares it before and after, and keeps its result only when no lock came. */
    locks: () => locks,
    /**
     * Records the freshness a re-authentication gave, unless a lock came since `before` (`locks()`).
     * @param {number} before
     * @param {number | null} until
     */
    markFresh(before, until) {
      if (locks === before) freshUntil = until;
    },
  };
  return { session, inner };
}

/**
 * The device of a device session: the stored key of the server and its tokens (read once, on first use), a new key
 * and new tokens for a sign-in, and one API client whose requests carry the tokens of the device in use.
 * @param {{ server: string, store: any, now: () => number, fetchImpl: typeof fetch, locks?: Pick<LockManager, "request"> | null }} o
 * @returns {import("./env.mjs").DeviceSlot & { api: import("../api.mjs").Api }}
 */
function createDeviceSlot({ server, store, now, fetchImpl, locks }) {
  // One clock for every proof of this device: the offset a refusal taught stays.
  const clock = createClock({ now });
  /** The tokens in use, once read. @type {import("../auth/tokens.mjs").TokenAuth | null} */
  let active = null;
  /** @type {Promise<import("../auth/tokens.mjs").TokenAuth | null> | null} */
  let loading = null;

  /** @param {any} db @param {import("../auth/deviceKey.mjs").DeviceKey} key */
  const tokensOf = (db, key) =>
    createTokenAuth({ serverUrl: server, store: db, key, clock, fetchImpl, ...(locks === undefined ? {} : { locks }) });

  /** The tokens of the stored device of the server, or null when there is none (or its record cannot be read). */
  function tokens() {
    loading ??= (async () => {
      const db = await store.open();
      /** @type {import("../auth/deviceKey.mjs").DeviceKey | null} */
      let key = null;
      try {
        key = await loadDeviceKey(db, server);
      } catch {
        // A damaged record is no device: the next sign-in replaces it.
      }
      active = key !== null && key.refreshToken !== null ? tokensOf(db, key) : null;
      return active;
    })().catch((error) => {
      loading = null;
      throw error;
    });
    return loading;
  }

  /** The tokens of a sign-in: a new key, not stored until the sign-in has worked. */
  async function fresh() {
    const db = await store.open();
    return tokensOf(db, await generateDeviceKey(server));
  }

  /** The tokens a sign-in has made are the device's from now on. @param {import("../auth/tokens.mjs").TokenAuth} next */
  function use(next) {
    active = next;
    loading = Promise.resolve(next);
  }

  /** The tokens in use, or the refusal of a request made without any. */
  async function inUse() {
    const inPlace = await tokens();
    if (inPlace === null) throw new ApiError(401, "signed_out");
    return inPlace;
  }

  const api = createApi({
    base: server,
    fetchImpl,
    auth: {
      prepare: async (method, url) => (await inUse()).prepare(method, url),
      observe: (response) => active?.observe(response),
      refresh: async (used) => (await inUse()).refresh(used),
      refused: async (code) => (await inUse()).refused(code),
    },
  });
  return { tokens, fresh, use, api };
}

/**
 * The account session (see the top of this file).
 * @param {Parameters<typeof createSessionCore>[0]} options
 */
export function createCryptoSession(options) {
  return createSessionCore(options).session;
}
