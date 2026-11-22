// The account session of the extension, in the background page (design
// document, sections 7.2 and 7.6). The extension is a device: it signs in with
// its own key and tokens (`mode: "device"` of the shared session), and an
// unlock after a lock needs only the master password (and the secret key when
// this device does not keep it).
//
// This module is part of the core host. It holds the shared account session,
// which works over the WASM client, so only the entry (main.mjs) imports it,
// and it hands the core host the operations of the session (`ops`):
//
//   server_check    reads an address a user typed: `https` only, the origin of
//                   it, and its host as the core shows it (`display_host`)
//   session_state   whether a device is signed in, its server and account
//   sign_in         the first sign-in of this device (or one after it was
//                   signed out): `signIn` of the shared session, in device mode
//   unlock          the unlock of a signed-in device: `unlock` of the shared session
//
// An op answers with plain data: the account's e-mail, the server's address
// and host. The master password goes from the request to the shared flow,
// which hands it to the vault worker as bytes; it is never stored, logged or
// sent anywhere else, and no answer carries it.
//
// The lock is the core host's: `client.lock()` of the shared session goes to
// the core host (which ends the worker), and every lock of the core host
// (timeout, the lock button, a failed worker) resets the shared session.
//
// The shared session reaches the workers through the core host's live client
// (`coreHost.liveClient()`), never through the client an op was handed: an op's
// view ends with the op, and the session (and the sync engine after it) also
// runs between the ops. Every call of the live client goes through the core
// host's lock and worker rules.
//
// After an op has opened the vault, the listeners of `onOpen` hear it (the sync
// engine starts there); every lock of the core host stops what they started.

import { loadDeviceKey } from "../shared/auth/deviceKey.mjs";
import { hex16 } from "../shared/b64.mjs";
import { createCryptoSession } from "../shared/crypto/session.mjs";
import { cache } from "../shared/store/cache.mjs";
import { forgetServer, pendingWrites, sharedAccount } from "../shared/store/forget.mjs";
import { openStore, req, run, serverKey } from "../shared/store/idb.mjs";
import { outbox } from "../shared/store/outbox.mjs";
import { loadPinned, loadPinnedAccount, pinnedElsewhere, pinnedForSignIn, savePinned } from "../shared/store/pinned.mjs";
import { deleteSetting, deviceId, getSetting, setSetting } from "../shared/store/settings.mjs";
import { loadSyncState, saveSyncState } from "../shared/store/syncState.mjs";
import { trash } from "../shared/store/trash.mjs";

/** Where the address of the signed-in server is kept (`storage.local`; an address is not a secret). */
export const SERVER_KEY = "server";

/** The longest address the protocol carries. */
const MAX_SERVER = 300;

/** How many hosts the background keeps as the core showed them (the server in use and the addresses checked last). */
const MAX_HOSTS = 8;

/**
 * The host permission of a server: a match pattern has no port, so it is the
 * host's (and covers the server on any port). The sign-in tab asks for the same.
 * @param {string} server an origin from `checkServer`
 */
export function permissionOf(server) {
  return `https://${new URL(server).hostname}/*`;
}

/**
 * Special-use names (RFC 2606 and RFC 6761) that no real server has. A release
 * refuses them; the test build signs in against its test stacks under them.
 */
const RESERVED_SUFFIXES = Object.freeze(["test", "invalid", "example", "localhost"]);

/** The platforms of `runtime.getPlatformInfo().os`, as the wire's word and the name shown in the list of devices. */
const PLATFORMS = Object.freeze({
  win: Object.freeze(["windows", "Windows"]),
  mac: Object.freeze(["macos", "macOS"]),
  linux: Object.freeze(["linux", "Linux"]),
  android: Object.freeze(["android", "Android"]),
  cros: Object.freeze(["chromeos", "ChromeOS"]),
});

/** The error of this module: a short code, never a text the user typed. */
export class SessionError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "SessionError";
    this.code = code;
  }
}

/**
 * The name and the platform this device signs in with: "Ferret for Firefox
 * (Windows)" and `windows`, from `runtime.getPlatformInfo().os`.
 * @param {unknown} os
 * @returns {{ deviceName: string, platform: string }}
 */
export function deviceIdentity(os) {
  if (typeof os === "string" && Object.hasOwn(PLATFORMS, os)) {
    const [platform, shown] = /** @type {Record<string, readonly string[]>} */ (PLATFORMS)[os];
    return { deviceName: `Ferret for Firefox (${shown})`, platform };
  }
  return { deviceName: "Ferret for Firefox", platform: "other" };
}

/**
 * Checks an address a user typed. Only `https`, only an origin (no user name,
 * path, query or fragment), never an IP address, and in a release never a
 * special-use name. An address without a scheme is read as `https://`.
 * @param {unknown} text
 * @param {{ allowTestHosts?: boolean }} [options] `allowTestHosts`: the test build, which signs in against its test stacks
 * @returns {{ ok: true, server: string, hostname: string } | { ok: false, reason: "server_invalid" | "server_not_https" | "server_reserved" }}
 */
export function checkServer(text, { allowTestHosts = false } = {}) {
  if (typeof text !== "string") return { ok: false, reason: "server_invalid" };
  const typed = text.trim();
  if (typed === "" || typed.length > MAX_SERVER || /[\s\\]/.test(typed)) return { ok: false, reason: "server_invalid" };
  /** @type {URL} */
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(typed) ? typed : `https://${typed}`);
  } catch {
    return { ok: false, reason: "server_invalid" };
  }
  if (url.protocol !== "https:") return { ok: false, reason: url.protocol === "http:" ? "server_not_https" : "server_invalid" };
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || url.pathname !== "/") {
    return { ok: false, reason: "server_invalid" };
  }
  const hostname = url.hostname;
  // An IP address has no name to check a certificate against that a user can read; the server refuses it too.
  if (hostname.startsWith("[") || /^\d+(?:\.\d+){3}$/.test(hostname)) return { ok: false, reason: "server_invalid" };
  const name = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  const last = name.slice(name.lastIndexOf(".") + 1);
  if (!allowTestHosts && RESERVED_SUFFIXES.includes(last)) return { ok: false, reason: "server_reserved" };
  if (url.origin.length > MAX_SERVER) return { ok: false, reason: "server_invalid" };
  return { ok: true, server: serverKey(url.origin), hostname };
}

/**
 * The local stores the shared session and the sync engine need, over the
 * extension's IndexedDB (the same stores and layout as the web vault's).
 * @param {{ factory?: IDBFactory, keyRange?: typeof IDBKeyRange }} [options]
 */
export function createLocalStore({ factory, keyRange } = {}) {
  /** @type {Promise<import("../shared/store/idb.mjs").Store> | null} */
  let opened = null;
  return {
    open() {
      opened ??= openStore(factory ?? globalThis.indexedDB, undefined, keyRange ?? globalThis.IDBKeyRange, () => {
        opened = null; // the browser closed the handle: the next call opens a new one
      }).catch((error) => {
        opened = null;
        throw error;
      });
      return opened;
    },
    pinnedForSignIn,
    pinnedElsewhere,
    // The record the typed e-mail maps to, as an early guard of the core's `login_finish` (see the web vault's store).
    pinHintForEmail: loadPinned,
    loadPinnedAccount,
    savePinned,
    deviceId,
    cache,
    // The sync engine's (as web/src/services/store.service.mjs gives them): the sync state holds no lock; the engine's
    // memory takes the Web Lock around every read-modify-write.
    getSetting,
    setSetting,
    deleteSetting,
    outbox,
    trash,
    loadSyncState,
    saveSyncState,
    // "Forget this server".
    forgetServer,
    pendingWrites,
    sharedAccount,
    accountsOf,
  };
}

/**
 * The accounts this device keeps records of under a server: the account ids in the keys of its pinned records, its
 * sync states and its device secrets (`[server, account]`). Read from this device's own stores, never from the
 * server, so "forget this server" finds them also after the device's tokens and key record have gone.
 * @param {import("../shared/store/idb.mjs").Store} db
 * @param {string} serverUrl
 * @returns {Promise<string[]>}
 */
export async function accountsOf(db, serverUrl) {
  const server = serverKey(serverUrl);
  return run(db, ["pinned", "sync_state", "device_secrets"], "readonly", async (tables) => {
    /** @type {Set<string>} */
    const found = new Set();
    for (const table of tables) {
      for (const key of await req(table.getAllKeys())) {
        if (Array.isArray(key) && key[0] === server && hex16.is(key[1])) found.add(/** @type {string} */ (key[1]));
      }
    }
    return [...found].sort();
  });
}

/**
 * @typedef {{
 *   signIn(args: Record<string, unknown>): Promise<{ email: string }>,
 *   unlock(args: Record<string, unknown>): Promise<{ email: string }>,
 *   lock(): Promise<void>,
 *   current(): { email: string, accountId?: string, vaultId?: string, vkEpoch?: number } | null,
 *   deviceState(): Promise<"ok" | "signed_out" | "revoked" | null>,
 *   signOut?(): Promise<void>,
 *   forgetSecretKey?(accountId: string): Promise<void>,
 *   api?: any,
 * }} AccountSession the part of the shared session (`crypto/session.mjs`) this module and the sync use
 *
 * @typedef {{ server: string, session: AccountSession }} Opened what `onOpen` hears: the server and its session, whose
 *   `current()` names the account and the vault that were opened
 *
 * @typedef {{
 *   storageLocal: {
 *     get(key: string): Promise<Record<string, unknown>>,
 *     set(items: Record<string, unknown>): Promise<void>,
 *     remove?(key: string): Promise<void>,
 *   },
 *   permissions: { contains(p: { origins: string[] }): Promise<boolean> },
 *   platformInfo: () => Promise<{ os?: string }>,
 *   store?: any,
 *   allowTestHosts?: boolean,
 *   now?: () => number,
 *   createSession?: (options: Record<string, any>) => AccountSession,
 * }} SessionHostOptions
 *   `createSession` makes the shared session (`createCryptoSession` by default; the tests pass a fake one)
 */

/**
 * The session of the extension and its core-host operations. Call `attach`
 * once the core host exists, so a lock of either side reaches the other.
 * @param {SessionHostOptions} options
 */
export function createSessionHost({
  storageLocal,
  permissions,
  platformInfo,
  store = createLocalStore(),
  allowTestHosts = false,
  now = Date.now,
  createSession = (options) => /** @type {AccountSession} */ (/** @type {unknown} */ (createCryptoSession(/** @type {any} */ (options)))),
}) {
  /** The core host's live client (`attach`): the shared session's only way to the workers. @type {any} */
  let live = null;
  /** The core host's lock, set by `attach`. @type {((reason: "manual") => Promise<void>) | null} */
  let hostLock = null;
  // True while a lock is passed on between the core host and the session, so it does not come back.
  let passing = false;
  /** The session of the server in use. @type {{ server: string, session: AccountSession } | null} */
  let active = null;
  /** @type {Map<string, { host: string, host_a_label: string }>} */
  const hosts = new Map();
  /** @type {Promise<{ deviceName: string, platform: string }> | null} */
  let identity = null;
  /** The e-mail of the account opened last (not a secret), for when the stored record cannot be read. @type {{ server: string, email: string } | null} */
  let lastAccount = null;
  /** Who hears that an op opened the vault. @type {Set<(opened: Opened) => void>} */
  const openListeners = new Set();

  // The client the shared session works over: the core host's live client, and the core host's lock.
  const client = {
    get vault() {
      if (live === null) throw new SessionError("vault_locked");
      return live.vault;
    },
    get job() {
      if (live === null) throw new SessionError("vault_locked");
      return live.job;
    },
    async lock() {
      if (passing || hostLock === null) return;
      passing = true;
      try {
        await hostLock("manual");
      } finally {
        passing = false;
      }
    },
  };

  /** Forgets the open account of the session when the core host has locked already (its worker is ended). */
  async function resetSession() {
    if (active === null || active.session.current() === null || passing) return;
    passing = true;
    try {
      await active.session.lock();
    } finally {
      passing = false;
    }
  }

  /** @returns {Promise<string | null>} the server this device is signed in at */
  async function storedServer() {
    const value = (await storageLocal.get(SERVER_KEY))?.[SERVER_KEY];
    if (typeof value !== "string") return null;
    const checked = checkServer(value, { allowTestHosts });
    return checked.ok ? checked.server : null;
  }

  /** @returns {Promise<{ deviceName: string, platform: string }>} */
  function deviceOf() {
    identity ??= Promise.resolve()
      .then(() => platformInfo())
      .then((info) => deviceIdentity(info?.os))
      .catch(() => deviceIdentity(undefined));
    return identity;
  }

  /** The session of `server`, made once. @param {string} server */
  async function sessionOf(server) {
    if (active !== null && active.server === server) return active.session;
    const { deviceName, platform } = await deviceOf();
    if (active !== null && active.server === server) return active.session;
    if (active !== null) await resetSession();
    const session = createSession({ client, store, serverUrl: server, mode: "device", deviceName, platform, now });
    active = { server, session };
    return session;
  }

  /** The host of an address, as the core shows it. @param {string} server */
  async function hostOf(server) {
    const known = hosts.get(server);
    if (known) return known;
    const shown = await client.vault.display_host(server);
    const unicode = typeof shown?.unicode === "string" ? shown.unicode : "";
    const aLabel = typeof shown?.a_label === "string" ? shown.a_label : "";
    if (unicode === "" || aLabel === "" || unicode.length > MAX_SERVER || aLabel.length > MAX_SERVER) throw new SessionError("server_invalid");
    const host = { host: unicode, host_a_label: aLabel };
    // A bounded cache: every address typed on the sign-in page would add one.
    if (hosts.size >= MAX_HOSTS) hosts.delete(/** @type {string} */ (hosts.keys().next().value));
    hosts.set(server, host);
    return host;
  }

  /** The e-mail of the account this device is signed in with, or null. @param {string} server */
  async function accountOf(server) {
    const open = active?.server === server ? active.session.current() : null;
    if (open) return open.email;
    const remembered = lastAccount?.server === server ? lastAccount.email : null;
    try {
      const db = await store.open();
      const key = await loadDeviceKey(db, server);
      if (key === null || key.accountId === null) return remembered;
      return (await store.loadPinnedAccount(db, server, key.accountId))?.email ?? remembered;
    } catch {
      return remembered;
    }
  }

  /**
   * The answer to "does this account have a secret key?" from what the page sends.
   * @param {{ sk?: string, sk_bit?: boolean }} args
   * @returns {boolean | undefined} undefined: not answered here (the sheet or the device's record answers it)
   */
  function skBitOf(args) {
    if (typeof args.sk === "string") return true;
    return args.sk_bit === false ? false : undefined;
  }

  // An op does not keep the client it is handed: the session works over the live client (see the top of this file).
  /** @param {(args: any, context: import("./coreHost.mjs").OpContext) => Promise<unknown>} run */
  const op = (run) => ({
    vault: false,
    worker: /** @type {"vault"} */ ("vault"),
    /** @param {any} _given @param {any} args @param {import("./coreHost.mjs").OpContext} context */
    run(_given, args, context) {
      return run(args ?? {}, context);
    },
  });

  // A sign-in or an unlock and "forget this server" never run at the same time: a forget that came while a sign-in
  // was on its way would remove the old records while the sign-in saves a new device key and pin for the server
  // being forgotten. Whichever comes second is refused with `busy` (the page says to try again).
  /** How many sign-ins and unlocks are running. */
  let opening = 0;
  /** A forget is running. */
  let forgetting = false;

  /** @param {(args: any, context: import("./coreHost.mjs").OpContext) => Promise<unknown>} run */
  const opener = (run) =>
    op(async (args, context) => {
      if (forgetting) throw new SessionError("busy");
      opening += 1;
      try {
        return await run(args, context);
      } finally {
        opening -= 1;
      }
    });

  /**
   * After the shared session opened the vault: the core host opens too, and the
   * listeners of `onOpen` hear it; or (a lock came in the meantime) the session
   * forgets the account again.
   * @param {import("./coreHost.mjs").OpContext} context
   * @param {string} server
   * @param {AccountSession} session
   */
  async function open(context, server, session) {
    if (context.setUnlocked()) {
      for (const listener of [...openListeners]) {
        try {
          listener({ server, session });
        } catch {
          // A listener that fails must not undo the unlock.
        }
      }
      return;
    }
    await resetSession();
    throw new SessionError("vault_locked");
  }

  const ops = Object.freeze({
    server_check: op(async (args) => {
      const checked = checkServer(args.server, { allowTestHosts });
      if (!checked.ok) return { ok: false, reason: checked.reason };
      return { ok: true, server: checked.server, ...(await hostOf(checked.server)) };
    }),

    session_state: op(async () => {
      const server = await storedServer();
      if (server === null) return { signed_in: false };
      const session = await sessionOf(server);
      const state = await session.deviceState().catch(() => null);
      const shown = await hostOf(server).catch(() => null);
      const account = await accountOf(server);
      return {
        signed_in: state === "ok",
        server,
        ...(shown ?? {}),
        ...(account !== null ? { account } : {}),
      };
    }),

    sign_in: opener(async (args, context) => {
      const checked = checkServer(args.server, { allowTestHosts });
      if (!checked.ok) throw new SessionError(checked.reason);
      const server = checked.server;
      const stored = await storedServer();
      // One server at a time: another one needs "forget this server" first.
      if (stored !== null && stored !== server) throw new SessionError("another_server");
      // The page asks for the permission; without it no request could reach the server.
      if (!(await permissions.contains({ origins: [permissionOf(server)] }))) throw new SessionError("permission_needed");
      const session = await sessionOf(server);
      await resetSession();
      const unlocked = await session.signIn({
        email: args.email,
        password: args.mp,
        skCode: args.sk,
        skBit: skBitOf(args),
        rememberSk: args.remember_sk !== false,
        qr: typeof args.qr_text === "string" ? args.qr_text : null,
      });
      await open(context, server, session);
      lastAccount = { server, email: unlocked.email };
      await storageLocal.set({ [SERVER_KEY]: server });
      return { ok: true, account_email: unlocked.email, server };
    }),

    unlock: opener(async (args, context) => {
      const server = await storedServer();
      if (server === null) throw new SessionError("signed_out");
      const session = await sessionOf(server);
      await resetSession();
      const unlocked = await session.unlock({ password: args.mp, ...(typeof args.sk === "string" ? { skCode: args.sk, skBit: true } : {}) });
      await open(context, server, session);
      lastAccount = { server, email: unlocked.email };
      return { ok: true };
    }),
  });

  return {
    ops,

    /**
     * Joins the core host: the session reaches the workers through its live
     * client and locks through it, and every lock of it resets the session.
     * @param {{
     *   lock: (reason: "manual") => Promise<void>,
     *   onLocked: (listener: (reason: string) => void) => unknown,
     *   liveClient: (options?: { open?: boolean }) => any,
     * }} coreHost
     */
    attach(coreHost) {
      live = coreHost.liveClient();
      hostLock = (reason) => coreHost.lock(reason);
      coreHost.onLocked(() => {
        resetSession().catch(() => {});
      });
    },

    /** The shared session in use; null before the first op that names a server. */
    session: () => active?.session ?? null,

    /** The local stores (the sync engine works over the same ones). */
    store,

    /**
     * Calls `listener({ server, session })` after an op has opened the vault,
     * in the turn the core host opened. Returns the function that stops it.
     * @param {(opened: Opened) => void} listener
     * @returns {() => void}
     */
    onOpen(listener) {
      openListeners.add(listener);
      return () => void openListeners.delete(listener);
    },

    /** The server this device is signed in at (`storage.local`), or null. */
    storedServer,

    /** The shared session of `server`, made once (for "forget this server" of a locked device). @param {string} server */
    sessionFor: sessionOf,

    /** The name this device writes into what it saves ("Ferret for Firefox (Windows)"). */
    deviceName: async () => (await deviceOf()).deviceName,

    /**
     * Runs `fn` ("forget this server") while no sign-in or unlock runs, and keeps
     * them out until it is done; refused with `busy` while one runs.
     * @template T
     * @param {() => Promise<T>} fn
     * @returns {Promise<T>}
     */
    async exclusive(fn) {
      if (opening > 0 || forgetting) throw new SessionError("busy");
      forgetting = true;
      try {
        return await fn();
      } finally {
        forgetting = false;
      }
    },

    /**
     * Forgets the server this device was signed in at: its address in
     * `storage.local`, its session and what this module showed of it. The
     * caller has locked, revoked the device and removed the local records first.
     */
    async forget() {
      active = null;
      lastAccount = null;
      hosts.clear();
      if (typeof storageLocal.remove === "function") await storageLocal.remove(SERVER_KEY);
      else await storageLocal.set({ [SERVER_KEY]: null });
    },
  };
}
