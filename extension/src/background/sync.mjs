// The sync of the extension, in the background page (design document, sections
// 7.6, 8.2 and 8.6). The engine is the web vault's own (`sync/engine.mjs`,
// shared unchanged), with the extension's local stores, the sync memory under
// the Web Locks of the extension's origin, and the API client of the device's
// session, whose requests carry the device's access token and a DPoP proof and
// never a cookie (`credentials: "omit"`). The live channel (`sync/events.mjs`)
// reads the server's event stream through the same client, so the stream too
// carries a proof and no cookie. When the stream cannot be kept open, the engine
// reads the feed every 5 minutes on its own.
//
// This module is part of the core host: only the entry (main.mjs) imports it,
// and it hands the core host its operations (`ops`):
//
//   sync_state     what the popup shows: whether the engine runs, its state,
//                  the stop and the warnings, as codes (never an item, a name
//                  or a value)
//   sync_retry     "Try again" after a stop
//   forget_server  "Forget this server": the device is revoked at the server,
//                  its key record deleted, and everything this device keeps of
//                  the server and the account removed
//
// The engine starts when an op of the session has opened the vault, and stops
// at every lock of the core host. It reaches the workers only through a live
// client of the core host made for that one unlock (`liveClient({ open: true })`):
// after a lock every call of it is refused before it reaches a worker, so an
// engine that is still winding down cannot start a new worker or read a vault
// opened later. `stop()` drops the decrypted index and closes the handles.
//
// A device whose tokens have ended (revoked in the web vault, `token_reused`,
// expired) stops syncing at once: the engine is stopped and the vault locks, and
// the popup shows "signed out". The device keeps its local data (section 7.6);
// a sign-in with the master password brings it back.

import { deleteDeviceKey, loadDeviceKey } from "../shared/auth/deviceKey.mjs";
import { hex16 } from "../shared/b64.mjs";
import { forgetServer } from "../shared/flows/forgetServer.mjs";
import { createSyncEngine, SyncError } from "../shared/sync/engine.mjs";
import { createLiveChannel } from "../shared/sync/events.mjs";
import { memoryStore, unavailableMemory } from "../shared/sync/memory.mjs";
import { permissionOf } from "./session.mjs";

/** How often the engine reads the feed on its own when no stream hint comes (and the fallback of the stream). */
export const FALLBACK_POLL_MS = 300_000;

/** The most warnings the popup is given at once. */
const MAX_WARNINGS = 16;

/** A code the popup may be given: a word of letters, digits and underscores. @param {unknown} code @returns {code is string} */
const isCode = (code) => typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code);

/** The states of the live channel (`sync/events.mjs`). */
const LIVE_STATES = Object.freeze(["connecting", "live", "fallback", "offline", "unauthorized"]);

/** The error of this module: a short code. */
export class SyncHostError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "SyncHostError";
    this.code = code;
  }
}

/**
 * @typedef {import("./session.mjs").AccountSession} AccountSession
 * @typedef {{
 *   start(): Promise<void>,
 *   stop(): void,
 *   status(): string,
 *   health(): { halted: string | null, warnings: string[] },
 *   resumeAfterHalt(): Promise<void>,
 *   syncNow(): Promise<void>,
 *   on(event: string, fn: (payload: any) => void): () => void,
 * }} Engine the part of the sync engine this module uses
 * @typedef {{ start(): void, stop(): void, state(): string }} Channel
 * @typedef {{
 *   engine: Engine,
 *   server: string,
 *   session: AccountSession,
 *   channel: Channel | null,
 *   live: string,
 *   seen: Set<string>,
 *   ended: boolean,
 * }} Running
 */

/**
 * The sync of the extension and its core-host operations. Call `attach` once
 * the core host exists.
 * @param {{
 *   sessionHost: {
 *     store: any,
 *     onOpen(listener: (opened: { server: string, session: AccountSession }) => void): unknown,
 *     storedServer(): Promise<string | null>,
 *     sessionFor(server: string): Promise<AccountSession>,
 *     deviceName(): Promise<string>,
 *     forget(): Promise<void>,
 *   },
 *   permissions?: { remove?(p: { origins: string[] }): Promise<boolean> },
 *   locks?: any,
 *   win?: any,
 *   createEngine?: (options: Record<string, any>) => Engine,
 *   createChannel?: (options: Record<string, any>) => Channel,
 * }} options `createEngine` and `createChannel` are the shared engine and live channel (the tests pass fakes); `win`
 *   is where the `online` event comes from; `locks` is the Web Locks of the origin (`navigator.locks`)
 */
export function createSyncHost({
  sessionHost,
  permissions = {},
  locks = /** @type {any} */ (globalThis).navigator?.locks,
  win = globalThis,
  createEngine = (options) => /** @type {Engine} */ (/** @type {unknown} */ (createSyncEngine(/** @type {any} */ (options)))),
  createChannel = (options) => /** @type {Channel} */ (createLiveChannel(/** @type {any} */ (options))),
}) {
  const store = sessionHost.store;
  /** The engine of the vault that is open, or null. @type {Running | null} */
  let running = null;
  /** The core host, set by `attach`. @type {any} */
  let host = null;

  /** Stops the engine and its channel, if one runs. */
  function stop() {
    const old = running;
    running = null;
    if (old === null) return;
    old.ended = true;
    try {
      old.channel?.stop();
    } catch {
      // A channel that cannot stop has nothing left to do.
    }
    old.channel = null;
    try {
      old.engine.stop();
    } catch {
      // As above: the engine drops what it holds in any case.
    }
  }

  /** @param {Running} run */
  function openChannel(run) {
    if (run.ended || run.channel !== null || run.engine.health().halted !== null) return;
    /** @type {Channel} */
    const channel = createChannel({
      api: run.session.api,
      win,
      fallbackRetryMs: FALLBACK_POLL_MS,
      onHint: () => (run.ended ? undefined : run.engine.syncNow()),
      onState: (/** @type {string} */ state) => {
        if (run.channel !== channel) return;
        run.live = LIVE_STATES.includes(state) ? state : "offline";
        if (state === "unauthorized") void checkDevice(run);
      },
    });
    run.channel = channel;
    channel.start();
  }

  /** @param {Running} run */
  function closeChannel(run) {
    const channel = run.channel;
    run.channel = null;
    run.live = "offline";
    try {
      channel?.stop();
    } catch {
      // nothing left to do
    }
  }

  /**
   * The server refused the device: when its tokens have ended (revoked, reused, expired), sync stops at once and the
   * vault locks, so the popup shows "signed out". A refusal that left the tokens alive changes nothing.
   * @param {Running} run
   */
  async function checkDevice(run) {
    if (run.ended) return;
    const state = await run.session.deviceState().catch(() => null);
    if (state === "ok" || run.ended || running !== run) return;
    stop();
    await host?.lock("sign_out").catch(() => {});
  }

  /** @param {Running} run @param {any} payload */
  function onEngineState(run, payload) {
    if (run.ended) return;
    const kind = payload?.kind;
    if (kind === "warning" && isCode(payload.code)) {
      run.seen.delete(payload.code);
      run.seen.add(payload.code);
      while (run.seen.size > MAX_WARNINGS) run.seen.delete(/** @type {string} */ (run.seen.values().next().value));
    } else if (kind === "warning_cleared" && isCode(payload.code)) {
      run.seen.delete(payload.code);
    }
    if (kind === "halted") closeChannel(run);
    else if (kind === "unauthorized") void checkDevice(run);
    else if (run.channel === null) openChannel(run);
  }

  /**
   * Starts the engine for the vault an op has just opened.
   * @param {{ server: string, session: AccountSession }} opened
   */
  function start({ server, session }) {
    stop();
    const unlocked = session.current();
    if (host === null || unlocked === null || !hex16.is(unlocked.accountId) || !hex16.is(unlocked.vaultId)) return;
    const scope = { accountId: unlocked.accountId, vaultId: unlocked.vaultId, vkEpoch: unlocked.vkEpoch };
    /** @type {any} */
    let client;
    try {
      client = host.liveClient({ open: true });
    } catch {
      return; // locked again already
    }
    /** @type {any} */
    let memory;
    try {
      memory = memoryStore({ store, serverUrl: server, accountId: scope.accountId, locks, newMemory: () => client.vault.sync_memory_new() });
    } catch (error) {
      // Without Web Locks the engine is still made, with a memory that fails: it halts with `unsupported`.
      if (!(error instanceof SyncError)) return;
      memory = unavailableMemory(error);
    }
    const engine = createEngine({
      api: session.api,
      client,
      store,
      scope,
      memory,
      deviceName: () => sessionHost.deviceName(),
      pollMs: FALLBACK_POLL_MS,
      win,
    });
    /** @type {Running} */
    const run = { engine, server, session, channel: null, live: "offline", seen: new Set(), ended: false };
    running = run;
    engine.on("state", (payload) => onEngineState(run, payload));
    engine.start().then(
      () => openChannel(run),
      () => {
        // An engine that cannot start reports nothing more; the next unlock makes a new one.
      },
    );
  }

  /** What the popup shows (see `sync_state`). */
  function snapshot() {
    const run = running;
    if (run === null) return { running: false, live: "offline", warnings: [] };
    const health = run.engine.health();
    const warnings = [...new Set([...health.warnings, ...run.seen])].filter(isCode).slice(-MAX_WARNINGS);
    const status = run.engine.status();
    return {
      running: true,
      ...(isCode(status) ? { status } : {}),
      live: run.live,
      ...(isCode(health.halted) ? { halted: health.halted } : {}),
      warnings,
    };
  }

  /** "Try again" after a stop. */
  async function retry() {
    const run = running;
    if (run === null) throw new SyncHostError("sync_not_running");
    if (run.engine.health().halted === null) return { ok: true };
    await run.engine.resumeAfterHalt();
    if (run.ended) throw new SyncHostError("vault_locked");
    return run.engine.health().halted === null ? { ok: true } : { ok: false, reason: "sync_still_halted" };
  }

  /**
   * "Forget this server" (design document, section 8.6), the steps of the shared
   * `forgetServer`: the device is revoked at the server and its key record
   * deleted, the vault locks, and the account's records are removed inside the
   * Web Lock of the sync memory. Then the stored address goes, and the host
   * permission. Nothing is left of the server, so another one can be signed in at.
   * @param {unknown} expected the server the page showed: a different stored one is not forgotten
   */
  async function forget(expected) {
    const server = await sessionHost.storedServer();
    if (server === null) return { ok: true };
    if (expected !== server) return { ok: false, reason: "another_server" };
    stop();
    const session = await sessionHost.sessionFor(server);
    const db = await store.open();
    // The account comes from this device's own records, never from the server.
    let accountId = session.current()?.accountId ?? null;
    if (!hex16.is(accountId)) accountId = (await loadDeviceKey(db, server).catch(() => null))?.accountId ?? null;
    await host?.lock("sign_out");
    // The device is signed out at the server (best effort: it is forgotten here whether or not the server answers), and
    // whatever is left of its key record goes after that.
    const revoke = async () => {
      try {
        await session.signOut?.();
      } catch {
        // `signout_incomplete`: the server could not be reached; the device is forgotten here all the same.
      }
      await deleteDeviceKey(db, server);
    };
    if (hex16.is(accountId)) {
      await forgetServer({
        api: { post: revoke },
        session: {
          lock: () => host?.lock("sign_out") ?? Promise.resolve(),
          forgetSecretKey: (/** @type {string} */ id) => session.forgetSecretKey?.(id) ?? Promise.resolve(),
        },
        store,
        serverUrl: server,
        accountId: /** @type {string} */ (accountId),
        // The page asked before it sent the request.
        confirm: async () => true,
        navigate: () => {},
        // The extension has one background page: no other tab runs an engine.
        channel: null,
        locks,
      });
    } else {
      await revoke();
    }
    await sessionHost.forget();
    try {
      await permissions.remove?.({ origins: [permissionOf(server)] });
    } catch {
      // A permission that cannot be taken back is asked for again at the next sign-in anyway.
    }
    return { ok: true };
  }

  const ops = Object.freeze({
    sync_state: { vault: false, worker: /** @type {const} */ ("none"), run: async () => snapshot() },
    sync_retry: { vault: true, worker: /** @type {const} */ ("vault"), run: async () => retry() },
    forget_server: {
      vault: false,
      worker: /** @type {const} */ ("none"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) => forget(args?.server),
    },
  });

  return {
    ops,

    /**
     * Joins the core host: the engine starts when an op of the session opens the
     * vault, and stops at every lock.
     * @param {{ lock(reason: string): Promise<void>, onLocked(listener: () => void): unknown, liveClient(options?: { open?: boolean }): any }} coreHost
     */
    attach(coreHost) {
      host = coreHost;
      coreHost.onLocked(() => stop());
      sessionHost.onOpen((opened) => start(opened));
    },

    /** The engine that runs now, or null (for the tests). */
    engine: () => running?.engine ?? null,
  };
}
