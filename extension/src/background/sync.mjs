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
//                  or a value), and why the device's tokens ended when the
//                  server said it (`ended`)
//   sync_retry     "Try again" after a stop
//   forget_server  "Forget this server": the device is revoked at the server,
//                  its key record deleted, and everything this device keeps of
//                  the server and the account removed
//   offer_classify what an offer to save a password means for the vault
//                  (offerWrite.mjs): save, update, choose or nothing, with the
//                  ids, names and hosts of the items it is about
//   offer_save     the user's click on "Save": a new login from the offer
//   offer_update   the user's click on "Update": the new password into one item
//   folder_names   the folders the save card offers
//
// The four offer ops belong to saving passwords from the extension, which is
// off in a release until it is finished (the build flag `save`): with it off,
// each of them only refuses (`not_available`). An offer is named by its id and
// the popup session it was given to; the captured form itself comes from the
// background's store of offers (`captures`), never from a message. It is used
// once: after the write it is taken from the store, and while one write of it
// runs no other can start. A write that the engine refuses because the item
// changed since the offer was classified (`item_changed`) is answered with a new
// classification, and the offer stays for another click.
//
// The engine is this module's own: it is made here, and the only module it is
// handed to is the offer writer (`createOfferWriter`), the one place outside the
// shared modules that calls its `create` and `update`. The matching and the
// popup's item ops read the items through `items()`, which has the engine's
// `list` and `open` and nothing else.
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
// a sign-in with the master password brings it back. When the server ended them
// because the refresh token came with another key's proof (`token_reused`: it
// was used from somewhere else), `sync_state` says so (`ended`), so the popup
// can tell the user why. Only this background's own requests (the engine's and
// the live channel's) are watched for it, and only a code is kept, in memory,
// until the next unlock or "Forget this server".

import { deleteDeviceKey, loadDeviceKey } from "../shared/auth/deviceKey.mjs";
import { hex16 } from "../shared/b64.mjs";
import { forgetServer } from "../shared/flows/forgetServer.mjs";
import { createSyncEngine, SyncError } from "../shared/sync/engine.mjs";
import { createLiveChannel } from "../shared/sync/events.mjs";
import { memoryStore, unavailableMemory } from "../shared/sync/memory.mjs";
import { FEATURES } from "../shared/features.mjs";
import { createOfferWriter, folderNames } from "./offerWrite.mjs";
import { permissionOf } from "./session.mjs";

/** How often the engine reads the feed on its own when no stream hint comes (and the fallback of the stream). */
export const FALLBACK_POLL_MS = 300_000;

/** The most warnings the popup is given at once. */
const MAX_WARNINGS = 16;

/** A code the popup may be given: a word of letters, digits and underscores. @param {unknown} code @returns {code is string} */
const isCode = (code) => typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code);

/** The engine's `error` events that the popup shows as warnings (the engine clears them with `warning_cleared`). */
const ERROR_WARNINGS = Object.freeze(["checkpoint_upload_failed"]);

/** The refusal that ends a device's tokens because they were used from somewhere else (design document, section 7.6). */
export const TOKEN_REUSED = "token_reused";

/**
 * The session's API client as the engine and the live channel use it: the same calls, the same answers and errors,
 * and one thing more: a call the server refuses with `token_reused` is noted (`onReused`).
 * @param {any} api
 * @param {() => void} onReused
 * @returns {any}
 */
export function watchedApi(api, onReused) {
  /** @param {unknown} result */
  const watch = (result) => {
    if (result !== null && typeof result === "object" && typeof (/** @type {any} */ (result).then) === "function") {
      // A branch of its own: the caller still gets the call's own promise, and this one never rejects.
      /** @type {Promise<unknown>} */ (result).then(undefined, (/** @type {any} */ error) => {
        if (error?.code === TOKEN_REUSED) onReused();
      });
    }
    return result;
  };
  return new Proxy(api, {
    get(target, key) {
      const value = Reflect.get(target, key, target);
      if (typeof value !== "function") return value;
      return (/** @type {unknown[]} */ ...args) => watch(Reflect.apply(value, target, args));
    },
  });
}

/** An offer id and a popup session: 16 bytes in lower-case hex. */
const HEX16 = /^[0-9a-f]{32}$/;

/** The codes that say the vault is gone: they go to the caller as errors, not as a refusal of the offer. */
const VAULT_GONE = Object.freeze(["vault_locked", "worker_failed", "internal", "kdf_out_of_memory", "locked", "stopped"]);

/**
 * The shared engine, made here and nowhere else. A factory given to `createSyncHost` gets this one as its second
 * argument (the test build's hooks make test items with the engine they get through it; a release has no hooks).
 * @param {Record<string, any>} options
 */
const defaultCreateEngine = (options) => /** @type {Engine} */ (/** @type {unknown} */ (createSyncEngine(/** @type {any} */ (options))));

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
 * } & import("./offerWrite.mjs").WriteEngine} Engine the part of the sync engine this module uses
 * @typedef {{ start(): void, stop(): void, state(): string }} Channel
 * @typedef {import("./offerWrite.mjs").Capture} Capture
 * @typedef {{
 *   peek(offerId: string, uiSession: string): Capture | null,
 *   take(offerId: string, uiSession: string): Capture | null,
 * }} CaptureSource the offers the background holds (only their captured forms are read here): `peek` reads the offer
 *   `offerId` that the popup session `uiSession` was given, `take` reads it and removes it; both answer null for an
 *   offer that is not there, has expired or belongs to another session
 * @typedef {{
 *   engine: Engine,
 *   writer: ReturnType<typeof createOfferWriter>,
 *   server: string,
 *   session: AccountSession,
 *   channel: Channel | null,
 *   live: string,
 *   seen: Set<string>,
 *   ended: boolean,
 *   api: any,
 *   watch: { reused: boolean },
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
 *     exclusive<T>(fn: () => Promise<T>): Promise<T>,
 *   },
 *   permissions?: { remove?(p: { origins: string[] }): Promise<boolean> },
 *   locks?: any,
 *   win?: any,
 *   createEngine?: (options: Record<string, any>, make: (options: Record<string, any>) => Engine) => Engine,
 *   createChannel?: (options: Record<string, any>) => Channel,
 *   captures?: CaptureSource | null,
 *   fillContext?: import("./offerWrite.mjs").FillContextReader | null,
 *   language?: string,
 * }} options `createEngine` and `createChannel` are the shared engine and live channel (the tests pass fakes); `win`
 *   is where the `online` event comes from; `locks` is the Web Locks of the origin (`navigator.locks`); `captures` is
 *   the store of offers (null: there is no offer to write); `fillContext` what Ferret filled where; `language` the
 *   language of the labels of a new item's fields
 */
export function createSyncHost({
  sessionHost,
  permissions = {},
  locks = /** @type {any} */ (globalThis).navigator?.locks,
  win = globalThis,
  createEngine = (options, make) => make(options),
  createChannel = (options) => /** @type {Channel} */ (createLiveChannel(/** @type {any} */ (options))),
  captures = null,
  fillContext = null,
  language = "en",
}) {
  const store = sessionHost.store;
  /** The engine of the vault that is open, or null. @type {Running | null} */
  let running = null;
  /** The core host, set by `attach`. @type {any} */
  let host = null;
  /** Why the server ended this device's tokens, when that is known (`token_reused`), until the next unlock. @type {string | null} */
  let endedBy = null;

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
      api: run.api,
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
    endedBy = state === "revoked" && run.watch.reused ? TOKEN_REUSED : null;
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
   * An error the engine reports: the ones that say something about the server and come back until they are fixed
   * stand as warnings until the engine clears them (as the web vault shows them). Item-level errors belong to a list
   * the popup does not have yet.
   * @param {Running} run @param {any} payload
   */
  function onEngineError(run, payload) {
    if (run.ended || !ERROR_WARNINGS.includes(payload?.code)) return;
    onEngineState(run, { kind: "warning", code: payload.code });
  }

  /**
   * Starts the engine for the vault an op has just opened.
   * @param {{ server: string, session: AccountSession }} opened
   */
  function start({ server, session }) {
    stop();
    endedBy = null;
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
    // The engine and the live channel share one client, the session's, watched for `token_reused`.
    const watch = { reused: false };
    const api = watchedApi(session.api, () => {
      watch.reused = true;
    });
    const engine = createEngine({
      api,
      client,
      store,
      scope,
      memory,
      deviceName: () => sessionHost.deviceName(),
      pollMs: FALLBACK_POLL_MS,
      win,
    }, defaultCreateEngine);
    // The one module the engine is handed to: the writer of offers, with the same client of this unlock.
    const writer = createOfferWriter({ engine, liveClient: client, fillContext, now: Date.now, language });
    /** @type {Running} */
    const run = { engine, writer, api, server, session, channel: null, live: "offline", seen: new Set(), ended: false, watch };
    running = run;
    engine.on("state", (payload) => onEngineState(run, payload));
    engine.on("error", (payload) => onEngineError(run, payload));
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
    if (run === null) return { running: false, live: "offline", warnings: [], ...(endedBy !== null ? { ended: endedBy } : {}) };
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
   * deleted, the vault locks, and each account's records are removed inside the
   * Web Lock of the sync memory. Then the stored address goes, and the host
   * permission. Nothing is left of the server, so another one can be signed in at.
   *
   * The accounts come from this device's own records, never from the server: the
   * open session, the key record, and the keys of the pinned records, sync states
   * and device secrets of that server. The last ones are still there when the
   * device's tokens have ended (revoked, reused, expired: the key record went with
   * them), and after a forget that failed half way, so a forget then still removes
   * everything. It answers `ok` only when nothing of the server is left; until
   * then the address stays, and the user can try again.
   *
   * It never runs at the same time as a sign-in or an unlock (`busy`).
   * @param {unknown} expected the server the page showed: a different stored one is not forgotten
   */
  async function forget(expected) {
    const server = await sessionHost.storedServer();
    if (server === null) return { ok: true };
    if (expected !== server) return { ok: false, reason: "another_server" };
    return sessionHost.exclusive(async () => {
      stop();
      const session = await sessionHost.sessionFor(server);
      const db = await store.open();
      /** @type {Set<string>} */
      const accounts = new Set();
      const open = session.current()?.accountId;
      if (hex16.is(open)) accounts.add(/** @type {string} */ (open));
      const keyed = (await loadDeviceKey(db, server).catch(() => null))?.accountId;
      if (hex16.is(keyed)) accounts.add(/** @type {string} */ (keyed));
      for (const id of await store.accountsOf(db, server)) accounts.add(id);
      await host?.lock("sign_out");
      // The device is signed out at the server once (best effort: it is forgotten here whether or not the server
      // answers), and whatever is left of its key record goes after that.
      let revoked = false;
      const revoke = async () => {
        if (revoked) return;
        revoked = true;
        try {
          await session.signOut?.();
        } catch {
          // `signout_incomplete`: the server could not be reached; the device is forgotten here all the same.
        }
        await deleteDeviceKey(db, server);
      };
      for (const accountId of [...accounts].sort()) {
        await forgetServer({
          api: { post: revoke },
          session: {
            lock: () => host?.lock("sign_out") ?? Promise.resolve(),
            forgetSecretKey: (/** @type {string} */ id) => session.forgetSecretKey?.(id) ?? Promise.resolve(),
          },
          store,
          serverUrl: server,
          accountId,
          // The page asked before it sent the request.
          confirm: async () => true,
          navigate: () => {},
          // The extension has one background page: no other tab runs an engine.
          channel: null,
          locks,
        });
      }
      // The shared flow keeps a failure of its sign-out step to itself: the key record is removed once more here, so
      // a failure to remove it is not lost (the address then stays, for another try).
      await revoke();
      await deleteDeviceKey(db, server);
      if ((await store.accountsOf(db, server)).length > 0 || (await loadDeviceKey(db, server)) !== null) {
        throw new SyncHostError("forget_incomplete");
      }
      await sessionHost.forget();
      endedBy = null;
      try {
        await permissions.remove?.({ origins: [permissionOf(server)] });
      } catch {
        // A permission that cannot be taken back is asked for again at the next sign-in anyway.
      }
      return { ok: true };
    });
  }

  /** The offers whose write runs now: one write of an offer at a time. @type {Set<string>} */
  const writing = new Set();

  /** Refuses when saving passwords is off in this build: no path of it is there. */
  const saveFeature = () => {
    if (FEATURES.save !== true) throw new SyncHostError("not_available");
  };

  /** The engine of the vault that is open, with its writer. @returns {Running} */
  const current = () => {
    const run = running;
    if (run === null || run.ended) throw new SyncHostError("sync_not_running");
    return run;
  };

  /** @param {any} args @returns {{ session: string, offerId: string }} */
  const offerArgs = (args) => {
    if (typeof args?.session !== "string" || !HEX16.test(args.session) || typeof args?.offer_id !== "string" || !HEX16.test(args.offer_id)) {
      throw new SyncHostError("invalid_input");
    }
    return { session: args.session, offerId: args.offer_id };
  };

  /**
   * A classification as the popup gets it: the outcome, item ids, names and hosts; never a value.
   * @param {import("./offerWrite.mjs").Classification} c
   */
  const wire = (c) => ({
    action: c.action,
    targets: c.targets.map((t) => ({ id: t.id, rev: t.rev, name: t.name, username: t.username, how: t.how })),
    domain_only: c.domainOnly.map((d) => ({ id: d.id, rev: d.rev, name: d.name, host: d.host })),
    reused: c.reused.map((r) => ({ name: r.name, host: r.host })),
    username_from: c.usernameFrom,
  });

  /** @param {unknown} error */
  const reasonOf = (error) => {
    const code = /** @type {any} */ (error)?.code;
    return isCode(code) ? code : "internal";
  };

  /** @param {any} args */
  async function classifyOffer(args) {
    saveFeature();
    const { session, offerId } = offerArgs(args);
    const run = current();
    const capture = captures?.peek(offerId, session) ?? null;
    if (capture === null) return { ok: false, reason: "not_offered" };
    return { ok: true, ...wire(await run.writer.classify(capture)) };
  }

  /**
   * The write of one offer, on the user's click: the offer is read, written once, and taken from the store when the
   * write is in the outbox. A refusal leaves the offer where it is.
   * @param {any} args
   * @param {(run: Running, capture: Capture) => Promise<Record<string, unknown>>} fn
   */
  async function writeOffer(args, fn) {
    saveFeature();
    const { session, offerId } = offerArgs(args);
    const run = current();
    if (writing.has(offerId)) return { ok: false, reason: "busy" };
    const capture = captures?.peek(offerId, session) ?? null;
    if (capture === null) return { ok: false, reason: "not_offered" };
    writing.add(offerId);
    try {
      const done = await fn(run, capture);
      captures?.take(offerId, session);
      return { ok: true, ...done };
    } catch (error) {
      const reason = reasonOf(error);
      if (run.ended || reason === "stopped") throw new SyncHostError("vault_locked");
      if (VAULT_GONE.includes(reason)) throw new SyncHostError(reason);
      if (reason === "item_changed") {
        // Another version came in since the card was shown: what the offer means now.
        const again = await run.writer.classify(capture).then(wire, () => null);
        return { ok: false, reason, ...(again !== null ? { classification: again } : {}) };
      }
      return { ok: false, reason };
    } finally {
      writing.delete(offerId);
    }
  }

  const ops = Object.freeze({
    sync_state: { vault: false, worker: /** @type {const} */ ("none"), run: async () => snapshot() },
    sync_retry: { vault: true, worker: /** @type {const} */ ("vault"), run: async () => retry() },
    forget_server: {
      vault: false,
      worker: /** @type {const} */ ("none"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) => forget(args?.server),
    },
    offer_classify: {
      vault: true,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) => classifyOffer(args),
    },
    offer_save: {
      vault: true,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) =>
        writeOffer(args, async (run, capture) => {
          const choice = { name: args?.name, username: args?.username ?? null, folder: args?.folder ?? null };
          const { id, pending } = await run.writer.save(capture, choice);
          return { id, pending };
        }),
    },
    offer_update: {
      vault: true,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) =>
        writeOffer(args, async (run, capture) => {
          const { pending } = await run.writer.update(capture, { id: args?.id, rev: args?.rev, picked: args?.picked === true });
          return { pending };
        }),
    },
    folder_names: {
      vault: true,
      worker: /** @type {const} */ ("vault"),
      run: async () => {
        saveFeature();
        return { folders: folderNames(current().engine.list()) };
      },
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

    /**
     * The items of the vault that is open, or null when no engine runs: the engine's `list` and `open`, which the
     * matching (match.mjs) and the popup's item ops (fillFlow.mjs) read. Nothing that writes.
     * @returns {{ list(): ReturnType<Engine["list"]>, open(id: string): ReturnType<Engine["open"]> } | null}
     */
    items() {
      const run = running;
      if (run === null) return null;
      return Object.freeze({ list: () => run.engine.list(), open: (/** @type {string} */ id) => run.engine.open(id) });
    },
  };
}
