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
//   sync_older_preview
//                  what accepting the older state of a restored server would
//                  do (counts only), for the popup to show before it asks
//   sync_accept_older
//                  "Accept the older state", after the user typed the word
//   forget_preview what "Forget this server" would lose: the changes this
//                  device has not sent yet, and whether another address of the
//                  server keeps the same account (counts and a yes or no)
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
// a build feature (the flag `save`, on in a release): with it off,
// each of them only refuses (`not_available`). An offer is named by its id and
// the popup session it was given to; the captured form itself comes from the
// background's store of offers (`captures`), never from a message. It is used
// once: after the write it is taken from the store, and while one write of it
// runs no other can start. A write that the engine refuses because the item
// changed since the offer was classified (`item_changed`) is answered with a new
// classification, and the offer stays for another click.
//
// The engine is this module's own: it is made here, and the only modules it is
// handed to are the offer writer (`createOfferWriter`), the one place outside the
// shared modules that calls its `create` and `update` for a person's form, and,
// in a build with Ferret as a passkey provider, the passkey writer
// (`passkeyWrite.mjs`, given to this module as a factory), which writes a new
// passkey straight to the server (never through the outbox) and undoes one the
// page never got. Its follow-ups are kept here across unlocks. The matching and the
// popup's item ops read the items through `items()`, which has the engine's
// `list` and `open` and nothing else.
//
// And, for the items whose change waits or was refused (saving from the
// extension; the popup shows them only in a build with that feature):
//
//   sync_items     the items with a conflict, a refused change or a change that
//                  waits to be sent: a name, a user name and a state each, with
//                  a reference good only in the page's session
//   item_conflict  the two versions of an item in conflict: name, user name,
//                  when and on which device each was changed (never a password
//                  or any other value of the item)
//   item_resolve   "Keep mine" or "Keep the server's", against the versions the
//                  page was shown last (`item_conflict`)
//   item_discard   "Discard the draft" of an item whose change was refused
//
// The engine stays here: these operations call its own methods for conflicts,
// discarding and the older state, and no other module is given it for them.
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
import { FEATURES } from "../shared/features.mjs";
import { memoryStore, unavailableMemory } from "../shared/sync/memory.mjs";
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

/** The most items `sync_items` lists. */
export const MAX_SYNC_ITEMS = 40;

/** The most page sessions whose references are kept (the oldest goes first), and the most references one may hold. */
const MAX_REF_SESSIONS = 8;
const MAX_SESSION_REFS = 256;

/** The most characters of a name, a user name or a device name the popup is given. */
const ITEM_TEXT = 128;

const SESSION = /^[0-9a-f]{32}$/;
const ITEM_ID = /^[0-9a-f]{32}$/;

/** The answers of the engine to a choice, a discard or an older state that the page has a text for; any other is an error. */
const ITEM_REASONS = Object.freeze(["not_found", "conflict_changed", "conflict_unsettled", "busy", "invalid_state"]);

/** The reasons `restore_not_verified` may carry that the page has a sentence for. */
const NOT_VERIFIED_REASONS = Object.freeze(["no_checkpoint"]);

/** @param {unknown} text @returns {string} the text, cut to ITEM_TEXT characters */
const itemText = (text) => {
  const chars = [...(typeof text === "string" ? text : "")];
  return chars.length > ITEM_TEXT ? `${chars.slice(0, ITEM_TEXT - 1).join("")}…` : chars.join("");
};

/** @param {Uint8Array} bytes */
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

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
 *   restorePreview(): Promise<{ reupload: number, conflicts: number, manifestOlder?: boolean }>,
 *   acceptOlderState(): Promise<{ reuploaded: number, conflicts: number, manifestOlder?: boolean }>,
 *   conflict(id: string): Promise<{ local: ConflictSide, server: ConflictSide, seen: Seen, close(): Promise<void> }>,
 *   resolve(id: string, choice: "mine" | "theirs", seen?: Seen): Promise<void>,
 *   discard(id: string): Promise<void>,
 * } & import("./offerWrite.mjs").WriteEngine} Engine the part of the sync engine this module uses
 * @typedef {{
 *   id: string, name: string, username: string, pending: boolean, blocked: boolean, blockedReason: string | null, conflict: boolean,
 * }} ItemState the part of the engine's item summary that says how an item stands with the server
 * @typedef {{ rev: number, deleted: boolean, view: any }} ConflictSide
 * @typedef {{ rev: number, deleted: boolean }} Seen the server row a page was shown, given back with the choice
 * @typedef {{ itemId: string, seen: Seen | null }} ItemRef
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
 *   passkeys: any,
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
 *   random?: (bytes: Uint8Array) => Uint8Array,
 *   passkeyWrite?: ((options: Record<string, any>) => any) | null,
 * }} options `createEngine` and `createChannel` are the shared engine and live channel (the tests pass fakes); `win`
 *   is where the `online` event comes from; `locks` is the Web Locks of the origin (`navigator.locks`); `captures` is
 *   the store of offers (null: there is no offer to write); `fillContext` what Ferret filled where; `language` the
 *   language of the labels of a new item's fields; `random` fills the bytes of a page's references to items
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
  random = (bytes) => {
    globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes));
    return bytes;
  },
  passkeyWrite = null,
}) {
  /** The follow-ups of passkey writes (passkeyWrite.mjs), kept across unlocks. @type {Map<string, any>} */
  const passkeyLeftovers = new Map();
  const store = sessionHost.store;
  /** The engine of the vault that is open, or null. @type {Running | null} */
  let running = null;
  /** The core host, set by `attach`. @type {any} */
  let host = null;
  /** Why the server ended this device's tokens, when that is known (`token_reused`), until the next unlock. @type {string | null} */
  let endedBy = null;
  /**
   * The references to items that the pages got from `sync_items`, by page session: random names that are good only in
   * that session and only until the vault locks, each with the server row the page was last shown for it.
   * @type {Map<string, Map<string, ItemRef>>}
   */
  const refs = new Map();

  /** Stops the engine and its channel, if one runs. */
  function stop() {
    const old = running;
    running = null;
    refs.clear();
    if (old === null) return;
    old.ended = true;
    try {
      old.passkeys?.stop();
    } catch {
      // Nothing more is sent from it in any case.
    }
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
    // The passkey writer, with the same client and the session's API client: the only path of a new passkey to the server.
    const passkeys =
      passkeyWrite === null
        ? null
        : passkeyWrite({
            engine,
            vault: client.vault,
            api,
            // The restore epoch the writes are conditional on, as the engine's own writes take it.
            epoch: async () => {
              try {
                return (await memory.load()).restoreEpoch ?? null;
              } catch (error) {
                if (/** @type {any} */ (error)?.code === "unsupported") return null;
                throw error;
              }
            },
            scope: `${server} ${scope.accountId}`,
            leftovers: passkeyLeftovers,
          });
    /** @type {Running} */
    const run = { engine, writer, passkeys, api, server, session, channel: null, live: "offline", seen: new Set(), ended: false, watch };
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
      // Only a build that shows them reads the list for them (the popup asks every 1.5 seconds).
      ...(FEATURES.save ? countsOf(run) : {}),
    };
  }

  /**
   * How the items stand with the server, as counts: changes that wait to be sent, changes the server refused, and
   * conflicts. Each item counts once, under the state that matters most (a conflict is also a refused change that waits).
   * @param {Running} run
   */
  function countsOf(run) {
    let pending = 0;
    let blocked = 0;
    let conflicts = 0;
    for (const item of listOf(run)) {
      if (item?.conflict === true) conflicts += 1;
      else if (item?.blocked === true) blocked += 1;
      else if (item?.pending === true) pending += 1;
    }
    return { pending, blocked, conflicts };
  }

  /** The engine's list of the items, with how each stands with the server. @param {Running} run @returns {ItemState[]} */
  const listOf = (run) => /** @type {ItemState[]} */ (/** @type {unknown} */ (run.engine.list()));

  /** @param {unknown} session */
  const sessionOf = (session) => {
    if (typeof session !== "string" || !SESSION.test(session)) throw new SyncHostError("invalid_input");
    return session;
  };

  /**
   * The reference of an item in a page session: the same item gets the same name in one session.
   * @param {string} session @param {string} itemId
   */
  function issue(session, itemId) {
    let own = refs.get(session);
    if (!own) {
      own = new Map();
      refs.set(session, own);
      // The oldest session goes when there are too many (a page that is still open asks again).
      while (refs.size > MAX_REF_SESSIONS) refs.delete(/** @type {string} */ (refs.keys().next().value));
    }
    for (const [ref, entry] of own) if (entry.itemId === itemId) return ref;
    if (own.size >= MAX_SESSION_REFS) own.delete(/** @type {string} */ (own.keys().next().value));
    const ref = hex(random(new Uint8Array(16)));
    own.set(ref, { itemId, seen: null });
    return ref;
  }

  /** @param {string} session @param {unknown} ref @returns {ItemRef | null} */
  const entryOf = (session, ref) => (typeof ref === "string" ? refs.get(session)?.get(ref) ?? null : null);

  /** A count from the engine, as a page may be given it. @param {unknown} n */
  const count = (n) => (typeof n === "number" && Number.isSafeInteger(n) && n >= 0 ? Math.min(n, 1_000_000) : 0);

  /**
   * Runs one call of the engine for an item: an answer the page has a text for comes back as a reason, a lock as
   * `vault_locked`, and anything else as the error it is.
   * @template T @param {Running} run @param {() => Promise<T>} work
   * @returns {Promise<T | { ok: false, reason: string }>}
   */
  async function itemCall(run, work) {
    try {
      const result = await work();
      if (run.ended) throw new SyncHostError("vault_locked");
      return result;
    } catch (error) {
      if (error instanceof SyncHostError) throw error;
      const code = /** @type {any} */ (error)?.code;
      if (code === "stopped" || run.ended) throw new SyncHostError("vault_locked");
      if (ITEM_REASONS.includes(code)) return { ok: false, reason: code };
      throw error;
    }
  }

  /**
   * The refusal of the engine about an older state, as a reason the page has a text for: the older state does not check
   * out (`not_verified`, with the reason the page has a sentence for), there is nothing to accept (`invalid_state`), it
   * is being accepted now (`busy`), or the server sent a feed that cannot be right (`bad_feed`).
   * @param {Running} run @param {unknown} error
   * @returns {{ ok: false, reason: string }}
   */
  function olderRefusal(run, error) {
    if (error instanceof SyncHostError) throw error;
    const code = /** @type {any} */ (error)?.code;
    if (code === "stopped" || run.ended) throw new SyncHostError("vault_locked");
    if (code === "restore_not_verified") {
      const why = /** @type {any} */ (error)?.reason;
      return { ok: false, reason: NOT_VERIFIED_REASONS.includes(why) ? `not_verified_${why}` : "not_verified" };
    }
    if (code === "invalid_state" || code === "busy" || code === "bad_feed") return { ok: false, reason: code };
    throw error;
  }

  /** What accepting the older state would do: counts only, nothing is stored or sent. */
  async function olderPreview() {
    const run = current();
    try {
      const counts = await run.engine.restorePreview();
      if (run.ended) throw new SyncHostError("vault_locked");
      return { ok: true, reupload: count(counts?.reupload), conflicts: count(counts?.conflicts), manifest_older: counts?.manifestOlder === true };
    } catch (error) {
      return olderRefusal(run, error);
    }
  }

  /**
   * "Accept the older state" (design document, section 8.6, "Legitimate rollbacks"). The page asks for a typed word
   * first; the request says it did (`confirmed`). The items the engine could not open are counted, never named.
   * @param {any} args
   */
  async function acceptOlder(args) {
    if (args?.confirmed !== true) return { ok: false, reason: "not_confirmed" };
    const run = current();
    /** @type {Set<string>} */
    const unreadable = new Set();
    const off = run.engine.on("error", (payload) => {
      if (payload?.code === "restore_item_unreadable") unreadable.add(String(payload.id ?? unreadable.size));
    });
    try {
      const done = await run.engine.acceptOlderState();
      if (run.ended) throw new SyncHostError("vault_locked");
      return {
        ok: true,
        reuploaded: count(done?.reuploaded),
        conflicts: count(done?.conflicts),
        manifest_older: done?.manifestOlder === true,
        unreadable: count(unreadable.size),
      };
    } catch (error) {
      return olderRefusal(run, error);
    } finally {
      off();
    }
  }

  /**
   * The accounts this device keeps records of for `server`, from its own records only (never the server's word): the
   * open session, the key record, and the keys of the pinned records, sync states and device secrets of that server.
   * @param {string} server @param {AccountSession} session @param {any} db
   */
  async function accountsFor(server, session, db) {
    /** @type {Set<string>} */
    const accounts = new Set();
    const open = session.current()?.accountId;
    if (hex16.is(open)) accounts.add(/** @type {string} */ (open));
    const keyed = (await loadDeviceKey(db, server).catch(() => null))?.accountId;
    if (hex16.is(keyed)) accounts.add(/** @type {string} */ (keyed));
    for (const id of await store.accountsOf(db, server)) accounts.add(id);
    return [...accounts].sort();
  }

  /**
   * What "Forget this server" would lose, for the question the page asks first (as the web vault asks it): the changes
   * of these accounts that were never sent, and whether another address of the server keeps the same account (then the
   * saved items, the trash, the sync flags and those changes stay, for that address). Counts and a yes or no only.
   * @param {unknown} expected the server the page shows
   */
  async function forgetPreview(expected) {
    const server = await sessionHost.storedServer();
    if (server === null) return { ok: true, pending: 0, shared: false };
    if (expected !== server) return { ok: false, reason: "another_server" };
    const session = await sessionHost.sessionFor(server);
    const db = await store.open();
    let pending = 0;
    let shared = false;
    for (const accountId of await accountsFor(server, session, db)) {
      pending += count(await store.pendingWrites(db, accountId));
      if ((await store.sharedAccount(db, server, accountId)) === true) shared = true;
    }
    return { ok: true, pending: count(pending), shared };
  }

  /**
   * The items whose change waits or was refused, conflicts first, then refused changes, then changes that wait to be
   * sent, each with a reference for this page session. A refused change carries the server's code (`reason`).
   * @param {any} args
   */
  function itemsOf(args) {
    const run = current();
    const session = sessionOf(args?.session);
    const rank = (/** @type {ItemState} */ item) => (item.conflict === true ? 0 : item.blocked === true ? 1 : 2);
    const found = listOf(run)
      .filter((item) => typeof item?.id === "string" && ITEM_ID.test(item.id) && (item.conflict === true || item.blocked === true || item.pending === true))
      .map((item, index) => ({ item, index }))
      .sort((a, b) => rank(a.item) - rank(b.item) || a.index - b.index)
      .map(({ item }) => item);
    const items = found.slice(0, MAX_SYNC_ITEMS).map((item) => {
      const state = item.conflict === true ? "conflict" : item.blocked === true ? "blocked" : "pending";
      const username = itemText(item.username);
      return {
        ref: issue(session, item.id),
        name: itemText(item.name),
        ...(username !== "" ? { username } : {}),
        state,
        ...(state === "blocked" && isCode(item.blockedReason) ? { reason: item.blockedReason } : {}),
      };
    });
    return { items, total: found.length };
  }

  /**
   * One version of an item in conflict as a page may see it: its name, its user name (or e-mail), when and on which
   * device it was last changed, or that it is a deletion. The view the engine gives holds no secret value; only these
   * fields of it are read.
   * @param {ConflictSide} side
   */
  function sideOf(side) {
    const deleted = side?.deleted === true;
    const view = deleted || side?.view === null || typeof side?.view !== "object" ? null : side.view;
    /** @type {any[]} */
    const fields = Array.isArray(view?.fields) ? view.fields : [];
    const plain = (/** @type {string} */ id) => {
      const value = fields.find((f) => f?.id === id)?.value;
      return typeof value === "string" ? value : "";
    };
    const username = itemText(plain("username") || plain("email"));
    const device = itemText(view?.device);
    const modified = Number.isSafeInteger(view?.modified) && view.modified > 0 ? view.modified : null;
    return {
      deleted,
      ...(view !== null ? { name: itemText(view.name) } : {}),
      ...(username !== "" ? { username } : {}),
      ...(modified !== null ? { modified } : {}),
      ...(device !== "" ? { device } : {}),
    };
  }

  /** The field kinds whose value a view shows: the core hides every other kind (and any kind it does not know). */
  const PLAIN_KINDS = Object.freeze(["text", "url", "email", "phone"]);

  /**
   * Which parts of an item differ between this device's version and the server's, as names: the name, the user name,
   * the addresses, the folders, the favourite mark, whether there are notes or a one-time code, and the item's own
   * fields by their labels. The view holds no secret value, so a password or another hidden field cannot be compared:
   * it is named as "hidden" when a hidden field is on one side only, changed its label or kind, or the earlier
   * passwords differ in number (a new password moved the old one into the history). Never a value of a hidden field.
   * @param {ConflictSide} mine @param {ConflictSide} theirs
   * @returns {Array<{ what: string, label?: string }>}
   */
  function differencesOf(mine, theirs) {
    const a = mine?.deleted === true || typeof mine?.view !== "object" ? null : mine.view;
    const b = theirs?.deleted === true || typeof theirs?.view !== "object" ? null : theirs.view;
    // A deletion on either side is what the card already says; there is no field to compare.
    if (a === null || b === null) return [];
    /** @type {Array<{ what: string, label?: string }>} */
    const out = [];
    let hidden = false;
    if (a.name !== b.name) out.push({ what: "name" });
    /** @param {any} view @returns {Map<string, any>} */
    const byId = (view) => new Map((Array.isArray(view.fields) ? view.fields : []).map((/** @type {any} */ f) => [String(f?.id), f]));
    const fa = byId(a);
    const fb = byId(b);
    for (const id of new Set([...fa.keys(), ...fb.keys()])) {
      const x = fa.get(id);
      const y = fb.get(id);
      const present = x ?? y;
      // Only the kinds the core shows are compared; any other kind is secret, whatever a view holds.
      const secret = !PLAIN_KINDS.includes(present?.kind) || typeof present?.value !== "string";
      if (x === undefined || y === undefined || x.kind !== y.kind || x.label !== y.label) {
        if (secret) hidden = true;
        else out.push(id === "username" ? { what: "username" } : { what: "field", label: itemText(present?.label) });
        continue;
      }
      if (secret || typeof x.value !== "string" || typeof y.value !== "string") continue;
      if (x.value !== y.value) out.push(id === "username" ? { what: "username" } : { what: "field", label: itemText(x.label) });
    }
    const urls = (/** @type {any} */ view) => (Array.isArray(view.urls) ? view.urls.map((/** @type {any} */ u) => `${u?.matching}\u0000${u?.url}`) : []).sort().join("\u0001");
    if (urls(a) !== urls(b)) out.push({ what: "urls" });
    const folders = (/** @type {any} */ view) => (Array.isArray(view.folders) ? [...view.folders].map(String).sort().join("\u0001") : "");
    if (folders(a) !== folders(b)) out.push({ what: "folders" });
    if ((a.favorite === true) !== (b.favorite === true)) out.push({ what: "favorite" });
    if ((a.has_notes === true) !== (b.has_notes === true)) out.push({ what: "notes" });
    if ((a.has_totp === true) !== (b.has_totp === true)) out.push({ what: "totp" });
    if ((Array.isArray(a.password_history) ? a.password_history.length : 0) !== (Array.isArray(b.password_history) ? b.password_history.length : 0)) hidden = true;
    if (hidden) out.push({ what: "hidden" });
    return out.slice(0, 40);
  }

  /**
   * The two versions of an item in conflict, for the card. The handles the engine opens for them are closed before the
   * answer goes out. The server row they were shown against is kept with the reference: a choice is made against it.
   * @param {any} args
   */
  async function conflictCard(args) {
    const run = current();
    const entry = entryOf(sessionOf(args?.session), args?.ref);
    if (entry === null) return { ok: false, reason: "not_offered" };
    entry.seen = null;
    return itemCall(run, async () => {
      const data = await run.engine.conflict(entry.itemId);
      try {
        const seen = data?.seen;
        if (!Number.isSafeInteger(seen?.rev) || typeof seen?.deleted !== "boolean") throw new SyncHostError("internal");
        entry.seen = { rev: seen.rev, deleted: seen.deleted };
        return { ok: true, mine: sideOf(data.local), theirs: sideOf(data.server), differs: differencesOf(data.local, data.server) };
      } finally {
        await Promise.resolve(data?.close()).catch(() => {});
      }
    });
  }

  /**
   * "Keep mine" (the version of this device is written on top of the server's) or "Keep the server's" (the draft is
   * dropped), against the server row the page was shown last. A choice the page was not shown the versions for is
   * refused (`not_shown`); so is one whose server row has changed since (`conflict_changed`). Either way the page reads
   * the versions again before the next choice.
   * @param {any} args
   */
  async function resolveItem(args) {
    const run = current();
    const entry = entryOf(sessionOf(args?.session), args?.ref);
    if (entry === null) return { ok: false, reason: "not_offered" };
    const choice = args?.choice;
    if (choice !== "mine" && choice !== "theirs") throw new SyncHostError("invalid_input");
    const seen = entry.seen;
    entry.seen = null;
    if (seen === null) return { ok: false, reason: "not_shown" };
    return itemCall(run, async () => {
      await run.engine.resolve(entry.itemId, choice, seen);
      return { ok: true };
    });
  }

  /**
   * "Discard the draft" of an item whose change the server refused: the draft goes, and the server's version stays. Not
   * for a conflict, which has its own two choices.
   * @param {any} args
   */
  async function discardItem(args) {
    const run = current();
    const entry = entryOf(sessionOf(args?.session), args?.ref);
    if (entry === null) return { ok: false, reason: "not_offered" };
    const now = listOf(run).find((item) => item?.id === entry.itemId);
    if (now?.blocked !== true) return { ok: false, reason: "not_found" };
    if (now.conflict === true) return { ok: false, reason: "in_conflict" };
    return itemCall(run, async () => {
      await run.engine.discard(entry.itemId);
      return { ok: true };
    });
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
   *
   * The question the page asked named the changes that were never sent (`forget_preview`); the page sends the count it
   * showed (`expectPending`). When more changes wait now than the question said, nothing is forgotten (`changed`), so
   * the user is asked again: before anything is done, and once more inside the shared flow, which counts them again
   * right before it would remove them.
   * @param {unknown} expected the server the page showed: a different stored one is not forgotten
   * @param {unknown} [expectPending] the count of unsent changes the page's question showed, if it showed one
   */
  async function forget(expected, expectPending) {
    const server = await sessionHost.storedServer();
    if (server === null) return { ok: true };
    if (expected !== server) return { ok: false, reason: "another_server" };
    const bound = typeof expectPending === "number" && Number.isSafeInteger(expectPending) && expectPending >= 0 ? expectPending : null;
    return sessionHost.exclusive(async () => {
      const session = await sessionHost.sessionFor(server);
      const db = await store.open();
      const accounts = await accountsFor(server, session, db);
      if (bound !== null) {
        let pending = 0;
        for (const accountId of accounts) pending += count(await store.pendingWrites(db, accountId));
        if (pending > bound) return { ok: false, reason: "changed" };
      }
      stop();
      await host?.lock("sign_out");
      /** The unsent changes the flow found so far, over the accounts. */
      let found = 0;
      let changed = false;
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
      for (const accountId of accounts) {
        await forgetServer({
          api: { post: revoke },
          session: {
            lock: () => host?.lock("sign_out") ?? Promise.resolve(),
            forgetSecretKey: (/** @type {string} */ id) => session.forgetSecretKey?.(id) ?? Promise.resolve(),
          },
          store,
          serverUrl: server,
          accountId,
          // The page asked before it sent the request; the changes are counted once more against what it showed.
          confirm: async (/** @type {{ pending: number }} */ { pending }) => {
            found += count(pending);
            if (bound !== null && found > bound) {
              changed = true;
              return false;
            }
            return true;
          },
          navigate: () => {},
          // The extension has one background page: no other tab runs an engine.
          channel: null,
          locks,
        });
        if (changed) return { ok: false, reason: "changed" };
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
    sync_older_preview: { vault: true, worker: /** @type {const} */ ("vault"), run: async () => olderPreview() },
    sync_accept_older: {
      vault: true,
      worker: /** @type {const} */ ("vault"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) => acceptOlder(args),
    },
    forget_preview: {
      vault: false,
      worker: /** @type {const} */ ("none"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) => forgetPreview(args?.server),
    },
    forget_server: {
      vault: false,
      worker: /** @type {const} */ ("none"),
      run: async (/** @type {any} */ _client, /** @type {any} */ args) => forget(args?.server, args?.expect_pending),
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
    sync_items: { vault: true, worker: /** @type {const} */ ("vault"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => itemsOf(args) },
    item_conflict: { vault: true, worker: /** @type {const} */ ("vault"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => conflictCard(args) },
    item_resolve: { vault: true, worker: /** @type {const} */ ("vault"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => resolveItem(args) },
    item_discard: { vault: true, worker: /** @type {const} */ ("vault"), run: async (/** @type {any} */ _client, /** @type {any} */ args) => discardItem(args) },
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

    /** The passkey writer of the vault that is open (passkeyWrite.mjs), or null when no engine runs or the build has none. */
    passkeys() {
      return running?.passkeys ?? null;
    },

    /**
     * What a captured form means for the vault, for the store of offers: the write path's classification, read only
     * (nothing is written and nothing is shown), or null when no engine runs or saving is off. The store drops an offer
     * for a login the vault holds already.
     * @param {Capture} capture
     * @returns {Promise<{ action: string } | null>}
     */
    async classifyCapture(capture) {
      if (FEATURES.save !== true) return null;
      const run = running;
      if (run === null || run.ended) return null;
      const outcome = await run.writer.classify(capture);
      return { action: outcome.action };
    },

    /**
     * The page whose port this was has gone: its references to items end with it.
     * @param {string} session
     */
    endSession(session) {
      refs.delete(session);
    },
  };
}
