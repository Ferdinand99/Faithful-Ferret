// The core host: the one module that holds the WASM client, and so the only
// place a key can ever be. The router (router.mjs) reaches it through
// `call(op, args)` with a name from a fixed list, and it never answers with a
// key: a reply is plain data that the op built.
//
// Where the vault lives (design document, section 7.2): the vault worker of the
// client and the core host are in the same background page and die together. If
// the page dies, the vault is locked. `lock()` is `client.lock()`: it ends the
// worker at once, which frees the heap. If the vault worker fails, the host
// locks itself: it never says "unlocked" about a worker that is gone.
//
// Only this file may import the WASM client (`../js/client.mjs`, copied into
// the package by the build). A test reads the import graph of the built package
// and fails on any other importer.
//
// Boundary: an op gets the raw client. Production ops therefore live in this
// file or in a background module that only the entry (main.mjs) imports and
// passes in as `ops`: the session's ops (session.mjs), which hold the account
// session over the same client, the sync's ops (sync.mjs, with the offer ops
// over offerWrite.mjs), the matching's ops (match.mjs) and the item ops of the
// popup (fillFlow.mjs) and the generator's (generator.mjs). The only other
// code that passes ops in is the test build's hooks (the test build only),
// which a release does not contain.
//
// The modules that work beside the ops (the account session and the sync
// engine, which runs between the calls) never keep an op's client: they get a
// client of their own from `liveClient`, which goes through the same lock and
// worker rules on every call (see there).

/** The reasons a lock can have. */
export const LOCK_REASONS = Object.freeze(["timeout", "idle", "manual", "sign_out", "restart", "worker_failed"]);

/**
 * The operations the router may call. A name outside this list is refused,
 * whatever else is passed to `createCoreHost`. A later task adds its own names.
 * `argon2_bench`, `measure_open`, `frames_probe`, `item_probe`, `item_rename_probe`,
 * `match_bench`, `offer_plant`, `offer_bench` and `offers_peek` are only available in the test
 * build, which passes their implementations in (`ops`); in a release they are
 * refused like any other name. The offer ops (`offer_classify`, `offer_save`,
 * `offer_update`, `folder_names`) and the generator's (`generate`, `generate_copy`,
 * `fill_generated`) refuse with `not_available` in a build without the `save`
 * feature. The capture ops (`capture_event`, `capture_settings`, and the popup's `offer_list`,
 * `offer_dismiss`, `offer_reveal`) are the capture
 * host's (captureHost.mjs); a build without the feature does not have them. The PIN ops (`unlock_policy`, `pin_set`,
 * `pin_unlock`, `pin_off`) and the passkey's (`prf_options`, `prf_unlock`) are the PIN host's (pinHost.mjs); a build without the `unlock` feature does not have them.
 * `passkey_event` (the reports of the passkey bridge) belongs to the `passkeys` feature (passkeyRequests.mjs); a build
 * without the feature does not have it. `passkey_reconcile` is the test build's only (its hooks).
 */
export const CORE_OPS = Object.freeze([
  "ping",
  "argon2_bench",
  "measure_open",
  "server_check",
  "session_state",
  "sign_in",
  "unlock",
  "sync_state",
  "sync_retry",
  "sync_older_preview",
  "sync_accept_older",
  "forget_preview",
  "forget_server",
  "sync_items",
  "item_conflict",
  "item_resolve",
  "item_discard",
  "page_origin",
  "same_site",
  "display_host",
  "candidates_match",
  "grant_listed",
  "frames_probe",
  "item_probe",
  "item_rename_probe",
  "match_bench",
  "fill_offer",
  "fill",
  "fill_report",
  "search",
  "item",
  "item_code",
  "copy",
  "open_site",
  "offer_classify",
  "offer_save",
  "offer_update",
  "folder_names",
  "offer_plant",
  "offer_bench",
  "offers_peek",
  "offer_list",
  "offer_dismiss",
  "offer_reveal",
  "capture_event",
  "capture_settings",
  "generate",
  "generate_copy",
  "fill_generated",
  "unlock_policy",
  "pin_set",
  "pin_unlock",
  "pin_off",
  "prf_options",
  "prf_unlock",
  "prf_window",
  "passkey_event",
  "passkey_reconcile",
]);

/**
 * The codes that say the worker which holds the vault is gone or was ended:
 * the client ends it on `worker_failed`, `internal` and `kdf_out_of_memory`,
 * and rejects the calls that wait for it with `locked`.
 */
const WORKERS = Object.freeze(["vault", "job", "none"]);

const WORKER_GONE = new Set(["worker_failed", "internal", "kdf_out_of_memory", "locked", "vault_locked"]);

/** The error of this module. Only a short code leaves it, never a message of the client. */
export class CoreError extends Error {
  /** @param {string} code a snake_case code */
  constructor(code) {
    super(code);
    this.name = "CoreError";
    this.code = code;
  }
}

/**
 * @typedef {"timeout" | "idle" | "manual" | "sign_out" | "restart" | "worker_failed"} LockReason
 * @typedef {{ setTimeout: (fn: () => void, ms: number) => unknown, clearTimeout: (id: unknown) => void }} Timers
 * @typedef {{ now: () => number, timers: Timers, setUnlocked: () => boolean }} OpContext
 *   `setUnlocked` opens the host and answers true. It does nothing and answers
 *   false if a lock ran after the call started, and the call then fails with
 *   `vault_locked`.
 * @typedef {{
 *   vault: boolean,
 *   worker: "vault" | "job" | "none",
 *   run: (client: { vault: any, job: any, pinWrap: (...args: any[]) => Promise<any> }, args: any, context: OpContext) => Promise<unknown>,
 * }} CoreOp
 *   `vault` is true when the op needs an unlocked vault: it is refused while
 *   the host is locked, without touching the client. `worker` says which worker
 *   the op runs on and is required (`vault` ops run on the vault worker). A
 *   failure of the vault worker locks the host; so does a failure of any op that
 *   touched `client.vault`, whatever it says, and of any op not declared `job`.
 */

/**
 * Reads a stateless function of the core. No key, no state: the AAGUID is public.
 * @type {CoreOp}
 */
const ping = {
  vault: false,
  worker: "vault",
  async run(client) {
    const bytes = await client.vault.ferret_aaguid();
    if (!(bytes instanceof Uint8Array) || bytes.length !== 16) throw new CoreError("internal");
    return { ok: true, aaguid: Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("") };
  },
};

/** @type {Readonly<Record<string, CoreOp>>} */
const BASE_OPS = Object.freeze({ ping });

/**
 * The default client factory: loads the WASM client from the package. The
 * import is lazy so that this file can be loaded where the package is absent
 * (the unit tests), and it is the only import of the client there is.
 *
 * @returns {Promise<any>}
 */
export async function defaultCreateClient() {
  // @ts-ignore -- the client is copied into the package by the build (js/client.mjs)
  const { createClient } = await import("../js/client.mjs");
  return createClient();
}

/** @param {unknown} error @returns {string} a code that is safe to hand on */
function codeOf(error) {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  if (typeof code !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(code)) return "internal";
  // The client rejects the calls that wait for a worker that is ended with `locked`.
  return code === "locked" ? "vault_locked" : code;
}

/**
 * @param {{
 *   createClient?: () => any,
 *   now?: () => number,
 *   timers?: Timers,
 *   ops?: Readonly<Record<string, CoreOp>>,
 *   names?: readonly string[],
 * }} [options]
 *   `createClient` makes the WASM client (once, on the first call). `ops` adds
 *   operations to the base ones (the test build's `argon2_bench`; a later task's
 *   operations); it cannot replace one. `names` replaces `CORE_OPS` and exists
 *   for the tests only.
 */
export function createCoreHost({
  createClient = defaultCreateClient,
  now = Date.now,
  timers = {
    setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id) => globalThis.clearTimeout(/** @type {any} */ (id)),
  },
  ops = {},
  names = CORE_OPS,
} = {}) {
  /** @type {Promise<any> | null} */
  let clientPromise = null;
  /** @type {"locked" | "unlocked"} */
  let current = "locked";
  // Counts the locks. A call remembers it at the start; if it moved, a lock ran
  // since, and nothing the call does may open the host again.
  let epoch = 0;
  /** @type {Set<(reason: string) => void>} */
  const listeners = new Set();
  /** @type {Set<() => void>} */
  const openListeners = new Set();

  /** @type {Record<string, CoreOp>} */
  const table = { ...BASE_OPS };
  const allowed = new Set(names);

  /** @param {Readonly<Record<string, CoreOp>>} extra */
  const register = (extra) => {
    for (const [name, def] of Object.entries(extra)) {
      if (!allowed.has(name)) throw new CoreError("unknown_core_op");
      if (Object.hasOwn(table, name)) throw new CoreError("op_exists");
      // An op says which worker it runs on. A missing or unknown value is an
      // error, and an op that needs the vault runs on the vault worker. (What
      // an op really uses is also watched at run time, see `call`.)
      if (typeof def?.run !== "function" || typeof def.vault !== "boolean") throw new CoreError("bad_op");
      if (!WORKERS.includes(def.worker)) throw new CoreError("bad_op");
      if (def.vault && def.worker !== "vault") throw new CoreError("bad_op");
    }
    Object.assign(table, extra);
  };
  register(ops);

  const client = () => {
    if (!clientPromise) {
      const made = Promise.resolve().then(() => createClient());
      clientPromise = made;
      // A client that failed to start is not kept: the next call tries again.
      made.catch(() => {
        if (clientPromise === made) clientPromise = null;
      });
    }
    return clientPromise;
  };

  /**
   * The check of the deadline that the lock module gives the host (`setGuard`): true when the vault may not be used
   * now. Until one is set nothing is due, as in a host that is used without a lock.
   * @type {() => boolean}
   */
  let guard = () => false;

  /** @param {LockReason} reason @returns {Promise<void>} */
  async function lock(reason) {
    if (!LOCK_REASONS.includes(reason)) throw new CoreError("bad_reason");
    current = "locked";
    epoch += 1;
    const made = clientPromise;
    try {
      const started = await made?.catch(() => null);
      await started?.lock();
    } finally {
      for (const listener of [...listeners]) {
        try {
          listener(reason);
        } catch {
          // A listener that fails must not stop the others or undo the lock.
        }
      }
    }
  }

  /**
   * A client for the modules that work beside the ops (see the top of this
   * file). Every call goes to the one WASM client, and:
   *   - a failure of the vault worker (`worker_failed`, `internal`,
   *     `kdf_out_of_memory`, `locked`, `vault_locked`) while the host is open
   *     locks the host, whoever called: a worker that is gone never stays
   *     "unlocked";
   *   - with `open`, the client belongs to the vault that is open now: it is
   *     made only while the host is open, and once a lock has come (the epoch
   *     moved) every call is refused with `vault_locked` before it reaches the
   *     client, and an answer that arrives after a lock is dropped. Such a client
   *     never starts a new worker after a lock, so nothing it holds can reach a
   *     vault that was opened later. The sync engine gets one per unlock. Before
   *     every call on the vault worker the deadline is checked (the guard): a
   *     deadline that has passed locks the host and the call is refused, so a
   *     call that comes between two messages never uses a vault whose time
   *     has run out.
   * Without `open` (the account session, whose sign-in and unlock run on the
   * worker before the vault opens) the calls go through while the host is
   * locked; the epoch rules of `call` still decide whether the vault opens.
   * Errors of the client are passed on unchanged, so a caller still reads the
   * core's code.
   *
   * @param {{ open?: boolean }} [options]
   * @returns {{ vault: any, job: any, lock: () => Promise<void> }}
   */
  function liveClient({ open = false } = {}) {
    if (open && current !== "unlocked") throw new CoreError("vault_locked");
    const made = epoch;
    const usable = () => !open || (epoch === made && current === "unlocked");
    /** @param {"vault" | "job"} worker */
    const side = (worker) =>
      new Proxy(
        {},
        {
          get(_, method) {
            // Not a method of the client: a promise check (`then`) or a symbol must not look like a call.
            if (typeof method !== "string" || method === "then") return undefined;
            return async (/** @type {unknown[]} */ ...args) => {
              if (!usable()) throw new CoreError("vault_locked");
              if (open && worker === "vault" && guard()) {
                await lock("timeout").catch(() => {});
                throw new CoreError("vault_locked");
              }
              const real = await client();
              if (!usable()) throw new CoreError("vault_locked");
              const started = epoch;
              try {
                const value = await real[worker][method](...args);
                // An answer that arrives after a lock belongs to a vault that is gone.
                if (open && epoch !== started) throw new CoreError("vault_locked");
                return value;
              } catch (error) {
                if (error instanceof CoreError) throw error;
                if (worker === "vault" && WORKER_GONE.has(codeOf(error)) && current === "unlocked" && epoch === started) {
                  await lock("worker_failed").catch(() => {});
                }
                throw error;
              }
            };
          },
        },
      );
    return Object.freeze({ vault: side("vault"), job: side("job"), lock: () => lock("manual") });
  }

  return {
    /**
     * Sets the check of the deadline (see `liveClient`). The lock module gives it; it must answer at once.
     * @param {() => boolean} check
     */
    setGuard(check) {
      if (typeof check !== "function") throw new CoreError("bad_guard");
      guard = check;
    },

    /**
     * Runs one operation. Rejects with a `CoreError` (`unknown_core_op`,
     * `vault_locked`) or with the code of the client's error; never with a
     * message. A failure of the vault worker locks the host first.
     *
     * @param {string} op
     * @param {unknown} [args]
     * @returns {Promise<unknown>}
     */
    async call(op, args) {
      if (typeof op !== "string" || !allowed.has(op) || !Object.hasOwn(table, op)) {
        throw new CoreError("unknown_core_op");
      }
      const def = table[op];
      if (def.vault && current !== "unlocked") throw new CoreError("vault_locked");
      const started = epoch;
      let refusedUnlock = false;
      // What the op really uses decides the lock, not what it says: the view of
      // the client that it gets notes every use of the vault worker.
      let usedVault = false;
      /** @type {OpContext} */
      const context = {
        now,
        timers,
        setUnlocked: () => {
          if (epoch !== started) {
            refusedUnlock = true;
            return false;
          }
          current = "unlocked";
          // At once, in the same turn: an open vault never exists without a deadline.
          for (const listener of [...openListeners]) {
            try {
              listener();
            } catch {
              // A listener that fails must not undo the unlock.
            }
          }
          return true;
        },
      };
      /** @type {any} */
      let real = null;
      // An op that opened the vault after a lock had come (its unlock was refused) leaves the vault in a worker that
      // started after that lock: that worker is ended too, before the refusal goes out. If another call has opened the
      // host in the meantime, the host locks as a whole (fail closed).
      let ended = false;
      const endRefused = async () => {
        if (!refusedUnlock || ended) return;
        ended = true;
        if (current === "unlocked") await lock("manual").catch(() => {});
        else await Promise.resolve(real?.lock()).catch(() => {});
      };
      try {
        real = await client();
        const view = {
          get vault() {
            usedVault = true;
            return real.vault;
          },
          get job() {
            return real.job;
          },
          // Sets a PIN: the Argon2id runs in a job worker, and only its 32-byte key goes on to the vault worker, which
          // wraps the vault key. It uses the vault worker, so a failure of that worker locks the host like any other use.
          pinWrap(/** @type {unknown[]} */ ...args) {
            usedVault = true;
            return real.pinWrap(...args);
          },
        };
        const value = await def.run(view, args, context);
        // A lock that happened while the call ran wins: nothing is handed out for it.
        if (refusedUnlock) {
          await endRefused();
          throw new CoreError("vault_locked");
        }
        if (def.vault && current !== "unlocked") throw new CoreError("vault_locked");
        return value;
      } catch (error) {
        await endRefused();
        if (error instanceof CoreError) throw error;
        const code = codeOf(error);
        // The vault worker is gone (it failed, ran out of memory, or was ended):
        // the vault is gone with it, so the host says so.
        // Only an op that is declared a job-worker op and never touched the vault
        // is left alone (the client ends a job worker on its own).
        if (WORKER_GONE.has(code) && (usedVault || def.worker !== "job") && current === "unlocked") {
          await lock("worker_failed").catch(() => {});
        }
        throw new CoreError(code);
      }
    },

    /**
     * Locks: the vault worker is ended at once, and the next call starts a new
     * one. Never waits for a call that is running.
     */
    lock,

    /** @returns {"locked" | "unlocked"} */
    state: () => current,

    liveClient,

    /**
     * Adds the implementation of operations whose names are in the list. The
     * test build uses it for `argon2_bench`, once its module has loaded. A name
     * that is not in the list, or that has an implementation already, is an
     * error.
     */
    addOps: register,

    /**
     * Calls `listener(reason)` after every lock, also one that found the vault
     * locked already.
     *
     * @param {(reason: string) => void} listener
     * @returns {() => void} stops the listener
     */
    onLocked(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    /**
     * Calls `listener()` in the turn in which an op opens the host.
     *
     * @param {() => void} listener
     * @returns {() => void} stops the listener
     */
    onUnlocked(listener) {
      openListeners.add(listener);
      return () => openListeners.delete(listener);
    },
  };
}
