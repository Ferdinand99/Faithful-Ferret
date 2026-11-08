// The core host: the one module that holds the WASM client, and so the only
// place a key can ever be. The router (router.mjs) reaches it through
// `call(op, args)` with a name from a fixed list, and it never answers with a
// key: a reply is plain data that the op built.
//
// Where the vault lives (design document, section 7.2): the vault worker of the
// client and the core host are in the same background page and die together. If
// the page dies, the vault is locked. `lock()` is `client.lock()`: it ends the
// worker at once, which frees the heap.
//
// Only this file may import the WASM client (`../js/client.mjs`, copied into
// the package by the build). A test reads the import graph of the built package
// and fails on any other importer.

/** The reasons a lock can have. */
export const LOCK_REASONS = Object.freeze(["timeout", "idle", "manual", "sign_out", "restart"]);

/**
 * The operations the router may call. A name outside this list is refused,
 * whatever else is passed to `createCoreHost`. A later task adds its own names.
 * `argon2_bench` is only available in the test build, which passes its
 * implementation in (`ops`); in a release it is refused like any other name.
 */
export const CORE_OPS = Object.freeze(["ping", "argon2_bench"]);

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
 * @typedef {{ now: () => number, timers: Timers, setUnlocked: () => void }} OpContext
 * @typedef {{ setTimeout: (fn: () => void, ms: number) => unknown, clearTimeout: (id: unknown) => void }} Timers
 * @typedef {{ vault: boolean, run: (client: any, args: any, context: OpContext) => Promise<unknown> }} CoreOp
 *   `vault` is true when the op needs an unlocked vault: it is refused while
 *   the host is locked, without touching the client.
 */

/**
 * Reads a stateless function of the core. No key, no state: the AAGUID is public.
 * @type {CoreOp}
 */
const ping = {
  vault: false,
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
 *   operations). `names` replaces `CORE_OPS` and exists for the tests only.
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
  /** @type {Set<(reason: string) => void>} */
  const listeners = new Set();

  /** @type {Record<string, CoreOp>} */
  const table = { ...BASE_OPS, ...ops };
  const allowed = new Set(names);

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

  /** @type {OpContext} */
  const context = { now, timers, setUnlocked: () => { current = "unlocked"; } };

  return {
    /**
     * Runs one operation. Rejects with a `CoreError` (`unknown_core_op`,
     * `vault_locked`) or with the code of the client's error; never with a
     * message.
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
      try {
        const value = await def.run(await client(), args, context);
        // A lock that happened while the call ran wins: nothing is handed out for it.
        if (def.vault && current !== "unlocked") throw new CoreError("vault_locked");
        return value;
      } catch (error) {
        if (error instanceof CoreError) throw error;
        throw new CoreError(codeOf(error));
      }
    },

    /**
     * Locks: the vault worker is ended at once, and the next call starts a new
     * one. Never waits for a call that is running.
     *
     * @param {"timeout" | "idle" | "manual" | "sign_out" | "restart"} reason
     * @returns {Promise<void>}
     */
    async lock(reason) {
      if (!LOCK_REASONS.includes(reason)) throw new CoreError("bad_reason");
      current = "locked";
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
    },

    /** @returns {"locked" | "unlocked"} */
    state: () => current,

    /**
     * Adds the implementation of operations whose names are in the list. The
     * test build uses it for `argon2_bench`, once its module has loaded. A name
     * that is not in the list is an error.
     *
     * @param {Readonly<Record<string, CoreOp>>} extra
     */
    addOps(extra) {
      for (const name of Object.keys(extra)) {
        if (!allowed.has(name)) throw new CoreError("unknown_core_op");
      }
      Object.assign(table, extra);
    },

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
  };
}
