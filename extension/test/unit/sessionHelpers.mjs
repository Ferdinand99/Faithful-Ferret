// Helpers for the tests of the session (sign-in, unlock and the lock button):
// the built package's modules, a page and the background joined by a port, a
// small in-memory IndexedDB, a fake server that answers like the vault server
// does for a device, and a fake core client. Not a test file (the runner picks
// up *.test.mjs only).
//
// The background's session imports the shared copies of web/src, which exist
// only in a build, so the tests load the modules from a package that this file
// builds once (with a fake WASM package).
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { after } from "node:test";
import { build } from "../../scripts/build.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createSessionStorage } from "./backgroundHelpers.mjs";
import { contentScriptSender, createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";

export const SERVER = "https://vault.example.com";
export const ACCOUNT = "a1".repeat(16);
export const VAULT = "b2".repeat(16);
export const EMAIL = "ola@example.com";
export const SK_CODE = "FFS1-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF";

/** @type {Promise<{ dir: string, load: (path: string) => Promise<any> }> | null} */
let built = null;
/** @type {(() => void) | null} */
let cleanup = null;
// Registered when the test file loads, so the package stays until its last test.
after(() => cleanup?.());

/** The test variant of the package, built once for the whole file. */
export function pkg() {
  built ??= (async () => {
    const env = makeRoot();
    cleanup = env.cleanup;
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest: "mv2", variant: "test" });
    return { dir: result.dir, load: (/** @type {string} */ path) => import(pathToFileURL(join(result.dir, ...path.split("/"))).href) };
  })();
  return built;
}

/** `n` bytes of `fill`. @param {number} n @param {number} fill */
export const filled = (n, fill) => new Uint8Array(n).fill(fill);

/** @param {Uint8Array} bytes */
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

/** @param {string} hex */
const hexBytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

// ------------------------------------------------------------------ the port

/**
 * A port between a page and the background, as the browser makes it: the
 * background's end goes to `router.onConnect`, the page's end is what
 * `runtime.connect` returns. Messages arrive in a later turn.
 * @param {string} name
 * @param {unknown} sender
 */
export function portPair(name, sender) {
  /** @type {Array<(raw: unknown) => void>} */
  const toBackground = [];
  /** @type {Array<(raw: unknown) => void>} */
  const toPage = [];
  /** @type {Array<() => void>} */
  const pageDisconnect = [];
  /** Everything the background sent to the page. @type {string[]} */
  const fromBackground = [];
  let open = true;
  const background = {
    name,
    sender,
    postMessage(/** @type {string} */ text) {
      if (!open) throw new Error("disconnected");
      fromBackground.push(text);
      setTimeout(() => {
        for (const fn of toPage) fn(text);
      }, 0);
    },
    disconnect() {
      open = false;
      setTimeout(() => {
        for (const fn of pageDisconnect) fn();
      }, 0);
    },
    onMessage: { addListener: (/** @type {any} */ fn) => toBackground.push(fn) },
    get disconnected() {
      return !open;
    },
  };
  const page = {
    name,
    postMessage(/** @type {string} */ raw) {
      if (!open) throw new Error("disconnected");
      setTimeout(() => {
        for (const fn of toBackground) fn(raw);
      }, 0);
    },
    disconnect() {
      open = false;
    },
    onMessage: { addListener: (/** @type {any} */ fn) => toPage.push(fn) },
    onDisconnect: { addListener: (/** @type {any} */ fn) => pageDisconnect.push(fn) },
  };
  return { background, page, fromBackground };
}

// --------------------------------------------------------------- IndexedDB

/**
 * An in-memory IndexedDB with what the device key and the sealed secret key
 * use: transactions over object stores with `get`, `put` and `delete`, requests
 * that answer in a later turn, and a commit once no request is left.
 */
export function memoryDb() {
  /** @type {Record<string, string | string[] | null>} */
  const keyPaths = { device_keys: "serverUrl", device_secrets: null, settings: null };
  /** @type {Map<string, Map<string, unknown>>} */
  const data = new Map();
  const tableOf = (/** @type {string} */ name) => {
    if (!data.has(name)) data.set(name, new Map());
    return /** @type {Map<string, unknown>} */ (data.get(name));
  };
  const db = {
    transaction(/** @type {string[]} */ names, /** @type {string} */ _mode) {
      let pending = 0;
      let done = false;
      /** @type {Array<() => void>} */
      const undo = [];
      const tx = {
        /** @type {null | (() => void)} */
        oncomplete: null,
        /** @type {null | (() => void)} */
        onabort: null,
        error: null,
        abort() {
          if (done) return;
          done = true;
          for (const step of undo.reverse()) step();
          setTimeout(() => tx.onabort?.(), 0);
        },
        objectStore(/** @type {string} */ name) {
          if (!names.includes(name)) throw new Error(`${name} is not in the transaction`);
          const table = tableOf(name);
          const path = keyPaths[name] ?? null;
          const keyOf = (/** @type {any} */ value, /** @type {unknown} */ key) =>
            JSON.stringify(key !== undefined ? key : Array.isArray(path) ? path.map((k) => value[k]) : value[/** @type {string} */ (path)]);
          /** @param {() => unknown} work */
          const request = (work) => {
            pending += 1;
            /** @type {any} */
            const req = { result: undefined, error: null, onsuccess: null, onerror: null };
            setTimeout(() => {
              pending -= 1;
              if (done) return;
              try {
                req.result = work();
                req.onsuccess?.({});
              } catch (error) {
                req.error = error;
                req.onerror?.({ preventDefault() {} });
              }
              settle();
            }, 0);
            return req;
          };
          return {
            get: (/** @type {unknown} */ key) => request(() => table.get(JSON.stringify(key))),
            put: (/** @type {any} */ value, /** @type {unknown} */ key) =>
              request(() => {
                const k = keyOf(value, key);
                const before = table.has(k) ? { had: true, value: table.get(k) } : { had: false, value: undefined };
                undo.push(() => (before.had ? table.set(k, before.value) : table.delete(k)));
                table.set(k, value);
                return JSON.parse(k);
              }),
            delete: (/** @type {unknown} */ key) =>
              request(() => {
                const k = JSON.stringify(key);
                const before = table.has(k) ? { had: true, value: table.get(k) } : { had: false, value: undefined };
                undo.push(() => (before.had ? table.set(k, before.value) : undefined));
                table.delete(k);
              }),
          };
        },
      };
      const settle = () =>
        setTimeout(() => {
          if (!done && pending === 0) {
            done = true;
            tx.oncomplete?.();
          }
        }, 0);
      settle();
      return tx;
    },
  };
  return { handle: { db, close() {}, keyRange: null }, data };
}

// ------------------------------------------------------------------ the server

/**
 * A JSON answer the way the server writes it.
 * @param {number} status @param {unknown} body
 */
export function answer(status, body) {
  /** @type {Record<string, string>} */
  const headers = { "cache-control": "no-store" };
  if (body !== null) headers["content-type"] = "application/json";
  return new Response(body === null ? null : JSON.stringify(body), { status, headers });
}

/** The answer of `GET /api/vault/unlock-methods` that the fake core's account has. */
export const methodsRes = () => ({
  methods: [
    { method_id: "11".repeat(16), method_type: 1, kek_generation: 1, wrap: b64u(filled(104, 5)) },
    { method_id: "22".repeat(16), method_type: 2, kek_generation: 1, wrap: b64u(filled(72, 6)) },
  ],
  pk_a: b64u(filled(32, 3)),
  vk_epoch: 1,
  manifest: { rev: 1, envelope: b64u(filled(80, 4)), tag: b64u(filled(32, 5)) },
});

/**
 * A fake vault server for a device: it records every request (`calls`) and
 * answers by path; `overrides[path]` may answer instead.
 * @param {Record<string, (call: any) => Response | undefined>} [overrides]
 */
export function deviceServer(overrides = {}) {
  /** @type {Array<{ url: string, path: string, method: string, headers: Record<string, string>, body: unknown }>} */
  const calls = [];
  let signIns = 0;
  /** @type {typeof fetch} */
  const fetchImpl = async (url, init = {}) => {
    const call = {
      url: String(url),
      path: new URL(String(url)).pathname,
      method: String(init.method ?? "GET"),
      headers: /** @type {Record<string, string>} */ ({ ...(init.headers ?? {}) }),
      body: typeof init.body === "string" ? JSON.parse(init.body) : init.body ?? null,
    };
    calls.push(call);
    const response = overrides[call.path]?.(call) ?? defaults(call);
    Object.defineProperty(response, "url", { value: call.url });
    return response;
  };
  /** @param {{ path: string }} call */
  const defaults = (call) => {
    switch (call.path) {
      case "/api/auth/opaque/login/start":
        return answer(200, { login_id: "cd".repeat(16), ke2: b64u(filled(320, 4)), ksf_profile: 1, sk_hint: true });
      case "/api/auth/opaque/login/finish": {
        signIns += 1;
        const token = (/** @type {number} */ fill) => Buffer.alloc(32, fill).toString("base64url");
        return answer(200, {
          account_id: ACCOUNT,
          vault_id: VAULT,
          vk_epoch: 1,
          device_id: `${"7e".repeat(15)}${String(signIns).padStart(2, "0")}`,
          access_token: token(10 * signIns + 1),
          refresh_token: token(10 * signIns + 2),
          token_type: "DPoP",
          expires_in: 900,
        });
      }
      case "/api/vault/unlock-methods":
        return answer(200, methodsRes());
      case "/api/auth/token/revoke":
        return answer(204, null);
      default:
        return answer(404, { error: "not_found" });
    }
  };
  return { calls, fetchImpl, to: (/** @type {string} */ path) => calls.filter((c) => c.path === path) };
}

// ------------------------------------------------------------------ the core

/**
 * The record the fake core pins for the account.
 * @param {{ skBit?: boolean }} [o]
 */
export const pinnedRecord = ({ skBit = true } = {}) => ({
  server_url: SERVER,
  account_id: hexBytes(ACCOUNT),
  vault_id: hexBytes(VAULT),
  ksf_profile: 1,
  sk_bit: skBit,
  pk_a: filled(32, 3),
  server_public_key: filled(32, 9),
  kek_generation_max: [{ type: "password", generation: 1 }, { type: "recovery", generation: 1 }],
  vk_epoch_max: 1,
});

/** What the fake core reads from a sheet's QR text. @param {{ serverKey?: Uint8Array, server?: string }} [o] */
export const sheet = ({ serverKey = filled(32, 9), server = SERVER } = {}) => ({
  server_url: server,
  scheme: "https",
  host: new URL(server).hostname,
  port: null,
  account_id: hexBytes(ACCOUNT),
  ksf_profile: 1,
  sk_bit: true,
  server_public_key: serverKey,
});

/**
 * A fake WASM client with the vault methods the shared sign-in calls. A method
 * of `methods` replaces the default one.
 * @param {Record<string, (...args: any[]) => any>} [methods]
 */
export function coreClient(methods = {}) {
  return createFakeClient({
    vault: {
      display_host: (/** @type {string} */ url) => ({ unicode: new URL(url).hostname, a_label: new URL(url).hostname }),
      login_start: () => filled(96, 1),
      login_finish: () => ({ ke3: filled(64, 2), server_public_key: filled(32, 9) }),
      unlock_password: () => ({ pinned: pinnedRecord() }),
      seed_pinned: (/** @type {any} */ pinned) => pinned,
      check_server_methods: () => undefined,
      setup_qr_parse: () => sheet(),
      clear: () => undefined,
      ...methods,
    },
  });
}

/**
 * The local stores of the session with the pinned records in memory (the
 * device key and the sealed secret key go to `db`).
 * @param {ReturnType<typeof memoryDb>} db
 */
export function memoryStore(db) {
  /** @type {Map<string, { email: string, record: any }>} */
  const pinned = new Map();
  const hex = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("hex");
  return {
    pinned,
    open: async () => db.handle,
    pinHintForEmail: async (/** @type {any} */ _db, /** @type {string} */ _server, /** @type {string} */ email) =>
      [...pinned.values()].find((p) => p.email === email)?.record ?? null,
    pinnedForSignIn: async (/** @type {any} */ _db, /** @type {string} */ _server, /** @type {string} */ email, /** @type {string} */ accountId) =>
      [...pinned.values()].find((p) => p.email === email || hex(p.record.account_id) === accountId)?.record ?? null,
    pinnedElsewhere: async () => null,
    loadPinnedAccount: async (/** @type {any} */ _db, /** @type {string} */ _server, /** @type {string} */ accountId) => {
      const found = pinned.get(accountId);
      return found ? { email: found.email } : null;
    },
    savePinned: async (/** @type {any} */ _db, /** @type {string} */ _server, /** @type {string} */ accountId, /** @type {string} */ email, /** @type {any} */ record) => {
      pinned.set(accountId, { email, record });
    },
    deviceId: async () => "d".repeat(32),
    cache: { clearAccount: async () => undefined },
    loadSyncState: async () => null,
  };
}

// ------------------------------------------------------------------ the sync

/**
 * Web Locks with one holder per name at a time; `held` names the locks held now, `taken` every name asked for.
 * Takes `request(name, callback)` and `request(name, options, callback)`.
 */
export function fakeLocks() {
  /** @type {Map<string, Promise<unknown>>} */
  const tails = new Map();
  /** @type {Set<string>} */
  const held = new Set();
  /** @type {string[]} */
  const taken = [];
  return {
    held,
    taken,
    request(/** @type {string} */ name, /** @type {any} */ optionsOrCallback, /** @type {any} */ maybeCallback) {
      const callback = maybeCallback ?? optionsOrCallback;
      taken.push(name);
      const before = tails.get(name) ?? Promise.resolve();
      const run = before.then(async () => {
        held.add(name);
        try {
          return await callback({ name });
        } finally {
          held.delete(name);
        }
      });
      tails.set(name, run.catch(() => {}));
      return run;
    },
  };
}

/**
 * A fake of the shared sync engine: it records what it was made with and what is asked of it, and a test makes
 * it announce states (`emit`), stop (`halt`), go on (`clear`) and raise a standing warning (`stand`).
 * `behaviour.start` runs in `start()`, `behaviour.resume` in `resumeAfterHalt()`.
 * @param {{ start?: (engine: any) => unknown, resume?: (engine: any) => unknown }} [behaviour]
 */
export function fakeEngines(behaviour = {}) {
  /** @type {any[]} */
  const made = [];
  /** @param {any} options */
  const create = (options) => {
    /** @type {Map<string, Set<(payload: any) => void>>} */
    const listeners = new Map();
    /** @type {string | null} */
    let halted = null;
    /** @type {string[]} */
    const standing = [];
    const engine = {
      options,
      started: false,
      stopped: false,
      syncs: 0,
      resumes: 0,
      lastStatus: "idle",
      async start() {
        engine.started = true;
        await behaviour.start?.(engine);
      },
      stop() {
        engine.stopped = true;
        listeners.clear();
      },
      status: () => engine.lastStatus,
      health: () => ({ halted, warnings: [...standing] }),
      async resumeAfterHalt() {
        engine.resumes += 1;
        await behaviour.resume?.(engine);
      },
      async syncNow() {
        engine.syncs += 1;
      },
      on(/** @type {string} */ event, /** @type {(payload: any) => void} */ fn) {
        if (!listeners.has(event)) listeners.set(event, new Set());
        /** @type {Set<(payload: any) => void>} */ (listeners.get(event)).add(fn);
        return () => listeners.get(event)?.delete(fn);
      },
      emit(/** @type {string} */ event, /** @type {any} */ payload) {
        for (const fn of [...(listeners.get(event) ?? [])]) fn(payload);
      },
      /** @param {string} code */
      halt(code) {
        halted = code;
        engine.lastStatus = "halted";
        engine.emit("state", { kind: "halted", code });
      },
      clear() {
        halted = null;
        engine.lastStatus = "syncing";
        engine.emit("state", { kind: "syncing" });
      },
      /** @param {string} code */
      stand(code) {
        standing.push(code);
        engine.emit("state", { kind: "warning", code });
      },
    };
    made.push(engine);
    return engine;
  };
  return { create, made };
}

/** A fake of the live channel: it records what it was made with and whether it runs. */
export function fakeChannels() {
  /** @type {any[]} */
  const made = [];
  /** @param {any} options */
  const create = (options) => {
    const channel = {
      options,
      running: false,
      starts: 0,
      start() {
        channel.running = true;
        channel.starts += 1;
      },
      stop() {
        channel.running = false;
      },
      state: () => (channel.running ? "live" : "offline"),
    };
    made.push(channel);
    return channel;
  };
  return { create, made };
}

// ------------------------------------------------------------------ the world

/**
 * A fake of the shared session, for the tests of what the background does
 * around it. Its lock goes to the client like the real one; `behaviour` may
 * replace `signIn`, `unlock` and the device state.
 * @param {{ signIn?: (args: any) => any, unlock?: (args: any) => any, deviceState?: string }} [behaviour]
 */
export function fakeSessions(behaviour = {}) {
  /** @type {Array<[string, any]>} */
  const calls = [];
  /** @type {any[]} */
  const made = [];
  /** @param {any} options */
  const create = (options) => {
    /** @type {{ email: string } | null} */
    let current = null;
    const session = {
      options,
      async signIn(/** @type {any} */ args) {
        calls.push(["signIn", args]);
        try {
          await behaviour.signIn?.(args);
        } catch (error) {
          await session.lock();
          throw error;
        }
        current = { email: args.email };
        return current;
      },
      async unlock(/** @type {any} */ args) {
        calls.push(["unlock", args]);
        try {
          await behaviour.unlock?.(args);
        } catch (error) {
          await session.lock();
          throw error;
        }
        current = { email: EMAIL };
        return current;
      },
      async lock() {
        calls.push(["lock", null]);
        current = null;
        await options.client.lock();
      },
      current: () => current,
      deviceState: async () => behaviour.deviceState ?? (calls.some(([name]) => name === "signIn") ? "ok" : "signed_out"),
    };
    made.push(session);
    return session;
  };
  return { create, calls, made };
}

/**
 * The background (core host, session, lock and router with the session's
 * handler) and the way a page reaches it.
 * @param {{
 *   createSession?: (options: any) => any,
 *   client?: any,
 *   store?: any,
 *   permitted?: boolean,
 *   allowTestHosts?: boolean,
 *   server?: string | null,
 *   os?: string,
 *   gate?: (label: string) => Promise<void>,
 *   sync?: { createEngine?: (options: any) => any, createChannel?: (options: any) => any, locks?: any } | null,
 * }} [options] `gate` runs before every call to the local storage, the permissions and the platform (a test
 *   that locks at each await point passes one). `sync` wires the sync host (and its handler) as main.mjs does,
 *   with the engine and the live channel it names (the shared ones when left out)
 */
export async function sessionWorld({ createSession, client = coreClient(), store, permitted = true, allowTestHosts = false, server = null, os = "win", gate = async () => {}, sync = null } = {}) {
  const { load } = await pkg();
  const [{ createSessionHost }, { createCoreHost }, { createLock }, { createRouter }, handlerModule, ui, { createSyncHost }, syncHandler] = await Promise.all([
    load("background/session.mjs"),
    load("background/coreHost.mjs"),
    load("background/lock.mjs"),
    load("background/router.mjs"),
    load("background/handlers/session.handler.mjs"),
    load("pages/ui.mjs"),
    load("background/sync.mjs"),
    load("background/handlers/sync.handler.mjs"),
  ]);
  const fake = createFakeBrowser();
  const clock = createClock();
  const local = createSessionStorage();
  if (server !== null) await local.set({ server });
  const sessionStorage = createSessionStorage();
  /** @type {Array<{ origins: string[] }>} */
  const asked = [];
  const sessionHost = createSessionHost({
    storageLocal: {
      get: async (/** @type {string} */ key) => {
        await gate("storage.local.get");
        return local.get(key);
      },
      set: async (/** @type {Record<string, unknown>} */ items) => {
        await gate("storage.local.set");
        return local.set(items);
      },
      remove: async (/** @type {string} */ key) => {
        await gate("storage.local.remove");
        return local.remove(key);
      },
    },
    permissions: {
      contains: async (/** @type {{ origins: string[] }} */ wanted) => {
        await gate("permissions.contains");
        asked.push(wanted);
        return permitted;
      },
    },
    platformInfo: async () => {
      await gate("platformInfo");
      return { os };
    },
    allowTestHosts,
    now: clock.now,
    ...(store ? { store } : {}),
    ...(createSession ? { createSession } : {}),
  });
  /** The host permissions the sync took back. @type {Array<{ origins: string[] }>} */
  const removed = [];
  const locks = sync?.locks ?? fakeLocks();
  const syncHost = sync
    ? createSyncHost({
        sessionHost,
        permissions: { remove: async (/** @type {{ origins: string[] }} */ gone) => { removed.push(gone); return true; } },
        locks,
        win: null,
        ...(sync.createEngine ? { createEngine: sync.createEngine } : {}),
        ...(sync.createChannel ? { createChannel: sync.createChannel } : {}),
      })
    : null;
  const coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops: { ...sessionHost.ops, ...(syncHost?.ops ?? {}) } });
  sessionHost.attach(coreHost);
  syncHost?.attach(coreHost);
  const events = createAlarmsAndIdle();
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: sessionStorage, now: clock.now, coreHost });
  const router = createRouter({ runtime: fake.runtime, lock, coreHost, handlers: [handlerModule.default, ...(syncHost ? [syncHandler.default] : [])] });
  /** Every port a page opened. @type {ReturnType<typeof portPair>[]} */
  const ports = [];
  /** A page of the extension at `path`: its `runtime` for `connectUi`. */
  const pageRuntime = (path = "pages/signin.html", extra = {}) => ({
    connect: (/** @type {{ name: string }} */ { name }) => {
      const pair = portPair(name, extensionPageSender(fake, path, extra));
      ports.push(pair);
      router.onConnect(pair.background);
      return pair.page;
    },
  });
  return {
    fake,
    clock,
    client,
    local,
    sessionStorage,
    asked,
    coreHost,
    router,
    events,
    lock,
    sessionHost,
    syncHost,
    removed,
    locks,
    handler: handlerModule,
    ui,
    ports,
    pageRuntime,
    /** Opens a page's UI port and returns its `request`. */
    page: (/** @type {string} */ path = "pages/signin.html") => ui.connectUi(pageRuntime(path)),
    contentSender: (/** @type {string} */ url = "https://evil.example/") => contentScriptSender(fake, url),
    tick,
  };
}
