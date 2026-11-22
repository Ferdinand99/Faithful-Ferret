// The background with the sync wired in, for the tests of the sync (syncHost,
// acceptOlder, forgetPending and conflictCard): the real background over the
// real shared sign-in in device mode, a fake vault server and a fake core, and
// the engine and the live channel as fakes unless a test asks for the shared
// ones. Not a test file (the runner picks up *.test.mjs only).
import assert from "node:assert/strict";
import {
  EMAIL, SERVER, SK_CODE, coreClient, deviceServer, fakeChannels, fakeEngines, memoryDb, memoryStore, pkg, sessionWorld,
} from "./sessionHelpers.mjs";

export const MP = "Correct-horse-UNIQUE-4711";
export const OTHER = "https://other.example.org";

/** A shared session in device mode over `fetchImpl`, as the background makes it. @param {typeof fetch} fetchImpl */
export async function realSessions(fetchImpl) {
  const { load } = await pkg();
  const { createCryptoSession } = await load("shared/crypto/session.mjs");
  return (/** @type {any} */ options) => createCryptoSession({ ...options, fetchImpl, locks: null });
}

/** Waits until `condition()` holds (a few hundred turns at most). @param {() => unknown} condition @param {string} what */
export async function until(condition, what) {
  for (let i = 0; i < 400; i += 1) {
    if (await condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  assert.fail(`never: ${what}`);
}

/**
 * The local stores with what "forget this server" uses: it records each removal and the Web Locks held then. The
 * accounts this device keeps records of are the pinned ones (the fake keeps one server). `failures` makes the next
 * removals fail; `writes` is what the store says of an account's unsent changes and of another address that keeps it.
 * @param {ReturnType<typeof memoryDb>} db
 */
export function forgettingStore(db) {
  const store = memoryStore(db);
  /** @type {{ held: () => string[] }} */
  const locks = { held: () => [] };
  /** @type {Array<{ server: string, accountId: string, held: string[] }>} */
  const forgotten = [];
  const failures = { left: 0 };
  const writes = { pending: 0, shared: false };
  return Object.assign(store, {
    locks,
    forgotten,
    failures,
    writes,
    pendingWrites: async () => writes.pending,
    sharedAccount: async () => writes.shared,
    accountsOf: async () => [...store.pinned.keys()],
    forgetServer: async (/** @type {any} */ _db, /** @type {string} */ server, /** @type {string} */ accountId) => {
      if (failures.left > 0) {
        failures.left -= 1;
        throw new Error("the store failed");
      }
      forgotten.push({ server, accountId, held: locks.held() });
      store.pinned.delete(accountId);
      return { removed: { pinned: 1 } };
    },
  });
}

/**
 * The background with the sync wired in, the page's flows, and the fake server it talks to.
 * @param {{ engines?: ReturnType<typeof fakeEngines>, channels?: ReturnType<typeof fakeChannels> | null, server?: ReturnType<typeof deviceServer>, client?: any }} [o]
 *   `channels: null` uses the shared live channel
 */
export async function syncWorld({ engines = fakeEngines(), channels = fakeChannels(), server = deviceServer(), client = coreClient() } = {}) {
  /** Paths whose next request waits until the test lets it go (`hold(path)` returns that). @type {Map<string, { reached: Promise<void>, go: () => void, arrived: () => void }>} */
  const holds = new Map();
  const { load } = await pkg();
  const [{ createSignInFlow }, { createPopupFlow }] = await Promise.all([load("pages/signinFlow.mjs"), load("pages/popupFlow.mjs")]);
  /** Every request the background sent, with what it was sent with. @type {Array<{ url: string, init: RequestInit }>} */
  const inits = [];
  /** @type {typeof fetch} */
  const fetchImpl = async (url, init = {}) => {
    inits.push({ url: String(url), init });
    const path = new URL(String(url)).pathname;
    const held = holds.get(path);
    if (held) {
      holds.delete(path);
      held.arrived();
      await held.reached;
    }
    return server.fetchImpl(url, init);
  };
  /** The next request to `path` waits; `arrived` settles when it is there, `go()` lets it on. @param {string} path */
  const hold = (path) => {
    /** @type {() => void} */
    let go = () => {};
    /** @type {() => void} */
    let arrived = () => {};
    const reached = new Promise((resolve) => (go = () => resolve(undefined)));
    const there = new Promise((resolve) => (arrived = () => resolve(undefined)));
    holds.set(path, { reached, go, arrived });
    return { arrived: there, go: () => go() };
  };
  const db = memoryDb();
  const store = forgettingStore(db);
  const world = await sessionWorld({
    createSession: await realSessions(fetchImpl),
    client,
    store,
    sync: { createEngine: engines.create, ...(channels ? { createChannel: channels.create } : {}) },
  });
  store.locks.held = () => [...world.locks.held];
  const popup = createPopupFlow(world.page("pages/popup.html").request);
  const signIn = async () => {
    const flow = createSignInFlow({ request: world.page("pages/signin.html").request, requestPermission: async () => true });
    assert.equal((await flow.check(SERVER)).ok, true);
    assert.deepEqual(await flow.grant(), { ok: true });
    const result = await flow.signIn({ email: EMAIL, password: MP, skAnswer: "yes", secretKey: SK_CODE, remember: true });
    assert.deepEqual(result, { ok: true, account_email: EMAIL, server: SERVER });
  };
  return { world, engines, channels, server, inits, db, store, popup, signIn, hold };
}
