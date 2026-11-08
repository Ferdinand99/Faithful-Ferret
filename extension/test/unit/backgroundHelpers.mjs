// Stand-ins for the browser APIs and the WASM client that the background
// modules use, for the unit tests. Not a test file (the runner picks up
// *.test.mjs only).

/** A clock the tests move by hand. */
export function createClock(start = 1_000_000) {
  let t = start;
  return { now: () => t, set: (/** @type {number} */ n) => { t = n; }, advance: (/** @type {number} */ ms) => { t += ms; } };
}

/** `storage.session` over a Map, with a switch to make it fail. */
export function createSessionStorage() {
  /** @type {Map<string, unknown>} */
  const data = new Map();
  const storage = {
    data,
    broken: false,
    async get(/** @type {string} */ key) {
      if (storage.broken) throw new Error("storage failed");
      return data.has(key) ? { [key]: data.get(key) } : {};
    },
    async set(/** @type {Record<string, unknown>} */ items) {
      if (storage.broken) throw new Error("storage failed");
      for (const [k, v] of Object.entries(items)) data.set(k, v);
    },
    async remove(/** @type {string} */ key) {
      if (storage.broken) throw new Error("storage failed");
      data.delete(key);
    },
  };
  return storage;
}

/** `alarms` and `idle` that record what the code does and let a test fire events. */
export function createAlarmsAndIdle() {
  /** @type {Map<string, { when: number }>} */
  const alarmList = new Map();
  /** @type {Array<(alarm: { name: string }) => void>} */
  const alarmListeners = [];
  /** @type {Array<(state: string) => void>} */
  const idleListeners = [];
  return {
    alarmList,
    alarms: {
      create: (/** @type {string} */ name, /** @type {{ when: number }} */ info) => { alarmList.set(name, info); },
      clear: (/** @type {string} */ name) => { alarmList.delete(name); },
      onAlarm: { addListener: (/** @type {any} */ fn) => { alarmListeners.push(fn); } },
    },
    idle: { onStateChanged: { addListener: (/** @type {any} */ fn) => { idleListeners.push(fn); } } },
    fireAlarm: (/** @type {string} */ name) => Promise.all(alarmListeners.map((fn) => fn({ name }))),
    fireIdle: (/** @type {string} */ state) => { for (const fn of idleListeners) fn(state); },
    listenerCounts: () => ({ alarm: alarmListeners.length, idle: idleListeners.length }),
  };
}

/**
 * A fake WASM client: `vault` and `job` record every call, `lock()` counts and
 * rejects the calls that are waiting, as the real one does.
 *
 * @param {{ vault?: Record<string, (...args: any[]) => any>, job?: Record<string, (...args: any[]) => any> }} [methods]
 */
export function createFakeClient(methods = {}) {
  /** @type {Array<{ target: string, method: string, args: unknown[] }>} */
  const calls = [];
  /** @type {Array<(error: Error) => void>} */
  let waiting = [];
  const client = {
    calls,
    locks: 0,
    vault: new Proxy({}, {
      get: (_, method) => (...args) => {
        calls.push({ target: "vault", method: String(method), args });
        const impl = methods.vault?.[String(method)];
        if (!impl) return Promise.reject(Object.assign(new Error("no such method"), { code: "invalid_input" }));
        return new Promise((resolve, reject) => {
          waiting.push(reject);
          Promise.resolve().then(() => impl(...args)).then(resolve, reject);
        });
      },
    }),
    job: new Proxy({}, {
      get: (_, method) => async (...args) => {
        calls.push({ target: "job", method: String(method), args });
        const impl = methods.job?.[String(method)];
        if (!impl) throw Object.assign(new Error("no such method"), { code: "invalid_input" });
        return impl(...args);
      },
    }),
    async lock() {
      client.locks += 1;
      const pending = waiting;
      waiting = [];
      for (const reject of pending) reject(Object.assign(new Error("locked"), { code: "locked" }));
    },
  };
  return client;
}

/** The AAGUID the fake core answers `ferret_aaguid` with. */
export const AAGUID = Uint8Array.from([0xdc, 0x70, 0x4a, 0x44, 0xb9, 0x94, 0x41, 0x0c, 0xa6, 0x89, 0xed, 0x8d, 0x71, 0xa8, 0x4a, 0xc3]);

/**
 * A port as the browser gives it to `runtime.onConnect`, with the parts the
 * router uses: `onMessage`, `postMessage` and `disconnect`.
 *
 * @param {string} name
 * @param {unknown} sender
 */
export function createPort(name, sender) {
  /** @type {Array<(raw: unknown) => unknown>} */
  const listeners = [];
  /** @type {string[]} */
  const sent = [];
  const port = {
    name,
    sender,
    sent,
    disconnected: false,
    postMessage: (/** @type {string} */ text) => { sent.push(text); },
    disconnect: () => { port.disconnected = true; },
    onMessage: { addListener: (/** @type {any} */ fn) => { listeners.push(fn); } },
    /** Sends a message as the page would, and waits for the router to finish with it. */
    async send(/** @type {unknown} */ raw) {
      await Promise.all(listeners.map((fn) => fn(raw)));
      // The router handles a message in a promise of its own: let it settle.
      await new Promise((resolve) => setTimeout(resolve, 0));
    },
    listenerCount: () => listeners.length,
  };
  return port;
}
