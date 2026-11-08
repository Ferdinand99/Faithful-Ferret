// Helpers for the live-update tests: a fake event stream that a test feeds by
// hand, an `api` whose `stream` hands out those streams (or fails as scripted),
// and a page that has the two events the channel listens to.
import { ApiError } from "../../src/api.mjs";

const encoder = new TextEncoder();

/** A stream the test writes to. The reader ends with an error when `signal` aborts, as a real fetch does. */
export function fakeConnection(signal) {
  /** @type {Uint8Array[]} */
  const chunks = [];
  let waiting = null;
  let ended = false;
  let failure = null;
  const wake = () => {
    const resolve = waiting;
    waiting = null;
    resolve?.();
  };
  if (signal) {
    const onAbort = () => {
      failure ??= new ApiError(0, "aborted");
      wake();
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort);
  }
  const connection = {
    signal,
    cancelled: false,
    /** @param {string | Uint8Array} data */
    push(data) {
      chunks.push(typeof data === "string" ? encoder.encode(data) : data);
      wake();
    },
    end() {
      ended = true;
      wake();
    },
    fail(error) {
      failure = error;
      wake();
    },
    hello(seq = 1) {
      connection.push(`event: hello\ndata: {"seq":${seq}}\n\n`);
    },
    sync(seq) {
      connection.push(`event: sync\ndata: {"seq":${seq}}\n\n`);
    },
    comment() {
      connection.push(": \n\n");
    },
    reader: {
      async read() {
        for (;;) {
          if (failure) throw failure;
          const chunk = chunks.shift();
          if (chunk) return { done: false, value: chunk };
          if (ended) return { done: true, value: undefined };
          await new Promise((resolve) => {
            waiting = resolve;
          });
        }
      },
      async cancel() {
        connection.cancelled = true;
        ended = true;
        wake();
      },
    },
  };
  return connection;
}

/**
 * An `api` with a `stream`. `script` holds what the next calls do: an `Error`
 * is thrown, "hang" never answers (until the signal aborts), anything else
 * (or nothing) opens a fresh `fakeConnection`, which is added to `connections`.
 */
export function fakeStreamApi() {
  const api = {
    calls: [],
    connections: [],
    script: [],
    async stream(path, options = {}) {
      api.calls.push({ path, options });
      const step = api.script.shift();
      if (step instanceof Error) throw step;
      if (step === "hang") {
        await new Promise((_, reject) => {
          options.signal?.addEventListener("abort", () => reject(new ApiError(0, "aborted")));
        });
      }
      const connection = fakeConnection(options.signal);
      api.connections.push(connection);
      return connection.reader;
    },
    get last() {
      return api.connections.at(-1);
    },
  };
  return api;
}

/** A page with `focus` and `online` and a network that can be switched off. */
export function fakePageEvents() {
  /** @type {Map<string, Set<Function>>} */
  const listeners = new Map();
  const page = {
    navigator: { onLine: true },
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(fn);
    },
    removeEventListener(type, fn) {
      listeners.get(type)?.delete(fn);
    },
    fire(type) {
      for (const fn of [...(listeners.get(type) ?? [])]) fn();
    },
    count: () => [...listeners.values()].reduce((sum, set) => sum + set.size, 0),
  };
  return page;
}
