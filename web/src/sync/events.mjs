// The live-update channel: a reader for the server's event stream and the
// client that keeps one stream open. An event is only a hint (Spec: Fase 1
// section 8.2, 8.7): it carries a `seq` and nothing else, and the engine reads
// and checks the feed itself. Nothing here decodes anything but a small JSON
// number, and nothing here is ever evaluated.
//
// Reading the stream follows the WHATWG event-stream rules (lines end in LF,
// CR or CRLF; a blank line ends an event; a line that starts with a colon is a
// comment) with two limits the standard does not have, because the sender is a
// server we may not trust: a line is at most 64 KiB, and so is the data of one
// event. A stream that breaks a limit is dropped.
import { ApiError } from "../api.mjs";

/** The path of the stream. */
export const EVENTS_PATH = "/api/sync/events";

/** The longest line, and the most data in one event, in bytes. */
const MAX_LINE_BYTES = 64 * 1024;

/** @typedef {{ event: string, data: string } | { comment: true }} StreamItem */

/**
 * A reader that is given the chunks of a stream as they come and gives back the
 * events and comments they complete. A line or an event that is not complete
 * waits for the next chunk.
 * @returns {{ push(chunk: Uint8Array): StreamItem[] }}
 */
export function parseEventStream() {
  const decoder = new TextDecoder("utf-8");
  /** The text of the line that has not ended yet. */
  let pending = "";
  /** A CR ended the last line: an LF at the start of the next chunk belongs to it. */
  let skipLf = false;
  /** Bytes of the line that has not ended yet. */
  let lineBytes = 0;
  /** @type {string[]} */
  let data = [];
  let dataBytes = 0;
  let name = "";

  /** @param {string} text @param {StreamItem[]} out */
  function onLine(text, out) {
    if (text === "") {
      if (data.length > 0) out.push({ event: name === "" ? "message" : name, data: data.join("\n") });
      data = [];
      dataBytes = 0;
      name = "";
      return;
    }
    if (text.startsWith(":")) {
      out.push({ comment: true });
      return;
    }
    const colon = text.indexOf(":");
    const field = colon === -1 ? text : text.slice(0, colon);
    let value = colon === -1 ? "" : text.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") {
      name = value;
    } else if (field === "data") {
      dataBytes += value.length + 1; // characters: never more than the bytes
      if (dataBytes > MAX_LINE_BYTES) throw new RangeError("event stream: the data of one event is too long");
      data.push(value);
    }
    // `id` and `retry` are read by nobody here; any other field is ignored, as the standard says.
  }

  return {
    push(chunk) {
      // The limit is on bytes, counted before decoding, so a line cannot hide in a chunk.
      for (const byte of chunk) {
        if (byte === 0x0a || byte === 0x0d) lineBytes = 0;
        else if ((lineBytes += 1) > MAX_LINE_BYTES) throw new RangeError("event stream: a line is too long");
      }
      // The decoder drops a byte order mark at the start of the stream, as the standard asks.
      let text = decoder.decode(chunk, { stream: true });
      if (skipLf && text !== "") {
        skipLf = false;
        if (text.startsWith("\n")) text = text.slice(1);
      }
      pending += text;
      /** @type {StreamItem[]} */
      const out = [];
      let from = 0;
      for (;;) {
        let end = -1;
        for (let i = from; i < pending.length; i += 1) {
          const ch = pending.charCodeAt(i);
          if (ch === 0x0a || ch === 0x0d) {
            end = i;
            break;
          }
        }
        if (end === -1) break;
        const one = pending.slice(from, end);
        const cr = pending.charCodeAt(end) === 0x0d;
        from = end + 1;
        if (cr) {
          if (from < pending.length) {
            if (pending.charCodeAt(from) === 0x0a) from += 1;
          } else {
            skipLf = true;
          }
        }
        onLine(one, out);
      }
      pending = pending.slice(from);
      return out;
    },
  };
}

// ------------------------------------------------------------------ channel

/**
 * @typedef {object} Attempt a try to open the stream; `over` is set when it has ended (or been ended), and what it does after that is ignored
 * @property {AbortController} ctrl
 * @property {boolean} over
 * @property {boolean} hello
 * @property {ReadableStreamDefaultReader<Uint8Array> | null} reader
 * @property {unknown} helloTimer
 * @property {unknown} silenceTimer
 *
 * @typedef {"connecting" | "live" | "fallback" | "offline" | "unauthorized"} LiveState
 *
 * @typedef {object} Timers
 * @property {(fn: () => void, ms: number) => unknown} set
 * @property {(handle: unknown) => void} clear
 */

const realTimers = /** @type {Timers} */ ({
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (handle) => clearTimeout(/** @type {any} */ (handle)),
});

/** The wait before a new try after the first failure, doubled for each one after it, up to the longest. */
const BACKOFF_FIRST_MS = 1_000;
const BACKOFF_LONGEST_MS = 60_000;
/** The wait after a 429 when the server named none, and the longest wait we take on its word (seconds). */
const THROTTLED_DEFAULT_S = 30;
const THROTTLED_LONGEST_S = 300;
/** In the fallback, a return to the page asks for a new try at most this often. */
const WAKE_GAP_MS = 5_000;

/** @param {number} step */
const backoff = (step) => Math.min(BACKOFF_LONGEST_MS, BACKOFF_FIRST_MS * 2 ** Math.min(step, 16));

/**
 * The `seq` of a `hello` or `sync` event, or null when the data is not a JSON
 * object with a whole number in `seq`. Nothing else in the data is read.
 * @param {string} data
 * @returns {number | null}
 */
function seqOf(data) {
  try {
    const seq = JSON.parse(data)?.seq;
    return Number.isSafeInteger(seq) && seq >= 0 ? seq : null;
  } catch {
    return null;
  }
}

/**
 * Keeps one event stream open for as long as it is started, and says each time
 * the server has something new (`onHint`). Ruling K1:
 *
 * - No `hello` within `helloTimeoutMs` of the answer, or no bytes for
 *   `silenceMs`, ends the stream and counts as a failure of the connection.
 *   A new try follows after 1, 2, 4 ... 60 s.
 * - `maxFailures` failures in a row without a `hello` put the channel in the
 *   fallback: the engine is asked for a read every `fallbackRetryMs` (and when
 *   the page is shown again or the network returns), and the stream is tried
 *   again at the same times. A `hello` ends the fallback.
 * - 401 stops the channel for good (the session is over); 429 waits for the
 *   `Retry-After` of the server; a stream that ends after a `hello` (the
 *   server closes after an hour, or at a restart) is opened again.
 *
 * @param {{
 *   api: { stream(path: string, options?: { signal?: AbortSignal }): Promise<ReadableStreamDefaultReader<Uint8Array>> },
 *   timers?: Timers,
 *   now?: () => number,
 *   onHint: (seq: number | null) => unknown,
 *   onState?: (state: LiveState) => void,
 *   helloTimeoutMs?: number,
 *   silenceMs?: number,
 *   maxFailures?: number,
 *   fallbackRetryMs?: number,
 *   win?: any,
 * }} options
 *   `timers`, `now` and `win` are for tests (a fake clock; a target for `focus` and `online`).
 * @returns {{ start(): void, stop(): void, state(): LiveState }}
 */
export function createLiveChannel({
  api,
  timers = realTimers,
  now = Date.now,
  onHint,
  onState = () => {},
  helloTimeoutMs = 10_000,
  silenceMs = 60_000,
  maxFailures = 3,
  fallbackRetryMs = 300_000,
  win = globalThis,
}) {
  /** @type {LiveState} */
  let state = "offline";
  let running = false;
  /** The try that is going on, or null. @type {Attempt | null} */
  let attempt = null;
  /** @type {unknown} */
  let retryTimer = null;
  let failures = 0;
  let step = 0;
  let liveSince = 0;
  let lastTryAt = 0;

  /** @param {LiveState} next */
  function setState(next) {
    if (state === next) return;
    state = next;
    try {
      onState(next);
    } catch {
      // A listener must not break the channel.
    }
  }

  /** @param {number | null} seq */
  function hint(seq) {
    try {
      const result = onHint(seq);
      if (result && typeof (/** @type {any} */ (result)).catch === "function") /** @type {any} */ (result).catch(() => {});
    } catch {
      // A failed read is the engine's to report.
    }
  }

  function clearRetry() {
    if (retryTimer !== null) timers.clear(retryTimer);
    retryTimer = null;
  }

  /** @param {Attempt} one */
  function finish(one) {
    one.over = true;
    if (one.helloTimer !== null) timers.clear(one.helloTimer);
    if (one.silenceTimer !== null) timers.clear(one.silenceTimer);
    one.helloTimer = null;
    one.silenceTimer = null;
    try {
      one.ctrl.abort();
    } catch {
      // Already aborted.
    }
    try {
      void one.reader?.cancel().catch(() => {});
    } catch {
      // Nothing to cancel.
    }
    if (attempt === one) attempt = null;
  }

  /** @param {number} ms */
  function later(ms) {
    clearRetry();
    retryTimer = timers.set(() => {
      retryTimer = null;
      if (state === "fallback") hint(null);
      void connect();
    }, ms);
  }

  const offline = () => win?.navigator?.onLine === false;

  /**
   * A try is over. `error` is what ended it: an `ApiError` from the open, or
   * anything else for a broken stream; null for a stream the server closed.
   * @param {Attempt} one
   * @param {unknown} error
   */
  function ended(one, error) {
    if (one.over) return;
    const hadHello = one.hello;
    finish(one);
    if (!running) return;
    const status = error instanceof ApiError ? error.status : 0;
    if (status === 401) {
      setState("unauthorized");
      return; // the session is over: no retry until the next start
    }
    if (status === 429) {
      failures += 1;
      const seconds = Math.min(THROTTLED_LONGEST_S, Math.max(1, (error instanceof ApiError ? error.retryAfter : null) ?? THROTTLED_DEFAULT_S));
      if (failures >= maxFailures) fallback();
      else {
        setState("connecting");
        later(seconds * 1000);
      }
      return;
    }
    if (hadHello) {
      failures = 0;
      if (now() - liveSince >= silenceMs) step = 0;
      setState(offline() ? "offline" : "connecting");
      later(backoff(step));
      step += 1;
      return;
    }
    if (offline()) {
      // No network is not the server's fault: wait for the network (the `online` event) or the next try.
      setState("offline");
      later(backoff(step));
      step += 1;
      return;
    }
    failures += 1;
    if (failures >= maxFailures) {
      fallback();
      return;
    }
    setState("connecting");
    later(backoff(step));
    step += 1;
  }

  function fallback() {
    const entering = state !== "fallback";
    step = 0; // after minutes of waiting, the quick failures before are forgotten
    setState("fallback");
    if (entering) hint(null);
    later(fallbackRetryMs);
  }

  /** @param {Attempt} one */
  function armSilence(one) {
    if (one.silenceTimer !== null) timers.clear(one.silenceTimer);
    one.silenceTimer = timers.set(() => ended(one, new Error("silence")), silenceMs);
  }

  async function connect() {
    if (!running || attempt) return;
    clearRetry();
    lastTryAt = now();
    /** @type {Attempt} */
    const one = { ctrl: new AbortController(), over: false, hello: false, reader: null, helloTimer: null, silenceTimer: null };
    attempt = one;
    // The wait for the answer and the wait for the hello each get the same time.
    one.helloTimer = timers.set(() => ended(one, new Error("no_hello")), helloTimeoutMs);
    /** @type {ReadableStreamDefaultReader<Uint8Array>} */
    let reader;
    try {
      reader = await api.stream(EVENTS_PATH, { signal: one.ctrl.signal });
    } catch (error) {
      if (!one.over) ended(one, error);
      return;
    }
    if (one.over) {
      void reader.cancel().catch(() => {});
      return;
    }
    one.reader = reader;
    if (one.helloTimer !== null) timers.clear(one.helloTimer);
    one.helloTimer = timers.set(() => ended(one, new Error("no_hello")), helloTimeoutMs);
    const parser = parseEventStream();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (one.over) return;
        if (done) break;
        armSilence(one);
        for (const item of parser.push(value)) {
          if (one.over) return;
          if (!("event" in item)) continue;
          if (item.event === "hello") {
            const seq = seqOf(item.data);
            if (seq === null) throw new Error("bad hello");
            if (!one.hello) {
              one.hello = true;
              if (one.helloTimer !== null) timers.clear(one.helloTimer);
              one.helloTimer = null;
              failures = 0;
              liveSince = now();
              setState("live");
            }
            hint(seq);
          } else if (item.event === "sync" && one.hello) {
            hint(seqOf(item.data));
          }
        }
      }
    } catch (error) {
      if (!one.over) ended(one, error);
      return;
    }
    if (!one.over) ended(one, null);
  }

  /** The page is shown again, or the network is back: try now instead of waiting. */
  function wake() {
    if (!running || attempt || retryTimer === null) return;
    if (state === "fallback" && now() - lastTryAt < WAKE_GAP_MS) return;
    clearRetry();
    void connect();
  }

  const WAKE_EVENTS = ["focus", "online"];

  return {
    start() {
      if (running) return;
      running = true;
      failures = 0;
      step = 0;
      setState("connecting");
      for (const name of WAKE_EVENTS) win?.addEventListener?.(name, wake);
      void connect();
    },
    stop() {
      if (!running) return;
      running = false;
      for (const name of WAKE_EVENTS) win?.removeEventListener?.(name, wake);
      clearRetry();
      if (attempt) finish(attempt);
      // A stopped channel is not connected; nobody is told (the screen it served is gone).
      state = "offline";
    },
    state: () => state,
  };
}
