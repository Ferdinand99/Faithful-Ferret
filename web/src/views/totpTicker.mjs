// A one-time code that stays current on a screen. The core makes the code (`totp_code` in the worker, from the clock this
// page gives it); this file only decides when to ask again. It asks once when it starts and again when the code has run out;
// in between it only counts the seconds down, so a code is not made every second. A reply that comes after `stop` is dropped,
// and `stop` forgets the code, so a lock or a page change leaves nothing behind.

/**
 * @typedef {object} Clock
 * @property {() => number} now milliseconds since 1970
 * @property {(fn: () => void, ms: number) => any} setTimeout
 * @property {(id: any) => void} clearTimeout
 */

/** The page's own clock. @type {Clock} */
export const realClock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (id) => globalThis.clearTimeout(id),
};

/** A little after the second turns, so a tick never sees the second before. */
const SLACK_MS = 10;

/**
 * @param {{
 *   load: (seconds: number) => Promise<{ code: string, seconds_left: number }>,
 *   onCode: (code: string, left: number) => void,
 *   onLeft: (left: number) => void,
 *   onError: (error: unknown) => void,
 *   clock?: Clock,
 *   active?: () => boolean,
 * }} options `load` asks the worker for the code at `seconds` (Unix time, whole seconds); `onCode` gets a new code and the
 *   seconds it still holds; `onLeft` gets the seconds left on every tick; `onError` ends the ticking; `active` is asked before
 *   each tick, and a tick that finds it false stops for good
 */
export function codeTicker({ load, onCode, onLeft, onError, clock = realClock, active = () => true }) {
  /** Which run is current: a reply of an older one is dropped. */
  let run = 0;
  /** @type {any} */
  let timer = null;
  /** When the code on show runs out, in ms. */
  let expires = 0;

  /** @param {number} now */
  const secondsLeft = (now) => Math.max(0, Math.ceil((expires - now) / 1000));

  function clearTimer() {
    if (timer !== null) clock.clearTimeout(timer);
    timer = null;
  }

  function stop() {
    run += 1;
    clearTimer();
    expires = 0;
  }

  function schedule() {
    clearTimer();
    timer = clock.setTimeout(() => void tick(), 1000 - (clock.now() % 1000) + SLACK_MS);
    timer?.unref?.();
  }

  async function fetchCode() {
    const mine = run;
    const seconds = Math.floor(clock.now() / 1000);
    try {
      const reply = await load(seconds);
      if (mine !== run) return;
      if (typeof reply?.code !== "string" || !/^[0-9]{6,8}$/.test(reply.code) || !Number.isFinite(reply.seconds_left) || reply.seconds_left < 1) {
        throw new Error("totp_reply");
      }
      expires = (seconds + reply.seconds_left) * 1000;
      onCode(reply.code, secondsLeft(clock.now()));
      schedule();
    } catch (error) {
      if (mine !== run) return;
      stop();
      onError(error);
    }
  }

  async function tick() {
    timer = null;
    if (!active()) {
      stop();
      return;
    }
    const now = clock.now();
    if (now >= expires) {
      await fetchCode();
      return;
    }
    onLeft(secondsLeft(now));
    schedule();
  }

  return {
    /** Asks for the first code and goes on from there. */
    start() {
      stop();
      return fetchCode();
    },
    stop,
  };
}
