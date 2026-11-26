// The message side of the passkey leak scan (extension/test/firefox/passkeyLeak.mjs), in the test build only (a folder named
// test-only: a release leaves it out). Once started with the needles of a sentinel, it reads every message the background page
// receives or sends on a port opened while it is on (the passkey bridge's of a page loaded then, the chooser window's and the popup's UI
// ports, the test ports) and every runtime message it receives, and counts the ones that hold a needle. A core operation, called over the test build's core port:
//
//   leak_watch  { cmd: "start", needles: string[] } starts (and empties) the watch; { cmd: "read" } answers how many messages were
//               read, on ports and as runtime messages, and in which direction and on which port a needle was found.
//
// It answers with counts and port names only: never a message, a value or a key. The page's own MessagePort between the passkey
// script and the bridge is in the page and not seen here; what the bridge sends on is.

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/** The most needles, and their longest text. */
const MAX_NEEDLES = 16;
const MAX_NEEDLE = 512;

/**
 * The tap. The test hooks hand it every port the background is given (`port`) and every runtime message it receives (`message`)
 * from their own listeners, so it adds none.
 */
export function createLeakTap() {
  /** @type {string[]} */
  let needles = [];
  const state = { on: false, portMessages: 0, runtimeMessages: 0, hits: /** @type {string[]} */ ([]) };

  /** @param {string} where @param {unknown} value */
  const check = (where, value) => {
    if (!state.on) return;
    let text = "";
    try {
      text = typeof value === "string" ? value : JSON.stringify(value) ?? "";
    } catch {
      text = String(value);
    }
    if (needles.some((n) => text.includes(n))) state.hits.push(where);
  };

  /** Reads what a port of the background receives and sends. @param {any} port */
  const tapPort = (port) => {
    // Only the ports opened while the watch is on (a page, a window or a popup that the scanned flow opens): the others are left as
    // they are.
    if (!state.on) return;
    const name = typeof port?.name === "string" ? port.name.slice(0, 40) : "?";
    port.onMessage.addListener((/** @type {unknown} */ message) => {
      if (state.on) state.portMessages += 1;
      check(`received on ${name}`, message);
    });
    try {
      const post = port.postMessage.bind(port);
      port.postMessage = (/** @type {unknown} */ message) => {
        if (state.on) state.portMessages += 1;
        check(`sent on ${name}`, message);
        return post(message);
      };
    } catch {
      // A port whose postMessage cannot be wrapped: what it receives is still read.
    }
  };
  /** Reads a runtime message the background receives. @param {unknown} message */
  const tapMessage = (message) => {
    if (state.on) state.runtimeMessages += 1;
    check("runtime message", message);
  };

  /** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
  const ops = Object.freeze({
    leak_watch: {
      vault: false,
      worker: "none",
      async run(_client, args) {
        if (args?.cmd === "start") {
          const given = Array.isArray(args.needles) ? args.needles : [];
          if (given.length === 0 || given.length > MAX_NEEDLES || given.some((/** @type {unknown} */ n) => typeof n !== "string" || n.length < 8 || n.length > MAX_NEEDLE)) throw fail("invalid_input");
          needles = [...given];
          state.on = true;
          state.portMessages = 0;
          state.runtimeMessages = 0;
          state.hits = [];
          return { ok: true };
        }
        if (args?.cmd === "read") return { ok: true, on: state.on, port_messages: state.portMessages, runtime_messages: state.runtimeMessages, hits: [...state.hits] };
        throw fail("invalid_input");
      },
    },
  });
  return { ops, tapPort, tapMessage };
}
