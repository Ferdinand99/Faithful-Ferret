// A small world for the shortcut and the context menu (commands.mjs, menus.mjs):
// a page with the real fill engine, a `scripting` that runs the injected
// functions against that engine, a lock, a popup, and a core host whose
// `fill_offer` and `fill` behave as the fill flow does (a reference per item
// and frame; a fill puts the script in the frame, waits for its report and
// sends one value per reported kind). Not a test file.
import { injectFill } from "../../src/background/inject.mjs";
import { createFillEngine } from "../../src/content/fill.mjs";
import { decode, encode, CONTENT_TYPES } from "../../src/shared/protocol.mjs";
import { BACKGROUND_SENDER, EXTENSION_BASE, RUNTIME_ID, createPage } from "./fakeDom.mjs";

/** The values of the one login item of the world. */
export const ITEM = Object.freeze({ username: "alice@example.com", password: "correct horse battery staple" });

/**
 * @param {{
 *   url?: string,
 *   build?: (document: any) => Record<string, any>,
 *   offer?: Array<{ frameId: number, frameIds?: number[], items?: number, insecure?: boolean }>,
 *   state?: "locked" | "unlocked",
 *   allowed?: boolean,
 *   frames?: Record<number, { url: string, documentId?: string } | null>,
 * }} [options] `offer`: the handles the page matching gives, per frame; `frames`: what `webNavigation.getFrame` says
 */
export function createWorld({ url = "https://example.com/login", build = () => ({}), offer = [], state = "unlocked", allowed = true, frames } = {}) {
  const page = createPage({ url });
  const parts = build(page.document);
  /** Elements by the `targetElementId` a menu click names. @type {Map<number, any>} */
  const targets = new Map();
  let clockMs = 1_000_000;
  /** @type {string[]} */
  const sent = [];
  const engine = createFillEngine({
    window: page.window,
    document: page.document,
    send: (raw) => {
      sent.push(raw);
    },
    runtimeId: RUNTIME_ID,
    extensionBase: EXTENSION_BASE,
    targetOf: (id) => targets.get(id) ?? null,
    clock: () => clockMs,
  });
  const offered = Object.freeze({ begin: engine.begin, aim: engine.aim });

  /** Every injection, in order. @type {any[]} */
  const injections = [];
  const scripting = {
    executeScript: async (/** @type {any} */ injection) => {
      injections.push(injection);
      if (!("func" in injection)) return [{ frameId: 0, result: null }];
      // The serialised function runs in the frame's isolated world, which holds the engine.
      const run = new Function("globalThis", "args", `return (${String(injection.func)})(...args);`);
      return [{ frameId: 0, result: run({ __ferretFill: offered }, injection.args ?? []) }];
    },
  };

  const log = /** @type {Array<{ op: string, args: any }>} */ ([]);
  const popups = { count: 0 };
  const sessionsEnded = /** @type {string[]} */ ([]);
  const lockCalls = { checks: /** @type {string[]} */ ([]), touches: 0 };
  /** The values the page received, by kind. @type {Array<{ field: string, ok: boolean }>} */
  const fills = [];
  /** @type {Map<string, { session: string, frames: number[] }>} */
  const refs = new Map();
  let counter = 0;

  const coreHost = {
    state: () => world.state,
    /** @param {string} op @param {any} args */
    async call(op, args) {
      log.push({ op, args });
      if (world.state !== "unlocked") throw Object.assign(new Error("vault_locked"), { code: "vault_locked" });
      if (op === "fill_offer") {
        const handles = [];
        for (const frame of world.offer) {
          for (let i = 0; i < (frame.items ?? 1); i += 1) {
            counter += 1;
            const ref = `${String(counter).padStart(4, "0")}${"a".repeat(28)}`;
            const tied = frame.frameIds ?? [frame.frameId];
            refs.set(ref, { session: args.session, frames: tied });
            handles.push({ ref, name: `Item ${counter}`, username: "alice", frame_id: frame.frameId, ...(frame.frameIds ? { frame_ids: tied } : {}), insecure: frame.insecure === true });
          }
        }
        return { handles };
      }
      if (op === "fill") {
        const entry = refs.get(args.ref);
        if (!entry || entry.session !== args.session || !entry.frames.includes(args.frame_id)) return { ok: false, reason: "not_offered" };
        sent.length = 0;
        const requestId = `req-${counter}`;
        await injectFill({ scripting, tabId: args.tab_id, frameId: args.frame_id, requestId });
        const report = sent.map((raw) => decode(raw, CONTENT_TYPES)).find((m) => m.type === "frame_report");
        if (!report) return { ok: false, reason: "no_report" };
        const kinds = report.body.fields.map((/** @type {any} */ f) => f.kind);
        if (kinds.length === 0 && !world.pushEveryKind) return { ok: false, reason: "no_fields" };
        let all = true;
        for (const kind of ["username", "password"]) {
          if (!kinds.includes(kind) && !world.pushEveryKind) continue;
          sent.length = 0;
          const value = /** @type {any} */ (ITEM)[kind];
          engine.onMessage(encode("fill_field", { request_id: requestId, field: kind, value, expect: { origin: page.window.location.origin, frameUrl: page.window.location.href } }), BACKGROUND_SENDER);
          const answer = sent.map((raw) => decode(raw, CONTENT_TYPES)).find((m) => m.type === "fill_result");
          fills.push({ field: kind, ok: answer?.body.ok === true });
          if (answer?.body.ok !== true) {
            all = false;
            if (!world.pushEveryKind) return { ok: false, reason: answer?.body.reason ?? "not_filled" };
          }
        }
        return all && kinds.length > 0 ? { ok: true } : { ok: false, reason: "not_filled" };
      }
      throw Object.assign(new Error("unknown_core_op"), { code: "unknown_core_op" });
    },
  };

  const world = {
    ...page,
    ...parts,
    state,
    offer,
    /** Sends every value, also of a kind the frame did not report (a background that is wrong or worse). */
    pushEveryKind: false,
    targets,
    injections,
    log,
    popups,
    fills,
    sessionsEnded,
    lockCalls,
    coreHost,
    scripting,
    lock: {
      checkOrLock: async (/** @type {string} */ type) => {
        lockCalls.checks.push(type);
        return allowed;
      },
      touch: () => {
        lockCalls.touches += 1;
      },
    },
    sessions: { endSession: (/** @type {string} */ s) => { sessionsEnded.push(s); } },
    openPopup: () => {
      popups.count += 1;
      return Promise.resolve();
    },
    webNavigation: {
      getFrame: async (/** @type {{ tabId: number, frameId: number }} */ { frameId }) => {
        if (frames && Object.hasOwn(frames, frameId)) return frames[frameId];
        return frameId === 0 ? { url, documentId: "doc-0" } : null;
      },
    },
    /** Moves the clock of the engine. @param {number} ms */
    advance(ms) {
      clockMs += ms;
    },
    /** The ops called, by name. */
    ops: () => log.map((l) => l.op),
  };
  return world;
}

/** The value an input holds now. @param {any} input */
export const valueOf = (input) => /** @type {any} */ (Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")).get.call(input);
