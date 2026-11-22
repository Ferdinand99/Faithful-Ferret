// A world for the shortcut and the context menu (commands.mjs, menus.mjs): the
// real core host, page matching (match.mjs), frame rules (frames.mjs) and fill
// flow (fillFlow.mjs) of the built package, over a fake WASM client and a fake
// sync engine with logins. Each frame of the tab is a fake page with the real
// fill engine (content/fill.mjs); `scripting` runs the injected functions
// against the engine of the frame (or document) it targets, a frame's reports
// reach the fill flow as the router hands them on, and `tabs.sendMessage` gives
// a value to the engine of one frame. Not a test file.
import { createFillEngine } from "../../src/content/fill.mjs";
import { CONTENT_TYPES, PUSH_TYPES, decode } from "../../src/shared/protocol.mjs";
import { createFakeClient } from "./backgroundHelpers.mjs";
import { BACKGROUND_SENDER, EXTENSION_BASE, RUNTIME_ID, createPage } from "./fakeDom.mjs";
import { pkg } from "./sessionHelpers.mjs";

export const TAB = 7;
export const PAGE = "https://example.com/login";

/** The values of the logins of the world. */
export const ITEM = Object.freeze({ username: "alice@example.com", password: "correct horse battery staple" });

/** An item id from one byte. @param {number} n */
const idOf = (n) => n.toString(16).padStart(2, "0").repeat(16);

/** The test's own idea of a site, for the names these tests use: the scheme and the last two labels. Not a rule of the extension. @param {string} origin */
const siteOf = (origin) => {
  const u = new URL(origin);
  return `${u.protocol}${/[^.]+\.[^.]+$/.exec(u.hostname)?.[0] ?? u.hostname}`;
};

/**
 * @typedef {{
 *   frameId: number, parentFrameId?: number, url: string, documentId?: string,
 *   build?: (document: any) => Record<string, any>,
 *   holder?: (element: any) => void,
 * }} FrameSpec `holder` styles the element that holds the frame in its parent's page (a visible iframe by default)
 * @typedef {{ name?: string, urls: string[] }} ItemSpec
 */

/**
 * @param {{
 *   frames?: FrameSpec[],
 *   items?: ItemSpec[],
 *   state?: "locked" | "unlocked",
 *   allowed?: boolean,
 * }} [options] `frames`: the tab's frames, the top first (frame 0); `items`: the logins of the vault, each with the
 *   saved addresses the fake core matches by origin
 */
export async function createWorld({ frames = [{ frameId: 0, url: PAGE }], items = [{ urls: ["https://example.com/"] }], state = "unlocked", allowed = true } = {}) {
  const { load } = await pkg();
  const [{ createCoreHost, CORE_OPS }, { createFillHost }, { createCandidateSource }, { createMatchHost }] = await Promise.all([
    load("background/coreHost.mjs"),
    load("background/fillFlow.mjs"),
    load("background/frames.mjs"),
    load("background/match.mjs"),
  ]);

  // ------------------------------------------------------------ the vault
  const logins = items.map((item, i) => ({ id: idOf(i + 1), name: item.name ?? `Login ${i + 1}`, username: ITEM.username, password: ITEM.password, urls: item.urls }));
  let nextHandle = 100;
  /** @type {Map<number, typeof logins[number]>} */
  const live = new Map();
  const engineOf = {
    list: () => logins.map((l) => ({ id: l.id, rev: 1, name: l.name, username: l.username, favorite: false, type: "login", urls: [...l.urls] })),
    async open(/** @type {string} */ id) {
      const login = logins.find((l) => l.id === id);
      if (!login) throw Object.assign(new Error("not found"), { code: "not_found" });
      const handle = nextHandle++;
      live.set(handle, login);
      return {
        handle,
        view: {
          item_type: "login",
          name: login.name,
          fields: [
            { id: "username", label: "User name", kind: "text", value: login.username },
            { id: "password", label: "Password", kind: "password", value: null },
          ],
          urls: login.urls.map((url) => ({ url, matching: "host" })),
          has_totp: false,
          favorite: false,
        },
        close: async () => {
          live.delete(handle);
        },
      };
    },
  };
  const originOf = (/** @type {string} */ url) => {
    const u = new URL(url);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw Object.assign(new Error("malformed_origin"), { code: "malformed_origin" });
    return u.origin;
  };
  const client = createFakeClient({
    vault: {
      page_origin: originOf,
      same_site: (/** @type {string} */ a, /** @type {string} */ b) => siteOf(a) === siteOf(b),
      display_host: (/** @type {string} */ url) => ({ a_label: new URL(url).hostname, unicode: new URL(url).hostname }),
      // The fake core's match: an item matches a page of the same origin as one of its addresses.
      match_page: (/** @type {string} */ url, /** @type {number[]} */ handles) =>
        handles.flatMap((handle) => ((live.get(handle)?.urls ?? []).some((saved) => originOf(saved) === originOf(url)) ? [{ handle, how: "host" }] : [])),
      reveal_item_field: (/** @type {number} */ handle, /** @type {number} */ index) => {
        const login = live.get(handle);
        if (!login) throw Object.assign(new Error("invalid handle"), { code: "invalid_handle" });
        return index === 1 ? login.password : login.username;
      },
    },
  });

  // ------------------------------------------------------------ the tab
  let clockMs = 1_000_000;
  /** Elements by the `targetElementId` a menu click names. @type {Map<number, any>} */
  const targets = new Map();
  /** What the browser says of each frame now (a test changes it to play a navigation). */
  const nav = new Map(frames.map((f) => [f.frameId, { frameId: f.frameId, parentFrameId: f.parentFrameId ?? (f.frameId === 0 ? -1 : 0), url: f.url, documentId: f.documentId ?? `doc-${f.frameId}` }]));
  /** @type {any} */
  let coreHost = null;
  /** Every answer of a frame to a value, in order. @type {Array<{ frameId: number, field: string, ok: boolean }>} */
  const fills = [];
  /** The frame each holder element holds, as `runtime.getFrameId` says. @type {Map<any, number>} */
  const holders = new Map();
  const sims = frames.map((spec) => {
    const page = createPage({ url: spec.url });
    const parts = spec.build ? spec.build(page.document) : {};
    const facts = () => /** @type {any} */ (nav.get(spec.frameId));
    /** @type {string | null} */
    let lastField = null;
    const engine = createFillEngine({
      window: page.window,
      document: page.document,
      // A content script's report: the router hands it to the fill flow's one report operation.
      send: (raw) => {
        const { type, body } = decode(raw, CONTENT_TYPES);
        if (type === "fill_result" && lastField !== null) fills.push({ frameId: spec.frameId, field: lastField, ok: body.ok === true });
        setTimeout(() => {
          void coreHost.call("fill_report", { kind: type, body, sender: { tabId: TAB, frameId: spec.frameId, documentId: facts().documentId, url: page.window.location.href } }).catch(() => {});
        }, 0);
      },
      runtimeId: RUNTIME_ID,
      extensionBase: EXTENSION_BASE,
      targetOf: (id) => targets.get(id) ?? null,
      frameIdOf: (element) => {
        const id = holders.get(element);
        if (id === undefined) throw new Error("not a frame");
        return id;
      },
      clock: () => clockMs,
    });
    const setField = (/** @type {string} */ field) => {
      lastField = field;
    };
    return { spec, page, parts, engine, offered: Object.freeze({ begin: engine.begin, aim: engine.aim, frameShown: engine.frameShown }), facts, setField };
  });
  // Each frame below the top has an iframe in its parent's page, shown beside the parent's own form.
  sims.forEach((sim, i) => {
    if (sim.spec.frameId === 0) return;
    const parentId = sim.spec.parentFrameId ?? 0;
    const parent = sims.find((s) => s.spec.frameId === parentId);
    if (!parent) return;
    const iframe = parent.page.document.createElement("iframe", { id: `frame-${sim.spec.frameId}` });
    parent.page.document.body.append(iframe);
    iframe.rect = { left: 400 + 420 * ((i - 1) % 2), top: 60 + 330 * Math.floor((i - 1) / 2), width: 400, height: 300 };
    holders.set(iframe, sim.spec.frameId);
    sim.spec.holder?.(iframe);
  });
  /** @param {any} target @param {any} [options] */
  const simOf = (target, options) => {
    const doc = target?.documentIds?.[0] ?? options?.documentId;
    const id = target?.frameIds?.[0] ?? options?.frameId;
    return sims.find((s) => (doc !== undefined ? s.facts().documentId === doc : s.spec.frameId === id)) ?? null;
  };

  /** Every injection, in order. @type {any[]} */
  const injections = [];
  const scripting = {
    executeScript: async (/** @type {any} */ injection) => {
      injections.push(injection);
      const sim = simOf(injection.target);
      if (sim === null) return [{ error: "no frame" }];
      if (!("func" in injection)) return [{ frameId: sim.spec.frameId, result: null }];
      // The serialised function runs in the frame's isolated world, which holds the engine.
      const run = new Function("globalThis", "args", `return (${String(injection.func)})(...args);`);
      return [{ frameId: sim.spec.frameId, result: run({ __ferretFill: sim.offered }, injection.args ?? []) }];
    },
  };
  const tabs = {
    async sendMessage(/** @type {number} */ tabId, /** @type {string} */ raw, /** @type {any} */ options) {
      const sim = tabId === TAB ? simOf(null, options) : null;
      if (sim === null) return undefined;
      sim.setField(/** @type {any} */ (decode(raw, PUSH_TYPES)).body.field);
      sim.engine.onMessage(raw, BACKGROUND_SENDER);
      return undefined;
    },
    create: async () => ({}),
  };
  const webNavigation = {
    getAllFrames: async (/** @type {{ tabId: number }} */ { tabId }) => (tabId === TAB ? [...nav.values()].map((f) => ({ ...f })) : null),
    getFrame: async (/** @type {{ tabId: number, frameId: number }} */ { tabId, frameId }) => {
      const f = tabId === TAB ? nav.get(frameId) : undefined;
      return f ? { ...f } : null;
    },
  };

  // ------------------------------------------------------------ the background
  const matchHost = createMatchHost({ engine: () => engineOf });
  const call = (/** @type {string} */ op, /** @type {unknown} */ args) => coreHost.call(op, args);
  const fillHost = createFillHost({
    syncHost: { engine: () => (coreHost?.state() === "unlocked" ? engineOf : null) },
    clipboard: { copy: async () => {} },
    scripting,
    tabs,
    source: createCandidateSource({ webNavigation, permissions: { contains: async () => true }, call }),
    reportTimeoutMs: 500,
    resultTimeoutMs: 500,
  });
  const probe = {
    unlock_probe: {
      vault: false,
      worker: "none",
      run: async (/** @type {any} */ _c, /** @type {any} */ _a, /** @type {any} */ ctx) => {
        ctx.setUnlocked();
        return { ok: true };
      },
    },
  };
  coreHost = createCoreHost({ createClient: () => client, ops: { ...matchHost.ops, ...fillHost.ops, ...probe }, names: [...CORE_OPS, "unlock_probe"] });
  matchHost.attach(coreHost);
  fillHost.attach(coreHost);
  if (state === "unlocked") await coreHost.call("unlock_probe");

  const log = /** @type {Array<{ op: string, args: any }>} */ ([]);
  const popups = { count: 0 };
  const sessionsEnded = /** @type {string[]} */ ([]);
  const lockCalls = { checks: /** @type {string[]} */ ([]), touches: 0 };

  const top = sims[0];
  return {
    ...top.page,
    ...top.parts,
    /** The fill engine of frame `frameId`. @param {number} frameId */
    engineOf: (frameId) => /** @type {any} */ (sims.find((s) => s.spec.frameId === frameId)?.engine),
    /** The parts of frame `frameId`'s page. @param {number} frameId */
    frame: (frameId) => /** @type {any} */ (sims.find((s) => s.spec.frameId === frameId)?.parts),
    nav,
    targets,
    injections,
    fills,
    log,
    popups,
    sessionsEnded,
    lockCalls,
    scripting,
    webNavigation,
    /** The core host as the quick fill reaches it: every call logged. */
    coreHost: {
      state: () => coreHost.state(),
      /** @param {string} op @param {any} args */
      call: (op, args) => {
        log.push({ op, args });
        return coreHost.call(op, args);
      },
    },
    lock: {
      checkOrLock: async (/** @type {string} */ type) => {
        lockCalls.checks.push(type);
        return allowed;
      },
      touch: () => {
        lockCalls.touches += 1;
      },
    },
    sessions: {
      endSession: (/** @type {string} */ s) => {
        sessionsEnded.push(s);
        fillHost.endSession(s);
      },
    },
    /** How many sessions still hold references in the fill flow. */
    refSessions: () => fillHost.refs.size(),
    openPopup: () => {
      popups.count += 1;
      return Promise.resolve();
    },
    /** Moves the clock of the engines. @param {number} ms */
    advance(ms) {
      clockMs += ms;
    },
    /** The ops the quick fill called, by name. */
    ops: () => log.map((l) => l.op),
    /** The open item handles (every one is closed after an action). */
    openHandles: () => live.size,
  };
}

/** The value an input holds now. @param {any} input */
export const valueOf = (input) => /** @type {any} */ (Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")).get.call(input);
