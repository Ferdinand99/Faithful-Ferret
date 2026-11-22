// Helpers for the tests of the popup's item operations (fillFlow.mjs,
// clipboard.mjs and their handlers): the real core host, lock, router and
// handlers of the built package, a fake core client, a fake sync engine with a
// few items, a fake page matching, a clipboard and a page in a tab that the
// fill script "runs" in (its report and its answers go through the router as a
// content script's would). Not a test file (the runner picks up *.test.mjs
// only).
import { CONTENT_TYPES, PUSH_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createSessionStorage } from "./backgroundHelpers.mjs";
import { contentScriptSender, createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";
import { pkg } from "./sessionHelpers.mjs";

export const PASSWORD = "S3cret-PASSWORD-do-not-show";
export const OTHER_PASSWORD = "Another-S3cret-PASSWORD";
export const TOTP_CODE = "492039";
export const TAB = 7;
export const LOGIN_URL = "https://login.example.net/signin";
export const LOGIN_ORIGIN = "https://login.example.net";

/** An item id from one byte. @param {number} n */
export const idOf = (n) => n.toString(16).padStart(2, "0").repeat(16);

/** The items of the fake vault. */
export const ITEMS = Object.freeze([
  { id: idOf(1), name: "Example", username: "ola@example.net", password: PASSWORD, favorite: true, type: "login", urls: ["https://login.example.net/"], totp: true },
  { id: idOf(2), name: "Bank", username: "ola", password: OTHER_PASSWORD, favorite: false, type: "login", urls: ["https://bank.example.org/"], totp: false },
  { id: idOf(3), name: "Recipe", username: "", password: null, favorite: false, type: "note", urls: [], totp: false },
]);

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/** Whether an injection asks a document whether a frame of it is shown (inject.mjs `frameShownIn`). @param {any} injection */
export const isFrameCheck = (injection) => typeof injection?.func === "function" && String(injection.func).includes("frameShown");

/**
 * A port between a page and the background whose background end also has
 * `onDisconnect`, as the browser's: the page closing ends the session.
 * @param {string} name @param {unknown} sender
 */
function portPair(name, sender) {
  /** @type {Array<(raw: unknown) => void>} */
  const toBackground = [];
  /** @type {Array<(raw: unknown) => void>} */
  const toPage = [];
  /** @type {Array<() => void>} */
  const backgroundDisconnect = [];
  /** @type {Array<() => void>} */
  const pageDisconnect = [];
  /** Every text the background sent to the page. @type {string[]} */
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
    onDisconnect: { addListener: (/** @type {any} */ fn) => backgroundDisconnect.push(fn) },
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
      setTimeout(() => {
        for (const fn of backgroundDisconnect) fn();
      }, 0);
    },
    onMessage: { addListener: (/** @type {any} */ fn) => toPage.push(fn) },
    onDisconnect: { addListener: (/** @type {any} */ fn) => pageDisconnect.push(fn) },
  };
  return { background, page, fromBackground };
}

/**
 * The view the core gives of an item (`item_view`): the user name is shown, the password is hidden.
 * @param {typeof ITEMS[number]} item
 */
function viewOf(item) {
  const fields = [];
  if (item.username !== "" || item.type === "login") fields.push({ id: "username", label: "User name", kind: "text", value: item.username });
  if (item.password !== null) fields.push({ id: "password", label: "Password", kind: "password", value: null });
  return {
    item_type: item.type,
    name: item.name,
    fields,
    urls: item.urls.map((url) => ({ url, matching: "host" })),
    has_totp: item.totp,
    has_notes: false,
    favorite: item.favorite,
    read_only: false,
  };
}

/**
 * The world of the popup's item operations.
 * @param {{
 *   items?: ReadonlyArray<typeof ITEMS[number]>,
 *   frames?: Array<{
 *     frameId: number, documentId?: string, url: string, origin: string, insecure?: boolean, itemIds: string[],
 *     ancestors?: Array<{ frameId: number, documentId?: string }>,
 *   }>,
 *   source?: boolean,
 *   reportTimeoutMs?: number,
 *   resultTimeoutMs?: number,
 * }} [options] `frames` is what the page matching says of the tab `TAB` (it can be changed later through `world.frames`)
 */
export async function itemWorld({ items = ITEMS, frames, source = true, reportTimeoutMs = 200, resultTimeoutMs = 200 } = {}) {
  const { load } = await pkg();
  const [
    { createCoreHost, CORE_OPS },
    { createLock },
    { createRouter },
    { createFillHost },
    { createClipboard },
    ui,
    flows,
    ...handlerModules
  ] = await Promise.all([
    load("background/coreHost.mjs"),
    load("background/lock.mjs"),
    load("background/router.mjs"),
    load("background/fillFlow.mjs"),
    load("background/clipboard.mjs"),
    load("pages/ui.mjs"),
    load("pages/popupFlow.mjs"),
    load("background/handlers/fill.handler.mjs"),
    load("background/handlers/copy.handler.mjs"),
    load("background/handlers/search.handler.mjs"),
    load("background/handlers/fillReport.handler.mjs"),
    load("background/handlers/candidates.handler.mjs"),
  ]);
  const fake = createFakeBrowser();
  const clock = createClock(1_763_800_000_000);

  // ------------------------------------------------------------ the core
  /** The open handles: handle -> item. @type {Map<number, typeof ITEMS[number]>} */
  const handles = new Map();
  let nextHandle = 100;
  const client = createFakeClient({
    vault: {
      ferret_aaguid: () => new Uint8Array(16),
      reveal_item_field: (/** @type {number} */ handle, /** @type {number} */ index) => {
        const item = handles.get(handle);
        if (!item) throw Object.assign(new Error("invalid handle"), { code: "invalid_handle" });
        const field = viewOf(item).fields[index];
        if (!field) throw Object.assign(new Error("no field"), { code: "invalid_input" });
        return field.id === "password" ? item.password : field.value;
      },
      totp_code: (/** @type {number} */ handle, /** @type {number} */ seconds) => {
        const item = handles.get(handle);
        if (!item?.totp) throw Object.assign(new Error("no totp"), { code: "invalid_input" });
        return { code: TOTP_CODE, seconds_left: 30 - (seconds % 30) };
      },
      page_origin: (/** @type {string} */ url) => {
        const parsed = new URL(url);
        if (!/^https?:$/.test(parsed.protocol)) throw Object.assign(new Error("bad"), { code: "malformed_origin" });
        return parsed.origin;
      },
    },
  });

  // ------------------------------------------------------------ the engine
  /** Every open and close of an item, in order. @type {string[]} */
  const opens = [];
  const engine = {
    list: () =>
      items.map((item) => ({ id: item.id, rev: 1, name: item.name, username: item.username, favorite: item.favorite, type: item.type, urls: [...item.urls] })),
    async open(/** @type {string} */ id) {
      const item = items.find((i) => i.id === id);
      if (!item) throw Object.assign(new Error("not found"), { code: "not_found" });
      const handle = nextHandle++;
      handles.set(handle, item);
      opens.push(`open ${id}`);
      return {
        handle,
        view: viewOf(item),
        close: async () => {
          handles.delete(handle);
          opens.push(`close ${id}`);
        },
      };
    },
  };

  // ------------------------------------------------------------ the page
  /**
   * The page in the tab: the fill script answers as the real one would. `report` decides what the frame reports, and
   * `answer` what it answers to a value. A test changes them to play a page that changed.
   */
  /**
   * One frame of the tab, as the fill script in it would answer.
   * @param {{ url: string, frameId: number, documentId: string, selfOrigin: string }} sender
   * @param {string[]} [fields]
   */
  const frameSim = (sender, fields = ["username", "password"]) => ({
    /** The frame's own facts, as the browser gives them for its messages. */
    sender,
    fields,
    /** What was filled, by kind. @type {Record<string, string>} */
    filled: /** @type {Record<string, string>} */ ({}),
    /** Whether the frame reports at all. */
    reports: true,
    /** @type {(kind: string) => { ok: boolean, reason?: string }} */
    answer: (/** @type {string} */ _kind) => ({ ok: true }),
  });
  /** The frames of the tab by frame id; frame 0 is `page`. @type {Map<number, ReturnType<typeof frameSim>>} */
  const frameSims = new Map();
  const page = frameSim({ url: LOGIN_URL, frameId: 0, documentId: "doc-1", selfOrigin: LOGIN_ORIGIN });
  frameSims.set(0, page);
  /** @param {any} target @param {any} [options] */
  const simOf = (target, options) => {
    const doc = target?.documentIds?.[0] ?? options?.documentId;
    const id = target?.frameIds?.[0] ?? options?.frameId;
    return [...frameSims.values()].find((f) => (doc !== undefined ? f.sender.documentId === doc : f.sender.frameId === id)) ?? null;
  };
  /** Every injection: its target and what it ran. @type {any[]} */
  const injections = [];
  /** Every message the background sent to a tab: tab, the decoded message, and where it went. @type {Array<{ tabId: number, message: any, options: any }>} */
  const pushed = [];
  /**
   * Whether a frame is shown in its parent document, as the fill script there answers (content/fill.mjs `frameShown`):
   * a test changes `verdict` to play a page that hides or covers a frame. Every question is in `asked`.
   */
  const frameShown = {
    verdict: (/** @type {number} */ _frameId, /** @type {string} */ _parentDocumentId) => "shown",
    /** @type {Array<{ frameId: number, documentId: string }>} */
    asked: /** @type {Array<{ frameId: number, documentId: string }>} */ ([]),
  };

  /** A content script's message from a frame (the top's by default). @param {string} type @param {any} body @param {ReturnType<typeof frameSim>} [from] */
  const fromPage = (type, body, from = page) =>
    router.onMessage(
      encode(type, body),
      contentScriptSender(fake, from.sender.url, { tab: { id: TAB }, frameId: from.sender.frameId, documentId: from.sender.documentId }),
    );

  const scripting = {
    async executeScript(/** @type {any} */ injection) {
      injections.push(injection);
      const sim = simOf(injection.target);
      if (sim === null) return [{ error: "no frame" }];
      if (injection.files) return [{ frameId: sim.sender.frameId }];
      if (isFrameCheck(injection)) {
        const [frameId] = injection.args;
        frameShown.asked.push({ frameId, documentId: sim.sender.documentId });
        return [{ frameId: sim.sender.frameId, result: frameShown.verdict(frameId, sim.sender.documentId) }];
      }
      const [requestId] = injection.args;
      if (sim.reports) {
        setTimeout(() => {
          void fromPage("frame_report", {
            request_id: requestId,
            self_origin: sim.sender.selfOrigin,
            fields: sim.fields.map((kind, i) => ({ kind, id: `f${i}` })),
          }, sim);
        }, 0);
      }
      return [{ frameId: sim.sender.frameId, result: true }];
    },
  };

  /** Tabs opened by "Open the site". @type {string[]} */
  const opened = [];
  const tabs = {
    async sendMessage(/** @type {number} */ tabId, /** @type {string} */ raw, /** @type {any} */ options) {
      const message = decode(raw, PUSH_TYPES);
      pushed.push({ tabId, message, options });
      const sim = simOf(null, options);
      if (sim === null) return undefined;
      const { request_id: requestId, field, value, expect } = message.body;
      setTimeout(() => {
        const result = expect.origin === sim.sender.selfOrigin && expect.frameUrl === sim.sender.url ? sim.answer(field) : { ok: false, reason: "origin_changed" };
        if (result.ok) sim.filled[field] = value;
        void fromPage("fill_result", result.ok ? { request_id: requestId, ok: true } : { request_id: requestId, ok: false, reason: result.reason }, sim);
      }, 0);
      return undefined;
    },
    async create(/** @type {{ url: string }} */ info) {
      opened.push(info.url);
      return {};
    },
  };

  // ------------------------------------------------------------ the clipboard
  /** What was written to the clipboard, in order. @type {string[]} */
  const written = [];
  const clipboardState = { fails: false };
  const sessionStorage = createSessionStorage();
  const events = createAlarmsAndIdle();
  const clipboard = createClipboard({
    writeText: async (/** @type {string} */ text) => {
      if (clipboardState.fails) throw new Error("denied");
      written.push(text);
    },
    storageSession: sessionStorage,
    alarms: events.alarms,
    now: clock.now,
  });

  // ------------------------------------------------------------ the background
  const matching = {
    frames: frames ?? [{ frameId: 0, documentId: "doc-1", url: LOGIN_URL, origin: LOGIN_ORIGIN, itemIds: [idOf(1)] }],
    /** The frames of the page's site that wait for their host permission. @type {Array<{ origin: string, host: { a_label: string, unicode: string } }>} */
    grant: /** @type {Array<{ origin: string, host: { a_label: string, unicode: string } }>} */ ([]),
    /** Every frame id the fill flow asked about (undefined: all frames). @type {Array<number | undefined>} */
    askedFrames: /** @type {Array<number | undefined>} */ ([]),
    /** Every question the fill flow asked of the page matching. @type {number[]} */
    asked: /** @type {number[]} */ ([]),
    /** Runs before the page matching answers its n-th question (a test plays something that happens meanwhile). */
    before: async (/** @type {number} */ _n) => {},
    /** Whether the sync engine runs (an open vault whose sync did not start has none). */
    syncRunning: true,
  };
  /** @type {any} */
  let coreHost = null;
  const fillHost = createFillHost({
    syncHost: { engine: () => (coreHost?.state() === "unlocked" && matching.syncRunning ? engine : null) },
    clipboard,
    scripting,
    tabs,
    source: source
      ? {
          // The page matching's answer (frames.mjs), from the frames the test names: each item once, with the frames
          // that match it, the top first, at most 4.
          candidates: async (/** @type {number} */ tabId, /** @type {{ frameId?: number }} */ { frameId } = {}) => {
            matching.asked.push(tabId);
            matching.askedFrames.push(frameId);
            await matching.before(matching.asked.length);
            if (tabId !== TAB) return { host: null, insecure: false, items: [], grant: [] };
            const shown = matching.frames.filter((f) => frameId === undefined || f.frameId === frameId);
            const list = items
              .map((item) => ({
                itemId: item.id,
                name: item.name,
                username: item.username === "" ? null : item.username,
                how: "host",
                frames: shown.filter((f) => f.itemIds.includes(item.id)).slice(0, 4).map((f) => ({
                  frameId: f.frameId,
                  ...(f.documentId ? { documentId: f.documentId } : {}),
                  url: f.url,
                  origin: f.origin,
                  // The documents above the frame (a frame of the top by default).
                  ancestors: f.ancestors ?? (f.frameId === 0 ? [] : [{ frameId: 0, documentId: "doc-1" }]),
                })),
              }))
              .filter((i) => i.frames.length > 0);
            return {
              host: { unicode: "login.example.net", a_label: "login.example.net" },
              insecure: matching.frames.some((f) => f.insecure === true),
              items: list,
              grant: structuredClone(matching.grant),
            };
          },
        }
      : null,
    now: clock.now,
    reportTimeoutMs,
    resultTimeoutMs,
  });
  const probes = {
    unlock_probe: {
      vault: false,
      worker: "none",
      run: async (/** @type {any} */ _c, /** @type {any} */ _a, /** @type {any} */ ctx) => {
        ctx.setUnlocked();
        return { ok: true };
      },
    },
  };
  coreHost = createCoreHost({ createClient: () => client, now: clock.now, ops: { ...fillHost.ops, ...probes }, names: [...CORE_OPS, "unlock_probe"] });
  fillHost.attach(coreHost);
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: sessionStorage, now: clock.now, coreHost });
  const router = createRouter({
    runtime: fake.runtime,
    lock,
    coreHost,
    handlers: handlerModules.map((m) => m.default),
    onSessionEnd: (/** @type {string} */ session) => fillHost.endSession(session),
  });

  /** @type {ReturnType<typeof portPair>[]} */
  const ports = [];
  /** A page of the extension: its UI port's `request`, its flows, and the texts the background sent it. */
  const popup = (path = "pages/popup.html") => {
    /** @type {ReturnType<typeof portPair> | null} */
    let pair = null;
    const runtime = {
      connect: (/** @type {{ name: string }} */ { name }) => {
        pair = portPair(name, extensionPageSender(fake, path));
        ports.push(pair);
        router.onConnect(pair.background);
        return pair.page;
      },
    };
    const connection = ui.connectUi(runtime);
    return {
      request: connection.request,
      close: connection.close,
      list: flows.createListFlow(connection.request),
      /** Everything the background sent this page. */
      received: () => pair?.fromBackground ?? [],
    };
  };

  return {
    fake,
    clock,
    client,
    engine,
    opens,
    handles,
    page,
    /**
     * Adds a frame to the tab, whose fill script answers like the top's.
     * @param {{ url: string, frameId: number, documentId: string, selfOrigin: string }} sender @param {string[]} [fields]
     */
    addFrame(sender, fields) {
      const sim = frameSim(sender, fields);
      frameSims.set(sender.frameId, sim);
      return sim;
    },
    injections,
    /** The injections that began a fill request (not the questions about a frame). */
    begins: () => injections.filter((i) => i.func && !isFrameCheck(i)),
    frameShown,
    pushed,
    opened,
    written,
    clipboardState,
    sessionStorage,
    events,
    clipboard,
    matching,
    fillHost,
    coreHost,
    lock,
    router,
    ports,
    popup,
    flows,
    fromPage,
    decodeContent: (/** @type {string} */ raw) => decode(raw, CONTENT_TYPES),
    /** Opens the vault (no key: the fake core needs none). */
    async open() {
      await coreHost.call("unlock_probe");
      lock.touch();
      await tick();
    },
    tick,
    /** Waits until `condition()` holds. @param {() => unknown} condition @param {string} what */
    async until(condition, what) {
      for (let i = 0; i < 400; i += 1) {
        if (await condition()) return;
        await new Promise((resolve) => setTimeout(resolve, 1));
      }
      throw new Error(`never: ${what}`);
    },
  };
}
