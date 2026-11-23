// The world of the offer in Ferret's UI: the real router, lock, core host, handlers, capture host (the store of offers),
// badge and automatic opening of the built package, with the real sync host over a fake engine and a fake core
// (offerWriteWorld.mjs), a toolbar button that records what it shows, and a popup port that asks as the popup does.
// A page's form is captured through the router as a content script's message is. Not a test file (the runner picks up
// *.test.mjs only).
import { UI_PORT, UI_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import { createAlarmsAndIdle, createClock, createFakeTimers, createPort, createSessionStorage } from "./backgroundHelpers.mjs";
import { contentScriptSender, createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";
import { capture as plainCapture, syncWorld } from "./offerWriteWorld.mjs";
import { pkg } from "./sessionHelpers.mjs";

export const TAB = 5;
export const PAGE = "https://login.example.net/signup";
export const ORIGIN = "https://login.example.net";
export const TYPED = "Typed-by-the-user-in-the-form-9x";
export const USER = "anna@example.net";
const flush = () => new Promise((resolve) => setTimeout(resolve, 5));

/**
 * @param {any[]} [items] the items of the fake vault (`item()` of offerWriteWorld.mjs)
 * @param {{ incognito?: boolean, stored?: Record<string, unknown> }} [options]
 */
export async function uiWorld(items = [], { incognito = false, stored = {} } = {}) {
  const { load } = await pkg();
  const [{ createCaptureHost }, { createBadge }, { createAutoOpen }, { createLock, LOCK_AT_KEY }, { createRouter }, { HANDLERS }] = await Promise.all([
    load("background/captureHost.mjs"),
    load("background/badge.mjs"),
    load("background/autoOpen.mjs"),
    load("background/lock.mjs"),
    load("background/router.mjs"),
    load("background/handlers.gen.mjs"),
  ]);
  const fake = createFakeBrowser();
  const clock = createClock();
  const timers = createFakeTimers(clock);
  const events = createAlarmsAndIdle();
  const sessionStorage = createSessionStorage();

  /** What the toolbar button shows, by tab, and every call that set it. @type {Map<number, string>} */
  const badgeText = new Map();
  /** @type {Array<{ text: string, tabId: number }>} */
  const badgeCalls = [];
  /** The popup's opening: how many attempts, and whether the browser refuses them. */
  const popup = { attempts: 0, refuse: false };
  const action = {
    setBadgeText: async (/** @type {{ text: string, tabId: number }} */ { text, tabId }) => {
      badgeCalls.push({ text, tabId });
      badgeText.set(tabId, text);
    },
    setBadgeBackgroundColor: async () => {},
    openPopup: async () => {
      popup.attempts += 1;
      if (popup.refuse) throw new Error("openPopup may only be called from a user action handler");
    },
  };
  /** Where the tab is: active in its window, and the window has the focus. */
  const place = { active: true, focused: true, windowId: 1 };
  /** @type {Record<string, Array<(...args: any[]) => any>>} */
  const listeners = { committed: [], completed: [], history: [], tabRemoved: [] };
  /** @type {Record<string, unknown>} */
  const local = { ...stored };
  const storageLocal = {
    get: async (/** @type {string} */ key) => (key in local ? { [key]: local[key] } : {}),
    set: async (/** @type {Record<string, unknown>} */ items) => void Object.assign(local, items),
  };
  const frames = { [TAB]: [{ frameId: 0, parentFrameId: -1, url: PAGE, documentId: `doc-${TAB}-0` }] };
  const webNavigation = {
    getAllFrames: async (/** @type {{ tabId: number }} */ { tabId }) => /** @type {any} */ (frames)[tabId] ?? [],
    onCommitted: { addListener: (/** @type {any} */ fn) => listeners.committed.push(fn) },
    onCompleted: { addListener: (/** @type {any} */ fn) => listeners.completed.push(fn) },
    onHistoryStateUpdated: { addListener: (/** @type {any} */ fn) => listeners.history.push(fn) },
  };
  const tabs = {
    get: async () => ({ incognito, active: place.active, windowId: place.windowId }),
    onRemoved: { addListener: (/** @type {any} */ fn) => listeners.tabRemoved.push(fn) },
  };
  const windows = { get: async () => ({ focused: place.focused }) };
  const permissions = { contains: async () => true, onRemoved: { addListener() {} } };
  const scripting = { executeScript: async () => [], registerContentScripts: async () => {}, unregisterContentScripts: async () => {}, getRegisteredContentScripts: async () => [] };

  /** @type {any} */
  let world = null;
  /** @type {any} */
  let lock = null;
  const autoOpen = createAutoOpen({ storageLocal, action, tabs, windows, unlocked: () => world?.coreHost.state() === "unlocked" });
  const badge = createBadge({ action, now: clock.now, timers, onAppear: (tabId) => void autoOpen.maybeOpen(tabId) });
  let counter = 0;
  const captureHost = createCaptureHost({
    now: clock.now,
    random: (bytes) => {
      counter += 1;
      bytes.fill(counter & 0xff);
      bytes[0] = 0xcd;
      return bytes;
    },
    webNavigation,
    tabs,
    scripting,
    permissions,
    storageLocal,
    badge,
    autoOpen,
    timers,
    writer: { classify: (c) => world.sync.classifyCapture(c) },
  });

  const site = (/** @type {string} */ host) => host.split(".").slice(-2).join(".");
  const probes = {
    page_origin: { vault: false, worker: /** @type {"none"} */ ("none"), run: async (/** @type {any} */ _c, /** @type {any} */ a) => ({ origin: new URL(a.url).origin }) },
    same_site: { vault: false, worker: /** @type {"none"} */ ("none"), run: async (/** @type {any} */ _c, /** @type {any} */ a) => ({ same: site(new URL(a.a).hostname) === site(new URL(a.b).hostname) }) },
    display_host: { vault: false, worker: /** @type {"none"} */ ("none"), run: async (/** @type {any} */ _c, /** @type {any} */ a) => ({ a_label: new URL(a.url).hostname, unicode: new URL(a.url).hostname }) },
  };
  /** @type {any} */
  let router = null;
  world = await syncWorld(items, {
    offers: captureHost.offers,
    extraOps: { ...captureHost.ops, ...probes },
    attach: (/** @type {any} */ coreHost) => {
      captureHost.attach(coreHost);
      lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: sessionStorage, now: clock.now, coreHost });
      coreHost.setGuard(() => lock.isDue());
      router = createRouter({ runtime: fake.runtime, lock, coreHost, handlers: HANDLERS });
    },
  });
  await flush();

  /** A capture message from the page's content script. @param {Record<string, unknown>} [body] @param {Record<string, unknown>} [senderOver] */
  const capture = async (body = {}, senderOver = {}) => {
    const sender = contentScriptSender(fake, PAGE, { tab: { id: TAB }, frameId: 0, documentId: `doc-${TAB}-0`, ...senderOver });
    const message = Object.fromEntries(
      Object.entries({ capture_id: "cap1", self_origin: ORIGIN, kind: "signup", username: USER, username_from: "typed", password: TYPED, current_password: null, ...body }).map(([k, v]) => [k, v === undefined ? null : v]),
    );
    return router.onMessage(encode("form_capture", message), sender);
  };

  /** The time passes and the timers that are due run: a sign-up offer is ready three seconds after its capture. @param {number} [ms] */
  const wait = async (ms = 3100) => {
    clock.advance(ms);
    await timers.runDue();
    await flush();
  };

  /**
   * A popup page on a port of its own, as the popup asks. `ask` gives the reply of the type, or `{ refused: reason }`.
   * @param {unknown} [sender]
   */
  const connectPopup = (sender = extensionPageSender(fake, "pages/popup.html")) => {
    const port = createPort(UI_PORT, sender);
    router.onConnect(port);
    let n = 0;
    return {
      port,
      /** @param {string} type @param {Record<string, unknown>} [body] @returns {Promise<any>} */
      async ask(type, body = {}) {
        n += 1;
        const before = port.sent.length;
        await port.send(encode(type, body, { id: `r${n}` }));
        if (port.disconnected) return { disconnected: true };
        if (port.sent.length === before) return { silent: true };
        const reply = decode(/** @type {string} */ (port.sent.at(-1)), UI_TYPES, { reply: true });
        return reply.type === "refused" ? { refused: reply.body.reason } : reply.body;
      },
    };
  };

  return {
    ...world,
    fake,
    clock,
    timers,
    events,
    lock,
    router,
    captureHost,
    offers: captureHost.offers,
    badge,
    autoOpen,
    badgeText,
    badgeCalls,
    popup,
    place,
    listeners,
    local,
    capture,
    wait,
    connectPopup,
    flush,
    LOCK_AT_KEY,
    /** A capture of the sign-up form that has become an offer: its id as the popup is told it. */
    async offerReady(body = {}) {
      await capture(body);
      await wait();
    },
    plainCapture,
  };
}
