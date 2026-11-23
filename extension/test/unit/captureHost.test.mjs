// The capture host (captureHost.mjs) and what joins it to the rest of the
// background: the router's capture route, the lock, the handlers and the
// browser's events. The modules that read the build flag are loaded from a built
// package (the test variant, with saving passwords on).
//
// The browser and the core are fakes; the router, the lock, the core host, the
// handlers and the capture host are the package's own.
import assert from "node:assert/strict";
import { test } from "node:test";
import { REFUSAL_REASONS, UI_PORT, UI_TYPES, CONTENT_TYPES, PUSH_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import { keysOf } from "../../src/shared/schema.mjs";
import { contentScriptSender, createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createFakeTimers, createPort, createSessionStorage } from "./backgroundHelpers.mjs";
import { pkg } from "./sessionHelpers.mjs";

const TAB = 5;
const PAGE = "https://login.example.net/signup";
const ORIGIN = "https://login.example.net";
const SENTINEL_PASSWORD = "Sentinel-PASSWORD-q9Zx7-never-stored";
const SENTINEL_CURRENT = "Sentinel-CURRENT-k4Wm2-never-stored";
const SENTINEL_USER = "sentinel.user.t8Rv3@example.net";
const MINUTE = 60_000;
const flush = () => new Promise((resolve) => setTimeout(resolve, 5));

/**
 * Everything of the background that the capture touches, built from the package.
 * @param {{ granted?: boolean, stored?: Record<string, unknown> }} [options]
 */
async function world({ granted = false, stored = {} } = {}) {
  const { load } = await pkg();
  const [{ createCaptureHost }, { createCoreHost, CORE_OPS }, { createLock, LOCK_AT_KEY }, { createRouter }, { HANDLERS }] = await Promise.all([
    load("background/captureHost.mjs"),
    load("background/coreHost.mjs"),
    load("background/lock.mjs"),
    load("background/router.mjs"),
    load("background/handlers.gen.mjs"),
  ]);
  const fake = createFakeBrowser();
  const clock = createClock();
  const timers = createFakeTimers(clock);
  const sessionStorage = createSessionStorage();
  const events = createAlarmsAndIdle();

  /** What the browser calls the capture host with, and the listeners it registered. */
  /** @type {Record<string, Array<(...args: any[]) => any>>} */
  const listeners = { committed: [], completed: [], history: [], tabRemoved: [], permissionRemoved: [] };
  const frames = { [TAB]: [{ frameId: 0, parentFrameId: -1, url: PAGE, documentId: `doc-${TAB}-0` }] };
  const state = { granted, registered: false };
  /** @type {Record<string, unknown>} */
  const local = { ...stored };
  /** Every call that could carry a value to a disk or a log: kept to be searched. @type {unknown[][]} */
  const spied = [];
  const storageLocal = {
    get: async (/** @type {string} */ key) => (key in local ? { [key]: local[key] } : {}),
    set: async (/** @type {Record<string, unknown>} */ items) => {
      spied.push(["storage.local.set", items]);
      Object.assign(local, items);
    },
  };
  const spiedSession = {
    ...sessionStorage,
    set: async (/** @type {Record<string, unknown>} */ items) => {
      spied.push(["storage.session.set", items]);
      return sessionStorage.set(items);
    },
  };
  const webNavigation = {
    getAllFrames: async (/** @type {{ tabId: number }} */ { tabId }) => /** @type {any} */ (frames)[tabId] ?? [],
    onCommitted: { addListener: (/** @type {any} */ fn) => listeners.committed.push(fn) },
    onCompleted: { addListener: (/** @type {any} */ fn) => listeners.completed.push(fn) },
    onHistoryStateUpdated: { addListener: (/** @type {any} */ fn) => listeners.history.push(fn) },
  };
  const tabs = { get: async () => ({ incognito: false }), onRemoved: { addListener: (/** @type {any} */ fn) => listeners.tabRemoved.push(fn) } };
  const permissions = {
    contains: async () => state.granted,
    onRemoved: { addListener: (/** @type {any} */ fn) => listeners.permissionRemoved.push(fn) },
  };
  const scripting = {
    executeScript: async () => [],
    registerContentScripts: async () => void (state.registered = true),
    unregisterContentScripts: async () => void (state.registered = false),
    getRegisteredContentScripts: async () => (state.registered ? [{ id: "ferret-capture" }] : []),
  };
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
    timers,
  });

  // The core host with the capture host's ops and the three site functions the way the core answers them.
  const site = (/** @type {string} */ host) => host.split(".").slice(-2).join(".");
  const probes = {
    unlock_probe: { vault: false, worker: /** @type {"none"} */ ("none"), run: async (/** @type {any} */ _c, /** @type {any} */ _a, /** @type {any} */ ctx) => (ctx.setUnlocked(), { ok: true }) },
    page_origin: { vault: false, worker: /** @type {"none"} */ ("none"), run: async (/** @type {any} */ _c, /** @type {any} */ a) => ({ origin: new URL(a.url).origin }) },
    same_site: { vault: false, worker: /** @type {"none"} */ ("none"), run: async (/** @type {any} */ _c, /** @type {any} */ a) => ({ same: site(new URL(a.a).hostname) === site(new URL(a.b).hostname) }) },
    display_host: { vault: false, worker: /** @type {"none"} */ ("none"), run: async (/** @type {any} */ _c, /** @type {any} */ a) => ({ a_label: new URL(a.url).hostname, unicode: new URL(a.url).hostname }) },
  };
  const coreHost = createCoreHost({
    createClient: () => createFakeClient(),
    now: clock.now,
    ops: { ...captureHost.ops, ...probes },
    names: [...CORE_OPS, "unlock_probe"],
  });
  captureHost.attach(coreHost);
  const lock = createLock({ alarms: events.alarms, idle: events.idle, storageSession: spiedSession, now: clock.now, coreHost });
  coreHost.setGuard(() => lock.isDue());
  const router = createRouter({ runtime: fake.runtime, lock, coreHost, handlers: HANDLERS });

  const unlock = async () => {
    await coreHost.call("unlock_probe");
    await flush();
  };
  /** A capture message from the page's content script. @param {Record<string, unknown>} [body] @param {Record<string, unknown>} [senderOver] */
  const capture = async (body = {}, senderOver = {}) => {
    const sender = contentScriptSender(fake, PAGE, { tab: { id: TAB }, frameId: 0, documentId: `doc-${TAB}-0`, ...senderOver });
    // The script sends every key, `null` for what the form does not have: a key set to undefined is null here.
    const message = Object.fromEntries(
      Object.entries({
        capture_id: "cap1",
        self_origin: ORIGIN,
        kind: "signup",
        username: SENTINEL_USER,
        username_from: "typed",
        password: SENTINEL_PASSWORD,
        current_password: null,
        ...body,
      }).map(([key, value]) => [key, value === undefined ? null : value]),
    );
    return router.onMessage(encode("form_capture", message), sender);
  };
  const lockAt = async () => (await sessionStorage.get(LOCK_AT_KEY))[LOCK_AT_KEY];
  return { fake, clock, timers, events, coreHost, lock, router, captureHost, offers: captureHost.offers, listeners, frames, state, local, spied, sessionStorage, capture, unlock, lockAt, LOCK_AT_KEY, HANDLERS };
}

test("capture_messages_work_while_locked_and_do_not_move_lock_at", async () => {
  const w = await world();
  assert.equal(w.coreHost.state(), "locked");
  // A capture is taken while the vault is locked: no unlock, no key, no deadline written.
  assert.equal(await w.capture(), undefined, "nothing is answered to a content script");
  w.clock.advance(3000);
  assert.equal(w.coreHost.state(), "locked");
  assert.equal(w.offers.forTab(TAB).length, 1);
  assert.equal(await w.lockAt(), undefined, "a locked vault gets no deadline from a capture");

  // With the vault open, the three reports leave the deadline where it was.
  await w.unlock();
  const before = await w.lockAt();
  assert.equal(typeof before, "number");
  w.clock.advance(60_000);
  await w.capture({ password: "Another-typed-PASSWORD-2" });
  const sender = contentScriptSender(w.fake, PAGE, { tab: { id: TAB }, frameId: 0, documentId: `doc-${TAB}-0` });
  await w.router.onMessage(encode("form_gone", { capture_id: "cap1" }), sender);
  await w.router.onMessage(encode("page_ready", {}), sender);
  assert.equal(await w.lockAt(), before, "the deadline did not move");
  assert.equal(w.coreHost.state(), "unlocked");

  // A report is not an answer: a message of an extension page with the same type is refused at the door.
  const popup = createPort(UI_PORT, extensionPageSender(w.fake));
  w.router.onConnect(popup);
  await popup.send(encode("form_capture", { capture_id: "x", self_origin: ORIGIN, kind: "login", username: null, username_from: null, password: "p", current_password: null }));
  assert.equal(popup.disconnected, true, "a page cannot send what only a content script sends");
  // And a content script cannot send the settings page's type.
  const before2 = w.offers.size();
  assert.equal(await w.router.onMessage(encode("capture_settings", {}), sender), undefined);
  assert.equal(w.offers.size(), before2);
});

test("every_lock_clears_all_offers_and_captures", async () => {
  /** @type {Array<[string, (w: Awaited<ReturnType<typeof world>>) => Promise<void>]>} */
  const ways = [
    ["manual", async (w) => void (await w.coreHost.lock("manual"))],
    [
      "auto",
      async (w) => {
        w.clock.advance(15 * MINUTE);
        await w.lock.checkOrLock("state");
      },
    ],
    ["idle", async (w) => (w.events.fireIdle("idle"), flush())],
    ["screen locked", async (w) => (w.events.fireIdle("locked"), flush())],
    [
      "sleep",
      async (w) => {
        // The machine slept past the deadline: the first sign of life locks.
        w.clock.jump(16 * MINUTE);
        w.events.fireIdle("active");
        await flush();
      },
    ],
    ["sign out", async (w) => void (await w.coreHost.lock("sign_out"))],
    ["worker failed", async (w) => void (await w.coreHost.lock("worker_failed"))],
  ];
  for (const [name, way] of ways) {
    const w = await world();
    await w.unlock();
    await w.capture();
    w.clock.advance(2100);
    await w.capture({ kind: "identifier", password: undefined, username: "step@example.net" });
    w.clock.advance(3000);
    await w.offers.onGenerated({ tabId: 6, frameId: 0, frameUrl: PAGE, kind: "signup", password: "Generated-by-Ferret-9" });
    assert.equal(w.offers.size(), 2, `${name}: held before`);
    await way(w);
    assert.equal(w.coreHost.state(), "locked", name);
    assert.equal(w.offers.size(), 0, `${name}: a lock clears everything`);
    assert.deepEqual(w.offers.forTab(TAB), [], name);
    assert.deepEqual(w.offers.forTab(6), [], name);
  }
  // A lock that finds the vault locked already clears too (a capture was taken while it was locked).
  const locked = await world();
  await locked.capture();
  locked.clock.advance(3000);
  assert.equal(locked.offers.forTab(TAB).length, 1);
  await locked.coreHost.lock("manual");
  assert.equal(locked.offers.size(), 0);
});

test("the_browsers_events_reach_the_offers_and_a_removed_permission_ends_capture", async () => {
  const w = await world({ granted: true, stored: { offer_to_save: true } });
  await flush();
  assert.equal(w.state.registered, true, "reconciled at the start: setting on and permission granted");
  // A login: the capture, then the page's own events through the listeners the host registered.
  await w.capture({ kind: "login" });
  const [committed] = w.listeners.committed;
  const [completed] = w.listeners.completed;
  const to = "https://login.example.net/home";
  committed({ tabId: TAB, frameId: 0, url: to, documentId: "doc-new" });
  await flush();
  completed({ tabId: TAB, frameId: 0, url: to, documentId: "doc-new" });
  await flush();
  w.clock.advance(2000);
  assert.equal(w.offers.forTab(TAB).length, 1);
  // The tab closes: its offers go.
  w.listeners.tabRemoved[0](TAB);
  assert.equal(w.offers.size(), 0);
  // The history of a single-page login.
  w.clock.advance(3000);
  await w.capture({ kind: "login" });
  w.clock.advance(500);
  w.listeners.history[0]({ tabId: TAB, frameId: 0, url: "https://login.example.net/app" });
  await flush();
  w.clock.advance(2000);
  assert.equal(w.offers.forTab(TAB).length, 1);
  // The permission is taken back: the script goes, the setting goes off, the offers go.
  w.state.granted = false;
  w.listeners.permissionRemoved[0]({ origins: ["https://*/*"] });
  await flush();
  assert.equal(w.state.registered, false);
  assert.equal(w.local.offer_to_save, false);
  assert.equal(w.offers.size(), 0);
});

test("the_capture_settings_work_on_a_locked_device_and_check_the_permission_themselves", async () => {
  const w = await world();
  const page = createPort(UI_PORT, extensionPageSender(w.fake, "pages/settings.html"));
  w.router.onConnect(page);
  /** @param {Record<string, unknown>} body */
  const ask = async (body) => {
    page.sent.length = 0;
    await page.send(encode("capture_settings", body));
    return decode(page.sent[0], UI_TYPES, { reply: true });
  };
  // Off by default, on a locked device, with no deadline written.
  let reply = await ask({});
  assert.equal(reply.type, "capture_settings");
  assert.deepEqual(reply.body, { ok: true, on: false, permission: false, never: [] });
  assert.equal(await w.lockAt(), undefined);
  // The page says "on" without the permission: nothing is switched on or registered.
  reply = await ask({ enable: true });
  assert.deepEqual(reply.body, { ok: false, reason: "permission_missing", on: false, permission: false, never: [] });
  assert.equal(w.state.registered, false);
  // With the permission it is on, and the offers it held are not affected until it is turned off.
  w.state.granted = true;
  reply = await ask({ enable: true });
  assert.deepEqual(reply.body, { ok: true, on: true, permission: true, never: [] });
  assert.equal(w.state.registered, true);
  await w.capture();
  w.clock.advance(3000);
  assert.equal(w.offers.forTab(TAB).length, 1);
  reply = await ask({ enable: false });
  assert.equal(reply.body.on, false);
  assert.equal(w.state.registered, false);
  assert.equal(w.offers.size(), 0, "turning capture off clears what was held");
  // The never list: shown, one host taken off, all taken off.
  w.local.capture_never = ["a.example.net", "b.example.net"];
  const again = await world({ stored: { capture_never: ["a.example.net", "b.example.net"] } });
  const page2 = createPort(UI_PORT, extensionPageSender(again.fake, "pages/settings.html"));
  again.router.onConnect(page2);
  await page2.send(encode("capture_settings", { never_remove: "a.example.net" }));
  assert.deepEqual(decode(page2.sent[0], UI_TYPES, { reply: true }).body.never, ["b.example.net"]);
  page2.sent.length = 0;
  await page2.send(encode("capture_settings", { never_clear: true }));
  assert.deepEqual(decode(page2.sent[0], UI_TYPES, { reply: true }).body.never, []);
  assert.deepEqual(again.local.capture_never, []);
});

/**
 * Whether `needle` is anywhere in `value`, at any depth, in a string, a key, or a JSON text of any of them (the text of
 * a text, as a log line or a stored string would hold it), also with its characters escaped as JSON escapes them.
 * @param {unknown} value @param {string} needle @param {number} [depth]
 * @returns {boolean}
 */
function holds(value, needle, depth = 0) {
  if (depth > 12) return false;
  if (typeof value === "string") {
    if (value.includes(needle) || value.includes(JSON.stringify(needle).slice(1, -1)) || value.includes(encodeURIComponent(needle))) return true;
    return value.startsWith("{") || value.startsWith("[") ? safeJson(value, needle, depth) : false;
  }
  if (value === null || typeof value !== "object") return false;
  for (const [key, inner] of Object.entries(value)) if (holds(key, needle, depth + 1) || holds(inner, needle, depth + 1)) return true;
  return false;
}

/** @param {string} text @param {string} needle @param {number} depth */
function safeJson(text, needle, depth) {
  try {
    return holds(JSON.parse(text), needle, depth + 1);
  } catch {
    return false;
  }
}

test("captured_values_are_never_written_to_any_storage_or_console", async () => {
  const needles = [SENTINEL_PASSWORD, SENTINEL_CURRENT, SENTINEL_USER, "Generated-sentinel-w5Hn8"];
  // The spies: the console, and every storage the extension can write, besides the ones in the world.
  /** @type {unknown[][]} */
  const logged = [];
  const originals = /** @type {Record<string, any>} */ ({});
  for (const method of ["log", "info", "warn", "error", "debug", "trace"]) {
    originals[method] = /** @type {any} */ (console)[method];
    /** @type {any} */ (console)[method] = (/** @type {unknown[]} */ ...args) => void logged.push([method, ...args]);
  }
  const stringified = /** @type {string[]} */ ([]);
  try {
    const w = await world({ granted: true, stored: { offer_to_save: true } });
    await w.unlock();
    // A real capture of each kind, with the known values, and what a user does with them.
    await w.capture({ kind: "change", current_password: SENTINEL_CURRENT });
    w.clock.advance(3000);
    await w.capture({ kind: "login", password: SENTINEL_CURRENT });
    w.clock.advance(2100);
    await w.capture({ kind: "login" });
    await w.offers.onGenerated({ tabId: 6, frameId: 0, frameUrl: PAGE, kind: "signup", password: "Generated-sentinel-w5Hn8", username: SENTINEL_USER });
    w.clock.advance(3000);
    const session = "9".repeat(32);
    const listed = [...w.offers.forTab(TAB, session), ...w.offers.forTab(6, session)];
    assert.ok(listed.length >= 2);
    // The offer's own answers are metadata only.
    for (const meta of listed) {
      assert.deepEqual(Object.keys(meta).sort(), ["generated", "host", "kind", "offer_id", "username"]);
      stringified.push(JSON.stringify(meta));
    }
    // The settings page's answer and every sync of a lock.
    const page = createPort(UI_PORT, extensionPageSender(w.fake, "pages/settings.html"));
    w.router.onConnect(page);
    await page.send(encode("capture_settings", {}));
    stringified.push(...page.sent);
    // "Never for this site" writes the host to storage.local: the positive control that the spies see writes.
    w.offers.dismiss(listed[0].offer_id, { never: true });
    await flush();
    // One was taken for a write; then every lock.
    w.offers.take(listed[1].offer_id, session);
    await w.coreHost.lock("manual");
    await flush();
    assert.equal(w.offers.size(), 0);

    assert.ok(w.spied.some(([name, items]) => name === "storage.local.set" && holds(items, "login.example.net")), "the spies saw the never list written");
    assert.ok(w.spied.some(([name]) => name === "storage.session.set"), "the spies saw the deadline written");
    assert.equal(holds([{ deep: [{ deeper: `x ${JSON.stringify({ s: SENTINEL_PASSWORD })}` }] }], SENTINEL_PASSWORD), true, "the search finds an escaped value");
    for (const needle of needles) {
      assert.equal(holds(w.spied, needle), false, `storage got ${needle}`);
      assert.equal(holds(logged, needle), false, `the console got ${needle}`);
      // An offer's answer names the user name (the card shows it, editable); it never carries a password.
      if (needle !== SENTINEL_USER) assert.equal(holds(stringified, needle), false, `an answer carried ${needle}`);
      assert.equal(holds([...w.sessionStorage.data.entries()], needle), false, `storage.session holds ${needle}`);
      assert.equal(holds(w.local, needle), false, `storage.local holds ${needle}`);
    }
  } finally {
    for (const [method, original] of Object.entries(originals)) /** @type {any} */ (console)[method] = original;
  }
});

test("no_ui_reply_or_push_type_carries_a_captured_value", () => {
  // Only the capture's own request carries what the user typed, and only upwards: no reply and no push type has a
  // password-like key (a push carries the one value of one fill).
  for (const [type, def] of Object.entries(UI_TYPES)) {
    for (const key of keysOf(def.reply)) assert.doesNotMatch(key, /pass|secret|^value$/i, `ui reply ${type}: ${key}`);
    for (const key of keysOf(def.request)) {
      if (!["sign_in", "unlock"].includes(type)) assert.doesNotMatch(key, /pass|secret|^value$/i, `ui request ${type}: ${key}`);
    }
  }
  for (const [type, def] of Object.entries(PUSH_TYPES)) {
    if (type !== "fill_field") for (const key of keysOf(def.request)) assert.doesNotMatch(key, /pass|secret|^value$/i, `push ${type}: ${key}`);
  }
  const carriers = Object.entries(CONTENT_TYPES).filter(([, def]) => keysOf(def.request).some((key) => /pass/i.test(key))).map(([type]) => type);
  assert.deepEqual(carriers, ["form_capture"]);
  assert.equal(REFUSAL_REASONS.some((reason) => /pass/.test(reason)), false);
});

test("the_capture_handlers_refuse_what_is_not_theirs_and_a_content_script_is_never_answered", async () => {
  const { load } = await pkg();
  const [{ default: capture }, { default: settings }] = await Promise.all([load("background/handlers/capture.handler.mjs"), load("background/handlers/captureSettings.handler.mjs")]);
  assert.deepEqual([capture.types, capture.channel], [["form_capture", "form_gone", "page_ready"], "content"]);
  assert.deepEqual([settings.types, settings.channel], [["capture_settings"], "ui"]);
  // A context with no capture route (a UI context, say) is refused; with one, the body goes on and nothing comes back.
  await assert.rejects(capture.handle({}, { channel: "ui", type: "form_capture", state: () => "locked" }), { code: "not_available" });
  /** @type {unknown[]} */
  const handed = [];
  const answer = await capture.handle({ capture_id: "c" }, { channel: "content", type: "form_gone", state: () => "locked", capture: async (/** @type {unknown} */ body) => void handed.push(body) });
  assert.equal(answer, undefined);
  assert.deepEqual(handed, [{ capture_id: "c" }]);

  // The router names the type and the sender, whatever the handler says.
  const w = await world();
  /** @type {any[]} */
  const reached = [];
  const orig = w.coreHost.call.bind(w.coreHost);
  w.coreHost.call = async (op, args) => (op === "capture_event" ? void reached.push(args) : orig(op, args));
  const sender = contentScriptSender(w.fake, PAGE, { tab: { id: 12 }, frameId: 3, documentId: "doc-z" });
  await w.router.onMessage(encode("page_ready", {}), sender);
  assert.equal(reached.length, 1);
  assert.deepEqual({ ...reached[0], body: undefined }, { type: "page_ready", sender: { tabId: 12, frameId: 3, documentId: "doc-z", url: PAGE }, body: undefined });
  // A message that a content script sends with an unknown type or an odd shape is dropped silently.
  assert.equal(await w.router.onMessage(JSON.stringify({ v: 1, id: "a", type: "form_capture", body: { capture_id: "c", self_origin: ORIGIN, kind: "login", password: "p", extra: 1 } }), sender), undefined);
  assert.equal(reached.length, 1);
  assert.equal(await w.router.onMessage(encode("page_ready", {}), extensionPageSender(w.fake)), undefined, "an extension page is not a content script");
  assert.equal(reached.length, 1);
});

test("offers_peek_reports_kind_origin_user_and_a_hash_of_the_password_never_the_password", async () => {
  const { load } = await pkg();
  const { createOfferProbe } = await load("background/test-only/offerProbe.mjs");
  const { createHash } = await import("node:crypto");
  const w = await world();
  await w.capture();
  w.clock.advance(3000);
  const session = "ab".repeat(16);
  /** @type {Array<[string, unknown]>} */
  const asked = [];
  const probe = createOfferProbe({
    offers: w.offers,
    call: async (op, args) => (asked.push([op, args]), { ok: true, action: "update", targets: [{ id: "00".repeat(16), rev: 1, name: "Login item", username: "ola", how: "username" }], reused: [{ name: "Other", host: null }] }),
    items: () => [{ id: "00".repeat(16), urls: ["https://other.example.org/", `${ORIGIN}/`] }],
  });
  const reply = /** @type {any} */ (await probe.ops.offers_peek.run({}, { tab_id: TAB, session }));
  assert.equal(reply.available, true);
  assert.equal(reply.offers.length, 1);
  const [offer] = reply.offers;
  assert.deepEqual({ ...offer, offer_id: undefined }, {
    offer_id: undefined,
    kind: "signup",
    generated: false,
    type: "update",
    origin: ORIGIN,
    username: SENTINEL_USER,
    username_from: "typed",
    password_sha256: createHash("sha256").update(SENTINEL_PASSWORD).digest("hex"),
    reuse: true,
    target_name: "Login item",
    target_host: "login.example.net",
    target_match: "host",
  });
  assert.equal(JSON.stringify(reply).includes(SENTINEL_PASSWORD), false);
  assert.deepEqual(asked, [["offer_classify", { session, offer_id: offer.offer_id }]]);
  // Without the write path (locked), the offer is still shown, unclassified. Without the store there is nothing to read.
  const locked = createOfferProbe({ offers: w.offers, call: async () => Promise.reject(new Error("vault_locked")) });
  assert.equal(/** @type {any} */ (await locked.ops.offers_peek.run({}, { tab_id: TAB, session })).offers[0].type, "unclassified");
  assert.deepEqual(await createOfferProbe().ops.offers_peek.run({}, { tab_id: TAB, session }), { available: false, offers: [] });
  await assert.rejects(probe.ops.offers_peek.run({}, { tab_id: -1, session }), { code: "invalid_input" });
  await assert.rejects(probe.ops.offers_peek.run({}, { tab_id: TAB, session: "x" }), { code: "invalid_input" });
});
