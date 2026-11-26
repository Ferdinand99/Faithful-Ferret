// The request broker of Ferret as a passkey provider (background/passkeyRequests.mjs): who gets Ferret and who the browser,
// one modal request per tab and one window, the marks, deadlines, the page's abort, navigation, locks, the calm period, the
// automatic hand-over, and the chooser window's operations and handler.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  PASSKEY_SILENT_MS, automaticHandover, createPasskeyRequests, httpsOrigin, isLoopbackHost, malformedOptions, modalTimeout, pageErrorOf, refusedRpId,
  unsupportedOptions,
  PASSKEY_ERROR_DELAY_MS, PASSKEY_EVENT_OP, PASSKEY_GUARD_MS, PASSKEY_PASS_ONCE_MS, PASSKEY_QUIET, PASSKEY_TIMEOUT_MS, PASSKEY_WINDOW_OPS,
} from "../../src/background/passkeyRequests.mjs";
import { CORE_OPS } from "../../src/background/coreHost.mjs";
import { LOCK_EXEMPT } from "../../src/background/lock.mjs";
import { contentSender, withBrowserOrigin } from "../../src/shared/origin.mjs";
import { decode, PASSKEY_REQUEST_VIEW, PUSH_TYPES, UI_TYPES } from "../../src/shared/protocol.mjs";
import { validate } from "../../src/shared/schema.mjs";
import { build } from "../../scripts/build.mjs";
import { makeRoot } from "./buildHelpers.mjs";

const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
const RP = "https://rp-a.test";
const SERVER = "https://vault.example";

/** A few turns of the event loop: the broker's awaits on its fakes settle. */
const flush = async () => {
  for (let i = 0; i < 4; i += 1) await new Promise((r) => setImmediate(r));
};

/** A fake clock and timers that run when told to. */
function clockAndTimers() {
  let at = 1_000_000;
  /** @type {Map<number, { fn: () => void, at: number, ms: number }>} */
  const pending = new Map();
  let next = 1;
  return {
    now: () => at,
    /** @param {number} ms */
    advance(ms) {
      at += ms;
      for (const [id, t] of [...pending]) {
        if (t.at <= at) {
          pending.delete(id);
          t.fn();
        }
      }
    },
    pending: () => [...pending].map(([id, t]) => ({ id, ...t })),
    timers: {
      setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => {
        const id = next++;
        pending.set(id, { fn, at: at + ms, ms });
        return id;
      },
      clearTimeout: (/** @type {number} */ id) => void pending.delete(id),
    },
  };
}

/** The frames of a tab as webNavigation lists them: the top only, by default. */
const topOnly = (url = `${RP}/login`, documentId = "doc-1") => [{ frameId: 0, parentFrameId: -1, url, documentId }];

/**
 * A broker with fakes for everything it reaches.
 * @param {Record<string, any>} [over]
 */
function world(over = {}) {
  const clock = clockAndTimers();
  /** @type {Array<{ tabId: number, type: string, body: any, options: any }>} */
  const pushed = [];
  /** @type {Map<number, any[]>} */
  const tabFrames = new Map([[4, topOnly()], [7, topOnly(`${RP}/other`, "doc-7")]]);
  const opened = /** @type {string[]} */ ([]);
  const closed = /** @type {number[]} */ ([]);
  /** @type {Map<number, boolean>} */
  const marks = new Map();
  const state = { on: true, permission: true, server: /** @type {any} */ ({ origin: SERVER, live: true }), listening: 0, starts: 0 };
  let counter = 0;
  const requests = createPasskeyRequests({
    tabs: {
      sendMessage: async (tabId, raw) => {
        const { type, body } = decode(raw, PUSH_TYPES);
        pushed.push({ tabId, type, body, options: null });
      },
    },
    frames: { getAllFrames: async ({ tabId }) => tabFrames.get(tabId) ?? [] },
    windows: {
      open: async (id) => {
        opened.push(id);
        return 100 + opened.length;
      },
      close: async (windowId) => void closed.push(windowId),
    },
    badge: { passkey: (tabId, on) => void marks.set(tabId, on) },
    servers: { current: async () => state.server },
    storageLocal: { get: async () => ({ use_passkeys: state.on }) },
    permissions: { contains: async () => state.permission },
    listen: {
      start: () => {
        state.listening += 1;
        state.starts += 1;
      },
      stop: () => void (state.listening -= 1),
    },
    release: true,
    now: clock.now,
    // The monotonic clock moves with the fake one (a test of a clock jump passes its own).
    monotonic: clock.now,
    timers: clock.timers,
    random: (bytes) => {
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = (counter + i * 7) & 0xff;
      counter += 1;
      return bytes;
    },
    ...over,
  });
  // Every push goes through tabs.sendMessage with the binding; keep the options too.
  return { requests, clock, pushed, tabFrames, opened, closed, marks, state };
}

/** @param {Partial<{ tabId: number, frameId: number, documentId: string, url: string, origin: string }>} [o] */
const senderOf = (o = {}) => ({ tabId: 4, frameId: 0, documentId: "doc-1", url: `${RP}/login`, origin: RP, ...o });

const CHALLENGE = "Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2UtMzI";
/** @param {Record<string, any>} [o] */
const createOptions = (o = {}) => ({
  challenge: CHALLENGE,
  rp: { name: "RP A" },
  user: { id: "AQIDBA", name: "alice", display_name: "Alice" },
  pub_key_cred_params: [{ type: "public-key", alg: -7 }],
  exclude_credentials: [],
  hints: [],
  extensions: {},
  ...o,
});
/** @param {Record<string, any>} [o] */
const getOptions = (o = {}) => ({ challenge: CHALLENGE, allow_credentials: [], hints: [], extensions: {}, ...o });
/** @param {string} id @param {Record<string, any>} [o] */
const createBody = (id, o = {}) => ({ request_id: id, kind: "create", mediation: "optional", create: createOptions(o.options), activation: true, policy: true, ...o.body });
/** @param {string} id @param {Record<string, any>} [o] */
const getBody = (id, o = {}) => ({ request_id: id, kind: "get", mediation: "optional", get: getOptions(o.options), activation: true, policy: true, ...o.body });

const RESPONSE = {
  id: "AAAA",
  client_data_json: "e30",
  authenticator_data: "AAAA",
  authenticator_attachment: "platform",
  signature: "AAAA",
  user_handle: "AQIDBA",
  client_extension_results: {},
};

/** The pushes of one bridge id. @param {any[]} pushed @param {string} id */
const pushesOf = (pushed, id) => pushed.filter((p) => p.body.request_id === id);

// ------------------------------------------------------------------------------------------------------------- origin

test("the_origin_comes_from_the_sender_and_web_navigation_only", async () => {
  const w = world();
  const taken = await w.requests.open(senderOf(), createBody("r1"));
  assert.ok("request_id" in taken, JSON.stringify(taken));
  const id = /** @type {any} */ (taken).request_id;
  // The view and the caller the core gets carry the browser's origin of the frame, nothing of the page.
  assert.equal(w.requests.forUi(id, "s1")?.origin, RP);
  assert.deepEqual({ ...w.requests.callerOf(id, "s1") }, { origin: RP, top_origin_is_same: true });
  assert.equal(w.requests.callerOf(id, "another session"), null, "only the window that owns the request");

  // No origin from the browser, one that is not the origin of the frame's address, or no document: the browser answers.
  for (const [sender, why] of /** @type {const} */ ([
    [senderOf({ origin: undefined }), "origin"],
    [senderOf({ origin: "https://rp-b.test" }), "origin"],
    [senderOf({ url: "https://rp-b.test/", origin: RP }), "origin"],
  ])) {
    const out = await w.requests.open(sender, createBody(`x-${why}-${w.pushed.length}`));
    assert.equal(/** @type {any} */ (out).reason, why);
  }
  const before = w.pushed.length;
  assert.deepEqual(await w.requests.open({ ...senderOf(), documentId: undefined }, createBody("nodoc")), { error: "no_document" });
  assert.equal(w.pushed.length, before, "nothing can be sent to a sender without a document");

  // webNavigation decides the frame: a frame whose address the browser now lists with another origin is not answered.
  w.tabFrames.set(7, topOnly("https://rp-b.test/", "doc-7"));
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/x` }), getBody("r7"))).reason, "frames");
  // Another document in the frame than the sender's: refused too.
  w.tabFrames.set(7, topOnly(`${RP}/x`, "doc-other"));
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/x` }), getBody("r8"))).reason, "frames");

  // The router passes on the browser's origin, never one from the message, and refuses an opaque one.
  const runtime = { id: "ferret@x", getURL: (/** @type {string} */ p) => `moz-extension://u/${p}` };
  const browserSender = { id: "ferret@x", tab: { id: 4, incognito: true }, frameId: 0, documentId: "d", url: `${RP}/`, origin: RP };
  const from = contentSender(browserSender, runtime);
  assert.deepEqual(withBrowserOrigin(/** @type {any} */ (from), browserSender), { tabId: 4, frameId: 0, documentId: "d", url: `${RP}/`, origin: RP, incognito: true });
  assert.equal(withBrowserOrigin(/** @type {any} */ (from), { ...browserSender, origin: "null" }).origin, undefined);
  const router = readFileSync(join(src, "background", "router.mjs"), "utf8");
  assert.match(router, /call\(PASSKEY_OP, \{ type: message\.type, sender: withBrowserOrigin\(from, sender\), body \}\)/);
  assert.equal(contentSender({ id: "ferret@x", tab: { id: 4 }, frameId: 0, url: `${RP}/`, origin: "null" }, runtime), null);

  // Architecture: the caller for the core is built in the broker only, and the broker reads no origin, top or frame from a
  // message body.
  /** @type {string[]} */
  const builders = [];
  const walk = (/** @type {string} */ dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (/\.(?:mjs|html)$/.test(entry.name) && readFileSync(path, "utf8").includes("top_origin_is_same")) builders.push(path.slice(src.length + 1).split("\\").join("/"));
    }
  };
  walk(src);
  assert.deepEqual(builders, ["background/passkeyRequests.mjs"]);
  const broker = readFileSync(join(src, "background", "passkeyRequests.mjs"), "utf8");
  assert.doesNotMatch(broker, /body(?:\?\.|\.)(?:origin|top|frame|url)\b/);
  assert.doesNotMatch(broker, /options(?:\?\.|\.)(?:origin|top)\b/);
  assert.match(broker, /origin: req\.origin, top_origin_is_same: true/);
});

test("a_same_origin_frame_under_a_cross_origin_ancestor_goes_to_the_browser", async () => {
  const w = world();
  // rp-a.test → rp-b.test → rp-a.test: the inner frame has the top's origin, but a foreign frame sits between.
  w.tabFrames.set(4, [
    { frameId: 0, parentFrameId: -1, url: `${RP}/`, documentId: "doc-1" },
    { frameId: 5, parentFrameId: 0, url: "https://rp-b.test/frame", documentId: "doc-5" },
    { frameId: 9, parentFrameId: 5, url: `${RP}/inner`, documentId: "doc-9" },
    { frameId: 11, parentFrameId: 0, url: `${RP}/same`, documentId: "doc-11" },
  ]);
  const nested = await w.requests.open(senderOf({ frameId: 9, documentId: "doc-9", url: `${RP}/inner` }), getBody("n1"));
  assert.equal(/** @type {any} */ (nested).reason, "frames");
  assert.deepEqual(pushesOf(w.pushed, "n1").map((p) => [p.type, p.body.once]), [["passkey_handover", false]]);
  // A frame of another origin than the top never gets Ferret either (its own origin is not the top's).
  const foreignFrame = await w.requests.open(senderOf({ frameId: 5, documentId: "doc-5", url: "https://rp-b.test/frame", origin: "https://rp-b.test" }), getBody("n2"));
  assert.equal(/** @type {any} */ (foreignFrame).reason, "frames");
  // A frame of the top's origin right under the top is taken.
  const same = await w.requests.open(senderOf({ frameId: 11, documentId: "doc-11", url: `${RP}/same` }), getBody("n3"));
  assert.ok("request_id" in same);
  // A chain the browser does not list whole (a missing parent, a frame listed twice) goes to the browser.
  w.tabFrames.set(7, [{ frameId: 3, parentFrameId: 2, url: `${RP}/x`, documentId: "doc-3" }, { frameId: 0, parentFrameId: -1, url: `${RP}/`, documentId: "doc-7" }]);
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, frameId: 3, documentId: "doc-3", url: `${RP}/x` }), getBody("n4"))).reason, "frames");
  w.tabFrames.set(7, [...topOnly(`${RP}/`, "doc-7"), ...topOnly(`${RP}/`, "doc-7")]);
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7" }), getBody("n5"))).reason, "frames");
});

test("an_opaque_about_blank_srcdoc_or_data_frame_goes_to_the_browser", async () => {
  const w = world();
  const cases = [
    // The browser says the frame's origin is opaque (a sandboxed frame), or the frame's address is not https.
    { sender: senderOf({ frameId: 2, documentId: "d2", origin: "null" }), frames: [{ frameId: 2, parentFrameId: 0, url: `${RP}/sandboxed`, documentId: "d2" }] },
    { sender: senderOf({ frameId: 2, documentId: "d2", url: "about:blank" }), frames: [{ frameId: 2, parentFrameId: 0, url: "about:blank", documentId: "d2" }] },
    { sender: senderOf({ frameId: 2, documentId: "d2", url: "about:srcdoc" }), frames: [{ frameId: 2, parentFrameId: 0, url: "about:srcdoc", documentId: "d2" }] },
    { sender: senderOf({ frameId: 2, documentId: "d2", url: "data:text/html,x" }), frames: [{ frameId: 2, parentFrameId: 0, url: "data:text/html,x", documentId: "d2" }] },
    // A frame of the top's origin below an about:blank, srcdoc, data: or blob: frame.
    ...["about:blank", "about:srcdoc", "data:text/html,x", `blob:${RP}/0b6c`].map((middle) => ({
      sender: senderOf({ frameId: 3, documentId: "d3", url: `${RP}/inner` }),
      frames: [
        { frameId: 2, parentFrameId: 0, url: middle, documentId: "d2" },
        { frameId: 3, parentFrameId: 2, url: `${RP}/inner`, documentId: "d3" },
      ],
    })),
  ];
  let n = 0;
  for (const c of cases) {
    w.tabFrames.set(4, [...topOnly(`${RP}/`), ...c.frames]);
    const out = await w.requests.open(c.sender, getBody(`o${(n += 1)}`));
    assert.ok("handover" in out, `${JSON.stringify(c.frames)} ${JSON.stringify(out)}`);
  }
  assert.equal(w.opened.length, 0);
  assert.equal(httpsOrigin("about:blank"), null);
  assert.equal(httpsOrigin("data:text/html,x"), null);
  assert.equal(httpsOrigin(`blob:${RP}/x`), null);
  assert.equal(httpsOrigin(`${RP}:443/a`), RP);
});

test("a_ferret_server_origin_is_refused_in_the_background", async () => {
  // The signed-in server's host, on any port: the browser answers (the registration's filter has no port and lags).
  const w = world();
  w.state.server = { origin: "https://rp-a.test:8443", live: true };
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("f1"))).reason, "ferret_server");
  // Signed out, a device ended remotely (its server is still stored), the setting off, the permission gone: the browser.
  w.state.server = null;
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("f2"))).reason, "signed_out");
  w.state.server = { origin: SERVER, live: false };
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("f3"))).reason, "signed_out");
  w.state.server = { origin: SERVER, live: true };
  w.state.on = false;
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("f4"))).reason, "off");
  w.state.on = true;
  w.state.permission = false;
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("f5"))).reason, "off");
  w.state.permission = true;
  // The page's own policy, and a trailing dot (Firefox keeps it in the RP ID; the core would not).
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("f6", { body: { policy: false } }))).reason, "policy");
  w.tabFrames.set(7, topOnly("https://rp-a.test./", "doc-7"));
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: "https://rp-a.test./", origin: "https://rp-a.test." }), getBody("f7"))).reason, "trailing_dot");
  // Every one of them went to the browser at once.
  for (const id of ["f1", "f2", "f3", "f4", "f5", "f6", "f7"]) assert.deepEqual(pushesOf(w.pushed, id).map((p) => p.type), ["passkey_handover"], id);

  // A release leaves localhost and loopback to the browser; the test variant keeps https://localhost for its fixtures.
  for (const host of ["localhost", "a.localhost", "127.0.0.1", "127.8.9.10", "[::1]"]) {
    const origin = `https://${host}`;
    w.tabFrames.set(9, topOnly(`${origin}/`, "doc-9"));
    const out = await w.requests.open(senderOf({ tabId: 9, documentId: "doc-9", url: `${origin}/`, origin }), getBody(`l-${host.replace(/[^a-z0-9]/g, "")}`));
    assert.equal(/** @type {any} */ (out).reason, "loopback", host);
  }
  assert.equal(isLoopbackHost("[::ffff:7f00:1]"), true);
  assert.equal(isLoopbackHost("localhost.example"), false);
  const t = world({ release: false });
  t.tabFrames.set(9, topOnly("https://localhost/", "doc-9"));
  assert.ok("request_id" in (await t.requests.open(senderOf({ tabId: 9, documentId: "doc-9", url: "https://localhost/", origin: "https://localhost" }), getBody("l2"))));
  // The "never on this site" list (the RP ID the page names, or its host).
  const n = world({ never: { has: async (/** @type {string} */ host) => host === "rp-a.test" } });
  assert.equal(/** @type {any} */ (await n.requests.open(senderOf(), getBody("v1"))).reason, "never");
});

// ------------------------------------------------------------------------------------------------- tabs and windows

test("one_modal_request_per_tab_and_one_window", async () => {
  const w = world();
  const first = await w.requests.open(senderOf(), createBody("m1"));
  assert.ok("request_id" in first);
  assert.equal(w.opened.length, 1);
  assert.equal(w.opened[0], /** @type {any} */ (first).request_id, "the window names the background's own id, not the bridge's");
  assert.match(w.opened[0], /^[0-9a-f]{32}$/);
  // A second modal request from the same tab (also another frame of it) ends at once with AbortError; the first stays.
  w.tabFrames.set(4, [...topOnly(), { frameId: 6, parentFrameId: 0, url: `${RP}/f`, documentId: "doc-6" }]);
  assert.deepEqual(await w.requests.open(senderOf(), getBody("m2")), { error: "AbortError" });
  assert.deepEqual(await w.requests.open(senderOf({ frameId: 6, documentId: "doc-6", url: `${RP}/f` }), getBody("m3")), { error: "AbortError" });
  assert.deepEqual(pushesOf(w.pushed, "m2").map((p) => [p.type, p.body.name]), [["passkey_error", "AbortError"]]);
  assert.equal(w.requests.size(), 1);
  assert.equal(w.opened.length, 1, "never a second window");
  assert.ok(w.requests.forUi(/** @type {any} */ (first).request_id, "s1"));
  // A flood: still one window, AbortError for the rest.
  for (let i = 0; i < 40; i += 1) await w.requests.open(senderOf(), getBody(`fl${i}`));
  assert.equal(w.opened.length, 1);
  assert.equal(w.requests.size(), 1);
});

test("a_request_from_another_tab_waits_with_a_badge_and_never_replaces_the_open_one", async () => {
  const w = world();
  const a = /** @type {any} */ (await w.requests.open(senderOf(), createBody("a1"))).request_id;
  const b = /** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), getBody("b1"))).request_id;
  assert.equal(w.opened.length, 1, "the window stays with the first request");
  assert.equal(w.marks.get(7), true, "the other tab gets the mark");
  assert.equal(w.marks.get(4), false, "the tab whose request has the window has none");
  assert.equal(w.requests.waitingFor(7)?.request_id, b, "the popup's card");
  assert.equal(w.requests.forUi(a, "win")?.request_id, a);
  // When the first ends, the second keeps waiting (no window opens by itself); the card's click opens it.
  assert.equal(w.requests.cancel(a, "another window"), false, "only the window that owns it");
  assert.equal(w.requests.cancel(a, "win"), true);
  assert.equal(w.closed.length, 1);
  assert.equal(w.opened.length, 1);
  assert.equal(w.requests.waitingFor(7)?.request_id, b);
  assert.equal(await w.requests.show(4), false, "nothing waits in that tab");
  assert.equal(await w.requests.show(7), true);
  assert.deepEqual(w.opened.slice(1), [b]);
  assert.equal(w.marks.get(7), false);
});

test("a_modal_request_replaces_a_pending_conditional_one", async () => {
  const w = world();
  const c = /** @type {any} */ (await w.requests.open(senderOf(), getBody("c1", { body: { mediation: "conditional" } }))).request_id;
  assert.equal(w.opened.length, 0, "a conditional request opens no window");
  assert.equal(w.marks.get(4), true);
  assert.equal(w.requests.conditionalFor(4)?.request_id, c);
  // A new conditional one replaces it (AbortError for the old), and a modal one of the same document ends it.
  const c2 = /** @type {any} */ (await w.requests.open(senderOf(), getBody("c2", { body: { mediation: "conditional" } }))).request_id;
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "c1").map((p) => p.body.name), ["AbortError"]);
  const m = /** @type {any} */ (await w.requests.open(senderOf(), getBody("m1"))).request_id;
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "c2").map((p) => p.body.name), ["AbortError"]);
  assert.equal(w.requests.conditionalFor(4), null);
  assert.equal(w.requests.forUi(m, "s")?.mediation, "optional");
  assert.equal(w.opened.length, 1);
  assert.notEqual(c2, m);
  // A conditional request of another document of the tab stays beside a modal one.
  const x = world();
  x.tabFrames.set(4, [...topOnly(), { frameId: 6, parentFrameId: 0, url: `${RP}/f`, documentId: "doc-6" }]);
  await x.requests.open(senderOf({ frameId: 6, documentId: "doc-6", url: `${RP}/f` }), getBody("k1", { body: { mediation: "conditional" } }));
  await x.requests.open(senderOf(), getBody("k2"));
  assert.equal(x.requests.size(), 2);
});

test("a_conditional_request_has_no_timeout", async () => {
  const w = world();
  const c = /** @type {any} */ (await w.requests.open(senderOf(), getBody("c1", { body: { mediation: "conditional" }, options: { timeout: 1000 } }))).request_id;
  // Only the watch on the bridge's pings, no deadline.
  assert.deepEqual(w.clock.pending().map((t) => t.ms), [PASSKEY_SILENT_MS], "no deadline timer");
  // Past the longest deadline of a modal request, while its bridge pings.
  for (let i = 0; i < 33; i += 1) {
    w.clock.advance(20_000);
    await w.requests.onEvent({ type: "passkey_ping", sender: senderOf(), body: { request_ids: ["c1"] } });
  }
  assert.equal(w.requests.conditionalFor(4)?.request_id, c);
  assert.equal(w.requests.conditionalFor(4)?.expires_in, null);
  assert.equal(w.pushed.length, 0);
});

test("a_new_document_cancels_and_push_state_rechecks_the_origin", async () => {
  const w = world();
  const a = /** @type {any} */ (await w.requests.open(senderOf(), createBody("a1"))).request_id;
  assert.equal(w.state.listening, 1, "the navigation listeners run while a request waits");
  // pushState within the same origin: the request stays.
  w.requests.onSameDocument({ tabId: 4, frameId: 0, url: `${RP}/login/step-2` });
  assert.ok(w.requests.forUi(a, "s"));
  // A new document in its frame ends it (nobody to answer) and closes the window.
  w.requests.onNavigation({ tabId: 4, frameId: 0, documentId: "doc-2" });
  assert.equal(w.requests.forUi(a, "s"), null);
  assert.deepEqual(w.closed, [101]);
  assert.equal(w.state.listening, 0, "and stop when none does");
  // A same-document navigation that would change the origin ends it with NotAllowedError.
  const b = /** @type {any} */ (await w.requests.open(senderOf(), createBody("b1"))).request_id;
  w.requests.onSameDocument({ tabId: 4, frameId: 0, url: "https://rp-b.test/" });
  w.clock.advance(1000);
  await flush();
  assert.equal(w.requests.forUi(b, "s"), null);
  assert.deepEqual(pushesOf(w.pushed, "b1").map((p) => p.body.name), ["NotAllowedError"]);
  // A frame's request ends when the top gets a new document, and is checked again when another frame does.
  w.tabFrames.set(4, [...topOnly(), { frameId: 6, parentFrameId: 0, url: `${RP}/f`, documentId: "doc-6" }]);
  const f = /** @type {any} */ (await w.requests.open(senderOf({ frameId: 6, documentId: "doc-6", url: `${RP}/f` }), getBody("f1"))).request_id;
  w.tabFrames.set(4, [...topOnly(), { frameId: 6, parentFrameId: 0, url: `${RP}/f`, documentId: "doc-6b" }]);
  w.requests.onNavigation({ tabId: 4, frameId: 8, documentId: "doc-8" });
  await flush();
  assert.equal(w.requests.forUi(f, "s"), null, "its frame holds another document now");
  // The tab closing ends what waits in it.
  const g = /** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), getBody("g1"))).request_id;
  w.requests.onTabRemoved(7);
  assert.equal(w.requests.forUi(g, "s"), null);
});

test("the_answer_goes_only_to_the_bound_frame_and_document", async () => {
  /** @type {any[]} */
  const sent = [];
  const w = world({ tabs: { sendMessage: async (/** @type {number} */ tabId, /** @type {string} */ raw, /** @type {any} */ options) => void sent.push({ tabId, options, ...decode(raw, PUSH_TYPES) }) } });
  w.tabFrames.set(4, [...topOnly(), { frameId: 17179869185, parentFrameId: 0, url: `${RP}/f`, documentId: "doc-f" }]);
  const sender = senderOf({ frameId: 17179869185, documentId: "doc-f", url: `${RP}/f` });
  const id = /** @type {any} */ (await w.requests.open(sender, getBody("g1"))).request_id;
  assert.equal(await w.requests.answer(id, "s", RESPONSE), true);
  assert.deepEqual(sent.map((s) => [s.tabId, s.options, s.type, s.body.request_id]), [[4, { frameId: 17179869185, documentId: "doc-f" }, "passkey_result", "g1"]]);
  assert.equal(await w.requests.answer(id, "s", RESPONSE), false, "once");
  // A frame that holds another document by the time of the answer gets no result.
  const id2 = /** @type {any} */ (await w.requests.open(sender, getBody("g2"))).request_id;
  w.tabFrames.set(4, [...topOnly(), { frameId: 17179869185, parentFrameId: 0, url: `${RP}/f`, documentId: "doc-g" }]);
  assert.equal(await w.requests.answer(id2, "s", RESPONSE), false);
  w.clock.advance(1000);
  await flush();
  assert.deepEqual(sent.filter((s) => s.body.request_id === "g2").map((s) => s.type), ["passkey_error"]);
  assert.ok(sent.every((s) => s.options.documentId === "doc-f" && s.options.frameId === 17179869185));
});

test("no_window_without_user_activation_only_the_badge_and_a_card", async () => {
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), createBody("n1", { body: { activation: false } }))).request_id;
  assert.equal(w.opened.length, 0);
  assert.equal(w.marks.get(4), true);
  assert.equal(w.requests.waitingFor(4)?.request_id, id);
  assert.equal(w.requests.waitingFor(4)?.kind, "create");
  // The popup's card: its click is the user's activation and opens the window.
  assert.equal(await w.requests.show(4), true);
  assert.deepEqual(w.opened, [id]);
  assert.equal(w.marks.get(4), false);
  assert.equal(await w.requests.show(4), false, "only once");
});

test("the_quiet_period_gives_badge_only_and_keeps_the_request", async () => {
  const w = world();
  for (let i = 0; i < PASSKEY_QUIET.cancels; i += 1) {
    const id = /** @type {any} */ (await w.requests.open(senderOf(), createBody(`q${i}`))).request_id;
    w.clock.advance(1000);
    assert.equal(w.requests.cancel(id, "s"), true);
  }
  assert.equal(w.opened.length, PASSKEY_QUIET.cancels);
  const kept = /** @type {any} */ (await w.requests.open(senderOf(), createBody("q-next")));
  assert.ok("request_id" in kept, "kept, not refused");
  assert.equal(w.opened.length, PASSKEY_QUIET.cancels, "no window during the calm period");
  assert.equal(w.marks.get(4), true);
  assert.equal(w.requests.waitingFor(4)?.request_id, kept.request_id);
  // Another tab is not calm.
  await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), createBody("o1"));
  assert.equal(w.opened.length, PASSKEY_QUIET.cancels + 1);
  // After the period a new request opens the window again.
  w.requests.onTabRemoved(7);
  w.requests.handover(kept.request_id, "s", { once: false });
  w.clock.advance(PASSKEY_QUIET.quietMs);
  await w.requests.open(senderOf(), createBody("q-after"));
  assert.equal(w.opened.length, PASSKEY_QUIET.cancels + 2);
  // Cancels spread wider than the window start nothing.
  const s = world();
  for (let i = 0; i < 5; i += 1) {
    const id = /** @type {any} */ (await s.requests.open(senderOf(), createBody(`s${i}`))).request_id;
    s.clock.advance(PASSKEY_QUIET.windowMs);
    s.requests.cancel(id, "s");
  }
  assert.equal(s.opened.length, 5);
  assert.deepEqual({ ...PASSKEY_QUIET }, { cancels: 3, windowMs: 60_000, quietMs: 300_000 });
});

test("modal_timeouts_are_clamped", async () => {
  assert.deepEqual({ ...PASSKEY_TIMEOUT_MS }, { min: 30_000, max: 600_000, default: 300_000 });
  assert.equal(modalTimeout(undefined), 300_000);
  assert.equal(modalTimeout(0), 30_000);
  assert.equal(modalTimeout(1), 30_000);
  assert.equal(modalTimeout(120_000), 120_000);
  assert.equal(modalTimeout(4_294_967_295), 600_000);
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("t1", { options: { timeout: 5 } }))).request_id;
  assert.deepEqual(w.clock.pending().map((t) => t.ms), [30_000, PASSKEY_SILENT_MS], "the deadline, then the watch on the pings");
  assert.equal(w.requests.forUi(id, "s")?.expires_in, 30_000);
  w.clock.advance(29_999);
  assert.ok(w.requests.forUi(id, "s"));
  w.clock.advance(1);
  assert.equal(w.requests.forUi(id, "s"), null);
  assert.deepEqual(w.closed, [101]);
  w.clock.advance(PASSKEY_ERROR_DELAY_MS.min + PASSKEY_ERROR_DELAY_MS.spread);
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "t1").map((p) => p.body.name), ["NotAllowedError"]);
  // The clock decides even when the timer comes late.
  const v = world();
  const late = /** @type {any} */ (await v.requests.open(senderOf(), getBody("t2", { options: { timeout: 10_000_000 } }))).request_id;
  assert.deepEqual(v.clock.pending().map((t) => t.ms), [600_000, PASSKEY_SILENT_MS]);
  // Both timers are late (neither has run): the clock alone ends it, by its deadline.
  for (const { id } of v.clock.pending()) v.clock.timers.clearTimeout(id);
  v.clock.advance(600_000);
  assert.equal(v.requests.forUi(late, "s"), null);
  v.clock.advance(PASSKEY_ERROR_DELAY_MS.min + PASSKEY_ERROR_DELAY_MS.spread);
  await flush();
  assert.deepEqual(pushesOf(v.pushed, "t2").map((p) => p.body.name), ["NotAllowedError"]);
});

test("the_page_abort_closes_the_window_with_abort_error", async () => {
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), createBody("a1"))).request_id;
  // Another document's abort of the same bridge id does nothing.
  await w.requests.onEvent({ type: "passkey_abort", sender: senderOf({ documentId: "doc-x" }), body: { request_id: "a1" } });
  assert.ok(w.requests.forUi(id, "s"));
  await w.requests.onEvent({ type: "passkey_abort", sender: senderOf(), body: { request_id: "a1" } });
  await flush();
  assert.equal(w.requests.forUi(id, "s"), null);
  assert.deepEqual(w.closed, [101]);
  assert.deepEqual(pushesOf(w.pushed, "a1").map((p) => [p.type, p.body.name]), [["passkey_error", "AbortError"]]);
  // An abort that comes before its request: the request is dropped when it comes (no window, no mark).
  await w.requests.onEvent({ type: "passkey_abort", sender: senderOf(), body: { request_id: "a2" } });
  assert.deepEqual(await w.requests.open(senderOf(), createBody("a2")), { error: "AbortError" });
  assert.equal(w.opened.length, 1);
  assert.equal(w.requests.size(), 0);
});

test("cancelled_and_no_match_look_the_same_in_type_and_time", async () => {
  // The same random draws in three worlds: a cancel of a request with candidates, one without (no match: the user cancels
  // or closes the window the same way), and an expired one. The page sees the same error after the same delay.
  /** @type {Array<{ name: string, delay: number }>} */
  const seen = [];
  for (const how of ["cancel", "no_match_window_closed", "expired"]) {
    const w = world();
    const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("p1", { options: how === "no_match_window_closed" ? {} : { allow_credentials: [{ type: "public-key", id: "AAAA" }] } }))).request_id;
    if (how === "cancel") w.requests.cancel(id, "s");
    else if (how === "no_match_window_closed") w.requests.onWindowRemoved(101);
    else w.clock.advance(PASSKEY_TIMEOUT_MS.default);
    // The one timer left is the error's (the deadline's went with the request).
    const errorTimer = w.clock.pending().find((t) => t.ms < PASSKEY_TIMEOUT_MS.min);
    assert.ok(errorTimer, how);
    assert.equal(w.pushed.length, 0, "nothing at once");
    w.clock.advance(errorTimer.ms);
    await flush();
    const [push] = pushesOf(w.pushed, "p1");
    seen.push({ name: push.body.name, delay: errorTimer.ms });
  }
  assert.ok(seen.every((s) => s.name === "NotAllowedError"));
  assert.ok(seen.every((s) => s.delay >= PASSKEY_ERROR_DELAY_MS.min && s.delay < PASSKEY_ERROR_DELAY_MS.min + PASSKEY_ERROR_DELAY_MS.spread));
  // The delay is drawn the same way whatever the cause (same draws, same delay).
  assert.equal(new Set(seen.map((s) => s.delay)).size, 1, JSON.stringify(seen));
});

test("a_lock_of_the_open_vault_or_a_server_change_ends_requests_and_every_lock_drops_verify_marks", async () => {
  const w = world();
  const m = /** @type {any} */ (await w.requests.open(senderOf(), createBody("m1"))).request_id;
  const c = /** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), getBody("c1", { body: { mediation: "conditional" } }))).request_id;
  assert.equal(w.requests.markVerified(m, "win"), true);
  // A lock of a vault that was locked already (a wrong PIN in the window) drops the marks and ends nothing.
  w.requests.onLock(false);
  assert.equal(w.requests.takeVerified(m, "win"), false);
  assert.equal(w.requests.size(), 2);
  assert.equal(w.requests.markVerified(m, "win"), true);
  w.requests.onLock();
  assert.equal(w.requests.takeVerified(m, "win"), false, "the mark is gone");
  assert.equal(w.requests.size(), 0);
  assert.deepEqual(w.closed, [101]);
  w.clock.advance(1000);
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "m1").map((p) => p.body.name), ["NotAllowedError"]);
  assert.deepEqual(pushesOf(w.pushed, "c1").map((p) => p.body.name), ["NotAllowedError"]);
  assert.equal(w.requests.conditionalFor(7), null);
  assert.equal(w.requests.forUi(c, "x"), null);
  // A mark is good once, and only for the session that owns the request.
  const n = /** @type {any} */ (await w.requests.open(senderOf(), createBody("n1"))).request_id;
  assert.equal(w.requests.markVerified(n, "win"), true);
  assert.equal(w.requests.markVerified(n, "other"), false);
  assert.equal(w.requests.takeVerified(n, "other"), false, "only for the session that has it");
  assert.equal(w.requests.takeVerified(n, "win"), true);
  assert.equal(w.requests.takeVerified(n, "win"), false);
  // A sign-in or "forget this server", also while the vault is locked, ends every request (they were checked against the
  // server that was there).
  await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), getBody("c2", { body: { mediation: "conditional" } }));
  assert.equal(w.requests.size(), 2);
  w.requests.endAll();
  assert.equal(w.requests.size(), 0);
  assert.match(readFileSync(join(src, "background", "main.mjs"), "utf8"), /sessionHost\.onServerChange\(\(\) => \{[\s\S]{0,300}passkeyRequests\?\.endAll\(\)/);
  // The entry wires the lock of the open vault to the broker.
  const main = readFileSync(join(src, "background", "main.mjs"), "utf8");
  assert.match(main, /coreHost\.onLocked\(\(\) => \{[\s\S]{0,200}passkeyRequests\.onLock\(wasOpen\)/);
  assert.match(main, /coreHost\.onUnlocked\(\(\) => \{\s*vaultOpen = true;/);
});

// ---------------------------------------------------------------------------------------------- automatic hand-over

test("automatic_handover_cases_follow_the_request_properties", async () => {
  const cases = /** @type {Array<[string, "create" | "get", Record<string, any>, string | null, string?]>} */ ([
    ["only RS256", "create", { pub_key_cred_params: [{ type: "public-key", alg: -257 }] }, "algorithms"],
    ["only EdDSA", "create", { pub_key_cred_params: [{ type: "public-key", alg: -8 }] }, "algorithms"],
    ["ES256 of another type", "create", { pub_key_cred_params: [{ type: "other", alg: -7 }] }, "algorithms"],
    ["ES256 and RS256", "create", { pub_key_cred_params: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }] }, null],
    ["appid", "get", { extensions: { appid: "https://rp-a.test/app" } }, "appid"],
    ["appidExclude", "create", { extensions: { appid_exclude: "https://rp-a.test/app" } }, "appid"],
    ["enterprise attestation", "create", { attestation: "enterprise" }, "enterprise"],
    ["direct attestation (answered with none)", "create", { attestation: "direct" }, null],
    ["indirect attestation", "create", { attestation: "indirect" }, null],
    ["cross-platform, security key", "create", { authenticator_selection: { authenticator_attachment: "cross-platform" }, hints: ["security-key"] }, "security_key"],
    ["cross-platform, phone and key", "create", { authenticator_selection: { authenticator_attachment: "cross-platform" }, hints: ["hybrid", "security-key"] }, "security_key"],
    ["cross-platform, no hints", "create", { authenticator_selection: { authenticator_attachment: "cross-platform" } }, null],
    ["cross-platform, client-device hint", "create", { authenticator_selection: { authenticator_attachment: "cross-platform" }, hints: ["client-device"] }, null],
    ["platform, security key hint", "create", { authenticator_selection: { authenticator_attachment: "platform" }, hints: ["security-key"] }, null],
    ["conditional create", "create", {}, "conditional_create", "conditional"],
    ["a plain get", "get", {}, null],
  ]);
  for (const [title, kind, options, expected, mediation = "optional"] of cases) {
    assert.equal(automaticHandover(kind, kind === "create" ? createOptions(options) : getOptions(options), mediation), expected, title);
  }
  // Through the broker: the browser gets the call at once, with the page's own options (a hand-over, never an error).
  let n = 0;
  for (const [title, kind, options, expected, mediation = "optional"] of cases) {
    const w = world();
    const id = `u${(n += 1)}`;
    const body = kind === "create" ? createBody(id, { options, body: { mediation } }) : getBody(id, { options, body: { mediation } });
    const out = /** @type {any} */ (await w.requests.open(senderOf(), body));
    if (expected === null) assert.ok("request_id" in out, title);
    else {
      assert.equal(out.reason, expected, title);
      assert.deepEqual(w.pushed.map((p) => [p.type, p.body.once]), [["passkey_handover", false]], title);
      assert.equal(w.opened.length, 0, title);
    }
  }
  // Malformed options are the TypeError the browser gives (user.id of 0 or 65 bytes), never a window.
  assert.equal(malformedOptions("create", createOptions({ user: { id: "", name: "a", display_name: "A" } })), true);
  assert.equal(malformedOptions("create", createOptions({ user: { id: "A".repeat(87), name: "a", display_name: "A" } })), true);
  assert.equal(malformedOptions("create", createOptions({ user: { id: "A".repeat(86), name: "a", display_name: "A" } })), false);
  const w = world();
  assert.deepEqual(await w.requests.open(senderOf(), createBody("t1", { options: { user: { id: "", name: "a", display_name: "A" } } })), { error: "TypeError" });
  assert.deepEqual(w.pushed.map((p) => [p.type, p.body.name]), [["passkey_error", "TypeError"]]);
  assert.equal(w.opened.length, 0);
});

test("an_rp_id_the_browser_refuses_is_a_security_error_before_any_window", async () => {
  // The browser compares the RP ID as the page gave it with the page's host: one not already in canonical form, or one that is
  // neither the host nor a suffix of it, is refused before any UI. (The core would canonicalize the first kind to the host.)
  const refused = [
    "rp-a.test.", // a trailing dot
    "RP-A.Test", // upper case
    "rp-a.Test",
    `${String.fromCharCode(0xff52)}${String.fromCharCode(0xff50)}-a.test`, // full-width letters
    `rp-a${String.fromCharCode(0xff0e)}test`, // a full-width full stop
    `rp-a${String.fromCharCode(0xad)}test`, // a soft hyphen (IDNA drops it)
    `rp-${String.fromCharCode(0xe4)}.test`, // a U-label
    "rp-a.test:443", // a port
    "", // empty
    "-rp-a.test",
    "rp-a..test",
    "www.rp-a.test", // a subdomain of the host, not a suffix
    "rp-b.test", // another site
    "a.test", // a string suffix that is not a label suffix
  ];
  for (const rpId of refused) {
    for (const kind of /** @type {const} */ (["create", "get"])) {
      const options = kind === "create" ? createOptions({ rp: { name: "RP A", id: rpId } }) : getOptions({ rp_id: rpId });
      assert.equal(refusedRpId(kind, options, "rp-a.test"), true, `${kind} ${JSON.stringify(rpId)}`);
      const w = world();
      const body = kind === "create" ? createBody("d1", { options: { rp: { name: "RP A", id: rpId } } }) : getBody("d1", { options: { rp_id: rpId } });
      assert.deepEqual(await w.requests.open(senderOf(), body), { error: "SecurityError" }, `${kind} ${JSON.stringify(rpId)}`);
      assert.deepEqual(w.pushed.map((p) => [p.type, p.body.name]), [["passkey_error", "SecurityError"]], `${kind} ${JSON.stringify(rpId)}`);
      assert.equal(w.opened.length, 0, `${kind} ${JSON.stringify(rpId)}: no window`);
      assert.equal(w.requests.waitingFor(4), null, `${kind} ${JSON.stringify(rpId)}: nothing waits`);
    }
  }
  // The host itself, a registrable suffix of it, an A-label host, and no RP ID at all are Ferret's (a public suffix is still the
  // core's refusal, in the window).
  for (const [rpId, host] of /** @type {Array<[string | undefined, string]>} */ ([
    ["rp-a.test", "rp-a.test"],
    ["rp-a.test", "login.rp-a.test"],
    ["xn--rp--8cd.test", "xn--rp--8cd.test"],
    [undefined, "rp-a.test"],
  ])) {
    assert.equal(refusedRpId("create", createOptions({ rp: { name: "RP A", ...(rpId === undefined ? {} : { id: rpId }) } }), host), false, `${rpId} on ${host}`);
    assert.equal(refusedRpId("get", getOptions(rpId === undefined ? {} : { rp_id: rpId }), host), false, `${rpId} on ${host}`);
  }
  const w = world();
  const out = /** @type {any} */ (await w.requests.open(senderOf(), getBody("d2", { options: { rp_id: "rp-a.test" } })));
  assert.ok("request_id" in out);
  assert.deepEqual(w.opened, [out.request_id]);
});

test("prf_eval_by_credential_the_browser_does_not_process_is_not_supported_before_any_window", async () => {
  const SALT = { first: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
  const byCredential = [{ id: "AAAAAAAAAAAAAAAAAAAAAA", ...SALT }];
  const allow = [{ type: "public-key", id: "AAAAAAAAAAAAAAAAAAAAAA" }];
  // At registration any evalByCredential (even an empty one) is NotSupportedError (WebAuthn L3 § 10.1.4).
  assert.equal(unsupportedOptions("create", createOptions({ extensions: { prf: { eval_by_credential: byCredential } } })), true);
  assert.equal(unsupportedOptions("create", createOptions({ extensions: { prf: { eval_by_credential: [] } } })), true);
  assert.equal(unsupportedOptions("create", createOptions({ extensions: { prf: { eval: SALT } } })), false);
  assert.equal(unsupportedOptions("create", createOptions()), false);
  // At sign-in only a non-empty evalByCredential with an empty allow list.
  assert.equal(unsupportedOptions("get", getOptions({ extensions: { prf: { eval_by_credential: byCredential } } })), true);
  assert.equal(unsupportedOptions("get", getOptions({ allow_credentials: allow, extensions: { prf: { eval_by_credential: byCredential } } })), false);
  assert.equal(unsupportedOptions("get", getOptions({ extensions: { prf: { eval_by_credential: [] } } })), false);
  assert.equal(unsupportedOptions("get", getOptions({ extensions: { prf: { eval: SALT } } })), false);
  for (const [kind, options] of /** @type {const} */ ([
    ["create", { extensions: { prf: { eval_by_credential: byCredential } } }],
    ["get", { extensions: { prf: { eval_by_credential: byCredential } } }],
  ])) {
    const w = world();
    const body = kind === "create" ? createBody("p1", { options }) : getBody("p1", { options });
    assert.deepEqual(await w.requests.open(senderOf(), body), { error: "NotSupportedError" }, kind);
    assert.deepEqual(w.pushed.map((p) => [p.type, p.body.name]), [["passkey_error", "NotSupportedError"]], kind);
    assert.equal(w.opened.length, 0, `${kind}: no window`);
  }
  // With the allow list the get is Ferret's.
  const w = world();
  const out = /** @type {any} */ (await w.requests.open(senderOf(), getBody("p2", { options: { allow_credentials: allow, extensions: { prf: { eval_by_credential: byCredential } } } })));
  assert.ok("request_id" in out);
  // The core's own refusal of the same input reaches the page as the same error.
  assert.equal(pageErrorOf("unsupported"), "NotSupportedError");
});

test("a_request_whose_bridge_stops_pinging_ends_and_its_window_closes", async () => {
  // A removed frame fires no navigation; its bridge's abort may be lost. Without a ping for PASSKEY_SILENT_MS it ends.
  assert.equal(PASSKEY_SILENT_MS, 45_000);
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), createBody("q1"))).request_id;
  assert.deepEqual(w.opened, [id]);
  // The bridge pings every 20 s while it waits: the request stays, past 45 s.
  for (let i = 0; i < 3; i += 1) {
    w.clock.advance(20_000);
    await w.requests.onEvent({ type: "passkey_ping", sender: senderOf(), body: { request_ids: ["q1"] } });
    await flush();
  }
  assert.equal(w.requests.size(), 1);
  assert.deepEqual(w.closed, []);
  // Then it goes silent: 45 s after the last ping the request ends and the window closes. Nothing goes to the frame.
  w.clock.advance(44_999);
  await flush();
  assert.equal(w.requests.size(), 1);
  w.clock.advance(1);
  await flush();
  assert.equal(w.requests.size(), 0);
  assert.deepEqual(w.closed, [101]);
  assert.deepEqual(pushesOf(w.pushed, "q1"), []);
  // A conditional request (no deadline) ends the same way.
  const c = world();
  await c.requests.open(senderOf(), getBody("q2", { body: { mediation: "conditional" } }));
  assert.equal(c.requests.size(), 1);
  c.clock.advance(45_000);
  await flush();
  assert.equal(c.requests.size(), 0);
});

test("a_check_of_the_pings_that_comes_late_after_a_sleep_waits_for_the_next_ping", async () => {
  // The machine slept: the timer comes long after its time, and the bridge has not had a chance to ping yet.
  const w = world();
  await w.requests.open(senderOf(), getBody("z1", { body: { mediation: "conditional" } }));
  w.clock.advance(10 * 60_000);
  await flush();
  assert.equal(w.requests.size(), 1, "one more wait for the next ping");
  // The bridge pings after the wake-up: the request lives on.
  await w.requests.onEvent({ type: "passkey_ping", sender: senderOf(), body: { request_ids: ["z1"] } });
  w.clock.advance(25_000);
  await flush();
  assert.equal(w.requests.size(), 1);
  // Without that ping it would have ended after the extra wait.
  const v = world();
  await v.requests.open(senderOf(), getBody("z2", { body: { mediation: "conditional" } }));
  v.clock.advance(10 * 60_000);
  v.clock.advance(25_000);
  await flush();
  assert.equal(v.requests.size(), 0);
});

test("a_window_still_being_made_for_an_ended_request_keeps_the_one_window_place", async () => {
  // The first request's window is asked for; the page aborts before the browser has made it.
  /** @type {Array<(id: number) => void>} */
  const making = [];
  const closed = /** @type {number[]} */ ([]);
  const w = world({
    windows: {
      open: () => new Promise((resolve) => making.push(resolve)),
      close: async (/** @type {number} */ id) => void closed.push(id),
    },
  });
  const first = w.requests.open(senderOf(), createBody("m1"));
  await flush();
  assert.equal(making.length, 1);
  await w.requests.onEvent({ type: "passkey_abort", sender: senderOf(), body: { request_id: "m1" } });
  // Another tab's request meanwhile gets the mark and the card, not a second window beside the one about to appear.
  const second = /** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), createBody("m2")));
  assert.ok("request_id" in second);
  assert.equal(making.length, 1, "no second window while the first is being made");
  // The first window appears and is closed at once; then the waiting request can have the window (from its card).
  making[0](201);
  await first;
  assert.deepEqual(closed, [201]);
  void w.requests.show(7);
  await flush();
  assert.equal(making.length, 2);
  // A window the person closed frees the place at once (its request ends): the next request opens its own.
  const v = world();
  await v.requests.open(senderOf(), createBody("m3"));
  assert.equal(v.opened.length, 1);
  v.requests.onWindowRemoved(101);
  await flush();
  const next = /** @type {any} */ (await v.requests.open(senderOf(), createBody("m4")));
  assert.deepEqual(v.opened, [v.opened[0], next.request_id]);
});

test("an_empty_alg_list_is_answered_by_ferret", async () => {
  // WebAuthn reads an empty pubKeyCredParams as ES256 and RS256: Ferret answers.
  assert.equal(automaticHandover("create", createOptions({ pub_key_cred_params: [] }), "optional"), null);
  const w = world();
  const out = /** @type {any} */ (await w.requests.open(senderOf(), createBody("e1", { options: { pub_key_cred_params: [] } })));
  assert.ok("request_id" in out);
  assert.deepEqual(w.opened, [out.request_id]);
  assert.equal(w.pushed.length, 0);
});

test("a_suspended_mv3_background_fails_pending_requests_closed", async () => {
  // A request waits in the background; the bridge pings it every 20 s (which keeps the event page awake meanwhile).
  const before = world();
  const id = /** @type {any} */ (await before.requests.open(senderOf(), createBody("s1"))).request_id;
  await before.requests.onEvent({ type: "passkey_ping", sender: senderOf(), body: { request_ids: ["s1"] } });
  assert.equal(before.pushed.length, 0, "a request that waits is left alone");
  // A ping of another document names an id that is not its own: it fails for that document only.
  await before.requests.onEvent({ type: "passkey_ping", sender: senderOf({ documentId: "doc-x" }), body: { request_ids: ["s1"] } });
  await flush();
  assert.deepEqual(before.pushed.map((p) => [p.body.request_id, p.body.name]), [["s1", "NotAllowedError"]]);
  assert.ok(before.requests.forUi(id, "s"));
  // The event page was unloaded: a new background knows nothing of it, and the bridge's next ping ends the call.
  const after = world();
  await after.requests.onEvent({ type: "passkey_ping", sender: senderOf(), body: { request_ids: ["s1", "s2"] } });
  await flush();
  assert.deepEqual(after.pushed.map((p) => [p.type, p.body.request_id, p.body.name]), [
    ["passkey_error", "s1", "NotAllowedError"],
    ["passkey_error", "s2", "NotAllowedError"],
  ]);
});

// ------------------------------------------------------------------------------------------------ the chooser window

test("the_window_operations_belong_to_the_window_that_named_the_request_first", async () => {
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), createBody("w1", { options: { rp: { id: "rp-a.test", name: "RP\u202eA" } } }))).request_id;
  const ops = /** @type {any} */ (w.requests.ops);
  const pending = await ops.passkey_pending.run(null, { request_id: id, session: "win" });
  assert.equal(pending.ok, true);
  validate(PASSKEY_REQUEST_VIEW, pending.request);
  assert.deepEqual(pending.request, {
    request_id: id,
    kind: "create",
    mediation: "optional",
    origin: RP,
    rp_id: "rp-a.test",
    rp_name: "RP\u202eA",
    user_name: "alice",
    user_display_name: "Alice",
    user_verification: "preferred",
    credentials: 0,
    prf: false,
    expires_in: PASSKEY_TIMEOUT_MS.default,
    foreign: false,
    incognito: false,
  });
  assert.deepEqual(await ops.passkey_pending.run(null, { request_id: id, session: "other" }), { ok: false, reason: "gone" });
  assert.deepEqual(await ops.passkey_cancel.run(null, { request_id: id, session: "other" }), { ok: false, reason: "gone" });
  assert.deepEqual(await ops.passkey_pending.run(null, { request_id: "0".repeat(32), session: "win" }), { ok: false, reason: "gone" });

  // passkey_site: the core's check with the broker's caller; an RP ID the origin may not use ends with SecurityError.
  /** @type {any[]} */
  const calls = [];
  const client = (/** @type {any} */ answer) => ({
    vault: {
      passkey_site: async (/** @type {any} */ caller, /** @type {any} */ rpId) => {
        calls.push({ caller: { ...caller }, rpId });
        if (answer instanceof Error) throw answer;
        return answer;
      },
    },
  });
  const site = { origin: RP, host_unicode: "rp-a.test", rp_id: "rp-a.test", rp_id_unicode: "rp-a.test" };
  assert.deepEqual(await ops.passkey_site.run(client(site), { request_id: id, session: "win" }), { ok: true, site });
  assert.deepEqual(calls, [{ caller: { origin: RP, top_origin_is_same: true }, rpId: "rp-a.test" }]);
  assert.equal(ops.passkey_site.vault, true, "it needs the open vault");
  const bad = Object.assign(new Error("malformed_rp_id"), { code: "malformed_rp_id" });
  assert.deepEqual(await ops.passkey_site.run(client(bad), { request_id: id, session: "win" }), { ok: false, reason: "security_error" });
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "w1").map((p) => p.body.name), ["SecurityError"]);
  assert.deepEqual(w.closed, [101]);
  assert.equal(pageErrorOf("malformed_rp_id"), "SecurityError");
  assert.equal(pageErrorOf("not_allowed"), "NotAllowedError");
  assert.equal(pageErrorOf("invalid_state"), "InvalidStateError");
  assert.equal(pageErrorOf("too_large"), "TypeError");

  // passkey_browser: the browser answers with the page's own options; passkey_cancel: NotAllowedError.
  const b = /** @type {any} */ (await w.requests.open(senderOf(), getBody("w2"))).request_id;
  assert.deepEqual(await ops.passkey_browser.run(null, { request_id: b, session: "win2" }), { ok: true });
  // The browser is not called at once: this call ends and the next one of the kind from this document goes through (a pass).
  assert.deepEqual(pushesOf(w.pushed, "w2").map((p) => [p.type, p.body.once]), [["passkey_handover", true]]);
  // (The pass it made is for the next call of this kind: the tab is closed here, so that the next request below is Ferret's.)
  w.requests.onTabRemoved(4);
  const c = /** @type {any} */ (await w.requests.open(senderOf(), getBody("w3"))).request_id;
  assert.deepEqual(await ops.passkey_cancel.run(null, { request_id: c, session: "win3" }), { ok: true });
  // The window's port ending is a cancel too.
  const d = /** @type {any} */ (await w.requests.open(senderOf(), getBody("w4"))).request_id;
  await ops.passkey_pending.run(null, { request_id: d, session: "win4" });
  w.requests.endSession("win4");
  assert.equal(w.requests.size(), 0);
  // "Use the browser" once: the next call of that kind from that document goes through, once, within the time.
  const e = /** @type {any} */ (await w.requests.open(senderOf(), getBody("w5"))).request_id;
  w.requests.handover(e, "s", { once: true });
  assert.deepEqual(pushesOf(w.pushed, "w5").map((p) => p.body.once), [true]);
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), createBody("w6"))).request_id !== undefined, true, "another kind is not let through");
  w.requests.onTabRemoved(4);
  const f = /** @type {any} */ (await w.requests.open(senderOf(), getBody("w7"))).request_id;
  w.requests.handover(f, "s", { once: true });
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("w8"))).reason, "pass_once");
  assert.ok("request_id" in (await w.requests.open(senderOf(), getBody("w9"))), "only once");
  w.requests.onTabRemoved(4);
  const g = /** @type {any} */ (await w.requests.open(senderOf(), getBody("w10"))).request_id;
  w.requests.handover(g, "s", { once: true });
  w.clock.advance(PASSKEY_PASS_ONCE_MS);
  assert.ok("request_id" in (await w.requests.open(senderOf(), getBody("w11"))), "not after the time");
  assert.equal(PASSKEY_GUARD_MS, 400);
});

test("the_window_handler_answers_only_the_chooser_window", async () => {
  // The handler of a test package (its features module is the build's).
  const env = makeRoot();
  /** @type {any} */
  let windowHandler;
  try {
    const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest: "mv3", variant: "test" });
    windowHandler = (await import(pathToFileURL(join(result.dir, "background", "handlers", "passkeyWindow.handler.mjs")).href)).default;
  } finally {
    env.cleanup();
  }
  const runtime = { id: "ferret@x", getURL: (/** @type {string} */ p) => `moz-extension://u/${p}` };
  /** @type {any[]} */
  const calls = [];
  const ctx = (/** @type {any} */ sender, type = "passkey_pending") => ({
    channel: "ui",
    type,
    sender,
    runtime,
    session: "s1",
    state: () => "locked",
    call: async (/** @type {string} */ op, /** @type {any} */ args) => {
      calls.push({ op, args });
      return { ok: true };
    },
  });
  const window = { id: "ferret@x", url: "moz-extension://u/pages/passkey.html?r=" + "a".repeat(32), frameId: 0 };
  const id = "a".repeat(32);
  assert.deepEqual(await windowHandler.handle({ request_id: id }, ctx(window)), { ok: true });
  assert.deepEqual(calls, [{ op: "passkey_pending", args: { request_id: id, session: "s1" } }]);
  // In a tab of a window the browser names: that window goes along for the broker to check.
  await windowHandler.handle({ request_id: id }, ctx({ ...window, tab: { id: 9, windowId: 12 } }));
  assert.deepEqual(calls[1], { op: "passkey_pending", args: { request_id: id, session: "s1", window_id: 12 } });
  calls.length = 1;
  for (const sender of [
    { ...window, url: "moz-extension://u/pages/passkey.html" },
    { ...window, url: "moz-extension://u/pages/passkey.html?r=" + "b".repeat(32) },
    { ...window, url: "moz-extension://u/pages/popup.html" },
    { ...window, url: "moz-extension://u/pages/passkey.html.evil" },
    { ...window, frameId: 3, tab: { id: 1 } },
    { ...window, url: "https://rp-a.test/pages/passkey.html" },
    { ...window, id: "other@x" },
  ]) {
    await assert.rejects(Promise.resolve().then(() => windowHandler.handle({ request_id: id }, ctx(sender))), /not_available/, JSON.stringify(sender));
  }
  assert.equal(calls.length, 1);
  assert.deepEqual([...windowHandler.types], [...PASSKEY_WINDOW_OPS]);
  for (const type of PASSKEY_WINDOW_OPS) {
    assert.ok(Object.hasOwn(UI_TYPES, type), type);
    assert.ok(CORE_OPS.includes(type), type);
  }
  // The window works while the vault is locked, except for the core's check of the site.
  assert.deepEqual(PASSKEY_WINDOW_OPS.filter((t) => LOCK_EXEMPT.includes(t)), ["passkey_pending", "passkey_cancel", "passkey_browser"]);
  assert.ok(CORE_OPS.includes(PASSKEY_EVENT_OP));
});

// ------------------------------------------------------------------------------------------------- after review

test("an_http_sender_or_an_http_ancestor_and_a_frame_without_a_document_id_go_to_the_browser", async () => {
  const w = world();
  // A plain http page (the router lets http senders through; the broker does not).
  w.tabFrames.set(7, topOnly("http://rp-a.test/", "doc-7"));
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: "http://rp-a.test/", origin: "http://rp-a.test" }), getBody("h1"))).reason, "origin");
  // An https frame of the top's host under an http top.
  w.tabFrames.set(4, [
    { frameId: 0, parentFrameId: -1, url: "http://rp-a.test/", documentId: "doc-1" },
    { frameId: 6, parentFrameId: 0, url: `${RP}/f`, documentId: "doc-6" },
  ]);
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf({ frameId: 6, documentId: "doc-6", url: `${RP}/f` }), getBody("h2"))).reason, "frames");
  // The browser lists the calling frame without its document: not trusted.
  w.tabFrames.set(4, [{ frameId: 0, parentFrameId: -1, url: `${RP}/login` }]);
  assert.equal(/** @type {any} */ (await w.requests.open(senderOf(), getBody("h3"))).reason, "frames");
  assert.equal(w.opened.length, 0);
});

test("an_answer_after_a_sign_out_or_a_server_change_is_not_sent", async () => {
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("s1"))).request_id;
  // The device was ended remotely while the request waited.
  w.state.server = { origin: SERVER, live: false };
  assert.equal(await w.requests.answer(id, "s", RESPONSE), false);
  w.clock.advance(1000);
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "s1").map((p) => [p.type, p.body.name]), [["passkey_error", "NotAllowedError"]]);
  // The device is now signed in at a server on the page's own host.
  w.state.server = { origin: RP, live: true };
  const id2 = /** @type {any} */ (await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), getBody("s2")));
  assert.equal(id2.reason, "ferret_server");
});

test("the_ending_functions_belong_to_the_session_that_owns_the_request", async () => {
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("o1"))).request_id;
  assert.ok(w.requests.forUi(id, "win"));
  for (const [name, call] of /** @type {Array<[string, () => unknown]>} */ ([
    ["answer", () => w.requests.answer(id, "other", RESPONSE)],
    ["handover", () => w.requests.handover(id, "other", { once: false })],
    ["cancel", () => w.requests.cancel(id, "other")],
    ["fail", () => w.requests.fail(id, "other", "SecurityError")],
    ["takeVerified", () => w.requests.takeVerified(id, "other")],
    ["callerOf", () => w.requests.callerOf(id, "other")],
  ])) {
    const out = await call();
    assert.ok(out === false || out === null, name);
  }
  assert.equal(w.requests.size(), 1);
  assert.equal(w.pushed.length, 0);
  // A window op from another browser window than the one opened for the request is refused too.
  const ops = /** @type {any} */ (w.requests.ops);
  assert.deepEqual(await ops.passkey_pending.run(null, { request_id: id, session: "win", window_id: 999 }), { ok: false, reason: "gone" });
  assert.equal((await ops.passkey_pending.run(null, { request_id: id, session: "win", window_id: 101 })).ok, true);
  assert.equal(w.requests.fail(id, "win", "SecurityError"), true);
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "o1").map((p) => p.body.name), ["SecurityError"]);
});

test("passkey_site_ends_the_request_for_every_code_but_a_gone_vault", async () => {
  /** @param {string} code */
  const failing = (code) => ({ vault: { passkey_site: async () => Promise.reject(Object.assign(new Error(code), { code })) } });
  for (const [code, name, reason] of [
    ["malformed_rp_id", "SecurityError", "security_error"],
    ["too_large", "TypeError", "type_error"],
    ["invalid_input", "TypeError", "type_error"],
    ["not_allowed", "NotAllowedError", "not_allowed"],
  ]) {
    const w = world();
    const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("x1"))).request_id;
    const ops = /** @type {any} */ (w.requests.ops);
    assert.deepEqual(await ops.passkey_site.run(failing(code), { request_id: id, session: "win" }), { ok: false, reason }, code);
    w.clock.advance(1000);
    await flush();
    assert.deepEqual(pushesOf(w.pushed, "x1").map((p) => p.body.name), [name], code);
    assert.equal(w.requests.size(), 0, code);
  }
  // The vault went (a lock, a failed worker): the core host's business; the request waits for the unlock in the window.
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("x2"))).request_id;
  await assert.rejects(/** @type {any} */ (w.requests.ops).passkey_site.run(failing("vault_locked"), { request_id: id, session: "win" }), /vault_locked/);
  assert.equal(w.requests.size(), 1);
});

test("a_ping_inside_the_delay_of_an_error_does_not_bring_it_early", async () => {
  const w = world();
  const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("d1"))).request_id;
  w.requests.cancel(id, "s");
  await w.requests.onEvent({ type: "passkey_ping", sender: senderOf(), body: { request_ids: ["d1"] } });
  await flush();
  assert.equal(w.pushed.length, 0, "the error comes only after its delay");
  w.clock.advance(PASSKEY_ERROR_DELAY_MS.min + PASSKEY_ERROR_DELAY_MS.spread);
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "d1").map((p) => p.body.name), ["NotAllowedError"]);
  // A request that a ping finds past its deadline gets one error, after the delay.
  const late = /** @type {any} */ (await w.requests.open(senderOf(), getBody("d2"))).request_id;
  // Its deadline's timer does not run (as in a sleeping machine): the clock decides when the ping comes.
  w.clock.timers.clearTimeout(/** @type {any} */ (w.clock.pending().find((t) => t.ms === PASSKEY_TIMEOUT_MS.default)).id);
  w.clock.advance(PASSKEY_TIMEOUT_MS.default);
  await w.requests.onEvent({ type: "passkey_ping", sender: senderOf(), body: { request_ids: ["d2"] } });
  w.clock.advance(PASSKEY_ERROR_DELAY_MS.min + PASSKEY_ERROR_DELAY_MS.spread);
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "d2").map((p) => p.body.name), ["NotAllowedError"]);
  assert.equal(w.requests.forUi(late, "s"), null);
});

test("aborts_that_come_first_are_kept_per_tab", async () => {
  const w = world();
  // Tab 7's abort before its request.
  const other = senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` });
  await w.requests.onEvent({ type: "passkey_abort", sender: other, body: { request_id: "k1" } });
  // A frame of tab 4 floods aborts with made-up ids.
  for (let i = 0; i < 500; i += 1) await w.requests.onEvent({ type: "passkey_abort", sender: senderOf(), body: { request_id: `f${i}` } });
  assert.deepEqual(await w.requests.open(other, getBody("k1")), { error: "AbortError" }, "tab 7's abort is still there");
  assert.equal(w.opened.length, 0);
});

test("the_broker_listeners_are_added_only_while_a_request_waits", () => {
  const main = readFileSync(join(src, "background", "main.mjs"), "utf8");
  // Every listener of the broker is in the list that `listen.start` and `listen.stop` walk, and nowhere else.
  for (const name of ["committed", "sameDocument", "tabRemoved", "windowRemoved"]) {
    const uses = [...main.matchAll(new RegExp(`passkeyListeners\\.${name}\\b`, "g"))].length;
    assert.ok(uses >= 1, name);
    assert.doesNotMatch(main, new RegExp(`addListener\\(passkeyListeners\\.${name}`), name);
  }
  assert.match(main, /start\(\) \{\s*for \(const \[event, listener\] of passkeyEvents\(\)\) \{\s*try \{\s*event\.addListener\(listener\);/);
  assert.match(main, /stop\(\) \{\s*for \(const \[event, listener\] of passkeyEvents\(\)\) \{\s*try \{\s*event\.removeListener\(listener\);/);
  assert.equal([...main.matchAll(/event\.addListener\(listener\)/g)].length, 1);
});

test("passkey_never_keeps_the_cores_rp_id_on_the_list_and_hands_the_call_to_the_browser", async () => {
  /** @type {Array<[string, any]>} */
  const added = [];
  const w = world({ never: { has: async () => false, add: async (/** @type {string} */ rpId, /** @type {any} */ options) => void added.push([rpId, options]) } });
  const ops = /** @type {any} */ (w.requests.ops);
  assert.equal(ops.passkey_never.vault, true, "it needs the open vault: only then is there an RP ID the core has checked");
  // The list gets the RP ID the core checked, never the page's text. (A page's RP ID that the core would only take after
  // canonicalizing, such as "RP-A.test", never gets this far: it is a SecurityError before any window.)
  const id = /** @type {any} */ (await w.requests.open(senderOf(), getBody("n1", { options: { rp_id: "rp-a.test" } }))).request_id;
  const client = (/** @type {any} */ rpId) => ({ vault: { passkey_site: async () => ({ origin: RP, host_unicode: "rp-a.test", rp_id: rpId, rp_id_unicode: rpId }) } });
  // The first window that names the request owns it; another window's session cannot.
  assert.equal((await ops.passkey_pending.run(null, { request_id: id, session: "win" })).ok, true);
  assert.deepEqual(await ops.passkey_never.run(client("rp-a.test"), { request_id: id, session: "other" }), { ok: false, reason: "gone" });
  assert.deepEqual(added, []);
  // A locked vault is the router's refusal; nothing is stored and the request waits.
  const locked = { vault: { passkey_site: async () => Promise.reject(Object.assign(new Error("vault_locked"), { code: "vault_locked" })) } };
  await assert.rejects(ops.passkey_never.run(locked, { request_id: id, session: "win" }), /vault_locked/);
  assert.deepEqual(added, []);
  assert.equal(w.requests.size(), 1);
  // The core's RP ID is kept (a private window's choice carries the flag), and the browser answers with the page's own options.
  assert.deepEqual(await ops.passkey_never.run(client("rp-a.test"), { request_id: id, session: "win" }), { ok: true });
  assert.deepEqual(added, [["rp-a.test", { incognito: false }]]);
  // The site is on the list now; this call ends like the browser's own after the window closed, the next goes to the browser by the
  // list (no pass is made, and nothing waits on the toolbar button).
  assert.deepEqual(pushesOf(w.pushed, "n1").map((p) => [p.type, p.body.once]), [["passkey_handover", true]]);
  assert.equal(w.requests.passPendingFor(4), null);
  assert.equal(w.requests.size(), 0);
  const priv = /** @type {any} */ (await w.requests.open(senderOf({ incognito: true }), getBody("n2"))).request_id;
  await ops.passkey_never.run(client("rp-a.test"), { request_id: priv, session: "win2" });
  assert.deepEqual(added[1], ["rp-a.test", { incognito: true }]);
  // A broker without the list does not pretend.
  const bare = world();
  const bareId = /** @type {any} */ (await bare.requests.open(senderOf(), getBody("n3"))).request_id;
  assert.deepEqual(await /** @type {any} */ (bare.requests.ops).passkey_never.run(client("rp-a.test"), { request_id: bareId, session: "w" }), { ok: false, reason: "not_available" });
  assert.equal(bare.requests.size(), 1);
});

test("a_request_that_waits_is_not_answered_once_the_setting_is_off_or_the_permission_is_gone", async () => {
  for (const [what, off] of /** @type {Array<[string, (w: ReturnType<typeof world>) => void]>} */ ([
    ["the setting turned off", (w) => void (w.state.on = false)],
    ["the permission taken back", (w) => void (w.state.permission = false)],
  ])) {
    const w = world();
    const id = /** @type {any} */ (await w.requests.open(senderOf(), createBody("o1"))).request_id;
    assert.equal(await w.requests.recheck(id, "win"), true, `${what}: still allowed before`);
    off(w);
    // The check before anything is written ends the request and closes the window, with the same error as any refusal.
    assert.equal(await w.requests.recheck(id, "win"), false, what);
    assert.equal(w.requests.size(), 0, what);
    assert.deepEqual(w.closed, [101], what);
    w.clock.advance(1000);
    await flush();
    assert.deepEqual(pushesOf(w.pushed, "o1").map((p) => p.body.name), ["NotAllowedError"], what);
  }
  // The same for a request that waits without a window, and for the conditional one: `endAll` (what the registry calls when the
  // feature goes off) ends them with the same error.
  const w = world();
  await w.requests.open(senderOf(), createBody("o2"));
  await w.requests.open(senderOf({ tabId: 7, documentId: "doc-7", url: `${RP}/other` }), getBody("o3", { body: { mediation: "conditional" } }));
  w.state.on = false;
  w.requests.endAll();
  assert.equal(w.requests.size(), 0);
  assert.deepEqual(w.closed, [101]);
  w.clock.advance(1000);
  await flush();
  assert.deepEqual(pushesOf(w.pushed, "o2").map((p) => p.body.name), ["NotAllowedError"]);
  assert.deepEqual(pushesOf(w.pushed, "o3").map((p) => p.body.name), ["NotAllowedError"]);
});
