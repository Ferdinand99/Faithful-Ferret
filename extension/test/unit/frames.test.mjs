// Which frames of a tab are offered items, and the list a page is offered
// (design document, sections 10.4 and 10.5): the frame rules over the browser's
// frames, every site rule from the core, the core host's match (no handle and no
// reference leaves it), the fill flow's references per popup session on top of
// it, and the grant tab for a same-site frame of another origin.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { CORE_OPS, createCoreHost } from "../../src/background/coreHost.mjs";
import candidatesHandler from "../../src/background/handlers/candidates.handler.mjs";
import grantHandler from "../../src/background/handlers/grant.handler.mjs";
import { createFillHost } from "../../src/background/fillFlow.mjs";
import { candidates, confirmFrame, createCandidateSource, fillableFrames, grantUrl, isSecureOrigin, MAX_FRAMES, permissionPattern } from "../../src/background/frames.mjs";
import { createLock } from "../../src/background/lock.mjs";
import { createGrantList, createMatchHost } from "../../src/background/match.mjs";
import { createRouter } from "../../src/background/router.mjs";
import { createGrantFlow, originParam } from "../../src/pages/grantFlow.mjs";
import { UI_PORT, UI_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import { createAlarmsAndIdle, createClock, createFakeClient, createPort, createSessionStorage } from "./backgroundHelpers.mjs";
import { extensionRoot } from "./buildHelpers.mjs";
import { createFakeBrowser, extensionPageSender } from "./fakeBrowser.mjs";

const TAB = 7;
const LOGIN = "https://login.example.net";
const WWW = "https://www.example.net";

// ------------------------------------------------------------ stand-ins

/**
 * The parts of the core this file needs, written for the tests only: the origin of an http(s) address (no other
 * scheme has one), "same site" from a table the test gives (the extension has no rule of its own, so any answer the
 * core gives is the one used), and the host as written. Not a matching rule of the extension.
 * @param {{ sameSite?: (a: string, b: string) => boolean, display?: (url: string) => { a_label: string, unicode: string } }} [o]
 */
function fakeCore({ sameSite = (a, b) => siteOf(a) === siteOf(b), display } = {}) {
  /** @type {Array<[string, unknown[]]>} */
  const calls = [];
  const originOf = (/** @type {string} */ url) => {
    const u = new URL(url);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw Object.assign(new Error("malformed_origin"), { code: "malformed_origin" });
    return u.origin;
  };
  return {
    calls,
    page_origin: async (/** @type {string} */ url) => {
      calls.push(["page_origin", [url]]);
      return originOf(url);
    },
    same_site: async (/** @type {string} */ a, /** @type {string} */ b) => {
      calls.push(["same_site", [a, b]]);
      return sameSite(a, b);
    },
    display_host: async (/** @type {string} */ url) => {
      calls.push(["display_host", [url]]);
      if (display) return display(url);
      const host = new URL(url).hostname;
      return { a_label: host, unicode: host };
    },
  };
}

/** The test's own idea of a site, for the names these tests use: the scheme and the last two labels. @param {string} url */
function siteOf(url) {
  const u = new URL(url);
  return `${u.protocol}${/[^.]+\.[^.]+$/.exec(u.hostname)?.[0] ?? u.hostname}`;
}

/**
 * `webNavigation` over a fixed list of frames: `[frameId, parentFrameId, url]` (the top is frame 0).
 * @param {Array<[number, number, string, Record<string, unknown>?]>} rows
 */
function navigation(rows) {
  return {
    asked: 0,
    async getAllFrames(/** @type {{ tabId: number }} */ { tabId }) {
      this.asked += 1;
      if (tabId !== TAB) return null;
      return rows.map(([frameId, parentFrameId, url, extra]) => ({ frameId, parentFrameId, url, documentId: `doc-${frameId}`, ...extra }));
    },
  };
}

/**
 * The sync engine's list and items: each item has saved addresses; `open` hands out a new handle and counts what is
 * open, so a test sees every handle closed.
 * @param {Array<{ id: string, name: string, username?: string, urls: string[] }>} items
 */
function itemSource(items) {
  let next = 100;
  /** @type {Map<number, string>} */
  const live = new Map();
  const source = {
    opened: 0,
    closed: 0,
    live,
    list: () => items.map((i) => ({ id: i.id, name: i.name, username: i.username ?? "", urls: i.urls })),
    async open(/** @type {string} */ id) {
      const item = items.find((i) => i.id === id);
      if (!item) throw Object.assign(new Error("not_found"), { code: "not_found" });
      next += 1;
      const handle = next;
      live.set(handle, id);
      source.opened += 1;
      return {
        handle,
        close: async () => {
          if (live.delete(handle)) source.closed += 1;
        },
      };
    },
    /** The saved addresses of an open handle (the fake core's match reads them). @param {number} handle */
    urlsOf: (handle) => items.find((i) => i.id === live.get(handle))?.urls ?? [],
  };
  return source;
}

/** An item id: 16 bytes in hex. @param {number} n */
const itemId = (n) => n.toString(16).padStart(32, "0");

/**
 * The background as it runs: the real core host with the matching's ops (match.mjs, from the built package), a
 * fake WASM client whose `match_page` answers from `rule`, and the real handler and frame rules.
 * @param {{
 *   items?: Array<{ id: string, name: string, username?: string, urls: string[] }>,
 *   rule?: (page: string, saved: string) => string | null,
 *   core?: ReturnType<typeof fakeCore>,
 *   frames?: Array<[number, number, string, Record<string, unknown>?]>,
 *   granted?: string[],
 * }} [o] `rule` is the fake core's match: the `how` for a saved address on a page, or null
 */
async function world({ items = [], rule = (page, saved) => (new URL(page).origin === new URL(saved).origin ? "host" : null), core = fakeCore(), frames = [[0, -1, `${LOGIN}/`]], granted = [] } = {}) {
  const source = itemSource(items);
  /** @type {Array<{ url: string, handles: number[] }>} */
  const matches = [];
  const client = createFakeClient({
    vault: {
      page_origin: (/** @type {string} */ url) => core.page_origin(url),
      same_site: (/** @type {string} */ a, /** @type {string} */ b) => core.same_site(a, b),
      display_host: (/** @type {string} */ url) => core.display_host(url),
      match_page: (/** @type {string} */ url, /** @type {number[]} */ handles) => {
        matches.push({ url, handles: [...handles] });
        /** @type {Array<{ handle: number, how: string }>} */
        const out = [];
        for (const handle of handles) {
          assert.ok(source.live.has(handle), "the core is asked about open handles only");
          const how = source.urlsOf(handle).map((saved) => rule(url, saved)).find((h) => h !== null);
          if (how) out.push({ handle, how });
        }
        return out;
      },
    },
  });
  const matchHost = createMatchHost({ engine: () => source });
  const opener = {
    unlock_probe: {
      vault: false,
      worker: /** @type {const} */ ("none"),
      run: async (/** @type {any} */ _c, /** @type {any} */ _a, /** @type {any} */ ctx) => {
        ctx.setUnlocked();
        return { ok: true };
      },
    },
  };
  const webNavigation = navigation(frames);
  const permissions = {
    asked: /** @type {string[][]} */ ([]),
    contains: async (/** @type {{ origins: string[] }} */ { origins }) => {
      permissions.asked.push(origins);
      return origins.every((o) => granted.includes(o));
    },
  };
  /** @type {any} */
  let coreHost = null;
  const call = (/** @type {string} */ op, /** @type {unknown} */ args) => coreHost.call(op, args);
  // The fill flow over the real page matching: it makes the popup's references from the matching's answer.
  const fillHost = createFillHost({
    syncHost: { engine: () => /** @type {any} */ (source) },
    clipboard: { copy: async () => {} },
    scripting: { executeScript: async () => [] },
    tabs: { sendMessage: async () => undefined, create: async () => undefined },
    source: createCandidateSource({ webNavigation, permissions, call }),
  });
  coreHost = createCoreHost({ createClient: () => client, ops: { ...matchHost.ops, ...fillHost.ops, ...opener }, names: [...CORE_OPS, "unlock_probe"] });
  matchHost.attach(coreHost);
  fillHost.attach(coreHost);
  await coreHost.call("unlock_probe");
  const frameCore = {
    page_origin: async (/** @type {string} */ url) => /** @type {any} */ (await call("page_origin", { url })).origin,
    same_site: async (/** @type {string} */ a, /** @type {string} */ b) => /** @type {any} */ (await call("same_site", { a, b })).same,
  };
  /** @param {{ session?: string, frameId?: number }} [o] */
  const list = (o = {}) => candidates(TAB, { coreHost: { call }, frames: (tabId) => fillableFrames(tabId, { webNavigation, core: frameCore }), permissions, ...o });
  /** The popup's list over the candidates handler, in one popup session. @param {string} session @param {Record<string, unknown>} [body] */
  const offer = (session, body = {}) => candidatesHandler.handle({ tab_id: TAB, ...body }, /** @type {any} */ ({ type: "candidates", call, state: () => "unlocked", channel: "ui", sender: {}, session }));
  return { client, coreHost, matchHost, fillHost, source, matches, webNavigation, permissions, call, list, offer, core };
}

// ------------------------------------------------------------ the tests

test("top_frame_candidates_use_the_core_match", async () => {
  // The fake core matches by its own rule, which the extension cannot know: an item is offered exactly when the
  // core says so, also for an address that looks nothing like the page, and not for one that looks the same.
  const rule = (/** @type {string} */ _page, /** @type {string} */ saved) => (saved.includes("core-says-yes") ? "domain" : null);
  const items = [
    { id: itemId(1), name: "Looks the same", username: "ola", urls: [`${LOGIN}/`] },
    { id: itemId(2), name: "The core matched it", username: "kari", urls: ["https://core-says-yes.example/"] },
    { id: itemId(3), name: "No address", urls: [] },
  ];
  const w = await world({ items, rule });
  const list = await w.list({ session: "s1" });
  assert.deepEqual(list.items.map((i) => [i.name, i.username, i.how, i.frames.map((f) => f.frameId)]), [["The core matched it", "kari", "domain", [0]]]);
  // The list names the item by its id and the frame by the browser's facts: no handle and no reference.
  assert.deepEqual(list.items[0].frames, [{ frameId: 0, documentId: "doc-0", url: `${LOGIN}/`, origin: LOGIN, ancestors: [] }]);
  assert.equal(list.items[0].itemId, itemId(2));
  assert.equal("ref" in list.items[0], false);
  assert.equal(list.insecure, false);
  assert.deepEqual(list.grant, []);
  // The core was asked with the top's own address, once per batch, about the items that have an address.
  assert.deepEqual(w.matches.map((m) => m.url), [`${LOGIN}/`]);
  assert.equal(w.matches[0].handles.length, 2, "an item with no saved address is not even opened");
  assert.equal(w.source.opened, w.source.closed, "every handle is closed");

  // frames.mjs and match.mjs have no matching rule of their own: no URL is read there, only handed to the core.
  for (const file of ["src/background/frames.mjs", "src/background/match.mjs"]) {
    const code = readFileSync(join(extensionRoot, file), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
    assert.doesNotMatch(code, /new URL\(|\.hostname|\.host\b|\.split\(/, file);
  }
  // The batches: 150 items are opened 64 at a time, every handle closed after its batch, the best kept per item.
  const many = Array.from({ length: 150 }, (_, i) => ({ id: itemId(1000 + i), name: `Item ${String(i).padStart(3, "0")}`, urls: [`${LOGIN}/`] }));
  const w2 = await world({ items: many });
  const all = await w2.list();
  assert.equal(all.items.length, 100, "a list holds the best 100");
  assert.deepEqual(w2.matches.map((m) => m.handles.length), [64, 64, 22]);
  assert.equal(w2.source.opened, 150);
  assert.equal(w2.source.closed, 150);
  assert.equal(w2.source.live.size, 0);
});

test("each_fillable_frame_names_the_documents_above_it_up_to_the_top", async () => {
  // top → 11 (same site) → 13 (same site), and 12 beside 11: each frame carries its chain, the parent first, as the
  // browser gives it (the fill checks the frame's holder in each of these documents).
  const rows = /** @type {Array<[number, number, string]>} */ ([
    [0, -1, `${WWW}/`],
    [11, 0, `${WWW}/outer`],
    [13, 11, `${LOGIN}/inner`],
    [12, 0, `${LOGIN}/beside`],
  ]);
  const frames = await fillableFrames(TAB, { webNavigation: navigation(rows), core: fakeCore({ sameSite: () => true }) });
  assert.deepEqual(Object.fromEntries(frames.map((f) => [f.frameId, f.ancestors])), {
    0: [],
    11: [{ frameId: 0, documentId: "doc-0" }],
    13: [{ frameId: 11, documentId: "doc-11" }, { frameId: 0, documentId: "doc-0" }],
    12: [{ frameId: 0, documentId: "doc-0" }],
  });
  // A document id the browser does not give is left out, and the frame id stays.
  const bare = await fillableFrames(TAB, { webNavigation: navigation([[0, -1, `${WWW}/`, { documentId: undefined }], [11, 0, `${WWW}/x`]]), core: fakeCore({ sameSite: () => true }) });
  assert.deepEqual(bare.find((f) => f.frameId === 11)?.ancestors, [{ frameId: 0 }]);
  // The chain reaches the fill flow through the page matching: the item's frame carries it.
  /** The core host: the display host, and one item that matches frame 13. @param {string} op */
  const call = async (op) =>
    op === "display_host"
      ? { a_label: "www.example.net", unicode: "www.example.net" }
      : { items: [{ item_id: "ab".repeat(16), name: "Login", username: null, how: "host", frame_ids: [13] }], grant_frames: [] };
  const list = await candidates(TAB, { coreHost: { call }, frames: async () => frames, permissions: { contains: async () => true } });
  assert.deepEqual(list.items[0]?.frames.map((f) => f.ancestors), [[{ frameId: 11, documentId: "doc-11" }, { frameId: 0, documentId: "doc-0" }]]);
});

test("same_site_comes_from_the_core", async () => {
  const frames = /** @type {Array<[number, number, string]>} */ ([
    [0, -1, `${WWW}/`],
    [11, 0, `${LOGIN}/frame`],
    [12, 0, "https://evil.test/frame"],
  ]);
  // The core says evil.test is on the site and login.example.net is not: that is what counts.
  const core = fakeCore({ sameSite: (a) => a.startsWith("https://evil.test") || a === WWW });
  const chosen = await fillableFrames(TAB, { webNavigation: navigation(frames), core });
  assert.deepEqual(chosen.map((f) => f.frameId), [0, 12]);
  assert.deepEqual(core.calls.filter(([op]) => op === "same_site").map(([, args]) => args), [
    [LOGIN, WWW],
    ["https://evil.test", WWW],
  ], "every frame below the top is asked about against the top, with the origins the core gave");
  // The other answer of the core turns it round.
  const other = await fillableFrames(TAB, { webNavigation: navigation(frames), core: fakeCore({ sameSite: (a) => a === LOGIN }) });
  assert.deepEqual(other.map((f) => f.frameId), [0, 11]);
  // frames.mjs has no rule about sites and no list of suffixes.
  const code = readFileSync(join(extensionRoot, "src/background/frames.mjs"), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
  assert.doesNotMatch(code, /registrable|suffix|\.split\(|lastIndexOf/i);
  assert.match(code, /core\.same_site\(/);
});

test("a_cross_site_frame_gets_no_candidates_even_when_its_origin_matches_an_entry", async () => {
  const items = [{ id: itemId(1), name: "Login", username: "ola", urls: [`${LOGIN}/`] }];
  const w = await world({ items, frames: [[0, -1, "https://evil.test/embed"], [21, 0, `${LOGIN}/`]], granted: [`${LOGIN}/*`] });
  const list = await w.list();
  assert.deepEqual(list.items, []);
  assert.deepEqual(list.grant, [], "a cross-site frame is never offered a grant either");
  // The core was never asked to match the frame's address.
  assert.deepEqual(w.matches.map((m) => m.url), ["https://evil.test/embed"]);
  // Also for the one frame the menu names.
  const menu = await w.list({ frameId: 21 });
  assert.deepEqual(menu.items, []);
  // A frame inside a cross-site frame that is on the top's site again is refused as well.
  const w2 = await world({ items, frames: [[0, -1, `${WWW}/`], [31, 0, "https://evil.test/embed"], [32, 31, `${LOGIN}/`]], granted: [`${LOGIN}/*`] });
  const nested = await w2.list();
  assert.deepEqual(nested.items, []);
  assert.deepEqual((await fillableFrames(TAB, { webNavigation: navigation([[0, -1, `${WWW}/`], [31, 0, "https://evil.test/embed"], [32, 31, `${LOGIN}/`]]), core: fakeCore() })).map((f) => f.frameId), [0]);
});

test("a_same_site_frame_with_another_origin_asks_for_its_host_permission_in_the_grant_tab", async () => {
  const items = [{ id: itemId(1), name: "Login", username: "ola", urls: [`${LOGIN}/`] }];
  const frames = /** @type {Array<[number, number, string]>} */ ([[0, -1, `${WWW}/`], [41, 0, `${LOGIN}/`]]);
  const w = await world({ items, frames });
  const before = await w.list({ session: "s1" });
  // Not covered by activeTab (the top's origin): nothing is offered in the frame. Matching needs no permission, so
  // the frame is matched, and because an item matches it the list names it for the grant.
  assert.deepEqual(before.items, []);
  assert.deepEqual(before.grant, [{ origin: LOGIN, host: { a_label: "login.example.net", unicode: "login.example.net" } }]);
  assert.deepEqual(w.permissions.asked, [["https://login.example.net/*"]]);
  assert.deepEqual(w.matches.map((m) => m.url), [`${WWW}/`, `${LOGIN}/`], "the frame's own address is matched");
  // The popup's list gets no reference for a frame that waits for its permission.
  const popupBefore = await w.offer("a".repeat(32));
  assert.deepEqual(popupBefore.handles, []);
  assert.equal(w.fillHost.refs.size(), 0);

  // A same-site frame of another origin that no item matches asks for nothing (no permission without a use).
  const idle = await world({ items: [{ id: itemId(5), name: "Shop", urls: ["https://shop.example.net/"] }], frames });
  const quiet = await idle.list();
  assert.deepEqual(quiet.grant, []);
  assert.deepEqual(quiet.items, []);
  // ... and the grant tab refuses that origin: no list named it.
  const idleCheck = await grantHandler.handle({ origin: LOGIN }, /** @type {any} */ ({ type: "grant_check", call: idle.call, state: () => "unlocked", channel: "ui", sender: {} }));
  assert.deepEqual(idleCheck, { ok: false, reason: "origin_invalid" });

  // The grant tab is opened for the origin, checks it with the core and asks for the host's pattern on a click.
  const fake = createFakeBrowser();
  const url = grantUrl(fake.runtime.getURL, LOGIN);
  assert.equal(url, `${fake.base}pages/grant.html?origin=https%3A%2F%2Flogin.example.net`);
  const origin = originParam(new URL(url).search);
  assert.equal(origin, LOGIN);
  /** @type {Array<{ origins: string[] }>} */
  const requested = [];
  const handlerCtx = { type: "grant_check", call: w.call, state: () => "unlocked", channel: "ui", sender: {} };
  const flow = createGrantFlow({
    request: async (type, body) => {
      encode(type, body);
      const reply = await grantHandler.handle(body, /** @type {any} */ ({ ...handlerCtx, type }));
      encode(type, reply, { reply: true, id: "x1" });
      return reply;
    },
    requestPermission: async (wanted) => {
      requested.push(wanted);
      return true;
    },
  });
  const checked = await flow.check(origin);
  assert.deepEqual(checked, { ok: true, origin: LOGIN, host: { a_label: "login.example.net", unicode: "login.example.net" }, pattern: "https://login.example.net/*" });
  assert.equal(await flow.grant(checked), "granted");
  assert.deepEqual(requested, [{ origins: ["https://login.example.net/*"] }]);
  assert.equal(permissionPattern(/** @type {any} */ (checked).host), "https://login.example.net/*");

  // Only an https origin exactly as the core writes it is checked; anything else asks for nothing.
  for (const bad of ["http://login.example.net", `${LOGIN}/`, `${LOGIN}/path`, "null", "https://LOGIN.example.net", "javascript:alert(1)"]) {
    const refused = await flow.check(bad);
    assert.equal(refused.ok, false, bad);
    assert.equal(await flow.grant(refused), "refused", bad);
  }
  assert.equal(requested.length, 1);
  assert.equal(await flow.check(null).then((c) => c.ok), false);
  assert.equal(originParam("?origin=a&origin=b"), null, "two origins name none");
  assert.equal(originParam(""), null);

  // With the permission, the frame's item is offered for the frame.
  const w2 = await world({ items, frames, granted: ["https://login.example.net/*"] });
  const after = await w2.list();
  assert.deepEqual(after.grant, []);
  assert.deepEqual(after.items.map((i) => [i.name, i.frames.map((f) => f.frameId)]), [["Login", [41]]]);
  // An item that matches the top by its registrable domain and the frame by its host is offered for the frame,
  // where its form is: the closest answer of the core wins. On a tie every frame that ties is named, the top first.
  const rule = (/** @type {string} */ page, /** @type {string} */ saved) => (new URL(page).host === new URL(saved).host ? "host" : siteOf(page) === siteOf(saved) ? "domain" : null);
  const both = await (await world({ items, frames, granted: ["https://login.example.net/*"], rule })).list();
  assert.deepEqual(both.items.map((i) => [i.name, i.how, i.frames.map((f) => f.frameId)]), [["Login", "host", [41]]]);
  const tie = await (await world({ items: [{ id: itemId(9), name: "Site", urls: ["https://shop.example.net/"] }], frames, granted: ["https://login.example.net/*"], rule })).list();
  assert.deepEqual(tie.items.map((i) => [i.how, i.frames.map((f) => f.frameId)]), [["domain", [0, 41]]]);
  // A frame of the top's own origin needs no grant (activeTab covers it), and nothing is asked.
  const w3 = await world({ items, frames: [[0, -1, `${LOGIN}/`], [42, 0, `${LOGIN}/inner`]] });
  const own = await w3.list();
  assert.deepEqual(w3.permissions.asked, []);
  assert.deepEqual(own.items.map((i) => i.frames.map((f) => f.frameId)), [[0, 42]], "a frame of the top's origin ties with the top");
  // Each item once, with at most 4 frames, the top first.
  const many = await world({ items, frames: [[0, -1, `${LOGIN}/`], ...[51, 52, 53, 54, 55].map((id) => /** @type {[number, number, string]} */ ([id, 0, `${LOGIN}/f${id}`]))] });
  const listed = await many.list();
  assert.equal(listed.items.length, 1);
  assert.deepEqual(listed.items[0].frames.map((f) => f.frameId), [0, 51, 52, 53]);
});

test("opaque_frames_and_frames_with_an_http_ancestor_are_skipped", async () => {
  /** @param {Array<[number, number, string, Record<string, unknown>?]>} rows @param {any} [core] */
  const ids = async (rows, core = fakeCore({ sameSite: () => true })) => (await fillableFrames(TAB, { webNavigation: navigation(rows), core })).map((f) => f.frameId);
  // Opaque and special addresses: the core gives them no origin.
  assert.deepEqual(await ids([
    [0, -1, `${LOGIN}/`],
    [1, 0, "about:blank"],
    [2, 0, "about:srcdoc"],
    [3, 0, "data:text/html,<input type=password>"],
    [4, 0, `blob:${LOGIN}/9f1c`],
    [5, 0, "javascript:''"],
    [6, 0, "file:///etc/passwd"],
    [7, 0, `${LOGIN}/ok`],
  ]), [0, 7]);
  // An insecure frame or ancestor: an http frame (also in an http top, also when the core calls it the same site),
  // an https frame below an http top, an https frame below an http frame. The core's same_site says yes to all.
  assert.deepEqual(await ids([[0, -1, "http://www.example.net/"], [1, 0, "http://login.example.net/"], [2, 0, `${LOGIN}/`]]), [0]);
  assert.deepEqual(await ids([[0, -1, `${WWW}/`], [1, 0, "http://login.example.net/"], [2, 1, `${LOGIN}/`]]), [0]);
  // A frame inside an opaque frame, and a frame whose parent the browser does not list.
  assert.deepEqual(await ids([[0, -1, `${WWW}/`], [1, 0, "about:blank"], [2, 1, `${LOGIN}/`], [3, 99, `${LOGIN}/`]]), [0]);
  // A frame that failed to load, a top that is no web page, a top that is not frame 0, a list with a frame twice.
  assert.deepEqual(await ids([[0, -1, `${WWW}/`], [1, 0, `${LOGIN}/`, { errorOccurred: true }]]), [0]);
  assert.deepEqual(await ids([[0, -1, "about:addons"], [1, 0, `${LOGIN}/`]]), []);
  assert.deepEqual(await ids([[0, 3, `${WWW}/`]]), []);
  assert.deepEqual(await ids([[0, -1, `${WWW}/`], [1, 0, `${LOGIN}/`], [1, 0, "https://evil.test/"]]), []);
  assert.deepEqual(await ids([]), []);
  // Loopback counts as secure: an http loopback page may frame a loopback page.
  assert.deepEqual(await ids([[0, -1, "http://127.0.0.1/"], [1, 0, "http://127.0.0.1/t/login"]]), [0, 1]);
  assert.deepEqual(await ids([[0, -1, "http://localhost:8080/"], [1, 0, "http://localhost:8080/login"]]), [0, 1]);
  for (const secure of ["https://a.example", "http://localhost", "http://localhost:3000", "http://127.0.0.1", "http://127.255.0.9:81", "http://[::1]", "http://[::1]:8080"]) {
    assert.equal(isSecureOrigin(secure), true, secure);
  }
  for (const insecure of ["http://a.example", "http://localhost.evil.test", "http://127.0.0.1.evil.test", "http://128.0.0.1", "http://[::2]", "http://192.0.2.1", "null", "", "ws://localhost"]) {
    assert.equal(isSecureOrigin(insecure), false, insecure);
  }
  // At most MAX_FRAMES frames are offered, the top first.
  const crowd = /** @type {Array<[number, number, string]>} */ ([[0, -1, `${LOGIN}/`], ...Array.from({ length: 50 }, (_, i) => /** @type {[number, number, string]} */ ([i + 1, 0, `${LOGIN}/f${i}`]))]);
  const capped = await ids(crowd);
  assert.equal(capped.length, MAX_FRAMES);
  assert.equal(capped[0], 0);
  // A tab the browser does not know, and a browser that throws.
  assert.deepEqual(await fillableFrames(99, { webNavigation: navigation([[0, -1, `${LOGIN}/`]]), core: fakeCore() }), []);
  assert.deepEqual(await fillableFrames(TAB, { webNavigation: { getAllFrames: async () => { throw new Error("no tab"); } }, core: fakeCore() }), []);
  // The list for such a tab is empty and names no host.
  const w = await world({ frames: [[0, -1, "about:blank"]] });
  assert.deepEqual(await w.list(), { host: null, insecure: false, items: [], grant: [] });
});

test("sandboxed_frame_with_https_url_is_refused_via_self_origin", async () => {
  // The browser's facts cannot show the sandbox: the frame has an https address and the core gives it an origin.
  const frames = await fillableFrames(TAB, { webNavigation: navigation([[0, -1, `${LOGIN}/t/frames-opaque.html`], [51, 0, `${LOGIN}/t/sandboxed-login.html`]]), core: fakeCore() });
  const sandboxed = /** @type {import("../../src/background/frames.mjs").FillableFrame} */ (frames.find((f) => f.frameId === 51));
  assert.equal(sandboxed.origin, LOGIN);
  // The fill script's own `self.origin` is "null" there: the frame is refused.
  assert.equal(confirmFrame(sandboxed, "null"), false);
  // It can only narrow: another origin refuses, and the same one confirms what the browser said.
  assert.equal(confirmFrame(sandboxed, "https://evil.test"), false);
  assert.equal(confirmFrame(sandboxed, ""), false);
  assert.equal(confirmFrame(sandboxed, /** @type {any} */ (undefined)), false);
  assert.equal(confirmFrame(sandboxed, LOGIN), true);
  assert.equal(confirmFrame({ ...sandboxed, origin: "null" }, "null"), false, "two opaque origins are not the same");
});

test("http_page_gets_only_http_entries_and_the_insecure_flag", async () => {
  // The fake core's rule: the scheme and the origin must be equal (the real core says the same, section 10.4).
  const items = [
    { id: itemId(1), name: "Https entry", urls: [`${LOGIN}/`] },
    { id: itemId(2), name: "Http entry", urls: ["http://login.example.net/"] },
  ];
  const w = await world({ items, frames: [[0, -1, "http://login.example.net/"]] });
  const list = await w.list();
  assert.equal(list.insecure, true);
  assert.deepEqual(list.items.map((i) => i.name), ["Http entry"]);
  // The page's own address went to the core: the extension adds no exception for http.
  assert.deepEqual(w.matches.map((m) => m.url), ["http://login.example.net/"]);
  // The same over https: secure, only the https entry.
  const s = await (await world({ items, frames: [[0, -1, `${LOGIN}/`]] })).list();
  assert.equal(s.insecure, false);
  assert.deepEqual(s.items.map((i) => i.name), ["Https entry"]);
  // Loopback over http is secure: no warning.
  const loop = await (await world({ items: [{ id: itemId(3), name: "Local", urls: ["http://127.0.0.1/"] }], frames: [[0, -1, "http://127.0.0.1/"]] })).list();
  assert.equal(loop.insecure, false);
  assert.deepEqual(loop.items.map((i) => i.name), ["Local"]);
  // The flag reaches the popup on the wire, on the list and on each row.
  const reply = decode(encode("candidates", await w.offer("b".repeat(32)), { reply: true, id: "r1" }), UI_TYPES, { reply: true }).body;
  assert.equal(reply.insecure, true);
  assert.deepEqual(reply.handles.map((/** @type {any} */ h) => [h.name, h.insecure]), [["Http entry", true]]);
});

test("refs_are_random_per_popup_session_and_handles_never_leave_the_core_host", async () => {
  const items = [
    { id: itemId(1), name: "Ola", username: "ola", urls: [`${LOGIN}/`] },
    { id: itemId(2), name: "Kari", urls: [`${LOGIN}/`] },
  ];
  const w = await world({ items });
  const sa = "a".repeat(32);
  const sb = "b".repeat(32);
  const a = await w.offer(sa);
  const b = await w.offer(sb);
  assert.equal(a.handles.length, 2);
  for (const item of [...a.handles, ...b.handles]) {
    assert.match(item.ref, /^[0-9a-f]{32}$/);
    assert.equal(items.some((i) => i.id === item.ref), false, "a reference is not the item id");
  }
  assert.deepEqual(new Set([...a.handles, ...b.handles].map((i) => i.ref)).size, 4, "each session gets references of its own");
  assert.equal(a.handles.find((/** @type {any} */ i) => i.name === "Kari")?.username, undefined, "no user name is left out");

  // A reference names its item, its tab and its frames, in its own session only.
  const ref = a.handles[0].ref;
  assert.deepEqual(w.fillHost.refs.get(sa, ref), { purpose: "fill", itemId: itemId(2), tabId: TAB, frames: [{ frameId: 0, documentId: "doc-0", origin: LOGIN }] });
  assert.equal(w.fillHost.refs.get(sb, ref), null);
  assert.equal(w.fillHost.refs.get(sa, ref.toUpperCase()), null);
  // A new list in the same session keeps the same reference for the same item and frames.
  const a2 = await w.offer(sa);
  assert.equal(a2.handles[0].ref, ref);
  // A lock forgets every reference.
  await w.coreHost.lock("manual");
  assert.equal(w.fillHost.refs.size(), 0);
  assert.equal(w.fillHost.refs.get(sb, b.handles[0].ref), null);

  // Nothing of a handle leaves the core host: the op's answer has no handle, and every handle is closed.
  assert.equal(w.source.opened, 6);
  assert.equal(w.source.closed, 6);
  const handles = w.matches.flatMap((m) => m.handles);
  const text = JSON.stringify([a, b, a2]).replace(/"ref":"[0-9a-f]{32}"/g, "");
  assert.doesNotMatch(text, /"handle"/);
  for (const h of handles) assert.equal(new RegExp(`\\b${h}\\b`).test(text), false, `handle ${h} in the answer`);
  // A locked vault refuses the match without opening anything.
  await assert.rejects(w.list(), (/** @type {any} */ e) => e.code === "vault_locked");
  assert.equal(w.source.opened, 6);
  // An item that cannot be opened is left out, and the rest is still closed.
  const w3 = await world({ items });
  const realOpen = w3.source.open.bind(w3.source);
  w3.source.open = /** @type {any} */ (async (/** @type {string} */ id) => {
    if (id === itemId(1)) throw Object.assign(new Error("damaged"), { code: "damaged" });
    return realOpen(id);
  });
  assert.deepEqual((await w3.list()).items.map((i) => i.name), ["Kari"]);
  assert.equal(w3.source.opened, w3.source.closed);

  // Over the router: each UI port is its own session, so two popups never share references.
  const fake = createFakeBrowser();
  const clock = createClock();
  const lock = createLock({ ...createAlarmsAndIdle(), storageSession: createSessionStorage(), now: clock.now, coreHost: w.coreHost });
  /** @type {string[]} */
  const sessions = [];
  const router = createRouter({
    runtime: fake.runtime,
    lock,
    coreHost: w.coreHost,
    handlers: [{ types: ["candidates"], channel: "ui", handle: async (/** @type {any} */ _b, /** @type {any} */ ctx) => { sessions.push(ctx.session); return { handles: [], insecure: false, grant: [] }; } }],
  });
  // The router checks the lock before a message that needs the vault: open it again (with a deadline).
  await w.coreHost.call("unlock_probe");
  lock.touch();
  await new Promise((resolve) => setTimeout(resolve, 0));
  const one = createPort(UI_PORT, extensionPageSender(fake, "pages/popup.html"));
  const two = createPort(UI_PORT, extensionPageSender(fake, "pages/popup.html"));
  router.onConnect(one);
  router.onConnect(two);
  await one.send(encode("candidates", { tab_id: TAB }));
  await one.send(encode("candidates", { tab_id: TAB }));
  await two.send(encode("candidates", { tab_id: TAB }));
  assert.equal(sessions.length, 3);
  assert.match(sessions[0], /^[0-9a-f]{32}$/);
  assert.equal(sessions[0], sessions[1], "one port is one session");
  assert.notEqual(sessions[0], sessions[2], "another port is another session");
});

test("the_host_shown_comes_from_display_host_not_from_the_tab_title", async () => {
  // The core keeps the A-label of a label that mixes scripts; the title of the page says something else.
  const core = fakeCore({ display: (url) => (url.includes("xn--exmple-4nf") ? { a_label: "login.xn--exmple-4nf.net", unicode: "login.xn--exmple-4nf.net" } : { a_label: "login.xn--80ak6aa92e.net", unicode: "login.аррӏе.net" }) });
  const w = await world({ core, frames: [[0, -1, "https://login.xn--exmple-4nf.net/", { title: "Faithful Ferret - Unlock your vault" }]] });
  const list = await w.list();
  assert.deepEqual(list.host, { a_label: "login.xn--exmple-4nf.net", unicode: "login.xn--exmple-4nf.net" });
  assert.deepEqual(core.calls.filter(([op]) => op === "display_host").map(([, args]) => args), [["https://login.xn--exmple-4nf.net/"]]);
  const w2 = await world({ core: fakeCore({ display: () => ({ a_label: "login.xn--80ak6aa92e.net", unicode: "login.аррӏе.net" }) }), frames: [[0, -1, "https://login.xn--80ak6aa92e.net/"]] });
  assert.deepEqual((await w2.list()).host, { a_label: "login.xn--80ak6aa92e.net", unicode: "login.аррӏе.net" });
  // The handler's reply carries the core's host and nothing of a tab: frames.mjs never asks for one.
  const code = readFileSync(join(extensionRoot, "src/background/frames.mjs"), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
  assert.doesNotMatch(code, /\btitle\b|tabs\.|getTab|\.favIconUrl/);
  const handlerCode = readFileSync(join(extensionRoot, "src/background/fillFlow.mjs"), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
  assert.doesNotMatch(handlerCode, /\btitle\b|\.tabs\b/);
});

test("the_candidates_handler_answers_on_the_wire_and_its_reply_fits_the_protocol", async () => {
  const items = [
    { id: itemId(1), name: "Ola", username: "ola", urls: [`${LOGIN}/`] },
    { id: itemId(2), name: "N".repeat(300), urls: [`${LOGIN}/`] },
  ];
  const w = await world({ items, frames: [[0, -1, `${WWW}/`], [61, 0, `${LOGIN}/`]], rule: () => "host" });
  const session = "c".repeat(32);
  const reply = await w.offer(session);
  const wire = decode(encode("candidates", reply, { reply: true, id: "r1" }), UI_TYPES, { reply: true }).body;
  assert.deepEqual(wire.host, { a_label: "www.example.net", unicode: "www.example.net" });
  // The frame of another origin waits for its permission: the items are not offered there yet, the grant names it.
  assert.equal(wire.handles.length, 2);
  assert.deepEqual(wire.handles.map((/** @type {any} */ h) => h.frame_id), [0, 0]);
  assert.equal(Math.max(...wire.handles.map((/** @type {any} */ h) => h.name.length)), 128, "a long name is cut for the list");
  assert.deepEqual(wire.grant.map((/** @type {any} */ g) => g.origin), [LOGIN]);
  for (const item of wire.handles) assert.equal(w.fillHost.refs.get(session, item.ref)?.purpose, "fill");
  // Only the frame the menu names.
  const one = await w.offer(session, { frame_id: 61 });
  assert.deepEqual(one.handles, []);
  assert.deepEqual(one.grant.map((/** @type {any} */ g) => g.origin), [LOGIN]);
  assert.deepEqual(candidatesHandler.types, ["candidates"]);
  assert.equal(candidatesHandler.channel, "ui");
  assert.deepEqual(grantHandler.types, ["grant_check"]);
  assert.equal(grantHandler.channel, "ui");
});

test("the_grant_tab_asks_only_for_an_origin_a_list_named_and_only_for_a_while", async () => {
  const clock = { t: 1_000_000 };
  const grants = createGrantList({ now: () => clock.t });
  assert.equal(grants.has("https://login.example.net"), false);
  grants.add("https://login.example.net");
  assert.equal(grants.has("https://login.example.net"), true);
  assert.equal(grants.has("https://other.example.net"), false);
  assert.equal(grants.has(/** @type {any} */ (undefined)), false);
  // Ten minutes, then it is gone; a clock that went back forgets it too.
  clock.t += 10 * 60_000;
  assert.equal(grants.has("https://login.example.net"), true);
  clock.t += 1;
  assert.equal(grants.has("https://login.example.net"), false);
  grants.add("https://login.example.net");
  clock.t -= 5;
  assert.equal(grants.has("https://login.example.net"), false);
  // At most 32, the oldest first out.
  for (let i = 0; i < 40; i += 1) grants.add(`https://h${i}.example.net`);
  assert.equal(grants.has("https://h7.example.net"), false);
  assert.equal(grants.has("https://h8.example.net"), true);
  assert.equal(grants.has("https://h39.example.net"), true);

  // Through the background: listed by a list, refused once the vault locks.
  const items = [{ id: itemId(1), name: "Login", urls: [`${LOGIN}/`] }];
  const w = await world({ items, frames: [[0, -1, `${WWW}/`], [41, 0, `${LOGIN}/`]] });
  const check = (/** @type {string} */ origin) => grantHandler.handle({ origin }, /** @type {any} */ ({ type: "grant_check", call: w.call, state: () => "unlocked", channel: "ui", sender: {} }));
  assert.equal((await check(LOGIN)).ok, false, "not before a list named it");
  await w.list();
  assert.equal((await check(LOGIN)).ok, true);
  assert.equal((await check("https://shop.example.net")).ok, false, "a canonical https origin no list named");
  await w.coreHost.lock("manual");
  assert.equal((await check(LOGIN)).ok, false, "a lock forgets the named origins");
});
