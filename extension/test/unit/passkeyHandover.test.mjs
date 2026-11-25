// Handing a page's passkey request over to the browser (background/passkeyHandover.mjs and the broker's use of it, design document § 9.4):
// the one-time pass that is bound to a document, a kind and a minute, the page's own options reaching the browser, "never on this
// site" going through at once with the click whole, and the hints of a security key.
import assert from "node:assert/strict";
import { test } from "node:test";
import { BROWSER_USES_HINTS, createPassOnce, MAX_PASSES, PASSES_KEY, PASSKEY_PASS_ONCE_MS, withSecurityKeyHint } from "../../src/background/passkeyHandover.mjs";
import { createPasskeyRequests } from "../../src/background/passkeyRequests.mjs";
import { decode, PUSH_TYPES } from "../../src/shared/protocol.mjs";
import { createPasskeyPage } from "./passkeyWorld.mjs";

const RP = "https://rp.example";
const SERVER = "https://vault.example";

/** @param {number} [start] */
function clock(start = 1_000_000) {
  let at = start;
  /** @type {Map<number, { fn: () => void, at: number }>} */
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
    /** @param {number} to */
    set(to) {
      at = to;
    },
    timers: {
      setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => {
        const id = next++;
        pending.set(id, { fn, at: at + ms });
        return id;
      },
      clearTimeout: (/** @type {number} */ id) => void pending.delete(id),
    },
  };
}

const KEY = Object.freeze({ tabId: 4, frameId: 0, documentId: "doc-1", origin: RP, kind: "get" });

test("the_pass_once_window_is_one_call_of_the_same_kind_same_tab_frame_document_and_origin_within_60_s", () => {
  const c = clock();
  const passes = createPassOnce({ now: c.now });
  assert.equal(PASSKEY_PASS_ONCE_MS, 60_000);
  assert.equal(passes.take(KEY), false, "nothing granted: nothing passes");
  passes.grant(KEY);
  // Every part of the binding counts: another kind, tab, frame, document or origin is not let through, and does not use the pass up.
  for (const other of [{ kind: "create" }, { tabId: 5 }, { frameId: 3 }, { documentId: "doc-2" }, { origin: "https://rp-b.example" }]) {
    assert.equal(passes.take({ ...KEY, ...other }), false, JSON.stringify(other));
  }
  assert.deepEqual(passes.pendingIn(4)?.kind, "get");
  assert.equal(passes.pendingIn(5), null);
  // The same call: once.
  assert.equal(passes.take(KEY), true);
  assert.equal(passes.take(KEY), false, "only once");
  assert.equal(passes.pendingIn(4), null);
  // Not after the minute (the 60 s are the pass's life, from the moment it was granted).
  passes.grant(KEY);
  c.advance(PASSKEY_PASS_ONCE_MS - 1);
  assert.notEqual(passes.pendingIn(4), null, "still there one millisecond before the end");
  c.advance(1);
  assert.equal(passes.take(KEY), false, "gone at 60 s");
  assert.equal(passes.size(), 0);
  // A clock that went far back does not make a pass last longer than a minute.
  passes.grant(KEY);
  c.set(c.now() - 10 * PASSKEY_PASS_ONCE_MS);
  assert.equal(passes.take(KEY), false);
  // A second grant for the same document and kind replaces the first (one pass, not two).
  c.set(5_000_000);
  passes.grant(KEY);
  passes.grant(KEY);
  assert.equal(passes.size(), 1);
  assert.equal(passes.take(KEY), true);
  assert.equal(passes.take(KEY), false);
  // The number of passes is capped, the oldest goes first.
  for (let i = 0; i < MAX_PASSES + 5; i += 1) passes.grant({ ...KEY, documentId: `d${i}` });
  assert.equal(passes.size(), MAX_PASSES);
  assert.equal(passes.take({ ...KEY, documentId: "d0" }), false);
  assert.equal(passes.take({ ...KEY, documentId: `d${MAX_PASSES + 4}` }), true);
  // A closed tab and a navigated document lose theirs.
  passes.clear();
  passes.grant(KEY);
  passes.grant({ ...KEY, tabId: 9 });
  passes.forgetTab(4);
  assert.equal(passes.take(KEY), false);
  assert.equal(passes.take({ ...KEY, tabId: 9 }), true);
  passes.grant(KEY);
  passes.forgetDocument(4, 0, "doc-1");
  assert.equal(passes.take(KEY), false);
});

test("security_key_adds_hints_only_when_supported", () => {
  const options = Object.freeze({ challenge: "abc", hints: Object.freeze(["hybrid", "security-key", "client-device"]) });
  // The probe found that Firefox shows no routing by hints: this build does not add them.
  assert.equal(BROWSER_USES_HINTS, false);
  assert.equal(withSecurityKeyHint(options), options, "unsupported: the very same object, untouched");
  assert.equal(withSecurityKeyHint(options, false), options);
  // Where the browser uses them: "security-key" first, the page's own hints after, no repeat, nothing else changed.
  const hinted = withSecurityKeyHint(options, true);
  assert.deepEqual(hinted, { challenge: "abc", hints: ["security-key", "hybrid", "client-device"] });
  assert.deepEqual(options.hints, ["hybrid", "security-key", "client-device"], "the page's own object is not changed");
  assert.deepEqual(withSecurityKeyHint({ challenge: "abc" }, true), { challenge: "abc", hints: ["security-key"] });
  assert.deepEqual(withSecurityKeyHint({ challenge: "abc", hints: "nonsense" }, true), { challenge: "abc", hints: ["security-key"] });
  // Anything that is not an options object is left alone.
  assert.equal(withSecurityKeyHint(/** @type {any} */ (null), true), null);
});

/**
 * The real broker joined to the real scripts of a fake page: what the bridge sends goes to the broker, and the broker's pushes go
 * back to the bridge.
 * @param {{ never?: (rpId: string) => boolean }} [o]
 */
function joined({ never = () => false } = {}) {
  const page = createPasskeyPage({ origin: RP });
  const c = clock();
  const opened = /** @type {string[]} */ ([]);
  const marks = /** @type {Array<[number, boolean]>} */ ([]);
  const focused = /** @type {number[]} */ ([]);
  /** @type {Array<{ type: string, body: any }>} */
  const pushed = [];
  /** @type {Promise<unknown>} */
  let delivering = Promise.resolve();
  const requests = createPasskeyRequests({
    tabs: {
      sendMessage: async (_tabId, raw) => {
        const { type, body } = decode(raw, PUSH_TYPES);
        pushed.push({ type, body });
        delivering = delivering.then(() => page.push(type, body));
      },
      update: async (tabId) => void focused.push(tabId),
    },
    frames: { getAllFrames: async () => [{ frameId: 0, parentFrameId: -1, url: `${RP}/login`, documentId: "doc-1" }] },
    windows: {
      open: async (id) => {
        opened.push(id);
        return 100 + opened.length;
      },
      close: async () => {},
    },
    badge: { passkey: (tabId, on) => void marks.push([tabId, on]) },
    servers: { current: async () => ({ origin: SERVER, live: true }) },
    storageLocal: { get: async () => ({ use_passkeys: true }) },
    permissions: { contains: async () => true },
    never: { has: async (rpId) => never(rpId), add: async () => {} },
    release: true,
    now: c.now,
    timers: c.timers,
  });
  /** The bridge's last request goes to the broker, as the router would hand it over. */
  const deliverLast = async () => {
    await page.flush();
    const message = [...page.sent].reverse().find((m) => m.type === "passkey_request");
    assert.ok(message, "the bridge sent a request");
    const result = await requests.open({ tabId: 4, frameId: 0, documentId: "doc-1", url: `${RP}/login`, origin: RP }, message.body);
    await delivering;
    await page.flush();
    return { result, body: message.body };
  };
  const GET = '(() => { globalThis.out = { done: false }; globalThis.lastOptions = { publicKey: { challenge: new Uint8Array(32).fill(9), rpId: "rp.example", userVerification: "required" } }; navigator.credentials.get(globalThis.lastOptions).then((v) => { out.done = true; out.value = v; }, (e) => { out.done = true; out.error = e.name; }); })()';
  return { page, c, requests, opened, marks, focused, pushed, deliverLast, GET, settle: async () => { await delivering; await page.flush(); } };
}

test("browser_choice_calls_the_original_with_the_sites_own_options", async () => {
  const w = joined();
  // The page asks; Ferret's window opens; the person chooses "the browser".
  w.page.page(w.GET);
  const first = await w.deliverLast();
  const id = /** @type {any} */ (first.result).request_id;
  assert.equal(w.opened.length, 1, "the window opened");
  assert.equal(w.page.nativeCalls.length, 0, "the browser is not called while the person chooses");
  await /** @type {any} */ (w.requests.ops).passkey_pending.run(null, { request_id: id, session: "win" });
  assert.deepEqual(await /** @type {any} */ (w.requests.ops).passkey_browser.run(null, { request_id: id, session: "win" }), { ok: true });
  await w.settle();
  // The call that opened the window ends as the browser ends one the person left; the browser is not called at that moment.
  assert.deepEqual(w.pushed.map((p) => [p.type, p.body.once]), [["passkey_handover", true]]);
  assert.equal(w.page.page("out.error"), "NotAllowedError");
  assert.equal(w.page.nativeCalls.length, 0);
  assert.deepEqual(w.focused, [4], "the page's tab is brought to the front");
  assert.deepEqual(w.marks.at(-1), [4, true], "the toolbar button says: click the page again");
  // The person clicks the page's button again: the same kind from the same document goes to the original untouched, with the
  // page's own options object, and nothing is asked of the person.
  w.page.page(w.GET);
  const second = await w.deliverLast();
  assert.equal(/** @type {any} */ (second.result).reason, "pass_once");
  assert.equal(w.opened.length, 1, "no second window");
  assert.equal(w.page.nativeCalls.length, 1, "the browser's own function was called once");
  assert.equal(w.page.nativeCalls[0].args[0], w.page.page("globalThis.lastOptions"), "with the page's own options");
  assert.equal(w.page.page("out.value"), "browser");
  assert.deepEqual(w.marks.at(-1), [4, false], "the mark goes when the pass is used");
  // And only once: the third call asks Ferret again.
  w.page.page(w.GET);
  const third = await w.deliverLast();
  assert.ok("request_id" in /** @type {any} */ (third.result));
  assert.equal(w.opened.length, 2);
});

test("an_unused_pass_ends_after_a_minute_and_takes_its_mark_off", async () => {
  const w = joined();
  w.page.page(w.GET);
  const id = /** @type {any} */ ((await w.deliverLast()).result).request_id;
  await /** @type {any} */ (w.requests.ops).passkey_pending.run(null, { request_id: id, session: "win" });
  await /** @type {any} */ (w.requests.ops).passkey_browser.run(null, { request_id: id, session: "win" });
  assert.deepEqual(w.marks.at(-1), [4, true]);
  assert.deepEqual(w.requests.passPendingFor(4)?.kind, "get");
  w.c.advance(PASSKEY_PASS_ONCE_MS + 5);
  assert.deepEqual(w.marks.at(-1), [4, false], "nobody clicked: the mark is gone");
  assert.equal(w.requests.passPendingFor(4), null);
  // The call after the minute is Ferret's again.
  await w.settle();
  w.page.page(w.GET);
  assert.ok("request_id" in /** @type {any} */ ((await w.deliverLast()).result));
  // A closed tab and a sign-out lose the pass too.
  const x = joined();
  x.page.page(x.GET);
  const xid = /** @type {any} */ ((await x.deliverLast()).result).request_id;
  await /** @type {any} */ (x.requests.ops).passkey_pending.run(null, { request_id: xid, session: "win" });
  await /** @type {any} */ (x.requests.ops).passkey_browser.run(null, { request_id: xid, session: "win" });
  x.requests.onTabRemoved(4);
  assert.equal(x.requests.passPendingFor(4), null);
});

test("never_on_this_site_passes_through_with_the_activation_intact", async () => {
  const w = joined({ never: (rpId) => rpId === "rp.example" });
  w.page.page(w.GET);
  await w.page.flush();
  // The call goes to the browser straight away: no window, no error, no wait for a timer or a pass. Only the turns of the event
  // loop that carry the bridge's message and the answer lie between the click and the browser's own function, so the click's
  // transient activation (a few seconds in Firefox) is whole.
  const before = w.c.now();
  const message = [...w.page.sent].reverse().find((m) => m.type === "passkey_request");
  const result = await w.requests.open({ tabId: 4, frameId: 0, documentId: "doc-1", url: `${RP}/login`, origin: RP }, /** @type {any} */ (message).body);
  await w.settle();
  assert.deepEqual(result, { handover: true, reason: "never" });
  assert.equal(w.c.now(), before, "no clock moved");
  assert.equal(w.opened.length, 0, "no window");
  assert.deepEqual(w.pushed.map((p) => [p.type, p.body.once]), [["passkey_handover", false]], "the browser is called now, not on a second click");
  assert.equal(w.page.nativeCalls.length, 1);
  assert.equal(w.page.nativeCalls[0].args[0], w.page.page("globalThis.lastOptions"), "the page's own options");
  assert.equal(w.page.page("out.value"), "browser");
  assert.equal(w.requests.passPendingFor(4), null, "nothing waits for a second click");
  assert.deepEqual(w.marks, [], "no mark on the toolbar button");
});

test("a_pass_outlives_a_stopped_event_page_through_the_session_storage_and_nothing_else_does", async () => {
  /** @type {Record<string, unknown>} */
  const kept = {};
  const storage = { get: async (/** @type {string} */ key) => (key in kept ? { [key]: structuredClone(kept[key]) } : {}), set: async (/** @type {Record<string, unknown>} */ items) => void Object.assign(kept, structuredClone(items)) };
  const c = clock();
  const first = createPassOnce({ now: c.now, storage });
  await first.ready();
  first.grant(KEY);
  assert.equal(/** @type {any[]} */ (kept[PASSES_KEY]).length, 1, "the pass is written when it is made");
  // The event page stops and a new one starts: the pass is read again, for the same document and kind only, and only once.
  const second = createPassOnce({ now: c.now, storage });
  await second.ready();
  assert.equal(second.take({ ...KEY, documentId: "doc-2" }), false);
  assert.equal(second.take(KEY), true);
  assert.equal(second.take(KEY), false);
  assert.deepEqual(kept[PASSES_KEY], [], "a used pass is gone from the storage too");
  const third = createPassOnce({ now: c.now, storage });
  await third.ready();
  assert.equal(third.take(KEY), false, "and a third page does not find it");
  // It ends at its time wherever it is kept.
  first.grant(KEY);
  c.advance(PASSKEY_PASS_ONCE_MS);
  const late = createPassOnce({ now: c.now, storage });
  await late.ready();
  assert.equal(late.take(KEY), false);
  // Anything in the storage that is not a pass is not read as one.
  kept[PASSES_KEY] = [null, 7, "x", { tabId: "4" }, { ...KEY, until: c.now() + 1000, kind: "other" }, { ...KEY, documentId: "d".repeat(200), until: c.now() + 1000 }, { ...KEY, until: c.now() + 1000 }];
  const odd = createPassOnce({ now: c.now, storage });
  await odd.ready();
  assert.equal(odd.size(), 1, "only the well-formed one");
  assert.equal(odd.take(KEY), true);
  // A storage that fails costs the passes of the stopped page and nothing else: this page's own still work.
  const broken = createPassOnce({ now: c.now, storage: { get: async () => Promise.reject(new Error("no")), set: async () => Promise.reject(new Error("no")) } });
  await broken.ready();
  broken.grant(KEY);
  assert.equal(broken.take(KEY), true);
  const throwing = createPassOnce({ now: c.now, storage: /** @type {any} */ ({ get: async () => ({}), set: () => { throw new Error("no"); } }) });
  await throwing.ready();
  throwing.grant(KEY);
  assert.equal(throwing.take(KEY), true);
});
