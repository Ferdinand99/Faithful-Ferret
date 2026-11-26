// Signing in with a passkey of Ferret (the `passkeys` feature): the get side of the chooser window's operations
// (background/passkeyGet.mjs) over the real request broker, and user verification (background/passkeyVerify.mjs): the one-time
// mark of a request, the recent unlock on a monotonic clock, the order of the ways to verify, `required` / `preferred` /
// `discouraged`, the candidates from the vault, the PRF results, and that a get writes nothing. The core and the vault are fakes
// that answer like the binding for what these tests ask.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createPasskeyGet, getRequestOf, PASSKEY_GET_OPS } from "../../src/background/passkeyGet.mjs";
import { createPasskeyRequests, PASSKEY_WINDOW_OPS } from "../../src/background/passkeyRequests.mjs";
import { createPasskeyVerify, markingUnlocks, passwordCheck, RECENT_UNLOCK_MS, UNLOCK_OPS, VERIFY_METHODS } from "../../src/background/passkeyVerify.mjs";
import { CORE_OPS } from "../../src/background/coreHost.mjs";
import { LOCK_EXEMPT } from "../../src/background/lock.mjs";
import { decode, PUSH_TYPES, UI_TYPES } from "../../src/shared/protocol.mjs";
import { pkg } from "./sessionHelpers.mjs";

/** The window's handler of the test package (its features module is the build's). */
const loadWindowHandler = async () => (await (await pkg()).load("background/handlers/passkeyWindow.handler.mjs")).default;

const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
const RP = "https://rp-a.test";
const SERVER = "https://vault.example";
const SESSION = "s1";
const CHALLENGE = "Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2UtMzI";
const ID = (/** @type {number} */ n) => n.toString(16).padStart(32, "0");
const b64u = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("base64url");
const bytes = (/** @type {number} */ n, /** @type {number} */ fill) => new Uint8Array(n).fill(fill);

/** A few turns of the event loop: the broker's awaits on its fakes settle. */
const flush = async () => {
  for (let i = 0; i < 6; i += 1) await new Promise((r) => setImmediate(r));
};

/**
 * The passkeys of the fake vault: each item's RP ID, credential id, whether it has PRF seeds, and what the vault calls it.
 * @typedef {{ id: string, rp: string, cred: Uint8Array, prf: boolean, name: string, user: string, created: number, passkey?: boolean }} FakeItem
 */
const ITEMS = Object.freeze([
  { id: ID(3), rp: "rp-a.test", cred: bytes(16, 3), prf: true, name: "RP A (work)", user: "anna@rp-a.test", created: 1_700_000_000_000 },
  { id: ID(1), rp: "rp-a.test", cred: bytes(16, 1), prf: false, name: "RP A", user: "anna", created: 1_800_000_000_000 },
  { id: ID(2), rp: "rp-b.test", cred: bytes(16, 2), prf: true, name: "RP B", user: "bob", created: 1_600_000_000_000 },
  { id: ID(4), rp: "", cred: bytes(16, 4), prf: false, name: "A login", user: "", created: 0, passkey: false },
]);

/**
 * The broker, the verification, the get operations and the fake vault and core around them.
 * @param {Record<string, any>} [o]
 */
function world(o = {}) {
  /** @type {any[]} */
  const pushed = [];
  /** The two clocks of the five minutes: the monotonic one (`t`) and the wall clock (`w`). */
  const mono = { t: 50_000, w: 1_700_000_000_000 };
  const state = {
    online: true,
    setting: true,
    pin: { set: true, offlineOk: true },
    prf: true,
    pinAttempts: 0,
    /** Writes the vault was asked for (a get must make none). */
    writes: /** @type {string[]} */ ([]),
    /** What the core was asked to sign. */
    signs: /** @type {any[]} */ ([]),
    /** What the core was asked for the candidates. */
    asked: /** @type {any[]} */ ([]),
    closed: 0,
    activeTab: 4,
    top: { url: `${RP}/login`, documentId: "doc-1" },
    /** The windows the broker opened (by request id) and closed. */
    windowsOpened: /** @type {string[]} */ ([]),
    windowsClosed: /** @type {number[]} */ ([]),
    ...o.state,
  };
  const requests = createPasskeyRequests({
    tabs: {
      sendMessage: async (_tabId, raw) => {
        pushed.push(decode(raw, PUSH_TYPES));
      },
      // The active tab of the last focused window (the toolbar panel's tab).
      query: async () => [{ id: state.activeTab }],
    },
    // The tab's top document (a test may move the tab to another site).
    frames: { getAllFrames: async () => [{ frameId: 0, parentFrameId: -1, url: state.top.url, documentId: state.top.documentId }] },
    windows: {
      open: async (/** @type {string} */ id) => (state.windowsOpened.push(id), 101),
      close: async (/** @type {number} */ id) => void state.windowsClosed.push(id),
    },
    servers: { current: async () => ({ origin: SERVER, live: true }) },
    storageLocal: { get: async () => ({ use_passkeys: true }) },
    permissions: { contains: async () => true },
    release: true,
    now: () => mono.w,
    monotonic: () => mono.t,
  });
  const verify = createPasskeyVerify({
    password: { verify: async ({ mp }) => (mp === "right-password" ? { ok: true } : { ok: false, reason: "wrong_credentials" }) },
    pin: {
      status: async () => state.pin,
      verify: async (pin) => {
        state.pinAttempts += 1;
        return pin === "123456" ? { ok: true } : { ok: false, reason: "wrong_pin", left: 5 - state.pinAttempts, wait_ms: 0 };
      },
    },
    prf: {
      available: async () => state.prf,
      verify: async ({ prf_output }) => (prf_output === b64u(bytes(32, 7)) ? { ok: true } : { ok: false, reason: "prf_failed" }),
    },
    settings: { recentAllowed: async () => state.setting },
    marks: { mark: (id, session) => requests.markVerified(id, session), take: (id, session) => requests.takeVerified(id, session) },
    online: async () => state.online,
    now: () => mono.t,
    wall: () => mono.w,
  });
  /** @type {Map<number, FakeItem>} */
  const open = new Map();
  let nextHandle = 10;
  const source = {
    list: () => ITEMS.map((i) => ({ id: i.id, name: i.name, hasPasskey: i.passkey !== false, passkeySite: i.passkey === false ? null : i.rp })),
    open: async (/** @type {string} */ id) => {
      const item = ITEMS.find((i) => i.id === id);
      if (!item) throw Object.assign(new Error("not_found"), { code: "not_found" });
      const handle = nextHandle++;
      open.set(handle, item);
      return { handle, close: async () => void (open.delete(handle), (state.closed += 1)) };
    },
    // The engine's writes: a get reaches none of them.
    update: async () => void state.writes.push("update"),
    create: async () => void state.writes.push("create"),
    remove: async () => void state.writes.push("remove"),
  };
  const client = {
    vault: {
      passkey_candidates: async (/** @type {any} */ caller, /** @type {any} */ request) => {
        state.asked.push({ caller, request });
        const rp = request.rp_id ?? new URL(caller.origin).hostname;
        const allow = request.allow.map((/** @type {Uint8Array} */ a) => b64u(a));
        return [...open].filter(([, i]) => i.rp === rp && (allow.length === 0 || allow.includes(b64u(i.cred)))).map(([h]) => h);
      },
      item_view: async (/** @type {number} */ h) => {
        const i = /** @type {FakeItem} */ (open.get(h));
        return { name: i.name, passkey: { rp_id: i.rp, user_name: i.user, created: i.created, cred_id: i.cred } };
      },
      passkey_get: async (/** @type {number} */ h, /** @type {any} */ request, /** @type {any} */ caller, /** @type {any} */ uv) => {
        const i = /** @type {FakeItem} */ (open.get(h));
        state.signs.push({ item: i.id, uv, caller, prf: request.prf !== undefined });
        if (request.user_verification === "required" && !uv.user_verified) throw Object.assign(new Error("not_allowed"), { code: "not_allowed" });
        // The PRF seed follows UV, and only a passkey made with PRF has seeds.
        const prf = request.prf !== undefined && i.prf ? { first: bytes(32, uv.user_verified ? 0xa1 : 0xb1) } : undefined;
        return { id: i.cred, authenticator_attachment: "platform", authenticator_data: bytes(37, uv.user_verified ? 5 : 1), client_data_json: bytes(64, 9), signature: bytes(70, 8), user_handle: bytes(8, 6), ...(prf ? { prf } : {}) };
      },
    },
  };
  const get = createPasskeyGet({ requests, verify, items: () => source });
  /** A page's get from rp-a.test, owned by the window session. @param {Record<string, any>} [options] */
  const ask = async (options = {}) => {
    const bridgeId = `b${Math.random().toString(16).slice(2, 10)}`;
    const opened = /** @type {any} */ (await requests.open(
      { tabId: 4, frameId: 0, documentId: "doc-1", url: `${RP}/login`, origin: RP },
      { request_id: bridgeId, kind: "get", mediation: "optional", get: { challenge: CHALLENGE, allow_credentials: [], hints: [], extensions: {}, user_verification: "preferred", ...options }, activation: true, policy: true },
    ));
    assert.ok(opened.request_id, JSON.stringify(opened));
    assert.ok(requests.forUi(opened.request_id, SESSION), "the window session owns it");
    return { id: /** @type {string} */ (opened.request_id), bridgeId };
  };
  const ref = (/** @type {string} */ id) => ({ request_id: id, session: SESSION });
  const candidates = (/** @type {string} */ id) => get.ops.passkey_candidates.run(client, { request_id: id, session: SESSION });
  const choose = async (/** @type {string} */ id, /** @type {string} */ itemId = ID(3)) => {
    const reply = await get.ops.passkey_choose.run(client, { request_id: id, session: SESSION, kind: "get", item_id: itemId });
    await flush();
    return reply;
  };
  const verifyOp = (/** @type {string} */ id, /** @type {Record<string, unknown>} */ body) => get.ops.passkey_verify.run(client, { request_id: id, session: SESSION, ...body });
  /** What the page got for its bridge id. @param {string} bridgeId */
  const answerOf = (bridgeId) => pushed.find((p) => p.body.request_id === bridgeId);
  return { requests, verify, get, client, source, state, mono, pushed, ask, ref, candidates, choose, verifyOp, answerOf };
}

// ------------------------------------------------------------------------------------------------- the one-time mark

test("uv_is_true_only_with_a_token_issued_for_this_request", async () => {
  const w = world();
  const first = await w.ask({ user_verification: "required" });
  const second = await w.ask({ user_verification: "required" }).catch(() => null);
  // One modal request per tab: the second one ended at once, so a mark for it can never be issued.
  assert.equal(second, null);
  // No mark, no recent unlock: the core is not asked to sign, and the window is told to verify.
  assert.deepEqual(await w.choose(first.id), { ok: false, reason: "verification_needed" });
  assert.equal(w.state.signs.length, 0);
  // A mark for another session (another window) is no mark for this one.
  assert.equal(w.requests.markVerified(first.id, "s2"), false);
  assert.deepEqual(await w.choose(first.id), { ok: false, reason: "verification_needed" });
  // A failed verification issues nothing.
  assert.deepEqual(await w.verifyOp(first.id, { method: "pin", pin: "000000" }), { ok: false, reason: "wrong_pin", left: 4, wait_ms: 0 });
  assert.deepEqual(await w.choose(first.id), { ok: false, reason: "verification_needed" });
  assert.equal(w.state.signs.length, 0);
  // Verified for this request: UV is true in what the core signs, and the page gets its answer.
  assert.deepEqual(await w.verifyOp(first.id, { method: "pin", pin: "123456" }), { ok: true });
  assert.deepEqual(await w.choose(first.id), { ok: true });
  assert.equal(w.state.signs.length, 1);
  assert.deepEqual(w.state.signs[0].uv, { user_present: true, user_verified: true });
  assert.equal(w.answerOf(first.bridgeId)?.type, "passkey_result");
  // UV is never given from anywhere else: only the window's choice (a get here, a create in background/passkeyFlow.mjs) passes
  // `user_present: true` to the core, with the UV of the one decision of passkeyVerify.mjs.
  const files = ["background/passkeyFlow.mjs", "background/passkeyGet.mjs", "background/passkeyRequests.mjs", "background/passkeyVerify.mjs", "pages/passkeyChooser.mjs", "pages/passkeyFlow.mjs", "pages/passkeyVerify.mjs"];
  const present = files.filter((f) => /user_present:\s*true/.test(readFileSync(join(src, f), "utf8")));
  assert.deepEqual(present, ["background/passkeyFlow.mjs", "background/passkeyGet.mjs"]);
  assert.match(readFileSync(join(src, "background/passkeyGet.mjs"), "utf8"), /user_present: true, user_verified: decided\.uv \}/);
  assert.match(readFileSync(join(src, "background/passkeyFlow.mjs"), "utf8"), /user_present: true, user_verified: decided\.uv \}/);
});

test("a_token_is_used_once_and_dies_with_the_request", async () => {
  const w = world();
  const { id } = await w.ask({ user_verification: "required" });
  assert.deepEqual(await w.verifyOp(id, { method: "password", mp: "right-password" }), { ok: true });
  assert.equal(w.verify.take(w.ref(id)), true);
  assert.equal(w.verify.take(w.ref(id)), false, "used once");
  // A mark that is there when the request ends goes with it.
  assert.deepEqual(await w.verifyOp(id, { method: "password", mp: "right-password" }), { ok: true });
  assert.equal(w.requests.cancel(id, SESSION), true);
  await flush();
  assert.equal(w.verify.take(w.ref(id)), false, "gone with the request");
  assert.deepEqual(await w.verifyOp(id, { method: "password", mp: "right-password" }), { ok: false, reason: "gone" });
  // And at a lock.
  const next = await w.ask({ user_verification: "required" });
  assert.deepEqual(await w.verifyOp(next.id, { method: "pin", pin: "123456" }), { ok: true });
  w.requests.onLock(false);
  w.verify.onLock();
  assert.deepEqual(await w.choose(next.id), { ok: false, reason: "verification_needed" });
});

// ------------------------------------------------------------------------------------------------- the recent unlock

test("a_recent_unlock_within_5_minutes_needs_only_the_click", async () => {
  const w = world();
  w.verify.markUnlocked();
  // The five minutes are measured on both clocks; within them on both, the click is enough.
  {
    w.mono.t += RECENT_UNLOCK_MS - 1;
    w.mono.w += RECENT_UNLOCK_MS - 1;
    const { id, bridgeId } = await w.ask({ user_verification: "required" });
    const listed = /** @type {any} */ (await w.candidates(id));
    assert.equal(listed.recent, true, "the window says one click is enough");
    assert.deepEqual(await w.choose(id), { ok: true });
    assert.deepEqual(w.state.signs.at(-1).uv, { user_present: true, user_verified: true });
    assert.equal(w.answerOf(bridgeId)?.type, "passkey_result");
    // At five minutes it no longer counts.
    w.mono.t += 1;
    w.mono.w += 1;
    const later = await w.ask({ user_verification: "required" });
    assert.equal(/** @type {any} */ (await w.candidates(later.id)).recent, false);
    assert.deepEqual(await w.choose(later.id), { ok: false, reason: "verification_needed" });
  }
  // Either clock ends it: a machine that slept (the monotonic clock stood still while the wall clock went on), or a wall clock set
  // forward. And either going backwards ends it too: setting the system clock back cannot stretch it.
  for (const [what, move] of /** @type {Array<[string, (c: { t: number, w: number }) => void]>} */ ([
    ["asleep for six minutes", (c) => void (c.w += 6 * 60_000)],
    ["the monotonic clock past five minutes", (c) => void (c.t += RECENT_UNLOCK_MS)],
    ["the wall clock set back", (c) => void (c.w -= 1)],
    ["the monotonic clock back", (c) => void (c.t -= 1)],
  ])) {
    const c = world();
    c.verify.markUnlocked();
    assert.equal(await c.verify.recent(), true, what);
    move(c.mono);
    assert.equal(await c.verify.recent(), false, what);
  }
});

test("the_recent_unlock_is_forgotten_on_every_lock_and_when_the_setting_is_off", async () => {
  const w = world();
  w.verify.markUnlocked();
  assert.equal(await w.verify.recent(), true);
  w.state.setting = false;
  assert.equal(await w.verify.recent(), false, "the setting off: no recent unlock");
  const { id } = await w.ask({ user_verification: "required" });
  assert.deepEqual(await w.choose(id), { ok: false, reason: "verification_needed" });
  assert.deepEqual(await w.verifyOp(id, { method: "recent" }), { ok: false, reason: "verification_needed" });
  w.state.setting = true;
  assert.equal(await w.verify.recent(), true);
  // Every lock forgets it, whatever its reason (a lock of a vault that was locked already too).
  w.verify.onLock();
  assert.equal(await w.verify.recent(), false);
  // A verification that ends after a lock counts for nothing.
  w.verify.markUnlocked();
  let release = () => {};
  const slow = createPasskeyVerify({
    password: { verify: () => new Promise((r) => (release = () => r({ ok: true }))) },
    settings: { recentAllowed: async () => true },
    marks: { mark: () => true, take: () => true },
    now: () => w.mono.t,
  });
  const pending = slow.verify({ request_id: ID(9), session: SESSION }, "password", { mp: "x" });
  slow.onLock();
  release();
  assert.deepEqual(await pending, { ok: false, reason: "vault_locked" });
  assert.equal(await slow.recent(), false);
});

test("using_the_recent_unlock_does_not_extend_it", async () => {
  const w = world();
  w.verify.markUnlocked();
  w.mono.t += RECENT_UNLOCK_MS - 1000;
  const { id } = await w.ask({ user_verification: "preferred" });
  assert.deepEqual(await w.choose(id), { ok: true });
  assert.deepEqual(w.state.signs.at(-1).uv.user_verified, true);
  // The answer given through the recent unlock did not start the five minutes again.
  w.mono.t += 1000;
  assert.equal(await w.verify.recent(), false);
  // A verification in the window does.
  const next = await w.ask({ user_verification: "required" });
  assert.deepEqual(await w.verifyOp(next.id, { method: "pin", pin: "123456" }), { ok: true });
  w.mono.t += RECENT_UNLOCK_MS - 1;
  assert.equal(await w.verify.recent(), true);
});

test("a_restored_session_is_not_a_recent_unlock", async () => {
  // A background page that starts (after an update, an MV3 wake-up or a reload) knows of no unlock: the window counts as expired.
  const w = world();
  assert.equal(await w.verify.recent(), false);
  // Only the operations of an unlock the person made start it: not a sign-in, not a token renewal, not anything else that opens.
  const isOpen = { v: true };
  /** @type {Record<string, any>} */
  const ops = {};
  for (const name of ["sign_in", "unlock", "pin_unlock", "prf_unlock", "sync_retry", "session_state"]) {
    ops[name] = { vault: false, worker: "vault", run: async (/** @type {any} */ _c, /** @type {any} */ args) => ({ ok: args?.fail !== true }) };
  }
  let marked = 0;
  const marking = markingUnlocks(ops, { markUnlocked: () => void (marked += 1) }, () => isOpen.v);
  assert.deepEqual([...UNLOCK_OPS], ["unlock", "pin_unlock", "prf_unlock"]);
  for (const name of ["sign_in", "sync_retry", "session_state"]) {
    await marking[name].run(null, {}, null);
    assert.equal(marked, 0, name);
    assert.equal(marking[name], ops[name], `${name} is untouched`);
  }
  for (const name of UNLOCK_OPS) {
    await marking[name].run(null, { fail: true }, null);
    assert.equal(marked, 0, `${name}: a refused unlock starts nothing`);
    isOpen.v = false;
    await marking[name].run(null, {}, null);
    assert.equal(marked, 0, `${name}: a vault that is not open after it starts nothing`);
    isOpen.v = true;
  }
  for (const [n, name] of UNLOCK_OPS.entries()) {
    await marking[name].run(null, {}, null);
    assert.equal(marked, n + 1, name);
  }
  // The entry wires it this way, and every lock goes to the verification first.
  const main = readFileSync(join(src, "background/main.mjs"), "utf8");
  assert.match(main, /markingUnlocks\(allOps, passkeyVerify, \(\) => coreHostRef\?\.state\(\) === "unlocked"\)/);
  assert.match(main, /passkeyVerify\?\.onLock\(\);\n\s*passkeyRequests\.onLock\(wasOpen\);/);
  assert.match(main, /now: \(\) => globalThis\.performance\.now\(\)/);
  assert.equal((main.match(/markUnlocked/g) ?? []).length, 0, "nothing else in the entry starts the five minutes");
});

// ------------------------------------------------------------------------------------------------- the ways to verify

test("the_method_order_is_recent_prf_pin_password", async () => {
  const w = world();
  assert.deepEqual([...VERIFY_METHODS], ["recent", "prf", "pin", "password"]);
  w.verify.markUnlocked();
  const all = await w.verify.methods();
  assert.deepEqual(Object.keys(all), ["recent", "prf", "pin", "password", "online"]);
  assert.deepEqual(all, { recent: true, prf: true, pin: true, password: true, online: true });
  const { id } = await w.ask();
  const listed = /** @type {any} */ (await w.candidates(id));
  assert.deepEqual(listed.methods, ["recent", "prf", "pin", "password"]);
  assert.equal(listed.online, true);
  // Without the server: a passkey of the vault and the master password need it; a PIN within its offline window does not.
  w.state.online = false;
  w.verify.onLock();
  assert.deepEqual(await w.verify.methods(), { recent: false, prf: false, pin: true, password: false, online: false });
  w.state.pin = { set: true, offlineOk: false };
  assert.deepEqual(await w.verify.methods(), { recent: false, prf: false, pin: false, password: false, online: false });
  w.state.online = true;
  w.state.prf = false;
  w.state.pin = { set: false, offlineOk: false };
  assert.deepEqual(await w.verify.methods(), { recent: false, prf: false, pin: false, password: true, online: true });
  // The page's script for the step shows the ways in the same order.
  const page = readFileSync(join(src, "pages/passkeyVerify.mjs"), "utf8");
  assert.match(page, /VERIFY_WAYS = Object\.freeze\(\["prf", "pin", "password"\]\)/);
  assert.ok(page.indexOf('ways.includes("prf")') < page.indexOf('ways.includes("pin")') && page.indexOf('ways.includes("pin")') < page.indexOf('ways.includes("password")'));
});

test("prf_verification_runs_only_in_the_window_compares_pk_a_and_needs_the_network", async () => {
  const w = world();
  const { id } = await w.ask({ user_verification: "required" });
  // The 32 bytes the vault's passkey gave: a wrong one is refused, the right one marks the request.
  assert.deepEqual(await w.verifyOp(id, { method: "prf", credential_id: "AQID", prf_output: b64u(bytes(32, 1)) }), { ok: false, reason: "prf_failed" });
  assert.deepEqual(await w.verifyOp(id, { method: "prf", credential_id: "AQID", prf_output: b64u(bytes(32, 7)) }), { ok: true });
  assert.deepEqual(await w.choose(id), { ok: true });
  // Without the server the window is not offered it.
  w.state.online = false;
  assert.equal((await w.verify.methods()).prf, false);
  // Only Ferret's chooser window of this request may send it (never the popup or another page of the extension).
  const windowHandler = await loadWindowHandler();
  /** @type {any[]} */
  const calls = [];
  const runtime = { id: "ferret@x", getURL: (/** @type {string} */ p) => `moz-extension://u/${p}` };
  const ctx = (/** @type {any} */ sender) => ({ channel: "ui", type: "passkey_verify", sender, runtime, session: SESSION, state: () => "unlocked", call: async (/** @type {string} */ op, /** @type {any} */ args) => (calls.push({ op, args }), { ok: true }) });
  const body = { request_id: ID(5), method: "prf", credential_id: "AQID", prf_output: b64u(bytes(32, 7)) };
  const windowPage = { id: "ferret@x", url: `moz-extension://u/pages/passkey.html?r=${ID(5)}`, frameId: 0 };
  assert.deepEqual(await windowHandler.handle(body, ctx(windowPage)), { ok: true });
  assert.deepEqual(calls[0], { op: "passkey_verify", args: { method: "prf", credential_id: "AQID", prf_output: body.prf_output, request_id: ID(5), session: SESSION } });
  for (const sender of [{ ...windowPage, url: "moz-extension://u/pages/popup.html" }, { ...windowPage, url: "moz-extension://u/pages/unlockWindow.html" }, { ...windowPage, url: `moz-extension://u/pages/passkey.html?r=${ID(6)}` }]) {
    await assert.rejects(Promise.resolve().then(() => windowHandler.handle(body, ctx(sender))), /not_available/);
  }
  assert.equal(calls.length, 1);
  // The PIN host compares the account key: the core's unlock of a passkey runs with the pinned record (its pk_a), in a client
  // of its own, against the server's list read now (pinBackground/prfUnlock tests run it over the real session).
  const session = readFileSync(join(src, "background/pinSession.mjs"), "utf8");
  assert.match(session, /async checkPrf\(\{ credentialId, output, client \}\)[\s\S]*?await livingDevice\(\);[\s\S]*?\/api\/vault\/unlock-methods[\s\S]*?client\.vault\.unlock_prf\(env\.server, ctx, output, wrapToCore\(wrap, 0\), pinned\)[\s\S]*?client\.lock\(\)/);
});

test("password_verification_compares_pk_a_and_says_it_signs_in", async () => {
  const w = world();
  const { id } = await w.ask({ user_verification: "required" });
  assert.deepEqual(await w.verifyOp(id, { method: "password", mp: "wrong" }), { ok: false, reason: "wrong_credentials" });
  assert.deepEqual(await w.verifyOp(id, { method: "password", mp: "right-password" }), { ok: true });
  assert.deepEqual(await w.choose(id), { ok: true });
  // The check is the session's `verifyPassword` (OPAQUE with the server and the core's `confirm_password`, which compares the
  // account key of the password wrap with the pinned one; pinBackground.test.mjs runs it over the real session), for the open
  // vault of this device's account, and it needs nothing of the PIN.
  /** @type {any[]} */
  const asked = [];
  /** @type {unknown} */
  let refusal = null;
  const session = {
    deviceAccount: async () => "acc",
    current: () => ({ accountId: "acc" }),
    verifyPassword: async (/** @type {any} */ input) => {
      asked.push(input);
      if (refusal !== null) throw refusal;
    },
  };
  const check = passwordCheck({ sessionHost: { storedServer: async () => "https://vault.example", sessionFor: async () => session } });
  assert.deepEqual(await check.verify({ mp: "pw", sk: "A3-XYZ" }), { ok: true });
  assert.deepEqual(asked, [{ password: "pw", skCode: "A3-XYZ" }]);
  for (const [code, reason] of [["decrypt", "wrong_credentials"], ["pinned_auth_key", "attack_warning"], ["method_list_changed", "attack_warning"], ["sk_required", "sk_required"], ["session_ended", "signed_out"]]) {
    refusal = Object.assign(new Error(code), { code });
    assert.deepEqual(await check.verify({ mp: "pw" }), { ok: false, reason }, code);
  }
  refusal = Object.assign(new Error("network"), { status: 0 });
  assert.deepEqual(await check.verify({ mp: "pw" }), { ok: false, reason: "network" });
  // Another account's vault, or none, is not the one to verify for.
  session.current = () => ({ accountId: "other" });
  assert.deepEqual(await check.verify({ mp: "pw" }), { ok: false, reason: "vault_locked" });
  // The window says that it signs in.
  const en = JSON.parse(readFileSync(join(src, "locales/en/passkeys.json"), "utf8"));
  assert.match(en["passkeys.verify.signs_in"], /signing in/);
  assert.match(readFileSync(join(src, "pages/passkeyVerify.mjs"), "utf8"), /"data-role": "passkey-verify-signs-in"/);
});

// ------------------------------------------------------------------------------------------------- what the page asked

test("preferred_without_any_verification_answers_uv_0_after_the_click", async () => {
  const w = world({ state: { online: false, pin: { set: false, offlineOk: false }, prf: false } });
  const { id, bridgeId } = await w.ask({ user_verification: "preferred" });
  assert.deepEqual((/** @type {any} */ (await w.candidates(id))).methods, []);
  assert.deepEqual(await w.choose(id), { ok: true });
  assert.deepEqual(w.state.signs.at(-1).uv, { user_present: true, user_verified: false });
  assert.equal(w.answerOf(bridgeId)?.type, "passkey_result");
  // With a way to verify there, `preferred` asks for it.
  const v = world();
  const asked = await v.ask({ user_verification: "preferred" });
  assert.deepEqual(await v.choose(asked.id), { ok: false, reason: "verification_needed" });
  // An unknown value is `preferred`, as WebAuthn reads it.
  assert.equal(getRequestOf({ challenge: CHALLENGE, user_verification: "sometimes" })?.user_verification, "preferred");
});

test("required_without_any_verification_offers_the_browser", async () => {
  const w = world({ state: { online: false, pin: { set: true, offlineOk: false }, prf: false } });
  const { id, bridgeId } = await w.ask({ user_verification: "required" });
  // Nothing is signed; the window says why (its browser choice is there), and the page waits for the person.
  assert.deepEqual(await w.choose(id), { ok: false, reason: "verification_unavailable" });
  assert.equal(w.state.signs.length, 0);
  assert.equal(w.answerOf(bridgeId), undefined, "the page has no answer yet");
  assert.ok(w.requests.forUi(id, SESSION), "the request waits");
  assert.equal(w.requests.handover(id, SESSION, { once: false }), true);
  await flush();
  assert.equal(w.answerOf(bridgeId)?.type, "passkey_handover");
  const en = JSON.parse(readFileSync(join(src, "locales/en/passkeys.json"), "utf8"));
  assert.match(en["passkeys.error.verification_unavailable"], /browser/);
});

test("discouraged_needs_only_the_click", async () => {
  const w = world();
  const { id, bridgeId } = await w.ask({ user_verification: "discouraged" });
  assert.deepEqual(await w.choose(id), { ok: true });
  assert.deepEqual(w.state.signs.at(-1).uv, { user_present: true, user_verified: false });
  assert.equal(w.answerOf(bridgeId)?.type, "passkey_result");
  // Nothing is asked; when the person was verified anyway (here a PIN, which also starts the five minutes), UV says so: a strict
  // relying party compares it with the UV of the registration.
  const next = await w.ask({ user_verification: "discouraged" });
  assert.deepEqual(await w.verifyOp(next.id, { method: "pin", pin: "123456" }), { ok: true });
  assert.deepEqual(await w.choose(next.id), { ok: true });
  assert.equal(w.state.signs.at(-1).uv.user_verified, true);
  assert.equal(w.verify.take(w.ref(next.id)), false, "the mark was used");
});

// ------------------------------------------------------------------------------------------------- the candidates

test("several_candidates_show_a_list_from_the_vault_not_from_the_page", async () => {
  const w = world();
  const { id } = await w.ask({ rp_id: "rp-a.test" });
  const listed = /** @type {any} */ (await w.candidates(id));
  assert.equal(listed.ok, true);
  // The vault's names and dates, for the passkeys the core said may answer (the exact RP ID: never rp-b.test, never an item
  // without a passkey). The window sorts them; the background sends them as the vault has them.
  assert.deepEqual(
    [...listed.candidates].sort((a, b) => a.item_id.localeCompare(b.item_id)),
    [
      { item_id: ID(1), name: "RP A", user_name: "anna", created: 1_800_000_000_000 },
      { item_id: ID(3), name: "RP A (work)", user_name: "anna@rp-a.test", created: 1_700_000_000_000 },
    ],
  );
  // The core got the whole request (challenge, RP ID, allow list, UV) and the caller the broker built from the browser.
  const asked = w.state.asked.at(-1);
  assert.deepEqual(asked.caller, { origin: RP, top_origin_is_same: true });
  assert.equal(asked.request.rp_id, "rp-a.test");
  assert.deepEqual(Buffer.from(asked.request.challenge), Buffer.from(CHALLENGE, "base64url"));
  assert.deepEqual(asked.request.allow, []);
  // Every handle that was opened was closed again.
  assert.equal(w.state.closed, 3);
  // The page's allow list narrows it; the page names nothing else. (One modal request per tab: the first one ends.)
  w.requests.cancel(id, SESSION);
  const narrowed = await w.ask({ allow_credentials: [{ type: "public-key", id: b64u(bytes(16, 1)) }, { type: "public-key", id: b64u(bytes(16, 9)) }] });
  assert.deepEqual((/** @type {any} */ (await w.candidates(narrowed.id))).candidates.map((/** @type {any} */ c) => c.item_id), [ID(1)]);
  // A choice of an item that is not a candidate of this request signs nothing.
  assert.deepEqual(await w.choose(narrowed.id, ID(3)), { ok: false, reason: "not_found" });
  assert.deepEqual(await w.choose(narrowed.id, ID(2)), { ok: false, reason: "not_found" });
  assert.equal(w.state.signs.length, 0);
  // Only the window session that owns the request is told anything.
  assert.deepEqual(await w.get.ops.passkey_candidates.run(w.client, { request_id: narrowed.id, session: "s2" }), { ok: false, reason: "gone" });
  // Only the validated candidates of the core are asked (`Vault.passkey_candidates`, which runs `passkey_candidates_for`).
  assert.doesNotMatch(readFileSync(join(src, "background/passkeyGet.mjs"), "utf8"), /item_view\(handle\)[\s\S]{0,80}rp_id ===/);
});

test("no_candidate_shows_the_window_with_the_browser_choice", async () => {
  const w = world();
  // rp-a.test may use only its own RP ID here (the fake core lists nothing for an id no item has).
  const { id, bridgeId } = await w.ask({ allow_credentials: [{ type: "public-key", id: b64u(bytes(16, 9)) }] });
  const listed = /** @type {any} */ (await w.candidates(id));
  assert.equal(listed.ok, true);
  assert.deepEqual(listed.candidates, []);
  // The request still waits: the page cannot tell "none" from "the person has not chosen yet".
  assert.ok(w.requests.forUi(id, SESSION));
  assert.equal(w.answerOf(bridgeId), undefined);
  // A refusal of the core for the request itself ends it as the browser would (an RP ID the origin may not use).
  w.client.vault.passkey_candidates = async () => {
    throw Object.assign(new Error("malformed_rp_id"), { code: "malformed_rp_id" });
  };
  // (One modal request per tab: the first one ends.)
  w.requests.cancel(id, SESSION);
  const again = await w.ask({ rp_id: "rp-b.test" });
  assert.deepEqual(await w.candidates(again.id), { ok: false, reason: "security_error" });
  await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(w.answerOf(again.bridgeId)?.body.name, "SecurityError");
});

test("prf_results_only_when_asked_and_follow_uv", async () => {
  const salt = b64u(bytes(32, 0x42));
  // Not asked: no PRF in what the core is asked, nothing in the answer.
  const w = world();
  const plain = await w.ask({ user_verification: "discouraged" });
  await w.choose(plain.id);
  assert.equal(w.state.signs.at(-1).prf, false);
  assert.deepEqual(w.answerOf(plain.bridgeId)?.body.response.client_extension_results, {});
  // Asked, without UV: the results of the seed without UV.
  const nouv = await w.ask({ user_verification: "discouraged", extensions: { prf: { eval: { first: salt } } } });
  await w.choose(nouv.id);
  assert.deepEqual(w.answerOf(nouv.bridgeId)?.body.response.client_extension_results, { prf: { results: { first: b64u(bytes(32, 0xb1)) } } });
  // Asked, with UV: the other seed.
  const uv = await w.ask({ user_verification: "required", extensions: { prf: { eval: { first: salt } } } });
  await w.verifyOp(uv.id, { method: "pin", pin: "123456" });
  await w.choose(uv.id);
  assert.deepEqual(w.answerOf(uv.bridgeId)?.body.response.client_extension_results, { prf: { results: { first: b64u(bytes(32, 0xa1)) } } });
  // Asked, from a passkey made without PRF: an empty result, never one made up.
  const none = await w.ask({ user_verification: "discouraged", extensions: { prf: { eval: { first: salt } } } });
  await w.choose(none.id, ID(1));
  assert.deepEqual(w.answerOf(none.bridgeId)?.body.response.client_extension_results, { prf: {} });
  // The salts reach the core as bytes (the core hashes them), per credential too.
  const req = getRequestOf({ challenge: CHALLENGE, extensions: { prf: { eval: { first: salt, second: salt }, eval_by_credential: [{ id: "AQID", first: salt }] } } });
  assert.deepEqual(Buffer.from(/** @type {any} */ (req).prf.eval.first), Buffer.from(bytes(32, 0x42)));
  assert.deepEqual(Buffer.from(/** @type {any} */ (req).prf.eval_by_credential[0].id), Buffer.from([1, 2, 3]));
});

test("get_never_writes_the_item", async () => {
  const w = world();
  for (const uv of ["discouraged", "preferred", "required"]) {
    const { id } = await w.ask({ user_verification: uv });
    if (uv !== "discouraged") await w.verifyOp(id, { method: "pin", pin: "123456" });
    await w.candidates(id);
    assert.deepEqual(await w.choose(id), { ok: true }, uv);
  }
  assert.deepEqual(w.state.writes, []);
  assert.equal(w.state.signs.length, 3);
  // The get side reads the engine's list and opens items, and nothing more: no write of the engine or the vault is named.
  const text = readFileSync(join(src, "background/passkeyGet.mjs"), "utf8").replace(/\/\/.*$/gm, "");
  for (const write of [/\.update\(/, /\.create\(/, /\.remove\(/, /encrypt_item/, /importItems/, /passkey_create/, /outbox/]) assert.doesNotMatch(text, write);
});

// ------------------------------------------------------------------------------------------------- the window's types

test("the_get_types_are_in_the_ui_table_the_core_ops_and_the_windows_handler", async () => {
  const windowHandler = await loadWindowHandler();
  assert.deepEqual([...PASSKEY_GET_OPS], ["passkey_candidates", "passkey_choose", "passkey_verify"]);
  for (const type of PASSKEY_GET_OPS) {
    assert.ok(Object.hasOwn(UI_TYPES, type), type);
    assert.ok(CORE_OPS.includes(type), type);
    assert.ok(PASSKEY_WINDOW_OPS.includes(type), type);
    assert.ok(windowHandler.types.includes(type), type);
    // They use the vault: a locked one is opened in the window first.
    assert.ok(!LOCK_EXEMPT.includes(type), type);
  }
});

test("only_a_refusal_of_the_request_itself_ends_it", async () => {
  const w = world();
  const { id, bridgeId } = await w.ask();
  // An item that changed since the list (or a busy engine): the window says it did not work, and the request waits for the person.
  const view = w.client.vault.item_view;
  w.client.vault.item_view = async () => {
    throw Object.assign(new Error("not_found"), { code: "not_found" });
  };
  assert.deepEqual(await w.candidates(id), { ok: false, reason: "internal_error" });
  w.client.vault.item_view = view;
  const sign = w.client.vault.passkey_get;
  w.client.vault.passkey_get = async () => {
    throw Object.assign(new Error("busy"), { code: "busy" });
  };
  assert.deepEqual(await w.verifyOp(id, { method: "pin", pin: "123456" }), { ok: true });
  assert.deepEqual(await w.choose(id, ID(3)), { ok: false, reason: "internal_error" });
  // A key the core cannot sign with (`unsupported`) after the click is no NotSupportedError for the page: the request waits too.
  w.client.vault.passkey_get = async () => {
    throw Object.assign(new Error("unsupported"), { code: "unsupported" });
  };
  assert.deepEqual(await w.choose(id, ID(3)), { ok: false, reason: "internal_error" });
  w.client.vault.passkey_get = sign;
  await flush();
  assert.ok(w.requests.forUi(id, SESSION), "the request still waits");
  assert.equal(w.answerOf(bridgeId), undefined);
  // (The PIN verified the person, which starts the five minutes: the next click is enough.)
  assert.deepEqual(await w.choose(id, ID(3)), { ok: true });
});

// ------------------------------------------------------------------------- Ferret's popup: a conditional request, by tab

const PAGE = Object.freeze({ tabId: 4, frameId: 0, documentId: "doc-1", url: `${RP}/login`, origin: RP });

/**
 * A page's conditional get in tab 4 (the site's autofill UI): no window, the popup's list.
 * @param {ReturnType<typeof world>} w @param {Record<string, any>} [options]
 */
async function conditional(w, options = {}) {
  const bridgeId = `c${Math.random().toString(16).slice(2, 10)}`;
  const opened = /** @type {any} */ (await w.requests.open(PAGE, {
    request_id: bridgeId, kind: "get", mediation: "conditional",
    get: { challenge: CHALLENGE, allow_credentials: [], hints: [], extensions: {}, user_verification: "preferred", ...options },
    activation: false, policy: true,
  }));
  assert.ok(opened.request_id, JSON.stringify(opened));
  return { id: /** @type {string} */ (opened.request_id), bridgeId };
}
/** One of the popup's get ops, for tab 4. @param {ReturnType<typeof world>} w @param {string} op @param {Record<string, unknown>} [body] */
const tabOp = async (w, op, body = {}) => {
  // As the popup does: a choice and a verification name the request its last list was for.
  const listed = /** @type {any} */ (w).listed;
  const named = (op === "passkey_tab_choose" || op === "passkey_tab_verify") && listed ? { request_id: listed.request_id, origin: listed.origin } : {};
  const reply = await /** @type {any} */ (w.get.ops)[op].run(w.client, { tab_id: 4, ...named, ...body });
  if (op === "passkey_tab_list") /** @type {any} */ (w).listed = reply?.mode === "pick" ? { request_id: reply.request_id, origin: reply.origin } : null;
  await flush();
  return reply;
};
/** One of the broker's popup ops, for tab 4. @param {ReturnType<typeof world>} w @param {string} op @param {Record<string, unknown>} [body] */
const brokerOp = async (w, op, body = {}) => {
  const reply = await /** @type {any} */ (w.requests.ops)[op].run(null, { tab_id: 4, ...body });
  await flush();
  return reply;
};
/** The extension as the browser names it to a handler. */
const runtime = { id: "ferret@x", getURL: (/** @type {string} */ p) => `moz-extension://u/${p}` };
const POPUP = Object.freeze({ id: "ferret@x", url: "moz-extension://u/pages/popup.html", frameId: 0 });

test("the_popup_lists_ferret_passkeys_for_the_exact_rp_id_only", async () => {
  const w = world();
  // No request yet: the passkeys of the tab's site, for information (no way to sign), from the core only.
  const info = await tabOp(w, "passkey_tab_list");
  assert.equal(info.mode, "info");
  assert.deepEqual(info.candidates.map((/** @type {any} */ c) => c.item_id), [ID(3), ID(1)]);
  assert.equal(info.host, "rp-a.test");
  assert.equal(info.recent, undefined, "nothing about verification without a request");
  assert.deepEqual(w.state.asked.at(-1).caller, { origin: RP, top_origin_is_same: true });
  assert.equal(w.state.asked.at(-1).request.rp_id, undefined, "the core takes the origin's host as the RP ID");
  // A conditional request: the core gets the WHOLE request and the caller the broker built; the RP ID is compared exactly there.
  await conditional(w, { rp_id: "rp-a.test" });
  const list = await tabOp(w, "passkey_tab_list");
  assert.equal(list.mode, "pick");
  assert.deepEqual(list.candidates.map((/** @type {any} */ c) => [c.item_id, c.name, c.user_name]), [[ID(3), "RP A (work)", "anna@rp-a.test"], [ID(1), "RP A", "anna"]]);
  assert.equal(w.state.asked.at(-1).request.rp_id, "rp-a.test");
  assert.deepEqual(w.state.asked.at(-1).caller, { origin: RP, top_origin_is_same: true });
  assert.ok(!list.candidates.some((/** @type {any} */ c) => c.item_id === ID(2)), "another site's passkey is never listed");
  assert.deepEqual(list.methods, ["prf", "pin", "password"]);
  // The page's allow list is the core's to apply too.
  const w2 = world();
  await conditional(w2, { rp_id: "rp-a.test", allow_credentials: [{ type: "public-key", id: b64u(bytes(16, 1)) }] });
  assert.deepEqual((await tabOp(w2, "passkey_tab_list")).candidates.map((/** @type {any} */ c) => c.item_id), [ID(1)]);
  assert.equal(w.pushed.length, 0, "nothing of the list went to the page");
  // Where Ferret does not answer (the setting off), the popup lists nothing, not even for information.
  const off = world();
  const offGet = createPasskeyGet({ requests: { ...off.requests, tabSite: async () => null }, verify: off.verify, items: () => off.source });
  assert.deepEqual(await /** @type {any} */ (offGet.ops).passkey_tab_list.run(off.client, { tab_id: 4 }), { ok: true, mode: "none" });
});

test("a_pick_needs_a_pending_conditional_request_and_the_guards", async () => {
  const w = world();
  // No conditional request: a click in the popup answers nothing.
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "gone" });
  // A modal request is the window's (or the card's), never the popup list's.
  const modal = await w.ask();
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "gone" });
  w.requests.cancel(modal.id, SESSION);
  // A conditional request: the click is the presence; verification follows what the page asked.
  const { bridgeId } = await conditional(w, { user_verification: "required" });
  // Not the request it listed (no list yet): nothing.
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "gone" });
  assert.equal((await tabOp(w, "passkey_tab_list")).mode, "pick");
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(2) }), { ok: false, reason: "not_found" }, "only a candidate of the request");
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "verification_needed" });
  assert.equal(w.state.signs.length, 0);
  // The popup verifies with the PIN or the master password, never a passkey's bytes.
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "prf", credential_id: "AQID", prf_output: b64u(bytes(32, 7)) }), { ok: false, reason: "invalid_input" });
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456" }), { ok: true });
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: true });
  assert.deepEqual(w.state.signs.map((/** @type {any} */ x) => [x.item, x.uv]), [[ID(3), { user_present: true, user_verified: true }]]);
  assert.equal(w.answerOf(bridgeId)?.type, "passkey_result");
  // Answered: the next click has nothing to answer.
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "gone" });

  // The guards of the handler: the popup page only, a tab or a request (never both), a get only, and no passkey bytes.
  const windowHandler = await loadWindowHandler();
  /** @type {any[]} */
  const calls = [];
  const ctx = (/** @type {any} */ sender, /** @type {string} */ type) => ({ channel: "ui", type, sender, runtime, session: "ab".repeat(16), state: () => "unlocked", call: async (/** @type {string} */ op, /** @type {any} */ args) => (calls.push({ op, args }), { ok: true }) });
  const named = { request_id: ID(9), origin: RP };
  assert.deepEqual(await windowHandler.handle({ tab_id: 4, ...named, kind: "get", item_id: ID(3) }, ctx(POPUP, "passkey_choose")), { ok: true });
  assert.deepEqual(calls.at(-1), { op: "passkey_tab_choose", args: { tab_id: 4, ...named, popup_tab: null, item_id: ID(3) } });
  assert.deepEqual(await windowHandler.handle({ tab_id: 4, ...named, method: "pin", pin: "123456" }, ctx({ ...POPUP, url: `${POPUP.url}?tab=4` }, "passkey_verify")), { ok: true });
  assert.deepEqual(calls.at(-1), { op: "passkey_tab_verify", args: { method: "pin", pin: "123456", tab_id: 4, ...named, popup_tab: 4 } });
  const refused = [
    [{ tab_id: 4, kind: "get", item_id: ID(3) }, POPUP, "passkey_choose"],
    [{ tab_id: 4, request_id: ID(9), kind: "get", item_id: ID(3) }, POPUP, "passkey_choose"],
    [{ request_id: ID(9), origin: RP, kind: "get", item_id: ID(3) }, { ...POPUP, url: `moz-extension://u/pages/passkey.html?r=${ID(9)}` }, "passkey_choose"],
    [{ tab_id: 4, kind: "get", item_id: ID(3) }, { ...POPUP, url: "moz-extension://u/pages/settings.html" }, "passkey_choose"],
    [{ tab_id: 4, kind: "get", item_id: ID(3) }, { ...POPUP, url: `moz-extension://u/pages/passkey.html?r=${ID(5)}` }, "passkey_choose"],
    [{ tab_id: 4, kind: "get", item_id: ID(3) }, { ...POPUP, frameId: 3 }, "passkey_choose"],
    [{ tab_id: 4, kind: "get", item_id: ID(3) }, { id: "ferret@x", url: `${RP}/login`, frameId: 0, tab: { id: 4 } }, "passkey_choose"],
    [{ tab_id: 4, ...named, kind: "create", mode: "new", name: "x" }, POPUP, "passkey_choose"],
    [{ tab_id: 4, ...named, method: "prf", credential_id: "AQID", prf_output: b64u(bytes(32, 7)) }, POPUP, "passkey_verify"],
    [{ tab_id: 4, ...named, method: "recent" }, POPUP, "passkey_verify"],
  ];
  const before = calls.length;
  for (const [body, sender, type] of refused) {
    await assert.rejects(Promise.resolve().then(() => windowHandler.handle(body, ctx(sender, /** @type {string} */ (type)))), /not_available/, JSON.stringify(body));
  }
  assert.equal(calls.length, before);
  // The click guard (isTrusted, 400 ms after each change) is the popup page's: test/unit/popupPasskeys.test.mjs.
});

test("windows_hello_from_the_popup_opens_the_window", async () => {
  const w = world();
  const { id } = await conditional(w, { user_verification: "required" });
  await tabOp(w, "passkey_tab_list");
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "verification_needed" });
  // Windows Hello needs Ferret's window (the popup closes when the system's dialog takes the focus): the popup's click opens it.
  assert.deepEqual(await brokerOp(w, "passkey_tab_open", { which: "conditional" }), { ok: true });
  assert.deepEqual(w.state.windowsOpened, [id]);
  // The window owns the request now: the popup's list is gone, and a second window does not open.
  assert.equal(w.requests.tabRef(4), null);
  assert.deepEqual(await brokerOp(w, "passkey_tab"), { ok: true, waiting: null, conditional: false, request: null, again: null, foreign: false });
  assert.deepEqual(await brokerOp(w, "passkey_tab_open", { which: "conditional" }), { ok: false, reason: "busy" });
  assert.ok(w.requests.forUi(id, "window-1"), "the window's session takes it");
  assert.deepEqual(await w.get.ops.passkey_verify.run(w.client, { request_id: id, session: "window-1", method: "prf", credential_id: "AQID", prf_output: b64u(bytes(32, 7)) }), { ok: true });
  // The person closes the window: a conditional request is not ended by it, it waits for the popup again.
  w.requests.onWindowRemoved(101);
  await flush();
  assert.equal((await brokerOp(w, "passkey_tab")).conditional, true);
  assert.notEqual(w.requests.tabRef(4), null);
  // Its Cancel does the same, and closes the window.
  await brokerOp(w, "passkey_tab_open", { which: "conditional" });
  assert.ok(w.requests.forUi(id, "window-2"));
  assert.equal(w.requests.cancel(id, "window-2"), true);
  await flush();
  assert.deepEqual(w.state.windowsClosed, [101]);
  assert.equal((await brokerOp(w, "passkey_tab")).conditional, true);
  assert.equal(w.pushed.length, 0, "the page's call still waits");
  // "Use the browser" for a conditional request: straight to the browser's own call, no pass and no "click again".
  await brokerOp(w, "passkey_tab_open", { which: "conditional" });
  assert.ok(w.requests.forUi(id, "window-3"));
  assert.equal(w.requests.handover(id, "window-3", { once: true }), true);
  await flush();
  assert.equal(w.pushed.at(-1)?.type, "passkey_handover");
  assert.equal(w.pushed.at(-1)?.body.once, false);
  assert.equal(w.requests.passPendingFor(4), null);
});

test("the_section_disappears_on_page_abort_or_navigation", async () => {
  const w = world();
  const tabState = () => brokerOp(w, "passkey_tab");
  const first = await conditional(w);
  assert.equal((await tabState()).conditional, true);
  assert.equal((await tabOp(w, "passkey_tab_list")).mode, "pick");
  // The page aborts its call: the list goes (the popup asks again and finds nothing to pick).
  await w.requests.onEvent({ type: "passkey_abort", sender: PAGE, body: { request_id: first.bridgeId } });
  await flush();
  assert.equal((await tabState()).conditional, false);
  assert.equal((await tabOp(w, "passkey_tab_list")).mode, "info");
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "gone" });
  // A new document in the tab.
  await conditional(w);
  assert.equal((await tabState()).conditional, true);
  w.requests.onNavigation({ tabId: 4, frameId: 0, documentId: "doc-2" });
  await flush();
  assert.equal((await tabState()).conditional, false);
  // A lock of the open vault.
  await conditional(w);
  w.requests.onLock(true);
  await flush();
  assert.equal((await tabState()).conditional, false);
});

test("the_list_is_never_sent_to_the_page", async () => {
  const w = world();
  const { bridgeId } = await conditional(w);
  await tabOp(w, "passkey_tab_list");
  w.verify.markUnlocked();
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: true });
  // The page got one message: its credential. No name, user name or other passkey of the vault.
  assert.deepEqual(w.pushed.map((p) => p.type), ["passkey_result"]);
  assert.equal(w.answerOf(bridgeId)?.type, "passkey_result");
  const text = JSON.stringify(w.pushed);
  for (const item of ITEMS) {
    if (item.name !== "") assert.equal(text.includes(item.name), false, item.name);
    if (item.user !== "") assert.equal(text.includes(item.user), false, item.user);
  }
  // No message a page or its bridge can get has a list, and the popup's types are refused to anything but the popup page.
  for (const [type, def] of Object.entries(PUSH_TYPES)) assert.doesNotMatch(JSON.stringify(def), /candidates|user_name/, type);
  const popupHandler = (await (await pkg()).load("background/handlers/passkeyPopup.handler.mjs")).default;
  assert.deepEqual([...popupHandler.types], ["passkey_tab", "passkey_tab_list", "passkey_tab_open"]);
  /** @type {any[]} */
  const calls = [];
  const ctx = (/** @type {any} */ sender, /** @type {string} */ type) => ({ channel: "ui", type, sender, runtime, session: "ab".repeat(16), call: async (/** @type {string} */ op, /** @type {any} */ args) => (calls.push({ op, args }), { ok: true }) });
  assert.deepEqual(await popupHandler.handle({ tab_id: 4 }, ctx(POPUP, "passkey_tab_list")), { ok: true });
  assert.deepEqual(calls, [{ op: "passkey_tab_list", args: { tab_id: 4, popup_tab: null } }]);
  for (const sender of [{ ...POPUP, url: `moz-extension://u/pages/passkey.html?r=${ID(5)}` }, { ...POPUP, frameId: 2 }, { id: "ferret@x", url: `${RP}/login`, frameId: 0, tab: { id: 4 } }, { ...POPUP, id: "other@x" }]) {
    await assert.rejects(Promise.resolve().then(() => popupHandler.handle({ tab_id: 4 }, ctx(sender, "passkey_tab_list"))), /not_available/);
  }
  assert.equal(calls.length, 1);
});

test("a_modal_request_without_activation_shows_a_card_that_opens_the_window", async () => {
  const w = world();
  const opened = /** @type {any} */ (await w.requests.open(PAGE, {
    request_id: "m1", kind: "get", mediation: "optional", get: { challenge: CHALLENGE, allow_credentials: [], hints: [], extensions: {} }, activation: false, policy: true,
  }));
  assert.ok(opened.request_id);
  // No user activation: no window of its own accord, a card in the popup.
  assert.deepEqual(w.state.windowsOpened, []);
  assert.deepEqual(await brokerOp(w, "passkey_tab"), { ok: true, waiting: { origin: RP, kind: "get" }, conditional: false, request: null, again: null, foreign: false });
  // The card's click opens the window for it.
  assert.deepEqual(await brokerOp(w, "passkey_tab_open", { which: "waiting" }), { ok: true });
  assert.deepEqual(w.state.windowsOpened, [opened.request_id]);
  assert.equal((await brokerOp(w, "passkey_tab")).waiting, null);
  // The types of the popup: in the UI table and the core's ops; the two that read the tab and open the window work locked.
  for (const type of ["passkey_tab", "passkey_tab_list", "passkey_tab_open"]) {
    assert.ok(Object.hasOwn(UI_TYPES, type), type);
    assert.ok(CORE_OPS.includes(type), type);
  }
  assert.ok(LOCK_EXEMPT.includes("passkey_tab") && LOCK_EXEMPT.includes("passkey_tab_open") && !LOCK_EXEMPT.includes("passkey_tab_list"));
});

test("a_get_gives_the_mark_back_when_signing_fails", async () => {
  const w = world();
  const { id, bridgeId } = await w.ask({ user_verification: "required" });
  assert.deepEqual(await w.verifyOp(id, { method: "pin", pin: "123456" }), { ok: true });
  // The core fails to sign once (not a refusal of the request): nothing went to the page, and the person's verification is kept.
  const sign = w.client.vault.passkey_get;
  w.client.vault.passkey_get = async () => {
    throw Object.assign(new Error("busy"), { code: "busy" });
  };
  assert.deepEqual(await w.choose(id), { ok: false, reason: "internal_error" });
  w.client.vault.passkey_get = sign;
  // The next try needs no new verification.
  assert.deepEqual(await w.choose(id), { ok: true });
  assert.deepEqual(w.state.signs.at(-1).uv, { user_present: true, user_verified: true });
  assert.equal(w.answerOf(bridgeId)?.type, "passkey_result");
});

test("the_foreign_mark_is_text_only_and_never_routes", async () => {
  const w = world();
  // The top document says create or get were changed by something else (another password manager or the site itself).
  await w.requests.onEvent({ type: "passkey_foreign", sender: PAGE, body: {} });
  // A conditional request of that document is still Ferret's, listed in the popup: the mark changes no route.
  const { id, bridgeId } = await conditional(w);
  assert.equal(w.pushed.length, 0, "not handed to the browser");
  assert.deepEqual(await brokerOp(w, "passkey_tab"), { ok: true, waiting: null, conditional: true, request: { request_id: id, origin: RP }, again: null, foreign: true });
  assert.equal((await tabOp(w, "passkey_tab_list")).mode, "pick");
  w.verify.markUnlocked();
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: true });
  assert.equal(w.answerOf(bridgeId)?.type, "passkey_result");
  // A frame below the top cannot set it, and a new top document has none.
  const other = world();
  await other.requests.onEvent({ type: "passkey_foreign", sender: { ...PAGE, frameId: 3, documentId: "doc-3" }, body: {} });
  await conditional(other);
  assert.equal((await other.requests.ops.passkey_tab.run(null, { tab_id: 4 })).foreign, false);
});

test("the_popup_acts_only_on_the_request_it_listed", async () => {
  const w = world();
  const first = await conditional(w, { user_verification: "required" });
  const listed = await tabOp(w, "passkey_tab_list");
  assert.deepEqual([listed.mode, listed.request_id, listed.origin], ["pick", first.id, RP]);
  // Between two looks of the popup the tab goes to another site, which starts a conditional request of its own.
  w.requests.onNavigation({ tabId: 4, frameId: 0, documentId: "doc-2" });
  await flush();
  const OTHER = "https://rp-b.test";
  w.state.top = { url: `${OTHER}/login`, documentId: "doc-2" };
  const opened = /** @type {any} */ (await w.requests.open({ tabId: 4, frameId: 0, documentId: "doc-2", url: `${OTHER}/login`, origin: OTHER }, {
    request_id: "other", kind: "get", mediation: "conditional",
    get: { challenge: CHALLENGE, allow_credentials: [], hints: [], extensions: {}, user_verification: "required" }, activation: false, policy: true,
  }));
  assert.ok(opened.request_id);
  // The PIN typed in the step the popup still shows (for rp-a.test) marks nothing, and a click answers nothing.
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456" }), { ok: false, reason: "gone" });
  assert.equal(w.state.pinAttempts, 0, "the PIN was not even tried");
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "gone" });
  assert.equal(w.requests.takeVerified(opened.request_id, "popup"), false, "no mark for the other site's request");
  // The same id with another origin, or another id with the right origin: nothing either.
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456", request_id: opened.request_id, origin: RP }), { ok: false, reason: "gone" });
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456", request_id: first.id, origin: OTHER }), { ok: false, reason: "gone" });
  // The popup sees the new request (its id and origin) and lists again; then it acts on that one.
  const tab = await brokerOp(w, "passkey_tab");
  assert.deepEqual(tab.request, { request_id: opened.request_id, origin: OTHER });
  const again = await tabOp(w, "passkey_tab_list");
  assert.deepEqual([again.request_id, again.origin], [opened.request_id, OTHER]);
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456" }), { ok: true });
});

test("the_popup_acts_only_for_its_own_tab", async () => {
  const w = world();
  await conditional(w);
  // A popped-out popup about another tab (`?tab=7`): nothing for tab 4.
  assert.deepEqual(await tabOp(w, "passkey_tab_list", { popup_tab: 7 }), { ok: true, mode: "none" });
  assert.deepEqual(await brokerOp(w, "passkey_tab", { popup_tab: 7 }), { ok: false, reason: "gone" });
  assert.deepEqual(await brokerOp(w, "passkey_tab_open", { which: "conditional", popup_tab: 7 }), { ok: false, reason: "gone" });
  // Its own tab, named in its address, is fine; so is the active tab for the toolbar panel (no address tab).
  assert.equal((await tabOp(w, "passkey_tab_list", { popup_tab: 4 })).mode, "pick");
  assert.equal((await tabOp(w, "passkey_tab_list")).mode, "pick");
  w.verify.markUnlocked();
  // The panel while another tab is active: nothing.
  w.state.activeTab = 9;
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "gone" });
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456" }), { ok: false, reason: "gone" });
  w.state.activeTab = 4;
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: true });
  // The handlers pass the popup's own tab from its address.
  const popupHandler = (await (await pkg()).load("background/handlers/passkeyPopup.handler.mjs")).default;
  /** @type {any[]} */
  const calls = [];
  const ctx = (/** @type {any} */ sender) => ({ channel: "ui", type: "passkey_tab", sender, runtime, session: "ab".repeat(16), call: async (/** @type {string} */ op, /** @type {any} */ args) => (calls.push({ op, args }), { ok: true }) });
  await popupHandler.handle({ tab_id: 4 }, ctx({ ...POPUP, url: `${POPUP.url}?tab=12` }));
  assert.deepEqual(calls.at(-1).args, { tab_id: 4, popup_tab: 12 });
});

test("listing_never_ends_the_pages_conditional_request", async () => {
  const w = world();
  // Options the core cannot read (a challenge that is not base64url): the list says nothing, and the request still waits.
  await conditional(w, { challenge: "!!" });
  assert.deepEqual(await tabOp(w, "passkey_tab_list"), { ok: true, mode: "none" });
  await flush();
  assert.equal(w.pushed.length, 0, "the page learns nothing from the popup's look");
  assert.equal((await brokerOp(w, "passkey_tab")).conditional, true);
  // The core refuses the request (an RP ID the origin may not use): the same.
  const v = world();
  await conditional(v, { rp_id: "evil.test" });
  v.client.vault.passkey_candidates = async () => {
    throw Object.assign(new Error("malformed_rp_id"), { code: "malformed_rp_id" });
  };
  assert.deepEqual(await tabOp(v, "passkey_tab_list"), { ok: true, mode: "none" });
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(v.pushed.length, 0);
  assert.equal((await v.requests.ops.passkey_tab.run(null, { tab_id: 4 })).conditional, true);
});

test("a_verification_mark_of_a_conditional_request_lasts_five_minutes", async () => {
  for (const clock of /** @type {const} */ (["t", "w"])) {
    const w = world();
    await conditional(w, { user_verification: "required" });
    await tabOp(w, "passkey_tab_list");
    assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456" }), { ok: true });
    // The person does not pick at once: five minutes later on either clock the mark (and the recent unlock) count for nothing.
    w.mono[clock] += 5 * 60_000;
    assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: false, reason: "verification_needed" }, clock);
    assert.equal(w.state.signs.length, 0, clock);
  }
  // Within the five minutes it is used once, with UV.
  const w = world();
  await conditional(w, { user_verification: "required" });
  await tabOp(w, "passkey_tab_list");
  assert.deepEqual(await tabOp(w, "passkey_tab_verify", { method: "pin", pin: "123456" }), { ok: true });
  w.mono.t += 4 * 60_000;
  w.mono.w += 4 * 60_000;
  assert.deepEqual(await tabOp(w, "passkey_tab_choose", { item_id: ID(3) }), { ok: true });
  assert.deepEqual(w.state.signs.at(-1).uv, { user_present: true, user_verified: true });
});
