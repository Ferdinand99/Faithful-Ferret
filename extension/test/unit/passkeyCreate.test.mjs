// Making a passkey for a page (background/passkeyFlow.mjs and background/passkeyWrite.mjs, the `passkeys` feature): what the
// chooser window is offered for a create request, the person's choice, and the save protocol (design document § 8.3 and § 9.3):
// the page is answered only after the server has the item, a certain no leaves the choice to the person, an unknown outcome is
// sent again under the same key, the deadline waits for a started upload, and a write the server took after the page stopped
// waiting is undone. The write goes straight to the server: never through the outbox, never to the conflict view.
//
// The broker is the real one (with fake frames, tabs and clock); the core, the engine and the API client are fakes that keep what
// they were given. The modules come from the test variant's package (the writer needs the shared copies of web/src).
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { pkg } from "./sessionHelpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(here, "..", "..", "src");
const RP = "https://rp-a.test";
const SERVER = "https://vault.example";
const SESSION = "5e".repeat(16);
const USER_ID = "AQIDBA"; // bytes 1, 2, 3, 4
const CHALLENGE = "Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2UtMzI";

/** A few turns of the event loop. */
const flush = async (n = 6) => {
  for (let i = 0; i < n; i += 1) await new Promise((r) => setImmediate(r));
};
/** Real time, for the writer's short waits. @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** @param {number} n */
const idOf = (n) => n.toString(16).padStart(2, "0").repeat(16);
/** @param {string} b64u */
const bytesOf = (b64u) => Uint8Array.from(Buffer.from(b64u, "base64url"));

/** A deferred answer of the fake API. */
function deferred() {
  /** @type {(v: any) => void} */
  let resolve = () => {};
  /** @type {(e: any) => void} */
  let reject = () => {};
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** An error of the API client. @param {number} status @param {string} code @param {any} [body] */
const apiError = (status, code, body = null) => Object.assign(new Error(`${status} ${code}`), { name: "ApiError", status, code, body, retryAfter: null });

/**
 * An item of the fake engine.
 * @param {number} n
 * @param {{ name?: string, url?: string, how?: string, username?: string, passkey?: any, type?: string, rev?: number, pending?: boolean, folders?: string[] }} [o]
 */
function item(n, { name = `Item ${n}`, url = `${RP}/`, how = "host", username, passkey = null, type = "login", rev = 1, pending = false, folders = [] } = {}) {
  return {
    id: idOf(n), rev, type, name, url, how, pending, folders,
    view: { item_type: type, name, fields: username === undefined ? [] : [{ id: "username", value: username }], passkey },
  };
}

/**
 * @param {{ items?: any[], halted?: string | null, put?: (call: any) => Promise<any>, options?: Record<string, any>, timeout?: number, retry?: number }} [o]
 *   `retry`: the writer's wait between two tries (ms)
 */
async function world({ items = [], halted = null, put, options = {}, timeout, retry = 20 } = {}) {
  const { load } = await pkg();
  const [{ createPasskeyRequests }, { createPasskeyFlow }, { createPasskeyWrite }, { decode, PUSH_TYPES }, { createPasskeyVerify }] = await Promise.all([
    load("background/passkeyRequests.mjs"),
    load("background/passkeyFlow.mjs"),
    load("background/passkeyWrite.mjs"),
    load("shared/protocol.mjs"),
    load("background/passkeyVerify.mjs"),
  ]);
  // The broker's clock and timers, moved by the test.
  let at = 1_000_000;
  /** @type {Map<number, { fn: () => void, at: number }>} */
  const pending = new Map();
  let next = 1;
  const clock = {
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
  };
  /** @type {Array<{ type: string, body: any }>} */
  const pushed = [];
  const frames = { list: [{ frameId: 0, parentFrameId: -1, url: `${RP}/signup`, documentId: "doc-1" }] };
  let counter = 0;
  const requests = createPasskeyRequests({
    tabs: {
      sendMessage: async (/** @type {number} */ _tab, /** @type {string} */ raw) => {
        const { type, body } = decode(raw, PUSH_TYPES);
        pushed.push({ type, body });
      },
    },
    frames: { getAllFrames: async () => frames.list },
    windows: { open: async () => 101, close: async () => {} },
    servers: { current: async () => ({ origin: SERVER, live: true }) },
    storageLocal: { get: async () => ({ use_passkeys: true }) },
    permissions: { contains: async () => true },
    release: true,
    now: clock.now,
    timers: {
      setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => {
        const id = next++;
        pending.set(id, { fn, at: at + ms });
        return id;
      },
      clearTimeout: (/** @type {number} */ id) => void pending.delete(id),
    },
    random: (bytes) => {
      for (let i = 0; i < bytes.length; i += 1) bytes[i] = (counter * 31 + i * 7) & 0xff;
      counter += 1;
      return bytes;
    },
  });

  // ------------------------------------------------------------ the engine, the core and the server
  /** @type {Map<string, any>} */
  const byId = new Map(items.map((i) => [i.id, i]));
  /** What the server has accepted, by item id: the row the feed brings. @type {Map<string, any>} */
  const server = new Map();
  /** Whether the feed brings the server's rows to the engine. */
  const feed = { on: true };
  /** Whether the engine refuses a deletion. */
  const failRemove = { on: false };
  const writes = /** @type {any[]} */ ([]);
  const engineCalls = /** @type {string[]} */ ([]);
  let handleNo = 10;
  /** @type {Map<number, any>} */
  const handles = new Map();
  const engine = {
    list: () =>
      [...byId.values()].map((i) => ({
        id: i.id, rev: i.rev, type: i.type, name: i.name, urls: [i.url], folders: i.folders, hasPasskey: i.view.passkey !== null,
        passkeySite: i.view.passkey?.rp_id ?? null, pending: i.pending, readOnly: false, damaged: false, quarantined: false, blocked: false,
        conflict: false, missingOnServer: false,
      })),
    async open(/** @type {string} */ id) {
      const it = byId.get(id);
      if (!it) throw Object.assign(new Error("not_found"), { code: "not_found" });
      const handle = ++handleNo;
      handles.set(handle, it);
      return { handle, view: structuredClone(it.view), close: async () => void handles.delete(handle) };
    },
    async remove(/** @type {string} */ id) {
      if (failRemove.on) throw Object.assign(new Error("blocked"), { code: "blocked" });
      writes.push({ op: "remove", id, rev: byId.get(id)?.rev });
      byId.delete(id);
    },
    async update(/** @type {string} */ id, /** @type {any} */ draft, /** @type {number} */ rev) {
      writes.push({ op: "update", id, draft, rev });
      const it = byId.get(id);
      if (draft.remove_passkey) it.view.passkey = null;
      if (draft.folders) it.folders = draft.folders;
      it.rev += 1;
    },
    async syncNow() {
      engineCalls.push("syncNow");
      if (!feed.on) return;
      for (const [id, row] of server) {
        const it = byId.get(id);
        if (it && it.rev >= row.rev) continue;
        if (it) {
          it.rev = row.rev;
          it.view.passkey = row.passkey;
        } else {
          byId.set(id, { ...item(0, { name: row.name }), id, rev: row.rev, view: { item_type: "login", name: row.name, fields: [], passkey: row.passkey } });
        }
      }
    },
    health: () => ({ halted, warnings: [] }),
    // The outbox and the conflict view: never reached by a passkey's write.
    create: async () => void engineCalls.push("create"),
    importItems: async () => void engineCalls.push("importItems"),
    resolve: async () => void engineCalls.push("resolve"),
    conflict: async () => void engineCalls.push("conflict"),
  };
  const core = /** @type {any[]} */ ([]);
  /** The passkey being made: what passkey_create was given. @type {any} */
  let making = null;
  const vault = {
    match_page: async (/** @type {string} */ url, /** @type {number[]} */ hs) =>
      hs.flatMap((h) => {
        const it = handles.get(h);
        if (!it) return [];
        if (it.how === "exact") return it.url === url ? [{ handle: h, how: "exact" }] : [];
        return new URL(it.url).host === new URL(url).host ? [{ handle: h, how: it.how }] : [];
      }),
    passkey_site: async (/** @type {any} */ caller, /** @type {string | null} */ rpId) => {
      core.push({ op: "passkey_site", caller, rpId });
      const host = new URL(caller.origin).hostname;
      return { origin: caller.origin, host_unicode: host, rp_id: rpId ?? host, rp_id_unicode: rpId ?? host };
    },
    passkey_create: async (/** @type {any[]} */ ...args) => {
      const [itemId, rev, name, request, caller, uv, existing, nowMs, attach] = args;
      core.push({ op: "passkey_create", itemId: Buffer.from(itemId).toString("hex"), rev, name, request, caller, uv, existing, nowMs, attach });
      const stored = existing === "no_existing" ? [] : existing;
      if (request.exclude.some((/** @type {Uint8Array} */ x) => stored.some((/** @type {any} */ s) => Buffer.from(s.id).equals(Buffer.from(x))))) {
        throw Object.assign(new Error("invalid_state"), { code: "invalid_state" });
      }
      making = { itemId: Buffer.from(itemId).toString("hex"), rev, name, rpId: request.rp_id ?? new URL(caller.origin).hostname, created: nowMs, attach };
      return { item: { rev, envelope: new Uint8Array([9, 9, rev]), tag: new Uint8Array(32).fill(rev) }, item_id: itemId, pending: 77 };
    },
    passkey_create_confirm: async (/** @type {number} */ p) => {
      core.push({ op: "confirm", pending: p });
      return {
        response: {
          id: new Uint8Array(16).fill(5), attestation_object: new Uint8Array([1, 2]), client_data_json: new Uint8Array([3]), authenticator_data: new Uint8Array([4]),
          public_key_spki: new Uint8Array([6]), alg: -7, authenticator_attachment: "platform", transports: ["hybrid", "internal"], cred_props: { rk: true }, prf: null,
        },
        handle: 900,
      };
    },
    passkey_create_abort: async (/** @type {number} */ p) => void core.push({ op: "abort", pending: p }),
    close_item: async (/** @type {number} */ h) => void core.push({ op: "close", handle: h }),
  };
  /** @type {any[]} */
  const puts = [];
  const api = {
    put: async (/** @type {string} */ path, /** @type {Uint8Array} */ bytes, /** @type {any} */ opts) => {
      const call = { path, body: JSON.parse(Buffer.from(bytes).toString("utf8")), bytes: Buffer.from(bytes).toString("utf8"), opts };
      puts.push(call);
      const answer = put ? put(call) : Promise.resolve({ rev: call.body.base_rev + 1, seq: 1, replayed: false });
      return answer.then((value) => {
        // What the server took, the feed brings.
        const id = path.split("/").pop();
        server.set(id, { rev: call.body.base_rev + 1, name: making?.name ?? "", passkey: { rp_id: making?.rpId, created: making?.created, cred_id: new Uint8Array(16).fill(5), user_handle: bytesOf(USER_ID) } });
        return value;
      });
    },
  };
  /** @type {Map<string, any>} */
  let leftovers = new Map();
  /** The browser session's storage of the follow-ups (it outlives a restart of the background page). */
  const sessionStore = { list: /** @type {any} */ (null) };
  const store = { load: async () => sessionStore.list ?? [], save: async (/** @type {any[]} */ list) => void (sessionStore.list = structuredClone(list)) };
  const make = () => createPasskeyWrite({ engine, vault, api, epoch: async () => 3, scope: "s", leftovers, saveMs: 300, retryMs: () => retry, store });
  let writer = make();
  let writerOn = true;
  // User verification as the background has it: the master password is a way only while `ways` is on (it needs the server).
  const verifyState = { ways: false };
  const verify = createPasskeyVerify({
    password: { verify: async () => ({ ok: true }) },
    settings: { recentAllowed: async () => true },
    marks: { mark: (/** @type {string} */ id, /** @type {string} */ s) => requests.markVerified(id, s), take: (/** @type {string} */ id, /** @type {string} */ s) => requests.takeVerified(id, s) },
    online: async () => verifyState.ways,
  });
  const flow = createPasskeyFlow({ requests, writer: () => (writerOn ? writer : null), verify });
  const client = { vault };

  /** A create request of the page, owned by the window's session. @param {Record<string, any>} [over] */
  async function request(over = {}) {
    const create = {
      challenge: CHALLENGE, rp: { name: "RP A" }, user: { id: USER_ID, name: "alice", display_name: "Alice" },
      pub_key_cred_params: [{ type: "public-key", alg: -7 }], exclude_credentials: [], hints: [], extensions: {},
      ...(timeout !== undefined ? { timeout } : {}), ...options, ...over,
    };
    const opened = await requests.open({ tabId: 4, frameId: 0, documentId: "doc-1", url: `${RP}/signup`, origin: RP }, { request_id: "b".repeat(32), kind: "create", mediation: "optional", create, activation: true, policy: true });
    const id = /** @type {any} */ (opened).request_id;
    assert.match(id, /^[0-9a-f]{32}$/, JSON.stringify(opened));
    return id;
  }
  /** @param {string} op @param {Record<string, unknown>} args */
  const call = (op, args) =>
    /** @type {Promise<any>} */ (op === "passkey_choose" ? flow.chooseCreate(client, { session: SESSION, ...args }) : flow.ops[op].run(client, { session: SESSION, ...args }));
  return {
    requests, flow, verify, verifyState, engine, vault, api, puts, pushed, core, writes, engineCalls, byId, server, clock, frames, request, call, feed, failRemove, sessionStore,
    get writer() {
      return writer;
    },
    get leftovers() {
      return leftovers;
    },
    /** @param {boolean} on */
    setWriter: (on) => void (writerOn = on),
    /**
     * A lock and the next unlock: the writer stops and a new one is made (`restart`: the background page started again, so only
     * the browser session's storage has the follow-ups). @param {{ restart?: boolean }} [o]
     */
    relock({ restart = false } = {}) {
      writer.stop();
      if (restart) leftovers = new Map();
      writer = make();
      return writer;
    },
  };
}

const results = (/** @type {any[]} */ pushed) => pushed.filter((p) => p.type === "passkey_result");
const errors = (/** @type {any[]} */ pushed) => pushed.filter((p) => p.type === "passkey_error");

// -------------------------------------------------------------------------------------------------------- the save protocol

test("a_new_passkey_is_answered_only_after_the_server_accepted_the_item", async () => {
  const gate = deferred();
  const w = await world({ put: () => gate.promise });
  const id = await w.request();
  const choosing = w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" });
  await sleep(30);
  // The item is on its way: the core has made the passkey, the page has nothing and the answer is still held in the core.
  assert.equal(w.puts.length, 1);
  assert.deepEqual(results(w.pushed), []);
  assert.equal(w.core.filter((c) => c.op === "confirm").length, 0);
  // The write: the sealed item of the core, a new item (base 0), its own key, conditional on the restore epoch.
  const made = w.core.find((c) => c.op === "passkey_create");
  assert.equal(w.puts[0].path, `/api/sync/items/${made.itemId}`);
  assert.equal(w.puts[0].opts.shape, "put_item_res");
  assert.equal(w.puts[0].body.base_rev, 0);
  assert.match(w.puts[0].body.idem, /^[0-9a-f]{32}$/);
  assert.equal(w.puts[0].body.restore_epoch, 3);
  // The core got the caller of the broker, the click as presence, and the page's options as its request.
  assert.deepEqual(made.caller, { origin: RP, top_origin_is_same: true });
  assert.deepEqual(made.uv, { user_present: true, user_verified: false });
  assert.equal(made.request.cred_props, false);
  assert.deepEqual([...made.request.user_id], [1, 2, 3, 4]);
  assert.deepEqual(made.request.algorithms, [-7]);
  gate.resolve({ rev: 1, seq: 9, replayed: false });
  assert.deepEqual(await choosing, { ok: true });
  // Only now: the core gives the answer, and it goes to the page.
  const order = w.core.map((c) => c.op);
  assert.ok(order.indexOf("confirm") > order.indexOf("passkey_create"));
  assert.equal(results(w.pushed).length, 1);
  const answer = results(w.pushed)[0].body.response;
  assert.deepEqual(answer.transports, ["hybrid", "internal"]);
  assert.deepEqual(answer.client_extension_results, { cred_props: { rk: true } });
  assert.equal(answer.public_key_algorithm, -7);
  // The new item's handle of the core is closed again (the engine opens its own), nothing is aborted.
  assert.ok(w.core.some((c) => c.op === "close" && c.handle === 900));
  assert.equal(w.core.filter((c) => c.op === "abort").length, 0);
});

test("a_definite_no_aborts_and_the_page_gets_nothing_until_the_user_chooses", async () => {
  /** @type {any[]} */
  const answers = [apiError(409, "conflict", { current_rev: 4, deleted: false, blob: "AA", tag: "BB" }), apiError(429, "rate_limited"), apiError(503, "unavailable"), apiError(409, "restore_epoch_changed", { error: "restore_epoch_changed" })];
  const w = await world({ put: () => (answers.length > 0 ? Promise.reject(answers.shift()) : Promise.resolve({ rev: 1, seq: 1, replayed: false })) });
  const id = await w.request();
  for (const reason of ["busy", "network", "network", "network"]) {
    const reply = await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" });
    assert.deepEqual(reply, { ok: false, reason });
    // Sent once (a certain no is not sent again), the answer wiped in the core, nothing to the page, and the request still waits.
    assert.equal(w.core.filter((c) => c.op === "abort").length, w.puts.length);
    assert.deepEqual(w.pushed, []);
    assert.equal(w.requests.waiting(id, SESSION), true);
  }
  assert.equal(w.puts.length, 4);
  // The person tries again: that one is taken, and the page gets the answer.
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" }), { ok: true });
  assert.equal(results(w.pushed).length, 1);
  // Each try had a key of its own.
  assert.equal(new Set(w.puts.map((p) => p.body.idem)).size, 5);
});

test("an_unknown_upload_outcome_is_resent_with_the_same_idem", async () => {
  /** @type {any[]} */
  const answers = [apiError(0, "network"), apiError(502, "bad_gateway"), apiError(200, "bad_response")];
  const w = await world({ put: () => (answers.length > 0 ? Promise.reject(answers.shift()) : Promise.resolve({ rev: 1, seq: 1, replayed: true })) });
  const id = await w.request();
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" }), { ok: true });
  // The same bytes, under the same key, until the server answered for certain.
  assert.equal(w.puts.length, 4);
  assert.equal(new Set(w.puts.map((p) => p.bytes)).size, 1);
  assert.equal(new Set(w.puts.map((p) => p.body.idem)).size, 1);
  assert.equal(results(w.pushed).length, 1);

  // No certain answer within the time: a no for the person (the page gets nothing), and the write is followed up: when the server
  // turns out to have taken it, the item is undone.
  let silent = true;
  const v = await world({ put: () => (silent ? Promise.reject(apiError(0, "network")) : Promise.resolve({ rev: 1, seq: 2, replayed: true })) });
  const vid = await v.request();
  assert.deepEqual(await v.call("passkey_choose", { request_id: vid, kind: "create", mode: "new", name: "rp-a.test" }), { ok: false, reason: "network" });
  assert.ok(v.puts.length >= 2);
  assert.deepEqual(v.pushed, []);
  assert.equal(v.requests.waiting(vid, SESSION), true);
  assert.equal(v.leftovers.size, 1);
  silent = false;
  await sleep(120);
  assert.equal(new Set(v.puts.map((p) => p.body.idem)).size, 1, "the follow-up uses the same key");
  assert.deepEqual(v.writes.map((x) => x.op), ["remove"]);
  assert.equal(v.leftovers.size, 0);
});

test("the_deadline_waits_for_a_started_upload", async () => {
  const gate = deferred();
  const w = await world({ put: () => gate.promise, timeout: 30_000 });
  const id = await w.request();
  const choosing = w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" });
  await sleep(30);
  assert.equal(w.puts.length, 1);
  // The page's deadline passes while the item is on its way: the request waits for the outcome.
  w.clock.advance(31_000);
  await flush();
  assert.deepEqual(w.pushed, []);
  assert.equal(w.requests.waiting(id, SESSION), true);
  gate.resolve({ rev: 1, seq: 1, replayed: false });
  assert.deepEqual(await choosing, { ok: true });
  assert.equal(results(w.pushed).length, 1);
  assert.deepEqual(errors(w.pushed), []);

  // Without an upload the deadline ends the request as before; after a refused upload a deadline that passed ends it at once.
  const no = deferred();
  const v = await world({ put: () => no.promise, timeout: 30_000 });
  const vid = await v.request();
  const refusing = v.call("passkey_choose", { request_id: vid, kind: "create", mode: "new", name: "rp-a.test" });
  await sleep(30);
  v.clock.advance(31_000);
  await flush();
  assert.equal(v.requests.waiting(vid, SESSION), true);
  no.reject(apiError(409, "conflict"));
  assert.deepEqual(await refusing, { ok: false, reason: "busy" });
  await flush();
  assert.equal(v.requests.waiting(vid, SESSION), false);
});

test("an_item_accepted_after_the_page_left_goes_to_the_trash_with_a_note", async () => {
  const gate = deferred();
  const w = await world({ put: () => gate.promise });
  const id = await w.request();
  const choosing = w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" });
  await sleep(30);
  // The page navigates away while the item is on its way.
  w.requests.onNavigation({ tabId: 4, frameId: 0, documentId: "doc-2" });
  gate.resolve({ rev: 1, seq: 1, replayed: false });
  assert.deepEqual(await choosing, { ok: false, reason: "gone" });
  await sleep(50);
  // Nobody got the passkey: the answer is wiped, never released, and the item goes with an ordinary deletion of its first
  // revision (the trash shows such an item with the note that its passkey is not registered at the site).
  assert.equal(w.core.filter((c) => c.op === "confirm").length, 0);
  assert.equal(w.core.filter((c) => c.op === "abort").length, 1);
  assert.deepEqual(results(w.pushed), []);
  const made = w.core.find((c) => c.op === "passkey_create");
  assert.deepEqual(w.writes, [{ op: "remove", id: made.itemId, rev: 1 }]);
  const trash = readFileSync(resolve(SRC, "..", "..", "web", "src", "views", "trash.mjs"), "utf8");
  assert.match(trash, /firstRevision === true[^\n]*passkey\.trash_unregistered/);

  // The same when the server's yes comes and the answer cannot reach the page any more (its frame chain changed).
  const v = await world();
  const vid = await v.request();
  const original = v.requests.answer;
  /** @type {any} */ (v.requests).answer = async (/** @type {any[]} */ ...args) => {
    v.frames.list = [{ frameId: 0, parentFrameId: -1, url: "https://other.test/", documentId: "doc-1" }];
    return original(...args);
  };
  assert.deepEqual(await v.call("passkey_choose", { request_id: vid, kind: "create", mode: "new", name: "rp-a.test" }), { ok: false, reason: "gone" });
  await sleep(50);
  assert.deepEqual(v.writes.map((x) => x.op), ["remove"]);
});

test("an_attach_accepted_too_late_removes_only_the_passkey_again", async () => {
  const gate = deferred();
  const w = await world({ items: [item(1, { name: "RP A", username: "alice", rev: 4 })], put: () => gate.promise });
  const id = await w.request();
  const options = await w.call("passkey_create_options", { request_id: id });
  assert.deepEqual(options.targets.map((/** @type {any} */ t) => t.item_id), [idOf(1)]);
  const choosing = w.call("passkey_choose", { request_id: id, kind: "create", mode: "attach", item_id: idOf(1) });
  await sleep(30);
  // Added to the item as its next revision, through the open item's handle.
  const made = w.core.find((c) => c.op === "passkey_create");
  assert.equal(made.itemId, idOf(1));
  assert.equal(made.rev, 5);
  assert.equal(typeof made.attach, "number");
  assert.equal(w.puts[0].body.base_rev, 4);
  // The person cancels while it is on its way; then the server takes it.
  assert.equal(w.requests.cancel(id, SESSION), true);
  gate.resolve({ rev: 5, seq: 1, replayed: false });
  assert.deepEqual(await choosing, { ok: false, reason: "gone" });
  await sleep(50);
  // Only the passkey leaves the item again (the rest stays), so the next "add" is not stopped; the item is not deleted.
  assert.deepEqual(w.writes, [{ op: "update", id: idOf(1), draft: { remove_passkey: true }, rev: 5 }]);
  assert.equal(w.byId.get(idOf(1))?.view.passkey, null);
  assert.equal(w.byId.get(idOf(1))?.name, "RP A");
});

test("a_create_write_never_enters_the_outbox_or_the_conflict_view", async () => {
  /** @type {any[]} */
  const answers = [apiError(409, "conflict", { current_rev: 2, deleted: false, blob: "x", tag: "y" })];
  const w = await world({ items: [item(1)], put: () => (answers.length > 0 ? Promise.reject(answers.shift()) : Promise.resolve({ rev: 1, seq: 1, replayed: false })) });
  const id = await w.request();
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x" }), { ok: false, reason: "busy" });
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x" }), { ok: true });
  // The writes went to the server directly; the engine was asked to write nothing (no outbox entry, no draft, no conflict).
  assert.equal(w.puts.length, 2);
  assert.deepEqual(w.engineCalls.filter((c) => c !== "syncNow"), []);
  assert.deepEqual(w.writes, []);
  // A 409 that shows this very write counts as done (its key ran out), never as a conflict.
  const own = await world({ put: (/** @type {any} */ c) => Promise.reject(apiError(409, "conflict", { current_rev: 1, deleted: false, blob: c.body.blob, tag: c.body.tag })) });
  const oid = await own.request();
  assert.deepEqual(await own.call("passkey_choose", { request_id: oid, kind: "create", mode: "new", name: "x" }), { ok: true });
  // The source: the writer and the flow never reach the outbox, the engine's create or the conflict calls.
  for (const file of ["background/passkeyWrite.mjs", "background/passkeyFlow.mjs"]) {
    const text = readFileSync(join(SRC, file), "utf8").replace(/^\s*\/\/.*$/gm, "");
    for (const banned of [/engine\.create\b/, /importItems/, /enqueue/, /outbox/i, /engine\.(?:resolve|conflict|discard|acceptOlderState)\b/]) assert.doesNotMatch(text, banned, `${file}: ${banned}`);
  }
});

// -------------------------------------------------------------------------------------------------------- a lock on the way

test("a_lock_during_the_retry_wait_leaves_a_follow_up_that_the_next_unlock_finishes", async () => {
  let down = true;
  const w = await world({ retry: 60_000, put: () => (down ? Promise.reject(apiError(0, "network")) : Promise.resolve({ rev: 1, seq: 4, replayed: true })) });
  const id = await w.request();
  const choosing = w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" });
  await sleep(30);
  assert.equal(w.puts.length, 1, "the first try went, the writer waits a minute before the next");
  // The vault locks during the wait: the choice comes back at once (nothing hangs), as a no for the person.
  w.writer.stop();
  const reply = await Promise.race([choosing, sleep(1000).then(() => "hung")]);
  assert.deepEqual(reply, { ok: false, reason: "network" });
  assert.deepEqual(results(w.pushed), []);
  // The write is kept as a follow-up, in memory and in the browser session's storage (sealed bytes, no key).
  assert.equal(w.leftovers.size, 1);
  assert.equal(w.sessionStore.list.length, 1);
  assert.equal(w.sessionStore.list[0].key, w.puts[0].body.idem);
  // The background page starts again (memory gone) and the vault is opened: the follow-up goes on from storage, with the same key,
  // and the item the server took (the page never got it) goes again.
  down = false;
  w.relock({ restart: true });
  await sleep(150);
  assert.equal(new Set(w.puts.map((p) => p.body.idem)).size, 1);
  assert.ok(w.puts.length >= 2);
  const made = w.core.find((c) => c.op === "passkey_create");
  assert.deepEqual(w.writes, [{ op: "remove", id: made.itemId, rev: 1 }]);
  assert.equal(w.leftovers.size, 0);
  assert.deepEqual(w.sessionStore.list, []);
});

test("a_lock_during_the_undo_keeps_it_for_the_next_unlock_and_a_failed_undo_is_kept", async () => {
  const gate = deferred();
  const w = await world({ retry: 60_000, put: () => gate.promise });
  const id = await w.request();
  const choosing = w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" });
  await sleep(30);
  // The page leaves; the server takes the item; the feed does not bring it yet, so the undo waits for it.
  w.requests.onNavigation({ tabId: 4, frameId: 0, documentId: "doc-2" });
  w.feed.on = false;
  gate.resolve({ rev: 1, seq: 1, replayed: false });
  assert.deepEqual(await choosing, { ok: false, reason: "gone" });
  await sleep(30);
  assert.equal(w.leftovers.size, 1, "the undo is kept while it waits");
  // The vault locks during that wait: nothing hangs and the undo stays for the next unlock.
  w.relock();
  // The next unlock: the follow-up asks the server again (same key, a replay) and the feed now brings the item; the deletion is
  // refused this time (the engine is busy): it is not dropped.
  w.writer.stop();
  w.feed.on = true;
  w.failRemove.on = true;
  w.relock();
  await sleep(150);
  assert.deepEqual(w.writes, []);
  assert.equal(w.leftovers.size, 1, "a failed undo is kept, not dropped");
  // And the unlock after that finishes it.
  w.failRemove.on = false;
  w.relock();
  await sleep(150);
  const made = w.core.find((c) => c.op === "passkey_create");
  assert.deepEqual(w.writes, [{ op: "remove", id: made.itemId, rev: 1 }]);
  assert.equal(w.leftovers.size, 0);
  assert.equal(new Set(w.puts.map((p) => p.body.idem)).size, 1);
});

test("a_refused_write_keeps_the_verification_mark_for_the_next_try", async () => {
  /** @type {any[]} */
  const answers = [apiError(503, "unavailable")];
  const w = await world({ options: { authenticator_selection: { user_verification: "required" } }, put: () => (answers.length > 0 ? Promise.reject(answers.shift()) : Promise.resolve({ rev: 1, seq: 1, replayed: false })) });
  const id = await w.request();
  w.verifyState.ways = true;
  // Without a mark a required request asks for the verification first, and nothing is made.
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x" }), { ok: false, reason: "verification_needed" });
  assert.equal(w.core.filter((c) => c.op === "passkey_create").length, 0);
  assert.equal(w.requests.markVerified(id, SESSION), true);
  // The server refuses the write: the page got nothing, and the mark stays for the person's next try.
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x" }), { ok: false, reason: "network" });
  // (The mark was used for the try and given back: the next try needs no new verification.)
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x" }), { ok: true });
  assert.deepEqual(w.core.filter((c) => c.op === "passkey_create").map((c) => c.uv), [{ user_present: true, user_verified: true }, { user_present: true, user_verified: true }]);
  // The answer ends the request, and its mark with it.
  assert.equal(w.requests.takeVerified(id, SESSION), false);
});

// -------------------------------------------------------------------------------------------------------- what the window is offered

test("add_to_existing_offers_only_host_or_exact_items_without_a_passkey", async () => {
  const w = await world({
    items: [
      item(1, { name: "By host", username: "bob" }),
      item(2, { name: "By domain only", how: "domain", url: "https://login.rp-a.test/" }),
      item(3, { name: "Has a passkey", passkey: { rp_id: "rp-a.test", cred_id: new Uint8Array([7]), user_handle: new Uint8Array([9]) } }),
      item(4, { name: "Waiting to be sent", pending: true }),
      item(5, { name: "A note", type: "note" }),
      item(6, { name: "Exact", how: "exact", url: `${RP}/signup`, username: "Alice " }),
      item(7, { name: "Other site", url: "https://other.test/" }),
    ],
  });
  const id = await w.request();
  const reply = await w.call("passkey_create_options", { request_id: id });
  assert.equal(reply.ok, true);
  assert.deepEqual(
    reply.targets.map((/** @type {any} */ t) => [t.name, t.user_name, t.same_user]).sort(),
    [["By host", "bob", false], ["Exact", "Alice ", true]],
  );
  // Nothing of an item but its id, name and user name; the RP ID is the core's, from the broker's caller.
  assert.deepEqual(Object.keys(reply.targets[0]).sort(), ["item_id", "name", "same_user", "user_name"]);
  assert.deepEqual(w.core.find((c) => c.op === "passkey_site")?.caller, { origin: RP, top_origin_is_same: true });
  // Only a listed item can be chosen: one that was not offered is refused.
  for (const n of [2, 3, 4, 7]) {
    assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "attach", item_id: idOf(n) }), { ok: false, reason: "not_found" }, `item ${n}`);
  }
  assert.equal(w.puts.length, 0);
  // Another session (another window) gets nothing.
  assert.deepEqual(await w.call("passkey_create_options", { request_id: id, session: "7f".repeat(16) }), { ok: false, reason: "gone" });
});

test("an_existing_passkey_for_the_same_account_is_named_and_a_new_item_offered", async () => {
  const same = { rp_id: "rp-a.test", cred_id: new Uint8Array([7]), user_handle: new Uint8Array([1, 2, 3, 4]) };
  const w = await world({
    items: [
      item(1, { name: "Old passkey", passkey: same }),
      item(2, { name: "Other account", passkey: { ...same, cred_id: new Uint8Array([8]), user_handle: new Uint8Array([5]) } }),
      item(3, { name: "Other site", url: "https://rp-b.test/", passkey: { ...same, rp_id: "rp-b.test", cred_id: new Uint8Array([9]) } }),
    ],
  });
  const id = await w.request();
  const reply = await w.call("passkey_create_options", { request_id: id });
  assert.deepEqual(reply.existing, { item_id: idOf(1), name: "Old passkey" });
  // The text says it conditionally (a passkey restored from the trash may never have been registered), and a new item is offered.
  const en = JSON.parse(readFileSync(join(SRC, "locales", "en", "passkeys.json"), "utf8"));
  const nb = JSON.parse(readFileSync(join(SRC, "locales", "nb", "passkeys.json"), "utf8"));
  assert.match(en["passkeys.make.existing"], /\{item\}.*If the website accepted it/);
  assert.match(nb["passkeys.make.existing"], /\{item\}.*Hvis nettstedet tok den imot/);
  // The new item: every passkey of the vault goes to the core for excludeCredentials.
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" }), { ok: true });
  const made = w.core.find((c) => c.op === "passkey_create");
  assert.deepEqual(made.existing.map((/** @type {any} */ e) => [e.rp_id, [...e.id]]).sort(), [["rp-a.test", [7]], ["rp-a.test", [8]], ["rp-b.test", [9]]]);
  assert.equal(made.attach, undefined);
});

test("exclude_credentials_gives_invalid_state_after_the_click", async () => {
  const stored = { rp_id: "rp-a.test", cred_id: new Uint8Array(16).fill(7), user_handle: new Uint8Array([5]) };
  const w = await world({ items: [item(1, { passkey: stored })], options: { exclude_credentials: [{ type: "public-key", id: Buffer.from(stored.cred_id).toString("base64url") }] } });
  const id = await w.request();
  // The window is shown and offered as usual: the page learns nothing before the click.
  assert.equal((await w.call("passkey_create_options", { request_id: id })).ok, true);
  await flush();
  assert.deepEqual(w.pushed, []);
  // The click: the core finds the excluded passkey, the page gets InvalidStateError, and nothing is written.
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "rp-a.test" }), { ok: false, reason: "excluded" });
  await flush();
  assert.deepEqual(errors(w.pushed).map((p) => p.body.name), ["InvalidStateError"]);
  assert.equal(w.puts.length, 0);
  assert.equal(w.requests.waiting(id, SESSION), false);
});

test("offline_create_says_why_and_offers_the_browser", async () => {
  // The window finds out from the sync's state before it offers anything, and says why.
  const { load } = await pkg();
  const { createChooserBackend } = await load("pages/passkeyFlow.mjs");
  const id = "c".repeat(32);
  const answers = /** @type {Record<string, any>} */ ({
    passkey_pending: { ok: true, request: { request_id: id, kind: "create", origin: RP, rp_name: "RP A", user_name: "alice", user_display_name: "Alice" } },
    passkey_site: { ok: true, site: { origin: RP, host_unicode: "rp-a.test", rp_id: "rp-a.test", rp_id_unicode: "rp-a.test" } },
    sync_state: { running: true, status: "offline" },
    passkey_create_options: { ok: true, targets: [], existing: null, folders: [] },
  });
  const backend = createChooserBackend(async (/** @type {string} */ type) => answers[type], id, { has: () => true });
  const view = await backend.view();
  assert.equal(view.ok, true);
  assert.equal(view.view.online, false);
  const en = JSON.parse(readFileSync(join(SRC, "locales", "en", "passkeys.json"), "utf8"));
  assert.match(en["passkeys.make.offline"], /without contact with the server/);
  // The background refuses a write it cannot make (the sync is stopped, or there is none) with `network`, and the request stays
  // for the browser: "Use the browser" hands it over.
  const w = await world({ halted: "server_restored" });
  const rid = await w.request();
  assert.deepEqual(await w.call("passkey_choose", { request_id: rid, kind: "create", mode: "new", name: "rp-a.test" }), { ok: false, reason: "network" });
  w.setWriter(false);
  assert.deepEqual(await w.call("passkey_choose", { request_id: rid, kind: "create", mode: "new", name: "rp-a.test" }), { ok: false, reason: "network" });
  assert.equal(w.puts.length, 0);
  assert.equal(w.core.filter((c) => c.op === "passkey_create").length, 0);
  assert.deepEqual(await w.requests.ops.passkey_browser.run(null, { request_id: rid, session: SESSION }), { ok: true });
  await flush();
  // "Use the browser" hands over once (the page is asked to call again; the next call of the same kind goes through).
  assert.deepEqual(w.pushed.map((p) => [p.type, p.body.once]), [["passkey_handover", true]]);
});

test("the_new_item_name_is_the_host_and_editable", async () => {
  const { load } = await pkg();
  const { defaultItemName } = await load("pages/passkeyFlow.mjs");
  assert.equal(defaultItemName("www.rp-a.test"), "rp-a.test");
  assert.equal(defaultItemName("bücher.example"), "bücher.example");
  const w = await world({ items: [item(1, { folders: ["Work"] }), item(2, { url: "https://other.test/", folders: ["Private", "work"] })] });
  const id = await w.request();
  const reply = await w.call("passkey_create_options", { request_id: id });
  // Folders by a reference of this request; a name that differs only in case is one folder.
  assert.deepEqual(reply.folders.map((/** @type {any} */ f) => f.name), ["Private", "Work"]);
  for (const f of reply.folders) assert.match(f.id, /^[0-9a-f]{32}$/);
  // An empty name or an unknown folder is refused before anything is made.
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "   " }), { ok: false, reason: "invalid_input" });
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x", folder_id: "e".repeat(32) }), { ok: false, reason: "invalid_input" });
  // The person's own name (trimmed) and folder.
  const work = reply.folders.find((/** @type {any} */ f) => f.name === "Work");
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "  My RP  ", folder_id: work.id }), { ok: true });
  const made = w.core.find((c) => c.op === "passkey_create");
  assert.equal(made.name, "My RP");
  await sleep(50);
  // The folder follows the server's yes as an ordinary change of the new item's first revision.
  assert.deepEqual(w.writes, [{ op: "update", id: made.itemId, draft: { folders: ["Work"] }, rev: 1 }]);
});

// -------------------------------------------------------------------------------------------------------- the architecture

/** Every .mjs file under a directory. @param {string} dir @returns {string[]} */
function sources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return name.endsWith(".mjs") ? [path] : [];
  });
}

test("only_passkey_write_sends_a_passkey_create", async () => {
  /** @type {string[]} */
  const callers = [];
  /** @type {string[]} */
  const writers = [];
  for (const path of sources(SRC)) {
    const text = readFileSync(path, "utf8").replace(/^\s*\/\/.*$/gm, "").replace(/^\s*\*.*$/gm, "");
    const rel = relative(SRC, path).split("\\").join("/");
    if (/\.passkey_create(?:_confirm|_abort)?\s*\(/.test(text)) callers.push(rel);
    // (The test build's own probe that stores a test key in the vault, background/test-only, is never in a release.)
    if (/\/api\/sync\/items/.test(text) && !rel.startsWith("background/test-only/")) writers.push(rel);
  }
  assert.deepEqual(callers, ["background/passkeyWrite.mjs"]);
  assert.deepEqual(writers, ["background/passkeyWrite.mjs"]);
  // The built package: the writer reaches the engine only through the sync, and the flow only through the generated module.
  const { dir } = await pkg();
  const gen = readFileSync(join(dir, "background", "passkeys.gen.mjs"), "utf8");
  assert.match(gen, /export \{ createPasskeyWrite \} from "\.\/passkeyWrite\.mjs";/);
  assert.match(gen, /export \{ createPasskeyFlow \} from "\.\/passkeyFlow\.mjs";/);
  const sync = readFileSync(join(SRC, "background", "sync.mjs"), "utf8");
  assert.doesNotMatch(sync, /passkeyWrite\.mjs["']/, "the sync gets the writer as a factory, it does not import the feature");
  // The window's two types are in the UI table, the core's ops and the window handler, and need the open vault.
  const { load } = await pkg();
  const [{ UI_TYPES }, { CORE_OPS }, handler, { LOCK_EXEMPT }] = await Promise.all([
    load("shared/protocol.mjs"),
    load("background/coreHost.mjs"),
    load("background/handlers/passkeyWindow.handler.mjs"),
    load("background/lock.mjs"),
  ]);
  for (const type of ["passkey_create_options", "passkey_choose"]) {
    assert.ok(Object.hasOwn(UI_TYPES, type), type);
    assert.ok(CORE_OPS.includes(type), type);
    assert.ok(handler.default.types.includes(type), type);
    assert.ok(!LOCK_EXEMPT.includes(type), type);
  }
  // The choice carries no claim of presence or verification: the request schema has no such field.
  const { validate } = await load("shared/schema.mjs");
  assert.throws(() => validate(UI_TYPES.passkey_choose.request, { request_id: "a".repeat(32), kind: "create", mode: "new", name: "x", user_present: true }));
  assert.throws(() => validate(UI_TYPES.passkey_choose.request, { request_id: "a".repeat(32), kind: "create", mode: "new", name: "x", user_verified: true }));
});

test("a_create_decides_verification_as_a_get_does", async () => {
  const w = await world();
  w.verifyState.ways = true;
  const id = await w.request();
  // `preferred` (no `userVerification` given) asks for verification when there is a way, as a get does.
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x" }), { ok: false, reason: "verification_needed" });
  assert.equal(w.core.filter((c) => c.op === "passkey_create").length, 0);
  // The options tell the window which ways there are, and whether a recent unlock is enough.
  const options = await w.call("passkey_create_options", { request_id: id });
  assert.deepEqual(options.methods, ["password"]);
  assert.equal(options.recent, false);
  // A recent unlock is enough, and the mark it issues is used by the create.
  w.verify.markUnlocked();
  assert.equal((await w.call("passkey_create_options", { request_id: id })).recent, true);
  assert.deepEqual(await w.call("passkey_choose", { request_id: id, kind: "create", mode: "new", name: "x" }), { ok: true });
  assert.deepEqual(w.core.filter((c) => c.op === "passkey_create").map((c) => c.uv), [{ user_present: true, user_verified: true }]);
});
