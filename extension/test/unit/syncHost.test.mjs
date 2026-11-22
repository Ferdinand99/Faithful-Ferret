// The sync in the background: the shared engine starts when the vault opens
// and stops at every lock, a stop of the sync reaches the popup with "Try
// again" and "Forget this server" and nothing else, "Forget this server"
// revokes the device and keeps nothing of the server, the event stream carries
// a proof and no cookie, and a revoked device stops syncing and shows "signed
// out". The background is the real one (core host, session, sync host, lock,
// router and the two handlers) over the real shared sign-in in device mode, a
// fake vault server and a fake core; the engine is a fake where a test only
// needs to see what the background does with it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { UI_TYPES } from "../../src/shared/protocol.mjs";
import {
  ACCOUNT, EMAIL, SERVER, SK_CODE, VAULT, answer, coreClient, deviceServer, fakeChannels, fakeEngines, memoryDb, memoryStore, pkg, sessionWorld,
} from "./sessionHelpers.mjs";

const MP = "Correct-horse-UNIQUE-4711";
const OTHER = "https://other.example.org";

/** A shared session in device mode over `fetchImpl`, as the background makes it. @param {typeof fetch} fetchImpl */
async function realSessions(fetchImpl) {
  const { load } = await pkg();
  const { createCryptoSession } = await load("shared/crypto/session.mjs");
  return (/** @type {any} */ options) => createCryptoSession({ ...options, fetchImpl, locks: null });
}

/** Waits until `condition()` holds (a few hundred turns at most). @param {() => unknown} condition @param {string} what */
async function until(condition, what) {
  for (let i = 0; i < 400; i += 1) {
    if (await condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  assert.fail(`never: ${what}`);
}

/**
 * The local stores with what "forget this server" uses: it records each removal and the Web Locks held then. The
 * accounts this device keeps records of are the pinned ones (the fake keeps one server). `failures` makes the next
 * removals fail.
 * @param {ReturnType<typeof memoryDb>} db
 */
function forgettingStore(db) {
  const store = memoryStore(db);
  /** @type {{ held: () => string[] }} */
  const locks = { held: () => [] };
  /** @type {Array<{ server: string, accountId: string, held: string[] }>} */
  const forgotten = [];
  const failures = { left: 0 };
  return Object.assign(store, {
    locks,
    forgotten,
    failures,
    pendingWrites: async () => 0,
    sharedAccount: async () => false,
    accountsOf: async () => [...store.pinned.keys()],
    forgetServer: async (/** @type {any} */ _db, /** @type {string} */ server, /** @type {string} */ accountId) => {
      if (failures.left > 0) {
        failures.left -= 1;
        throw new Error("the store failed");
      }
      forgotten.push({ server, accountId, held: locks.held() });
      store.pinned.delete(accountId);
      return { removed: { pinned: 1 } };
    },
  });
}

/**
 * Makes every write transaction on the device key records fail while `on` is set (an IndexedDB that refuses).
 * @param {ReturnType<typeof memoryDb>} db
 */
function failingKeyRecords(db) {
  const switchOf = { on: false };
  const real = db.handle.db.transaction.bind(db.handle.db);
  db.handle.db.transaction = (/** @type {string[]} */ names, /** @type {string} */ mode) => {
    if (switchOf.on && mode === "readwrite" && names.includes("device_keys")) throw new Error("the disk is full");
    return real(names, mode);
  };
  return switchOf;
}

/**
 * The background with the sync wired in, the page's flows, and the fake server it talks to.
 * @param {{ engines?: ReturnType<typeof fakeEngines>, channels?: ReturnType<typeof fakeChannels> | null, server?: ReturnType<typeof deviceServer>, client?: any }} [o]
 *   `channels: null` uses the shared live channel
 */
async function syncWorld({ engines = fakeEngines(), channels = fakeChannels(), server = deviceServer(), client = coreClient() } = {}) {
  /** Paths whose next request waits until the test lets it go (`hold(path)` returns that). @type {Map<string, { reached: Promise<void>, go: () => void, arrived: () => void }>} */
  const holds = new Map();
  const { load } = await pkg();
  const [{ createSignInFlow }, { createPopupFlow }] = await Promise.all([load("pages/signinFlow.mjs"), load("pages/popupFlow.mjs")]);
  /** Every request the background sent, with what it was sent with. @type {Array<{ url: string, init: RequestInit }>} */
  const inits = [];
  /** @type {typeof fetch} */
  const fetchImpl = async (url, init = {}) => {
    inits.push({ url: String(url), init });
    const path = new URL(String(url)).pathname;
    const held = holds.get(path);
    if (held) {
      holds.delete(path);
      held.arrived();
      await held.reached;
    }
    return server.fetchImpl(url, init);
  };
  /** The next request to `path` waits; `arrived` settles when it is there, `go()` lets it on. @param {string} path */
  const hold = (path) => {
    /** @type {() => void} */
    let go = () => {};
    /** @type {() => void} */
    let arrived = () => {};
    const reached = new Promise((resolve) => (go = () => resolve(undefined)));
    const there = new Promise((resolve) => (arrived = () => resolve(undefined)));
    holds.set(path, { reached, go, arrived });
    return { arrived: there, go: () => go() };
  };
  const db = memoryDb();
  const store = forgettingStore(db);
  const world = await sessionWorld({
    createSession: await realSessions(fetchImpl),
    client,
    store,
    sync: { createEngine: engines.create, ...(channels ? { createChannel: channels.create } : {}) },
  });
  store.locks.held = () => [...world.locks.held];
  const popup = createPopupFlow(world.page("pages/popup.html").request);
  const signIn = async () => {
    const flow = createSignInFlow({ request: world.page("pages/signin.html").request, requestPermission: async () => true });
    assert.equal((await flow.check(SERVER)).ok, true);
    assert.deepEqual(await flow.grant(), { ok: true });
    const result = await flow.signIn({ email: EMAIL, password: MP, skAnswer: "yes", secretKey: SK_CODE, remember: true });
    assert.deepEqual(result, { ok: true, account_email: EMAIL, server: SERVER });
  };
  return { world, engines, channels, server, inits, db, store, popup, signIn, hold };
}

/** The device key records of the in-memory IndexedDB, by server. @param {ReturnType<typeof memoryDb>} db */
const deviceKeys = (db) => [...(db.data.get("device_keys")?.keys() ?? [])].map((key) => JSON.parse(key));

test("engine_starts_on_unlock_and_stops_on_lock", async () => {
  const { world, engines, channels, popup, signIn } = await syncWorld();
  assert.equal(engines.made.length, 0, "no engine before the vault is open");
  await signIn();
  await until(() => channels?.made.length === 1, "the channel opens");

  // One engine, for the vault the sign-in opened, with the device's API client and the extension's stores.
  assert.equal(engines.made.length, 1);
  const [first] = engines.made;
  assert.equal(first.started, true);
  assert.deepEqual(first.options.scope, { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 });
  assert.equal(first.options.api, world.sessionHost.session().api, "the session's client, which carries the device's tokens");
  assert.equal(first.options.store, world.sessionHost.store);
  assert.equal(first.options.pollMs, 5 * 60 * 1000, "the feed is read every 5 minutes when no hint comes");
  assert.equal(await first.options.deviceName(), "Ferret for Firefox (Windows)");
  assert.equal(typeof first.options.memory.withLock, "function", "the sync memory under the Web Locks");
  assert.equal(channels?.made[0].options.api, first.options.api, "the stream goes through the same client");
  assert.equal(channels?.made[0].running, true);

  // Its client reaches the worker while the vault is open.
  const before = world.client.calls.length;
  assert.deepEqual(await first.options.client.vault.display_host(SERVER), { unicode: "vault.example.com", a_label: "vault.example.com" });
  assert.equal(world.client.calls.length, before + 1);

  // The lock button stops it and its stream, and its client reaches no worker any more (no new worker is started).
  assert.equal((await popup.lock()).view, "locked");
  assert.equal(first.stopped, true);
  assert.equal(channels?.made[0].running, false);
  const afterLock = world.client.calls.length;
  await assert.rejects(first.options.client.vault.display_host(SERVER), { code: "vault_locked" });
  await assert.rejects(first.options.client.vault.open_item("00".repeat(16), 1, new Uint8Array(1), new Uint8Array(1)), { code: "vault_locked" });
  assert.equal(world.client.calls.length, afterLock, "a stopped engine's client never reaches a worker");
  assert.equal((await world.page().request("sync_state", {})).running, false);

  // The unlock (the master password only) starts a new engine; the stopped one stays stopped.
  const { result } = await popup.unlock({ password: MP });
  assert.deepEqual(result, { ok: true });
  assert.equal(engines.made.length, 2);
  assert.equal(engines.made[1].started, true);
  assert.equal(first.stopped, true);
  await assert.rejects(first.options.client.vault.display_host(SERVER), { code: "vault_locked" }, "a client of an earlier unlock never reaches the new vault");
  assert.deepEqual(engines.made[1].options.scope, { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 });

  // A lock from anywhere else (the screen lock, the timer) stops it too.
  await world.coreHost.lock("idle");
  assert.equal(engines.made[1].stopped, true);
});

test("a_sync_call_after_the_deadline_is_refused_and_locks_the_vault_before_any_timer_runs", async () => {
  const { world, engines, signIn } = await syncWorld();
  await signIn();
  const [engine] = engines.made;
  assert.deepEqual(await engine.options.client.vault.display_host(SERVER), { unicode: "vault.example.com", a_label: "vault.example.com" });
  const before = world.client.calls.length;
  // The machine slept past the deadline: no timer, alarm or message has run, and the engine reconnects and asks the worker.
  world.clock.jump(8 * 60 * 60 * 1000);
  assert.equal(world.coreHost.state(), "unlocked");
  await assert.rejects(engine.options.client.vault.display_host(SERVER), { code: "vault_locked" });
  assert.equal(world.client.calls.length, before, "the call never reached the worker");
  assert.equal(world.coreHost.state(), "locked", "the deadline locked it");
  assert.equal(engine.stopped, true, "and the sync stopped with it");
});

test("a_worker_that_fails_under_the_engine_locks_the_vault", async () => {
  const client = coreClient({ sync_memory_new: () => Promise.reject(Object.assign(new Error("gone"), { code: "worker_failed" })) });
  const { world, engines, signIn } = await syncWorld({ client });
  await signIn();
  const [engine] = engines.made;
  await assert.rejects(engine.options.client.vault.sync_memory_new(), { code: "worker_failed" });
  assert.equal(world.coreHost.state(), "locked", "a worker that is gone never stays unlocked");
  assert.equal(engine.stopped, true);
});

test("a_halt_shows_retry_and_forget_in_the_popup_and_nothing_else", async () => {
  const { load } = await pkg();
  const flowModule = await load("pages/popupFlow.mjs");
  const stillHalted = { value: true };
  const engines = fakeEngines({
    resume: (engine) => {
      if (!stillHalted.value) engine.clear();
    },
  });
  const { world, channels, popup, signIn } = await syncWorld({ engines });
  await signIn();
  await until(() => channels?.made.length === 1, "the channel opens");
  const [engine] = engines.made;

  // Before a stop: the state and no button.
  let view = await popup.load();
  assert.deepEqual(view.sync, { running: true, status: "idle", live: "offline", halted: null, actions: [], warnings: [] });

  // Every stop, a known one or one this version has no text for, offers exactly "Try again" and "Forget this server".
  for (const code of [...flowModule.STOP_TEXTS, "something_new"]) {
    engine.halt(code);
    view = await popup.load();
    assert.equal(view.sync.halted, code);
    assert.deepEqual(view.sync.actions, ["try_again", "forget"], code);
    assert.equal(flowModule.stopKey(code), `sync.stop.${code === "something_new" ? "generic" : code}`);
  }
  // A stop closes the stream (a stopped engine takes no hints).
  assert.equal(channels?.made[0].running, false);

  // Nothing else can be asked of a stopped sync: no message type accepts an older state or shows what happened.
  const syncTypes = Object.keys(UI_TYPES).filter((type) => /sync|forget|restore|accept|older/.test(type)).sort();
  assert.deepEqual(syncTypes, ["forget_server", "sync_retry", "sync_state"]);
  const { readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const popupSource = await readFile(join((await pkg()).dir, "pages", "popup.mjs"), "utf8");
  for (const word of ["acceptOlderState", "restorePreview", "see_what_happened", "check_again"]) assert.equal(popupSource.includes(word), false, word);

  // "Try again": the cause is still there, then it is gone.
  let answer_ = await popup.retry();
  assert.equal(engine.resumes, 1);
  assert.deepEqual(answer_.result, { ok: false, reason: "sync_still_halted" });
  assert.deepEqual(answer_.view.sync.actions, ["try_again", "forget"]);
  stillHalted.value = false;
  answer_ = await popup.retry();
  assert.deepEqual(answer_.result, { ok: true });
  assert.equal(answer_.view.sync.halted, null);
  assert.deepEqual(answer_.view.sync.actions, []);
  assert.equal(channels?.made.length, 2, "the stream opens again when the engine runs again");
  assert.equal(channels?.made[1].running, true);

  // A warning is a text with no button; a standing one and one from a read of the feed both show, as codes only.
  engine.stand("server_shows_older_state");
  engine.emit("state", { kind: "warning", code: "rev_lower_than_local", id: "ab".repeat(16), rev: 1, localRev: 2 });
  view = await popup.load();
  assert.deepEqual(view.sync.warnings, ["server_shows_older_state", "rev_lower_than_local"]);
  assert.deepEqual(view.sync.actions, []);
  const raw = await world.page().request("sync_state", {});
  assert.equal(JSON.stringify(raw).includes("ab".repeat(16)), false, "no item id reaches the popup");
  assert.equal(flowModule.warningKey("rev_lower_than_local"), "sync.warning.rev_lower_than_local");
  assert.equal(flowModule.warningKey("made_up"), "sync.warning.unknown");
  engine.emit("state", { kind: "warning_cleared", code: "rev_lower_than_local" });
  assert.deepEqual((await popup.load()).sync.warnings, ["server_shows_older_state"]);

  // A locked vault shows no sync, and "Try again" is refused there.
  await popup.lock();
  assert.equal((await popup.load()).sync, null);
  await assert.rejects(world.page().request("sync_retry", {}), { code: "vault_locked" });
});

test("forget_removes_local_data_revokes_the_device_and_keeps_nothing_of_another_server", async () => {
  const { world, engines, server, db, store, popup, signIn } = await syncWorld();
  await signIn();
  const [engine] = engines.made;
  assert.deepEqual(deviceKeys(db), [SERVER]);
  const ui = world.page();

  // A request to forget a server other than the one this device keeps forgets nothing.
  assert.deepEqual(await ui.request("forget_server", { server: OTHER }), { ok: false, reason: "another_server" });
  assert.equal(server.to("/api/auth/token/revoke").length, 0);
  assert.equal(world.coreHost.state(), "unlocked");
  assert.equal(engine.stopped, false);
  // One server at a time: another one is refused while this one is kept (the sign-in locks the open vault first).
  const other = { server: OTHER, email: EMAIL, mp: MP, sk: SK_CODE };
  assert.deepEqual(await ui.request("sign_in", other), { ok: false, reason: "another_server" });
  assert.equal(engine.stopped, true, "the lock stopped the engine");

  const [finish] = server.to("/api/auth/opaque/login/finish");
  assert.ok(finish);
  const { result, view } = await popup.forget(SERVER);
  assert.deepEqual(result, { ok: true });

  // The device was revoked at the server with its own refresh token and a proof of its key, and no cookie.
  const revokes = server.to("/api/auth/token/revoke");
  assert.equal(revokes.length, 1);
  assert.equal(typeof (/** @type {any} */ (revokes[0].body).refresh_token), "string");
  assert.ok(revokes[0].headers.DPoP);
  assert.equal(Object.keys(revokes[0].headers).some((name) => name.toLowerCase() === "cookie"), false);
  // Then its key record went, and the account's records went inside the Web Lock of the sync memory.
  assert.deepEqual(deviceKeys(db), []);
  assert.deepEqual(store.forgotten, [{ server: SERVER, accountId: ACCOUNT, held: [`ferret-sync-memory:${SERVER}:${ACCOUNT}`] }]);
  assert.equal(store.pinned.size, 0);
  // The vault is locked, the engine stopped, and the address and the host permission are gone.
  assert.equal(world.coreHost.state(), "locked");
  assert.equal(engine.stopped, true);
  assert.equal(world.local.data.has("server"), false);
  assert.deepEqual(world.removed, [{ origins: ["https://vault.example.com/*"] }]);
  assert.deepEqual(view, { view: "signed_out", host: "", account: "", server: "", sync: null });

  // Nothing of the server is left to hold the device back: another server is no longer refused (here it only lacks
  // the host permission, which the sign-in tab asks for), and forgetting again has nothing to do.
  assert.deepEqual(await ui.request("forget_server", { server: SERVER }), { ok: true });
  assert.equal(server.to("/api/auth/token/revoke").length, 1);
  assert.notEqual((await ui.request("sign_in", other)).reason, "another_server");
  await world.coreHost.lock("manual");
});

test("forget_works_on_a_locked_device_and_when_the_server_cannot_be_reached", async () => {
  const server = deviceServer({ "/api/auth/token/revoke": () => { throw new TypeError("offline"); } });
  const { world, db, store, popup, signIn } = await syncWorld({ server });
  await signIn();
  await popup.lock();
  assert.equal(world.coreHost.state(), "locked");
  // The locked popup offers it (the server is known), and the background takes it while locked.
  const { result, view } = await popup.forget(SERVER);
  assert.deepEqual(result, { ok: true });
  assert.equal(server.to("/api/auth/token/revoke").length, 1, "it was tried");
  assert.deepEqual(deviceKeys(db), [], "the key record goes whether or not the server answered");
  assert.deepEqual(store.forgotten.map(({ server: s, accountId }) => [s, accountId]), [[SERVER, ACCOUNT]]);
  assert.equal(view.view, "signed_out");
});

test("sse_uses_a_proof_and_no_cookie", async () => {
  const encoder = new TextEncoder();
  const server = deviceServer({
    "/api/sync/events": () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(encoder.encode('event: hello\ndata: {"seq":7}\n\n'));
          },
        }),
        { status: 200, headers: { "content-type": "text/event-stream", "cache-control": "no-store" } },
      ),
  });
  const { world, engines, inits, signIn } = await syncWorld({ server, channels: null });
  await signIn();
  const [engine] = engines.made;
  await until(() => server.to("/api/sync/events").length > 0 && engine.syncs > 0, "the stream opens and its hello reaches the engine");
  try {
    const [call] = server.to("/api/sync/events");
    const sent = /** @type {{ url: string, init: RequestInit }} */ (inits.find((entry) => entry.url.endsWith("/api/sync/events")));
    // The device's access token and a proof of its key: never a cookie.
    assert.equal(sent.init.credentials, "omit");
    assert.equal(Object.keys(call.headers).some((name) => name.toLowerCase() === "cookie"), false);
    assert.equal(call.headers["Ferret-Protocol"], "1");
    assert.match(call.headers.Authorization, /^DPoP [A-Za-z0-9_-]{43}$/);
    const [header, payload] = call.headers.DPoP.split(".").slice(0, 2).map((part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8")));
    assert.equal(header.typ, "dpop+jwt");
    assert.equal(header.alg, "ES256");
    assert.equal(payload.htm, "GET");
    assert.equal(payload.htu, `${SERVER}/api/sync/events`);
    const token = call.headers.Authorization.slice("DPoP ".length);
    const { createHash } = await import("node:crypto");
    assert.equal(payload.ath, createHash("sha256").update(token).digest("base64url"), "the proof is bound to the token it goes with");
    // The stream's hint only makes the engine read the feed.
    assert.ok(engine.syncs >= 1);
    assert.equal((await world.page().request("sync_state", {})).live, "live");
  } finally {
    await world.coreHost.lock("manual");
  }
});

test("a_revoked_device_stops_syncing_and_shows_signed_out", async () => {
  const server = deviceServer({ "/api/sync/changes": () => answer(401, { error: "device_revoked" }) });
  const engines = fakeEngines({
    start: async (engine) => {
      await engine.options.api.get("/api/sync/changes?since=0&limit=500").catch(() => {});
      engine.lastStatus = "unauthorized";
      engine.emit("state", { kind: "unauthorized" });
    },
  });
  const { world, channels, db, popup, signIn } = await syncWorld({ server, engines });
  await signIn();
  await until(() => world.coreHost.state() === "locked", "the vault locks");
  const [engine] = engines.made;
  assert.equal(engine.stopped, true);
  for (const channel of channels?.made ?? []) assert.equal(channel.running, false);
  // The device forgot its tokens and its key record (the server ended them); the popup shows "signed out".
  assert.deepEqual(deviceKeys(db), []);
  const view = await popup.load();
  assert.equal(view.view, "signed_out");
  assert.equal(view.server, SERVER, "the server is still named, so it can be forgotten or signed in at again");
  // Nothing more is sent for the sync.
  const sent = server.calls.length;
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(server.calls.length, sent);
  assert.equal(engines.made.length, 1);

  // A refusal that leaves the tokens alive does not stop anything.
  const live = await syncWorld();
  await live.signIn();
  const [running] = live.engines.made;
  running.emit("state", { kind: "unauthorized" });
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(live.world.coreHost.state(), "unlocked");
  assert.equal(running.stopped, false);
  await live.world.coreHost.lock("manual");
});

/** A world whose device the server has revoked: the engine's first request is refused, and the popup shows "signed out". */
async function revokedWorld() {
  const server = deviceServer({ "/api/sync/changes": () => answer(401, { error: "device_revoked" }) });
  const engines = fakeEngines({
    start: async (engine) => {
      await engine.options.api.get("/api/sync/changes?since=0&limit=500").catch(() => {});
      engine.emit("state", { kind: "unauthorized" });
    },
  });
  const world = await syncWorld({ server, engines });
  await world.signIn();
  await until(() => world.world.coreHost.state() === "locked", "the vault locks");
  assert.equal((await world.popup.load()).view, "signed_out");
  assert.deepEqual(deviceKeys(world.db), [], "the tokens and the key record went with the revocation");
  return world;
}

test("forget_after_the_tokens_ended_removes_every_local_record_of_the_server", async () => {
  const { world, store, popup } = await revokedWorld();
  // No session account and no key record: the account comes from this device's own records of the server.
  assert.equal(world.sessionHost.session()?.current(), null);
  assert.deepEqual([...store.pinned.keys()], [ACCOUNT]);
  const { result, view } = await popup.forget(SERVER);
  assert.deepEqual(result, { ok: true });
  assert.deepEqual(store.forgotten, [{ server: SERVER, accountId: ACCOUNT, held: [`ferret-sync-memory:${SERVER}:${ACCOUNT}`] }]);
  assert.equal(store.pinned.size, 0);
  assert.equal(world.local.data.has("server"), false);
  assert.deepEqual(view, { view: "signed_out", host: "", account: "", server: "", sync: null });
});

test("a_forget_that_failed_half_way_finishes_on_a_retry", async () => {
  const { world, store, db, popup } = await revokedWorld();
  store.failures.left = 1;
  const failed = await popup.forget(SERVER);
  assert.equal(failed.result.ok, false, "it says it did not finish");
  assert.equal(world.local.data.get("server"), SERVER, "the address stays, so it can be tried again");
  assert.equal(failed.view.server, SERVER);
  assert.equal(store.pinned.size, 1);
  // The retry finds the account in the records that are left, and removes them.
  const retried = await popup.forget(SERVER);
  assert.deepEqual(retried.result, { ok: true });
  assert.deepEqual(store.forgotten.map(({ accountId }) => accountId), [ACCOUNT]);
  assert.equal(store.pinned.size, 0);
  assert.deepEqual(deviceKeys(db), []);
  assert.equal(world.local.data.has("server"), false);
});

test("a_key_record_that_cannot_be_deleted_is_reported_and_kept_for_a_retry", async () => {
  const { world, db, popup, signIn } = await syncWorld();
  await signIn();
  const failing = failingKeyRecords(db);
  failing.on = true;
  const failed = await popup.forget(SERVER);
  assert.equal(failed.result.ok, false, "a key record that is still there is not a forgotten server");
  assert.equal(world.local.data.get("server"), SERVER);
  assert.deepEqual(deviceKeys(db), [SERVER]);
  failing.on = false;
  assert.deepEqual((await popup.forget(SERVER)).result, { ok: true });
  assert.deepEqual(deviceKeys(db), []);
  assert.equal(world.local.data.has("server"), false);
});

test("forget_and_a_sign_in_never_run_at_the_same_time", async () => {
  const { world, store, db, popup, signIn, hold } = await syncWorld();
  await signIn();
  await popup.lock();

  // An unlock on its way (held at its first request): a forget now is refused, and the unlock goes on.
  const start = hold("/api/auth/opaque/login/start");
  const unlocking = popup.unlock({ password: MP });
  await start.arrived;
  assert.deepEqual(await world.page().request("forget_server", { server: SERVER }), { ok: false, reason: "busy" });
  start.go();
  assert.deepEqual((await unlocking).result, { ok: true });
  assert.equal(store.forgotten.length, 0);
  assert.deepEqual(deviceKeys(db), [SERVER]);

  // A forget on its way (held at the device's sign-out): a sign-in or an unlock now is refused, and the forget goes on.
  const revoke = hold("/api/auth/token/revoke");
  const forgetting = popup.forget(SERVER);
  await revoke.arrived;
  const ui = world.page();
  assert.deepEqual(await ui.request("unlock", { mp: MP }), { ok: false, reason: "busy" });
  assert.deepEqual(await ui.request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE }), { ok: false, reason: "busy" });
  revoke.go();
  assert.deepEqual((await forgetting).result, { ok: true });
  assert.deepEqual(deviceKeys(db), [], "no key record of the forgotten server came back");
  assert.equal(store.pinned.size, 0);
});

test("a_revocation_seen_only_on_the_stream_stops_syncing_and_shows_signed_out", async () => {
  const server = deviceServer({ "/api/sync/events": () => answer(401, { error: "device_revoked" }) });
  const { world, engines, db, popup, signIn } = await syncWorld({ server, channels: null });
  await signIn();
  await until(() => world.coreHost.state() === "locked", "the vault locks");
  const [engine] = engines.made;
  assert.equal(engine.stopped, true);
  assert.equal(server.to("/api/sync/events").length, 1, "the stream was tried once and not again");
  assert.deepEqual(deviceKeys(db), []);
  assert.equal((await popup.load()).view, "signed_out");
});

test("an_error_of_the_engine_that_stands_reaches_the_popup_as_a_code", async () => {
  const { engines, popup, signIn, world } = await syncWorld();
  await signIn();
  const [engine] = engines.made;
  engine.emit("error", { code: "checkpoint_upload_failed", reason: "throttled" });
  engine.emit("error", { code: "storage" });
  assert.deepEqual((await popup.load()).sync?.warnings, ["checkpoint_upload_failed"]);
  engine.emit("state", { kind: "warning_cleared", code: "checkpoint_upload_failed" });
  assert.deepEqual((await popup.load()).sync?.warnings, []);
  await world.coreHost.lock("manual");
});

test("every_sync_text_is_there_in_both_languages", async () => {
  const { load } = await pkg();
  const flowModule = await load("pages/popupFlow.mjs");
  const { REASONS } = await load("background/handlers/sync.handler.mjs");
  const { readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { dir } = await pkg();
  for (const lang of ["en", "nb"]) {
    const texts = JSON.parse(await readFile(join(dir, `locales.${lang}.json`), "utf8"));
    const keys = [
      ...flowModule.STOP_TEXTS.map((/** @type {string} */ code) => `sync.stop.${code}`),
      "sync.stop.generic",
      "sync.stop.title",
      ...flowModule.WARNING_TEXTS.map((/** @type {string} */ code) => `sync.warning.${code}`),
      "sync.warning.unknown",
      ...flowModule.STATUS_TEXTS.map((/** @type {string} */ code) => `sync.status.${code}`),
      "sync.status.starting",
      ...REASONS.map((/** @type {string} */ code) => `sync.error.${code}`),
      "sync.action.try_again",
      "sync.action.forget",
      "sync.forget.title",
      "sync.forget.body",
      "sync.forget.confirm",
      "sync.forget.cancel",
    ];
    for (const key of keys) assert.equal(typeof texts[key], "string", `${lang}: ${key}`);
  }
});
