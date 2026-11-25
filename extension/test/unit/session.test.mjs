// The session in the background: sign-in, unlock and the lock button, from a
// page of the extension over the UI port to the core host's session and the
// shared sign-in of the web vault (in device mode).
import assert from "node:assert/strict";
import { test } from "node:test";
import { CONTENT_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import {
  ACCOUNT, EMAIL, SERVER, SK_CODE, coreClient, deviceServer, fakeSessions, filled, memoryDb, memoryStore, pinnedRecord, pkg, sessionWorld, sheet,
} from "./sessionHelpers.mjs";

const MP = "Correct-horse-UNIQUE-4711";

/** A shared session in device mode over the fake server, as the background makes it. */
async function realSessions(/** @type {ReturnType<typeof deviceServer>} */ server) {
  const { load } = await pkg();
  const { createCryptoSession } = await load("shared/crypto/session.mjs");
  return (/** @type {any} */ options) => createCryptoSession({ ...options, fetchImpl: server.fetchImpl, locks: null });
}

/** Signs in through the sign-in page's steps. */
async function signInThroughThePage(/** @type {any} */ world, fields = {}) {
  const { load } = await pkg();
  const { createSignInFlow } = await load("pages/signinFlow.mjs");
  const ui = world.page("pages/signin.html");
  const flow = createSignInFlow({ request: ui.request, requestPermission: async () => true });
  const checked = await flow.check(SERVER);
  assert.equal(checked.ok, true, JSON.stringify(checked));
  assert.deepEqual(await flow.grant(), { ok: true });
  const result = await flow.signIn({ email: EMAIL, password: MP, skAnswer: "yes", secretKey: SK_CODE, remember: true, ...fields });
  return { ui, flow, result };
}

/** Everything a value could hide in, as text: strings, and bytes as hex and base64. @param {unknown} value */
function dump(value) {
  const seen = new Set();
  /** @param {unknown} v @returns {string} */
  const walk = (v) => {
    if (v === null || v === undefined) return "";
    if (typeof v === "string") return v;
    if (typeof v !== "object") return String(v);
    if (seen.has(v)) return "";
    seen.add(v);
    if (v instanceof Uint8Array) return `${Buffer.from(v).toString("hex")} ${Buffer.from(v).toString("base64")}`;
    if (v instanceof Map) return [...v.entries()].map(walk).join(" ");
    if (v instanceof Set || Array.isArray(v)) return [...v].map(walk).join(" ");
    return Object.entries(v).map(([k, x]) => `${k} ${walk(x)}`).join(" ");
  };
  return walk(value);
}

/** The forms of the password that must not appear anywhere. */
const passwordForms = () => {
  const bytes = Buffer.from(MP, "utf8");
  return [MP, bytes.toString("hex"), bytes.toString("base64"), bytes.toString("base64url"), encodeURIComponent(MP)];
};

test("the_master_password_never_leaves_the_background_except_to_the_worker", async () => {
  const server = deviceServer();
  const db = memoryDb();
  const store = memoryStore(db);
  const client = coreClient();
  const world = await sessionWorld({ createSession: await realSessions(server), client, store });
  /** @type {unknown[]} */
  const logged = [];
  const saved = { ...console };
  for (const name of ["log", "info", "warn", "error", "debug", "trace"]) {
    /** @type {any} */ (console)[name] = (/** @type {unknown[]} */ ...args) => logged.push(args);
  }
  let result;
  try {
    ({ result } = await signInThroughThePage(world));
  } finally {
    Object.assign(console, saved);
  }
  assert.deepEqual(result, { ok: true, account_email: EMAIL, server: SERVER });
  assert.equal(world.coreHost.state(), "unlocked");

  // The worker got it once, as bytes, and those bytes were wiped after the call.
  const starts = client.calls.filter((c) => c.method === "login_start");
  assert.equal(starts.length, 1);
  const [given] = starts[0].args;
  assert.ok(given instanceof Uint8Array, "the password reaches the worker as bytes");
  assert.equal(given.length, Buffer.byteLength(MP, "utf8"));
  assert.ok(given.every((b) => b === 0), "and the bytes were wiped after the call");
  const others = client.calls.filter((c) => c.method !== "login_start");
  // Nothing else: not the server, the stores, the replies to the page, the log.
  const places = {
    "another call of the core": others,
    "the server": server.calls,
    "storage.local": world.local.data,
    "storage.session": world.sessionStorage.data,
    "IndexedDB": db.data,
    "the pinned records": store.pinned,
    "the replies to the page": world.ports.flatMap((p) => p.fromBackground),
    "the log": logged,
  };
  for (const [where, value] of Object.entries(places)) {
    const text = dump(value);
    for (const form of passwordForms()) assert.equal(text.includes(form), false, `${where} holds the master password`);
  }
  // The secret key went to the core with it and is kept only sealed.
  assert.equal(dump(db.data).includes(SK_CODE), false, "the secret key is stored sealed");
  assert.equal(dump(server.calls).includes(SK_CODE), false, "the secret key is never sent to the server");
  assert.ok(server.to("/api/auth/opaque/login/finish").length === 1);
});

test("the_sign_in_reply_carries_only_the_account_and_the_server_and_the_device_is_named_for_firefox", async () => {
  const server = deviceServer();
  const world = await sessionWorld({ createSession: await realSessions(server), store: memoryStore(memoryDb()), os: "linux" });
  const { result } = await signInThroughThePage(world);
  assert.deepEqual(Object.keys(result).sort(), ["account_email", "ok", "server"]);
  const [finish] = server.to("/api/auth/opaque/login/finish");
  assert.deepEqual(Object.keys(/** @type {any} */ (finish.body)).sort(), ["client", "device_name", "ke3", "login_id", "platform"]);
  assert.equal(/** @type {any} */ (finish.body).device_name, "Ferret for Firefox (Linux)");
  assert.equal(/** @type {any} */ (finish.body).platform, "linux");
  // A device signs in with a proof and never with a cookie.
  assert.ok(finish.headers.DPoP ?? finish.headers.dpop);
  // The server is kept as the one this device is signed in at.
  assert.deepEqual(world.local.data.get("server"), SERVER);
});

test("device_identity_names_the_extension_and_the_platform", async () => {
  const { load } = await pkg();
  const { deviceIdentity } = await load("background/session.mjs");
  assert.deepEqual(deviceIdentity("win"), { deviceName: "Ferret for Firefox (Windows)", platform: "windows" });
  assert.deepEqual(deviceIdentity("mac"), { deviceName: "Ferret for Firefox (macOS)", platform: "macos" });
  assert.deepEqual(deviceIdentity("linux"), { deviceName: "Ferret for Firefox (Linux)", platform: "linux" });
  assert.deepEqual(deviceIdentity("android"), { deviceName: "Ferret for Firefox (Android)", platform: "android" });
  assert.deepEqual(deviceIdentity("cros"), { deviceName: "Ferret for Firefox (ChromeOS)", platform: "chromeos" });
  for (const os of ["openbsd", "fuchsia", "", "__proto__", undefined]) {
    assert.deepEqual(deviceIdentity(os), { deviceName: "Ferret for Firefox", platform: "other" }, String(os));
  }
});

test("http_server_address_is_refused_in_the_release_variant", async () => {
  const { load } = await pkg();
  const { checkServer } = await load("background/session.mjs");
  for (const allowTestHosts of [false, true]) {
    assert.deepEqual(checkServer("http://vault.example.com", { allowTestHosts }), { ok: false, reason: "server_not_https" });
    assert.deepEqual(checkServer("HTTP://vault.example.com/", { allowTestHosts }), { ok: false, reason: "server_not_https" });
    for (const bad of ["ftp://vault.example.com", "https://user:pw@vault.example.com", "https://vault.example.com/vault", "https://vault.example.com/?a=1",
      "https://vault.example.com/#x", "https://192.168.1.10", "https://[::1]", "javascript:alert(1)", "", "   ", "https://", `https://${"a".repeat(300)}.com`, 42]) {
      assert.equal(checkServer(bad, { allowTestHosts }).ok, false, String(bad));
    }
  }
  // An address is its origin, written as the store and the core write it.
  assert.deepEqual(checkServer(" vault.example.com "), { ok: true, server: "https://vault.example.com", hostname: "vault.example.com" });
  assert.deepEqual(checkServer("https://Vault.Example.com:8443/"), { ok: true, server: "https://vault.example.com:8443", hostname: "vault.example.com" });
  // The release refuses the names of the test stacks; the test build signs in against them.
  for (const name of ["https://vault-e2e.test", "https://fixture.test", "https://x.invalid", "https://localhost", "https://a.localhost", "https://vault.example"]) {
    assert.deepEqual(checkServer(name), { ok: false, reason: "server_reserved" }, name);
    assert.equal(checkServer(name, { allowTestHosts: true }).ok, true, name);
  }

  // Through the page: the check and the sign-in both refuse, and nothing reaches the session.
  const sessions = fakeSessions();
  const world = await sessionWorld({ createSession: sessions.create });
  const ui = world.page();
  assert.deepEqual(await ui.request("server_check", { server: "http://vault.example.com" }), { ok: false, reason: "server_not_https" });
  assert.deepEqual(
    await ui.request("sign_in", { server: "http://vault.example.com", email: EMAIL, mp: MP }),
    { ok: false, reason: "server_not_https" },
  );
  assert.deepEqual(await ui.request("server_check", { server: "https://vault-e2e.test" }), { ok: false, reason: "server_reserved" });
  assert.deepEqual(sessions.calls, []);
  assert.deepEqual(world.asked, [], "not even the permission is looked at");
  // A stored address that is not https is no server.
  const stored = await sessionWorld({ createSession: sessions.create, server: "http://vault.example.com" });
  assert.equal((await stored.page().request("state", {})).state, "signed_out");
});

test("the_server_check_shows_the_host_from_the_core", async () => {
  const client = coreClient({ display_host: () => ({ unicode: "bücher.example.com", a_label: "xn--bcher-kva.example.com" }) });
  const world = await sessionWorld({ createSession: fakeSessions().create, client });
  const reply = await world.page().request("server_check", { server: "https://xn--bcher-kva.example.com" });
  assert.deepEqual(reply, { ok: true, server: "https://xn--bcher-kva.example.com", host: "bücher.example.com", host_a_label: "xn--bcher-kva.example.com" });
  assert.equal(world.ui.shownHost(reply), "bücher.example.com (xn--bcher-kva.example.com)");
  assert.equal(world.ui.shownHost({ host: "vault.example.com", host_a_label: "vault.example.com" }), "vault.example.com");
  assert.ok(client.calls.some((c) => c.method === "display_host" && c.args[0] === "https://xn--bcher-kva.example.com"));
});

test("signin_needs_the_host_permission_in_the_background_too", async () => {
  const sessions = fakeSessions();
  const world = await sessionWorld({ createSession: sessions.create, permitted: false });
  const reply = await world.page().request("sign_in", { server: SERVER, email: EMAIL, mp: MP });
  assert.deepEqual(reply, { ok: false, reason: "permission_needed" });
  assert.deepEqual(world.asked, [{ origins: [`${SERVER}/*`] }], "the permission of exactly that origin");
  assert.deepEqual(sessions.calls, []);
  assert.equal(world.local.data.has("server"), false);
  // A server on another port: a match pattern has no port, so the permission is the host's.
  const ported = await sessionWorld({ createSession: sessions.create, permitted: false });
  await ported.page().request("sign_in", { server: "https://vault.example.com:8443", email: EMAIL, mp: MP });
  assert.deepEqual(ported.asked, [{ origins: ["https://vault.example.com/*"] }]);
  const { load } = await pkg();
  const { permissionOf } = await load("background/session.mjs");
  assert.equal(permissionOf("https://xn--bcher-kva.example:8443"), "https://xn--bcher-kva.example/*");
});

test("a_content_script_cannot_send_sign_in_or_unlock", async () => {
  const sessions = fakeSessions();
  const world = await sessionWorld({ createSession: sessions.create });
  const sender = world.contentSender("https://evil.example/login");
  const messages = [
    encode("sign_in", { server: SERVER, email: EMAIL, mp: MP }),
    encode("unlock", { mp: MP }),
    encode("lock", {}),
    encode("state", {}),
    encode("server_check", { server: SERVER }),
  ];
  // Over runtime.sendMessage: not a type of the content table, so nothing happens and nothing is answered.
  for (const raw of messages) {
    assert.throws(() => decode(raw, CONTENT_TYPES), { code: "unknown_type" });
    assert.equal(await world.router.onMessage(raw, sender), undefined);
  }
  // Over the UI port: a content script's port is refused before any message is read.
  const { portPair } = await import("./sessionHelpers.mjs");
  const pair = portPair("ferret-ui", sender);
  world.router.onConnect(pair.background);
  assert.equal(pair.background.disconnected, true);
  assert.throws(() => pair.page.postMessage(messages[0]));
  // A framed extension page is refused the same way.
  const framed = world.ui.connectUi(world.pageRuntime("pages/signin.html", { frameId: 3, tab: { id: 9 } }));
  await assert.rejects(framed.request("sign_in", { server: SERVER, email: EMAIL, mp: MP }));
  await world.tick();
  assert.deepEqual(sessions.calls, []);
  assert.equal(world.coreHost.state(), "locked");
});

test("wrong_password_and_unknown_email_give_the_same_message", async () => {
  // The core cannot tell the two apart: the server answers an unknown e-mail from a made-up record, and the core's
  // finish fails the same way as for a wrong password.
  const replies = [];
  for (const email of [EMAIL, "nobody@example.com"]) {
    const server = deviceServer();
    const client = coreClient({ login_finish: () => Promise.reject(Object.assign(new Error("decrypt"), { code: "decrypt" })) });
    const world = await sessionWorld({ createSession: await realSessions(server), client, store: memoryStore(memoryDb()) });
    const { result } = await signInThroughThePage(world, { email });
    replies.push(result);
    // Nothing was proved to the server, nothing was kept.
    assert.deepEqual(server.to("/api/auth/opaque/login/finish"), []);
    assert.equal(world.local.data.has("server"), false);
    assert.equal(world.coreHost.state(), "locked");
  }
  assert.deepEqual(replies[0], { ok: false, reason: "wrong_credentials" });
  assert.deepEqual(replies[1], replies[0]);
  // A refusal of the server for either is the same reason too.
  const { load } = await pkg();
  const { reasonOf } = await load("background/handlers/session.handler.mjs");
  assert.equal(reasonOf({ code: "denied" }), "wrong_credentials");
  assert.equal(reasonOf({ code: "decrypt" }), "wrong_credentials");
});

test("a_vault_key_epoch_ahead_of_the_pinned_one_is_an_attack_warning", async () => {
  const { load } = await pkg();
  const { reasonOf } = await load("background/handlers/session.handler.mjs");
  assert.equal(reasonOf({ code: "pinned_epoch_ahead" }), "attack_warning");
  assert.equal(reasonOf({ code: "pinned_vk_epoch" }), "attack_warning");
});

test("a_pasted_sheet_qr_pins_the_server_key_and_a_different_server_key_is_refused", async () => {
  // A sheet whose server key is not the one the server proves: refused before KE3 is posted, nothing pinned.
  {
    const server = deviceServer();
    const store = memoryStore(memoryDb());
    const client = coreClient({ setup_qr_parse: () => sheet({ serverKey: filled(32, 7) }) });
    const world = await sessionWorld({ createSession: await realSessions(server), client, store });
    const { result } = await signInThroughThePage(world, { qrText: "ferret-setup:v1?u=x" });
    assert.deepEqual(result, { ok: false, reason: "qr_server_key" });
    assert.equal(server.to("/api/auth/opaque/login/start").length, 1);
    assert.deepEqual(server.to("/api/auth/opaque/login/finish"), [], "KE3 was never posted");
    assert.equal(store.pinned.size, 0, "nothing was pinned");
    assert.ok(client.calls.some((c) => c.method === "setup_qr_parse" && c.args[0] === "ferret-setup:v1?u=x"));
  }
  // The sheet of this server: the sign-in pins the server key the sheet states.
  {
    const server = deviceServer();
    const store = memoryStore(memoryDb());
    const client = coreClient({ setup_qr_parse: () => sheet({ serverKey: filled(32, 9) }) });
    const world = await sessionWorld({ createSession: await realSessions(server), client, store });
    const { result } = await signInThroughThePage(world, { qrText: "ferret-setup:v1?u=x" });
    assert.equal(result.ok, true);
    assert.deepEqual([...(store.pinned.get(ACCOUNT)?.record.server_public_key ?? [])], [...filled(32, 9)]);
  }
  // A sheet for another server: nothing is sent at all.
  {
    const server = deviceServer();
    const client = coreClient({ setup_qr_parse: () => sheet({ server: "https://other.example.com" }) });
    const world = await sessionWorld({ createSession: await realSessions(server), client, store: memoryStore(memoryDb()) });
    const { result } = await signInThroughThePage(world, { qrText: "ferret-setup:v1?u=y" });
    assert.deepEqual(result, { ok: false, reason: "qr_server_url" });
    assert.deepEqual(server.calls, []);
  }
});

test("the_lock_button_locks_and_the_popup_shows_the_unlock_view", async () => {
  const { load } = await pkg();
  const { createPopupFlow } = await load("pages/popupFlow.mjs");
  const sessions = fakeSessions();
  const world = await sessionWorld({ createSession: sessions.create });
  await signInThroughThePage(world);
  assert.equal(world.coreHost.state(), "unlocked");

  const popup = createPopupFlow(world.page("pages/popup.html").request);
  const open = await popup.load();
  // This world has no sync handler: the popup shows a sync that does not run.
  const idle = { running: false, status: null, live: "offline", halted: null, actions: [], warnings: [], pending: 0, blocked: 0, conflicts: 0 };
  assert.deepEqual(open, { view: "unlocked", host: "vault.example.com", account: EMAIL, server: SERVER, sync: idle });

  const locksBefore = world.client.locks;
  const after = await popup.lock();
  assert.deepEqual(after, { view: "locked", host: "vault.example.com", account: EMAIL, server: SERVER, sync: null });
  assert.equal(world.coreHost.state(), "locked");
  assert.ok(world.client.locks > locksBefore, "the worker that held the keys was ended");
  assert.equal(sessions.made[0].current(), null, "the session forgot the open account");

  // The unlock needs only the master password.
  const { result, view } = await popup.unlock({ password: MP });
  assert.deepEqual(result, { ok: true });
  assert.equal(view.view, "unlocked");
  assert.deepEqual(sessions.calls.filter(([name]) => name === "unlock").map(([, args]) => args), [{ password: MP }]);
  assert.equal(world.coreHost.state(), "unlocked");
});

test("a_lock_from_elsewhere_resets_the_session_and_the_next_unlock_opens_again", async () => {
  const sessions = fakeSessions();
  const world = await sessionWorld({ createSession: sessions.create });
  await signInThroughThePage(world);
  // The auto-lock (or a failed worker) locks the core host, not the session.
  await world.coreHost.lock("timeout");
  assert.equal(sessions.made[0].current(), null);
  const ui = world.page("pages/popup.html");
  assert.equal((await ui.request("state", {})).state, "locked");
  assert.deepEqual(await ui.request("unlock", { mp: MP }), { ok: true });
  assert.equal(world.coreHost.state(), "unlocked");
  // A sign-in on an open vault locks it first and opens it again.
  assert.equal((await ui.request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE })).ok, true);
  assert.equal(world.coreHost.state(), "unlocked");
  assert.ok(world.client.locks >= 2);
});

test("a_failed_sign_in_leaves_the_vault_locked_and_keeps_no_server", async () => {
  const sessions = fakeSessions({ signIn: () => Promise.reject(Object.assign(new Error("x"), { code: "network" })) });
  const world = await sessionWorld({ createSession: sessions.create });
  const reply = await world.page().request("sign_in", { server: SERVER, email: EMAIL, mp: MP });
  assert.deepEqual(reply, { ok: false, reason: "network" });
  assert.equal(world.coreHost.state(), "locked");
  assert.equal(world.local.data.has("server"), false);
  assert.equal((await world.page().request("state", {})).state, "signed_out");
});

test("the_session_tells_its_listeners_after_it_stored_or_forgot_the_server", async () => {
  // What the passkey registry hears instead of a storage listener: a sign-in that stored the server, and "forget this server".
  const world = await sessionWorld({ createSession: fakeSessions().create });
  /** @type {Array<string | null>} */
  const seen = [];
  const stop = world.sessionHost.onServerChange(() => seen.push(world.local.data.get("server") ?? null));
  assert.equal((await world.page().request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE })).ok, true);
  assert.deepEqual(seen, [SERVER], "after the server is stored");
  await world.sessionHost.forget();
  assert.deepEqual(seen, [SERVER, null], "after the server is removed");
  stop();
  await world.sessionHost.forget();
  assert.equal(seen.length, 2, "a listener that stopped hears nothing");
  // A sign-in that fails stores nothing and tells nobody.
  const failed = await sessionWorld({ createSession: fakeSessions({ signIn: () => Promise.reject(Object.assign(new Error("x"), { code: "network" })) }).create });
  let told = 0;
  failed.sessionHost.onServerChange(() => { told += 1; });
  assert.equal((await failed.page().request("sign_in", { server: SERVER, email: EMAIL, mp: MP })).ok, false);
  assert.equal(told, 0);
  // A forget whose storage write fails tells nobody (the server is still there).
  const broken = await sessionWorld({ createSession: fakeSessions().create, server: SERVER, gate: async (label) => { if (label === "storage.local.remove") throw new Error("disk"); } });
  broken.sessionHost.onServerChange(() => { told += 1; });
  await assert.rejects(broken.sessionHost.forget());
  assert.equal(told, 0);
  // A listener that throws does not undo the sign-in.
  const loud = await sessionWorld({ createSession: fakeSessions().create });
  loud.sessionHost.onServerChange(() => { throw new Error("listener"); });
  assert.equal((await loud.page().request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE })).ok, true);
});

test("an_unlock_without_a_signed_in_device_says_signed_out_and_another_server_is_refused", async () => {
  const sessions = fakeSessions();
  const none = await sessionWorld({ createSession: sessions.create });
  assert.deepEqual(await none.page().request("unlock", { mp: MP }), { ok: false, reason: "signed_out" });
  const other = await sessionWorld({ createSession: sessions.create, server: "https://other.example.com" });
  assert.deepEqual(
    await other.page().request("sign_in", { server: SERVER, email: EMAIL, mp: MP }),
    { ok: false, reason: "another_server" },
  );
  assert.equal(sessions.calls.some(([name]) => name === "signIn"), false);
});

test("the_sign_in_passes_the_secret_key_answer_and_the_sheet_on_unchanged", async () => {
  const sessions = fakeSessions();
  const world = await sessionWorld({ createSession: sessions.create });
  const ui = world.page();
  await ui.request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE, remember_sk: false, qr_text: "ferret-setup:v1" });
  await world.coreHost.lock("manual");
  await ui.request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk_bit: false });
  await world.coreHost.lock("manual");
  await ui.request("sign_in", { server: SERVER, email: EMAIL, mp: MP });
  const args = sessions.calls.filter(([name]) => name === "signIn").map(([, a]) => a);
  assert.deepEqual(args, [
    { email: EMAIL, password: MP, skCode: SK_CODE, skBit: true, rememberSk: false, qr: "ferret-setup:v1" },
    { email: EMAIL, password: MP, skCode: undefined, skBit: false, rememberSk: true, qr: null },
    { email: EMAIL, password: MP, skCode: undefined, skBit: undefined, rememberSk: true, qr: null },
  ]);
  // The session is a device session of that server, with the extension's name.
  const { options } = sessions.made[0];
  assert.equal(options.mode, "device");
  assert.equal(options.serverUrl, SERVER);
  assert.equal(options.deviceName, "Ferret for Firefox (Windows)");
  assert.equal(options.platform, "windows");
});

test("every_reason_has_a_text_in_both_languages", async () => {
  const { load } = await pkg();
  const { REASONS } = await load("background/handlers/session.handler.mjs");
  const { readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { extensionRoot } = await import("./buildHelpers.mjs");
  const pageOnly = ["password_required", "permission_refused", "disconnected", "internal_error", "invalid_input", "not_available"];
  for (const lang of ["en", "nb"]) {
    const texts = JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "session.json"), "utf8"));
    for (const reason of [...REASONS, ...pageOnly]) assert.equal(typeof texts[`session.error.${reason}`], "string", `${lang}: ${reason}`);
  }
  const en = JSON.parse(readFileSync(join(extensionRoot, "src", "locales", "en", "session.json"), "utf8"));
  const nb = JSON.parse(readFileSync(join(extensionRoot, "src", "locales", "nb", "session.json"), "utf8"));
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort());
});

/**
 * One sign-in or unlock with a lock at the `target`-th await point: before each call to the local storage, the
 * permissions, the platform, the local stores, the server and the core. Answers what happened and whether a worker
 * still holds keys (the fake core holds them from `unlock_password` until its worker is ended).
 * @param {"sign_in" | "unlock"} flow
 * @param {number} target
 */
async function lockedAt(flow, target) {
  let armed = false;
  let count = 0;
  /** @type {string | null} */
  let hit = null;
  /** @type {any} */
  let world = null;
  const gate = async (/** @type {string} */ label) => {
    if (!armed) return;
    count += 1;
    if (count !== target) return;
    hit = label;
    await world.coreHost.lock("idle");
  };
  let keyed = false;
  const base = coreClient({
    unlock_password: () => {
      keyed = true;
      return { pinned: pinnedRecord() };
    },
  });
  const baseLock = base.lock.bind(base);
  const client = {
    calls: base.calls,
    get locks() {
      return base.locks;
    },
    vault: new Proxy({}, {
      get: (_, method) => async (/** @type {unknown[]} */ ...args) => {
        await gate(`vault.${String(method)}`);
        return /** @type {any} */ (base.vault)[method](...args);
      },
    }),
    job: base.job,
    async lock() {
      keyed = false;
      await baseLock();
    },
  };
  const server = deviceServer();
  const gatedServer = {
    ...server,
    fetchImpl: /** @type {typeof fetch} */ (async (url, init) => {
      await gate(`fetch ${new URL(String(url)).pathname}`);
      return server.fetchImpl(url, init);
    }),
  };
  const plain = memoryStore(memoryDb());
  /** @type {any} */
  const store = { pinned: plain.pinned };
  for (const [name, value] of Object.entries(plain)) {
    if (typeof value === "function") {
      store[name] = async (/** @type {unknown[]} */ ...args) => {
        await gate(`store.${name}`);
        return /** @type {any} */ (value)(...args);
      };
    } else if (name !== "pinned") store[name] = value;
  }
  world = await sessionWorld({ createSession: await realSessions(gatedServer), client, store, gate });
  const ui = world.page();
  const signIn = { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE };
  if (flow === "unlock") {
    assert.equal((await ui.request("sign_in", signIn)).ok, true);
    await world.coreHost.lock("manual");
    assert.equal(keyed, false);
  }
  armed = true;
  const reply = await ui.request(flow, flow === "sign_in" ? signIn : { mp: MP });
  armed = false;
  return { reply, hit, keyed, state: world.coreHost.state(), session: world.sessionHost.session(), server };
}

test("a_lock_at_any_await_point_of_a_sign_in_or_an_unlock_leaves_no_worker_with_keys", async () => {
  for (const flow of /** @type {const} */ (["sign_in", "unlock"])) {
    let points = 0;
    for (let target = 1; target < 200; target += 1) {
      const outcome = await lockedAt(flow, target);
      if (outcome.hit === null) break;
      points += 1;
      const where = `${flow}, lock before ${outcome.hit} (#${target})`;
      assert.equal(outcome.keyed, false, `${where}: a worker still holds keys`);
      assert.equal(outcome.state, "locked", `${where}: the host is not locked`);
      assert.equal(outcome.session?.current() ?? null, null, `${where}: the session still names an open account`);
    }
    // Every point of the flow was tried: the core, the server and the stores are all among them.
    assert.ok(points >= 8, `${flow}: only ${points} await points`);
  }
});

test("an_unlock_after_a_lock_keeps_the_device_and_posts_no_ke3", async () => {
  // Model A, end to end in the extension: the unlock runs login/start and the core's finish, reads the wraps with
  // the device's token, and never posts KE3, so no device and no token is made.
  const server = deviceServer();
  const client = coreClient();
  const world = await sessionWorld({ createSession: await realSessions(server), client, store: memoryStore(memoryDb()) });
  const { ui } = await signInThroughThePage(world);
  const device = server.to("/api/auth/opaque/login/finish")[0];
  await ui.request("lock", {});
  assert.equal(world.coreHost.state(), "locked");
  const before = server.calls.length;
  assert.deepEqual(await ui.request("unlock", { mp: MP }), { ok: true });
  assert.equal(world.coreHost.state(), "unlocked");
  const unlockCalls = server.calls.slice(before).map((c) => c.path);
  assert.deepEqual(unlockCalls, ["/api/auth/opaque/login/start", "/api/vault/unlock-methods"], "no KE3, no new device, no renewal");
  assert.equal(server.to("/api/auth/opaque/login/finish").length, 1);
  assert.ok(device);
  // The unlock's start went to the worker as bytes, wiped after the call, and the password is nowhere else.
  const starts = client.calls.filter((c) => c.method === "login_start");
  assert.equal(starts.length, 2);
  assert.ok(starts[1].args[0] instanceof Uint8Array && starts[1].args[0].every((/** @type {number} */ b) => b === 0));
  const text = dump([server.calls, world.local.data, world.sessionStorage.data, world.ports.flatMap((p) => p.fromBackground)]);
  for (const form of passwordForms()) assert.equal(text.includes(form), false);
  // The unlock used the stored secret key: the page sent only the password.
  assert.equal(starts[1].args[1], SK_CODE);
});
