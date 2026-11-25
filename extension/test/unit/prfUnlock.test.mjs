// Unlocking with a passkey in the extension (design document, sections 7.2, 7.3 and 9.4; build flag `unlock`): the unlock window
// is the one page that makes the WebAuthn call and the one that may send the result; the background reads the list of
// unlock methods fresh each time (online, live tokens only), opens the vault with the 32 bytes and makes the checks that
// follow every unlock; the 32 bytes are wiped as soon as they are sent. The real session of the background (the shared
// one, in device mode, over a fake server), the real PIN host that carries the passkey operations, router, lock and
// handlers; the core is a fake that answers like the real one for what these tests ask.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { build } from "../../scripts/build.mjs";
import { UI_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { contentScriptSender, extensionPageSender } from "./fakeBrowser.mjs";
import { createFakeIdb, createSession as createUnlockSession } from "./localUnlockHelpers.mjs";
import { ACCOUNT, EMAIL, SERVER, SK_CODE, answer, coreClient, deviceServer, filled, memoryDb, memoryStore, methodsRes, pinnedRecord, pkg, portPair, sessionWorld } from "./sessionHelpers.mjs";

const MP = "Correct-horse-UNIQUE-4711";
const START = 1_700_000_000_000;
const HOST = new URL(SERVER).hostname;
const WINDOW_PAGE = "pages/unlockWindow.html";

const settle = () => new Promise((resolve) => setTimeout(resolve, 25));
const b64u = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("base64url");
const token = (/** @type {number} */ fill) => Buffer.alloc(32, fill).toString("base64url");
/** @param {string} code */
const coded = (code) => Object.assign(new Error(code), { code });

/** The passkey the account has (the one the fake authenticator answers for). */
const PASSKEY = Object.freeze({ method_id: "33".repeat(16), credential: Uint8Array.from({ length: 24 }, (_, i) => 0x40 + i), salt: filled(32, 0x51), output: Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + ((i * 7) % 61)) });
const KEY_TWO = Object.freeze({ method_id: "34".repeat(16), credential: Uint8Array.from({ length: 24 }, (_, i) => 0x80 + i), salt: filled(32, 0x52) });

/** The wire form of a passkey method of the server's list. @param {{ method_id: string, credential: Uint8Array, salt: Uint8Array }} p */
const wireOf = (p) => ({ method_id: p.method_id, method_type: 3, kek_generation: 1, wrap: b64u(filled(72, 9)), credential_id: b64u(p.credential), prf_salt: b64u(p.salt) });

/**
 * A device that is signed in and locked, with the PIN host that carries the passkey operations (over a PIN store that this
 * file never uses), and the fake core and server the tests change as they go.
 * @param {{ passkeys?: Array<typeof PASSKEY>, prfEnabled?: boolean, windows?: any }} [options]
 */
async function prfWorld({ passkeys = [PASSKEY], prfEnabled = true, windows = null } = {}) {
  const { load } = await pkg();
  const { createLocalUnlock } = await load("background/localUnlock.mjs");
  /** @type {any} */
  let w = null;
  const idb = createFakeIdb();
  const pinStore = createLocalUnlock({ idb: idb.factory, session: createUnlockSession(), now: () => w.clock.now() });

  const state = {
    online: true,
    prfEnabled,
    passkeys: [...passkeys],
    vkEpoch: 1,
    pkA: filled(32, 3),
    expireAccess: 0,
    refresh: "ok",
    refreshes: 0,
    listReads: 0,
    methodsStatus: 200,
    /** What the core was given to open the vault with, copied at the call (before anything wiped it). */
    prfCalls: /** @type {any[]} */ ([]),
    /** The array the core was handed, to see it wiped later. */
    handed: /** @type {Uint8Array[]} */ ([]),
    correctOutput: PASSKEY.output,
    unlockBehaviour: /** @type {null | (() => unknown)} */ (null),
    methodsCheck: /** @type {null | (() => unknown)} */ (null),
    seedCalls: 0,
  };

  const server = deviceServer({
    "/api/vault/policy": () => {
      if (state.expireAccess > 0) {
        state.expireAccess -= 1;
        return answer(401, { error: "token_expired" });
      }
      return answer(200, { pin: { allowed: true, after_restart: true, min_length: 6 }, prf: { enabled: state.prfEnabled } });
    },
    "/api/auth/token/refresh": () => {
      state.refreshes += 1;
      if (state.refresh !== "ok") return answer(401, { error: state.refresh });
      return answer(200, { access_token: token(100 + state.refreshes), refresh_token: token(150 + state.refreshes), token_type: "DPoP", expires_in: 900 });
    },
    "/api/vault/unlock-methods": () => {
      state.listReads += 1;
      if (state.methodsStatus !== 200) return answer(state.methodsStatus, { error: "throttled" });
      const base = methodsRes();
      return answer(200, { ...base, pk_a: b64u(state.pkA), vk_epoch: state.vkEpoch, methods: [...base.methods, ...state.passkeys.map(wireOf)] });
    },
  });
  /** @type {typeof fetch} */
  const fetchImpl = async (input, init) => {
    if (!state.online) throw new TypeError("fetch failed");
    return server.fetchImpl(input, init);
  };

  const client = coreClient({
    unlock_prf: async (/** @type {string} */ url, /** @type {any} */ ctx, /** @type {Uint8Array} */ output, /** @type {any} */ wrap, /** @type {any} */ pinned) => {
      state.handed.push(output);
      state.prfCalls.push({ url, ctx, output: Uint8Array.from(output), wrap, pinned });
      if (state.unlockBehaviour) await state.unlockBehaviour();
      if (pinned?.kind !== "pinned") throw coded("invalid_input");
      if (Number(ctx.vk_epoch) > Number(pinned.record.vk_epoch_max)) throw coded("pinned_epoch_ahead");
      if (!Buffer.from(output).equals(Buffer.from(state.correctOutput))) throw coded("decrypt");
      return { pinned: pinned.record };
    },
    seed_pinned: (/** @type {any} */ pinned) => {
      state.seedCalls += 1;
      return pinned;
    },
    check_server_methods: () => state.methodsCheck?.(),
  });

  const db = memoryDb();
  const store = memoryStore(db);
  w = await sessionWorld({ client, store, fetchImpl, pin: { store: pinStore, options: { policyTimeoutMs: 2000, ...(windows ? { windows, getURL: (/** @type {string} */ path) => `moz-extension://ferret/${path}`, windowPage: WINDOW_PAGE } : {}) } } });
  w.clock.set(START);
  const signinPage = w.page("pages/signin.html");
  const signIn = () => signinPage.request("sign_in", { server: SERVER, email: EMAIL, mp: MP, sk: SK_CODE, remember_sk: true });
  const lockNow = async () => {
    await w.coreHost.lock("manual");
    await settle();
  };
  const windowPage = w.page(WINDOW_PAGE);
  const options = () => windowPage.request("prf_options", {});
  const unlock = (/** @type {Record<string, unknown>} */ extra = {}) =>
    windowPage.request("prf_unlock", { credential_id: b64u(PASSKEY.credential), prf_output: b64u(PASSKEY.output), ...extra });
  return { ...w, state, server, client, db, store, pinStore, idb, signIn, lockNow, windowPage, options, unlock, fetchImpl };
}

/** A world with a device that is signed in and locked. */
async function lockedWorld(opts = {}) {
  const w = await prfWorld(opts);
  assert.equal((await w.signIn()).ok, true);
  await w.lockNow();
  return w;
}

const coreCalls = (/** @type {any} */ w, /** @type {string} */ name) => w.client.calls.filter((/** @type {any} */ c) => c.method === name);

// ------------------------------------------------------------------------------------------ who may do what

test("prf_unlock_runs_only_in_the_unlock_window_never_in_the_popup", async () => {
  const w = await lockedWorld();
  // The popup (and the settings and the sign-in page) may read what the window needs, and ask for the window, but a
  // `prf_unlock` from them is refused before anything happens: the call itself cannot be made from a popup either.
  for (const page of ["pages/popup.html", "pages/settings.html", "pages/signin.html"]) {
    const other = w.page(page);
    const options = await other.request("prf_options", {});
    assert.equal(options.ok, true, page);
    await assert.rejects(other.request("prf_unlock", { credential_id: b64u(PASSKEY.credential), prf_output: b64u(PASSKEY.output) }), { message: "not_available" }, page);
  }
  assert.equal(coreCalls(w, "unlock_prf").length, 0, "the core was never asked");
  assert.equal(w.coreHost.state(), "locked");
  // The window itself: a query or a fragment on its address is the same page.
  const reply = await w.unlock();
  assert.equal(reply.ok, true, JSON.stringify(reply));
  assert.equal(w.coreHost.state(), "unlocked");
  await w.lockNow();
  for (const extra of ["?x=1", "#top"]) {
    const page = w.page(`${WINDOW_PAGE}${extra}`);
    assert.equal((await page.request("prf_unlock", { credential_id: b64u(PASSKEY.credential), prf_output: b64u(PASSKEY.output) })).ok, true, extra);
    await w.lockNow();
  }
  // Another address that merely starts with the window's.
  const lookalike = w.page(`${WINDOW_PAGE}x`);
  await assert.rejects(lookalike.request("prf_unlock", { credential_id: b64u(PASSKEY.credential), prf_output: b64u(PASSKEY.output) }), { message: "not_available" });
  // A web page's script cannot reach it at all.
  const evil = portPair("ferret-ui", contentScriptSender(w.fake, "https://evil.example/"));
  w.router.onConnect(evil.background);
  assert.equal(evil.background.disconnected, true);

  // The one place in a package with a WebAuthn call is the window's page (the shared files make none; they are handed one).
  const { dir } = await pkg();
  /** @type {string[]} */
  const holders = [];
  /** @param {string} folder @param {string} prefix */
  const walkDir = (folder, prefix) => {
    for (const name of readdirSync(folder)) {
      const path = join(folder, name);
      const relative = prefix === "" ? name : `${prefix}/${name}`;
      if (statSync(path).isDirectory()) walkDir(path, relative);
      else if (/\.(?:mjs|js|html)$/.test(name) && !relative.startsWith("wasm") && !relative.includes("test-only") && /credentials\s*\.\s*(?:get|create)\b/.test(readFileSync(path, "utf8"))) holders.push(relative);
    }
  };
  walkDir(dir, "");
  assert.deepEqual(holders.filter((p) => !p.startsWith("test") && !p.startsWith("probe")), ["pages/unlockWindow.mjs"]);
  // The popup never imports it and opens the window only by asking the background.
  const popup = readFileSync(join(dir, "pages", "popup.mjs"), "utf8");
  assert.equal(/unlockWindow/.test(popup), false);
  assert.equal(/prf_window/.test(readFileSync(join(dir, "pages", "popupFlow.mjs"), "utf8")), true);
});

test("the_window_is_a_top_level_extension_page_and_cannot_be_framed", async () => {
  const w = await lockedWorld();
  // A frame of the window page (another page framing it) cannot connect, so cannot ask for anything.
  const framed = portPair("ferret-ui", extensionPageSender(w.fake, WINDOW_PAGE, { frameId: 1 }));
  w.router.onConnect(framed.background);
  assert.equal(framed.background.disconnected, true);
  // A top-level page that is not the window cannot send the result of a passkey, and a frame of the window (if one got a
  // port) is refused by the handler too.
  const handler = (await (await pkg()).load("background/handlers/unlock.handler.mjs")).default;
  const ctx = (/** @type {any} */ sender) => ({ channel: "ui", type: "prf_unlock", sender, runtime: w.fake.runtime, state: () => "locked", call: async () => ({ ok: true }), lock: async () => {} });
  await assert.rejects(handler.handle({}, ctx(extensionPageSender(w.fake, WINDOW_PAGE, { frameId: 3 }))), { code: "not_available" });
  await assert.rejects(handler.handle({}, ctx(extensionPageSender(w.fake, "pages/popup.html"))), { code: "not_available" });
  await assert.rejects(handler.handle({}, ctx(contentScriptSender(w.fake, "https://evil.example/"))), { code: "not_available" });
  assert.deepEqual(await handler.handle({}, ctx(extensionPageSender(w.fake, WINDOW_PAGE))), { ok: true });

  // The package: a page of its own, framed by nobody (the extension CSP forbids every ancestor, and no page of the package
  // is reachable from a web page), and made with a script and no frame of its own.
  const { dir } = await pkg();
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  assert.equal("web_accessible_resources" in manifest, false);
  const csp = typeof manifest.content_security_policy === "string" ? manifest.content_security_policy : manifest.content_security_policy.extension_pages;
  assert.match(csp, /frame-ancestors 'none'/);
  const html = readFileSync(join(dir, "pages", "unlockWindow.html"), "utf8");
  assert.equal(/<(?:iframe|frame|object|embed)\b/i.test(html), false);
  assert.match(html, /<script type="module" src="unlockWindow\.mjs"><\/script>/);
  const script = readFileSync(join(dir, "pages", "unlockWindow.mjs"), "utf8");
  assert.equal(/\b(?:window\.top|window\.parent|top\.location|postMessage\s*\()/.test(script), false, "the window talks to the background only");
});

test("the_window_is_opened_by_the_background_in_a_popup_window_of_its_own_and_only_once", async () => {
  /** @type {any[]} */
  const created = [];
  /** @type {any[]} */
  const updated = [];
  let open = true;
  const windows = {
    create: async (/** @type {any} */ info) => {
      created.push(info);
      return { id: created.length };
    },
    update: async (/** @type {number} */ id, /** @type {any} */ info) => {
      updated.push([id, info]);
      if (!open) throw new Error("no such window");
    },
  };
  const w = await lockedWorld({ windows });
  const popup = w.page("pages/popup.html");
  assert.deepEqual(await popup.request("prf_window", {}), { ok: true });
  assert.equal(created.length, 1);
  assert.equal(created[0].url, `moz-extension://ferret/${WINDOW_PAGE}`);
  assert.equal(created[0].type, "popup");
  // Asked again while it is open: the open one is brought forward, none is made.
  assert.deepEqual(await popup.request("prf_window", {}), { ok: true });
  assert.equal(created.length, 1);
  assert.deepEqual(updated.at(-1), [1, { focused: true }]);
  // It was closed meanwhile: a new one.
  open = false;
  assert.deepEqual(await popup.request("prf_window", {}), { ok: true });
  assert.equal(created.length, 2);
  // A build that cannot open it (no window API) says so.
  const bare = await lockedWorld();
  assert.deepEqual(await bare.page("pages/popup.html").request("prf_window", {}), { ok: false, reason: "prf_unavailable" });
});

// ------------------------------------------------------------------------------------------ live tokens and the network

test("prf_unlock_needs_live_tokens_and_the_network", async () => {
  // The options: the exact host of the vault and each passkey's id and salt, read now.
  const w = await lockedWorld({ passkeys: [PASSKEY, KEY_TWO] });
  const reads = w.state.listReads;
  const options = await w.options();
  assert.deepEqual(options, {
    ok: true,
    rp_id: HOST,
    credentials: [
      { id: b64u(PASSKEY.credential), salt: b64u(PASSKEY.salt) },
      { id: b64u(KEY_TWO.credential), salt: b64u(KEY_TWO.salt) },
    ],
  });
  assert.equal(w.state.listReads, reads + 1, "the list was read for the answer");
  await w.options();
  assert.equal(w.state.listReads, reads + 2, "and read again, never cached");

  // No network: nothing is asked of the core, and the answer says so.
  w.state.online = false;
  assert.deepEqual(await w.options(), { ok: false, reason: "network" });
  assert.deepEqual(await w.unlock(), { ok: false, reason: "network" });
  assert.equal(coreCalls(w, "unlock_prf").length, 0);
  assert.equal(w.coreHost.state(), "locked");
  w.state.online = true;

  // A server that answers with an error (not a revocation) is no network either, and the list route failing alone is too.
  w.state.methodsStatus = 503;
  assert.deepEqual(await w.options(), { ok: false, reason: "network" });
  assert.deepEqual(await w.unlock(), { ok: false, reason: "network" });
  w.state.methodsStatus = 200;

  // The rule says no passkeys now.
  w.state.prfEnabled = false;
  assert.deepEqual(await w.options(), { ok: false, reason: "prf_unavailable" });
  assert.deepEqual(await w.unlock(), { ok: false, reason: "prf_unavailable" });
  w.state.prfEnabled = true;

  // An account with no passkey method has nothing to offer.
  const none = await lockedWorld({ passkeys: [] });
  assert.deepEqual(await none.options(), { ok: false, reason: "prf_unavailable" });

  // Tokens that have ended (the access token ran out and the renewal is refused): no options and no unlock, whatever the
  // passkey said, and the core is never asked.
  const ended = await lockedWorld();
  ended.state.expireAccess = 1;
  ended.state.refresh = "device_revoked";
  assert.deepEqual(await ended.options(), { ok: false, reason: "signed_out" });
  assert.deepEqual(await ended.unlock(), { ok: false, reason: "signed_out" });
  assert.equal(coreCalls(ended, "unlock_prf").length, 0);
  assert.equal(ended.coreHost.state(), "locked");

  // A device that was never signed in has no server to ask.
  const fresh = await prfWorld();
  assert.deepEqual(await fresh.options(), { ok: false, reason: "prf_unavailable" });
});

test("a_passkey_unlock_opens_the_vault_with_the_listed_wrap_under_the_pinned_record", async () => {
  const w = await lockedWorld({ passkeys: [PASSKEY, KEY_TWO] });
  const reply = await w.unlock();
  assert.deepEqual(reply, { ok: true, account_email: EMAIL, server: SERVER });
  assert.equal(w.coreHost.state(), "unlocked");
  const [call] = w.state.prfCalls;
  assert.equal(call.url, SERVER);
  // The wrap of the credential that answered, from the list read for this unlock.
  assert.deepEqual(call.wrap.method, { type: "prf", credential_id: PASSKEY.credential, prf_salt: PASSKEY.salt });
  assert.equal(call.ctx.vk_epoch, 1);
  // The record this device pinned, and the server key it holds, never one that a response carried.
  assert.equal(call.pinned.kind, "pinned");
  assert.deepEqual(call.pinned.server_public_key, pinnedRecord().server_public_key);
  assert.deepEqual(call.pinned.record.server_public_key, pinnedRecord().server_public_key);
  assert.deepEqual(Buffer.from(call.output), Buffer.from(PASSKEY.output));
  // An unlock with the key of the other passkey opens the other wrap.
  await w.lockNow();
  w.state.correctOutput = filled(32, 0x77);
  const second = await w.unlock({ credential_id: b64u(KEY_TWO.credential), prf_output: b64u(filled(32, 0x77)) });
  assert.equal(second.ok, true);
  assert.deepEqual(w.state.prfCalls[1].wrap.method.credential_id, KEY_TWO.credential);
});

test("a_wrong_missing_or_removed_passkey_is_one_plain_failure_and_the_vault_stays_locked", async () => {
  const w = await lockedWorld();
  // A key that does not open the wrap.
  assert.deepEqual(await w.unlock({ prf_output: b64u(filled(32, 1)) }), { ok: false, reason: "prf_failed" });
  assert.equal(w.coreHost.state(), "locked");
  // A credential that is not in the list now (removed since the window asked): the core is not asked.
  const before = w.state.prfCalls.length;
  assert.deepEqual(await w.unlock({ credential_id: b64u(filled(24, 5)) }), { ok: false, reason: "prf_failed" });
  assert.equal(w.state.prfCalls.length, before);
  // A result of the wrong size cannot be encoded as a message at all.
  assert.throws(() => w.windowPage.request("prf_unlock", { credential_id: b64u(PASSKEY.credential), prf_output: b64u(filled(31, 1)) }), { code: "bad_shape" });
  assert.equal(w.coreHost.state(), "locked");
  // The list is read for each unlock: a passkey added later is there, one removed is gone.
  w.state.passkeys = [KEY_TWO];
  assert.deepEqual(await w.unlock(), { ok: false, reason: "prf_failed" });
});

test("the_post_unlock_checks_run_after_prf", async () => {
  // The order: the core opens, the manifest's floors are seeded, the server's list is compared, the account key is compared,
  // and only then the vault is open for the rest of the background.
  const w = await lockedWorld();
  const reply = await w.unlock();
  assert.equal(reply.ok, true);
  const order = w.client.calls.map((/** @type {any} */ c) => c.method).filter((/** @type {string} */ m) => ["unlock_prf", "seed_pinned", "check_server_methods"].includes(m));
  assert.deepEqual(order.slice(-3), ["unlock_prf", "seed_pinned", "check_server_methods"]);
  await w.lockNow();

  // The server's list disagrees with the manifest: the vault locks, and nothing is opened for the sync.
  w.state.methodsCheck = () => {
    throw coded("method_list_changed");
  };
  let opened = 0;
  w.sessionHost.onOpen(() => {
    opened += 1;
  });
  assert.deepEqual(await w.unlock(), { ok: false, reason: "attack_warning" });
  assert.equal(w.coreHost.state(), "locked");
  assert.equal(opened, 0);
  w.state.methodsCheck = null;

  // The account key the server lists is not the pinned one.
  w.state.pkA = filled(32, 99);
  assert.deepEqual(await w.unlock(), { ok: false, reason: "attack_warning" });
  assert.equal(w.coreHost.state(), "locked");
  w.state.pkA = filled(32, 3);

  // A key epoch ahead of the one this device pinned: the core refuses it (nothing here takes it as new).
  w.state.vkEpoch = 2;
  assert.deepEqual(await w.unlock(), { ok: false, reason: "attack_warning" });
  assert.equal(w.coreHost.state(), "locked");
  w.state.vkEpoch = 1;

  // And once all is as it was, it opens again: nothing was kept from the refusals.
  assert.equal((await w.unlock()).ok, true);
  assert.equal(w.coreHost.state(), "unlocked");
  assert.equal(opened, 1);
});

test("a_passkey_unlock_never_takes_the_server_key_from_a_response_and_pins_no_new_one", async () => {
  // A record that holds no server key: nothing is passed (the core then keeps none), whatever the responses say.
  const w = await lockedWorld();
  const record = await w.store.pinnedForSignIn(await w.store.open(), SERVER, EMAIL, ACCOUNT);
  assert.ok(record);
  const { server_public_key: _removed, ...without } = record;
  await w.store.savePinned(await w.store.open(), SERVER, ACCOUNT, EMAIL, without);
  assert.equal((await w.unlock()).ok, true);
  const [call] = w.state.prfCalls;
  assert.equal("server_public_key" in call.pinned, false);
  assert.equal(JSON.stringify(call.pinned).includes("server_public_key"), false);
  // A device that has no pinned record has no first use here: nothing is opened and the core is not asked.
  const empty = await lockedWorld();
  empty.store.pinned.clear();
  assert.deepEqual(await empty.unlock(), { ok: false, reason: "prf_unavailable" });
  assert.equal(empty.state.prfCalls.length, 0);
  assert.equal(empty.coreHost.state(), "locked");
});

// ------------------------------------------------------------------------------------------ the secret's path

/** A fake `getAssertion`: the authenticator answers for `credential` with `output` as the PRF result. */
async function fakeAssertion({ credential = PASSKEY.credential, output = PASSKEY.output, host = HOST, uv = true, origin = "moz-extension://ferret", reject = null } = {}) {
  const { createHash } = await import("node:crypto");
  /** The buffer the browser hands over, to see it wiped. @type {ArrayBuffer | null} */
  let first = null;
  const calls = /** @type {any[]} */ ([]);
  return {
    calls,
    get first() {
      return first;
    },
    getAssertion: async (/** @type {any} */ publicKey) => {
      calls.push(publicKey);
      if (reject) throw Object.assign(new Error(reject), { name: reject });
      const clientData = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: b64u(new Uint8Array(publicKey.challenge)), origin, crossOrigin: false }));
      const data = Uint8Array.from([...createHash("sha256").update(host).digest(), 0x01 | (uv ? 0x04 : 0), 0, 0, 0, 2]);
      first = Uint8Array.from(output).buffer;
      return {
        type: "public-key",
        rawId: Uint8Array.from(credential).buffer,
        response: { clientDataJSON: clientData.buffer.slice(0), authenticatorData: data.buffer.slice(0) },
        getClientExtensionResults: () => ({ prf: { results: { first } } }),
      };
    },
  };
}

const flowDeps = async () => {
  const { createHash } = await import("node:crypto");
  return {
    rand: (/** @type {Uint8Array} */ bytes) => bytes.fill(0x2a),
    now: () => 0,
    sha256: async (/** @type {Uint8Array} */ data) => Uint8Array.from(createHash("sha256").update(data).digest()),
    origin: "moz-extension://ferret",
  };
};

test("the_prf_output_buffer_is_zeroed_after_sending", async () => {
  const { load } = await pkg();
  const { createUnlockWindowFlow } = await load("pages/unlockWindowFlow.mjs");
  const offer = { rpId: HOST, credentials: [{ id: PASSKEY.credential, salt: PASSKEY.salt }] };

  // With the real evaluation of the shared flow: the copy the page holds is zero once the message is on its way, the
  // browser's own buffer is zero too, and what was sent is the bytes the passkey gave.
  const fake = await fakeAssertion();
  /** @type {any[]} */
  const sent = [];
  /** @type {Uint8Array | null} */
  let copy = null;
  const { evaluateOneOf } = await load("shared/flows/passkeyAnswer.mjs");
  const flow = createUnlockWindowFlow(
    async (/** @type {string} */ type, /** @type {any} */ body) => {
      sent.push({ type, body: { ...body } });
      return { ok: true, account_email: EMAIL, server: SERVER };
    },
    {
      getAssertion: fake.getAssertion,
      deps: await flowDeps(),
      evaluate: async (/** @type {any} */ request, /** @type {any} */ deps) => {
        const result = await evaluateOneOf(request, deps);
        copy = result.output;
        return result;
      },
    },
  );
  const outcome = await flow.unlock(offer);
  assert.deepEqual(outcome, { ok: true, email: EMAIL });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, "prf_unlock");
  assert.equal(sent[0].body.prf_output, b64u(PASSKEY.output));
  assert.equal(sent[0].body.credential_id, b64u(PASSKEY.credential));
  assert.ok(copy !== null && /** @type {Uint8Array} */ (copy).every((b) => b === 0), "the page's copy is zero");
  assert.ok(fake.first !== null && new Uint8Array(fake.first).every((b) => b === 0), "the browser's buffer is zero");
  assert.equal(fake.calls.length, 1, "one WebAuthn call");
  assert.equal(fake.calls[0].rpId, HOST);
  assert.equal(fake.calls[0].userVerification, "required");

  // The wipe comes before the answer is awaited: a background that never answers leaves nothing behind.
  /** @type {Uint8Array | null} */
  let held = null;
  let release = () => {};
  const hang = createUnlockWindowFlow(() => new Promise((resolve) => (release = () => resolve({ ok: true }))), {
    getAssertion: (await fakeAssertion()).getAssertion,
    deps: await flowDeps(),
    evaluate: async (/** @type {any} */ request, /** @type {any} */ deps) => {
      const result = await evaluateOneOf(request, deps);
      held = result.output;
      return result;
    },
  });
  const pending = hang.unlock(offer);
  await settle();
  assert.ok(held !== null && /** @type {Uint8Array} */ (held).every((b) => b === 0), "zero while the answer is still awaited");
  release();
  assert.equal((await pending).ok, true);

  // A request that fails also leaves nothing behind.
  /** @type {Uint8Array | null} */
  let failed = null;
  const broken = createUnlockWindowFlow(async () => {
    throw Object.assign(new Error("disconnected"), { code: "disconnected" });
  }, {
    getAssertion: (await fakeAssertion()).getAssertion,
    deps: await flowDeps(),
    evaluate: async (/** @type {any} */ request, /** @type {any} */ deps) => {
      const result = await evaluateOneOf(request, deps);
      failed = result.output;
      return result;
    },
  });
  assert.deepEqual(await broken.unlock(offer), { ok: false, reason: "disconnected" });
  assert.ok(failed !== null && /** @type {Uint8Array} */ (failed).every((b) => b === 0));

  // The background wipes the copy it decoded, whatever the core did with it.
  const w = await lockedWorld();
  assert.equal((await w.unlock()).ok, true);
  assert.ok(w.state.handed.length > 0 && w.state.handed.every((bytes) => bytes.every((b) => b === 0)), "the core's copy is zero afterwards");
  await w.lockNow();
  w.state.unlockBehaviour = () => {
    throw coded("decrypt");
  };
  assert.equal((await w.unlock()).ok, false);
  assert.ok(w.state.handed.every((bytes) => bytes.every((b) => b === 0)), "and after a refusal");
});

test("the_flow_says_one_plain_thing_for_every_failure_of_the_ceremony", async () => {
  const { load } = await pkg();
  const { createUnlockWindowFlow, passkeyErrorKey } = await load("pages/unlockWindowFlow.mjs");
  const offer = { rpId: HOST, credentials: [{ id: PASSKEY.credential, salt: PASSKEY.salt }] };
  /** @type {any[]} */
  const asked = [];
  const run = async (/** @type {any} */ fake) => {
    const flow = createUnlockWindowFlow(async (/** @type {string} */ type) => {
      asked.push(type);
      return { ok: true, account_email: EMAIL, server: SERVER };
    }, { getAssertion: fake.getAssertion, deps: await flowDeps() });
    return flow.unlock(offer);
  };
  // The browser says no at once (another provider, no provider, Windows Hello not set up): it says so, with the help.
  assert.deepEqual(await run(await fakeAssertion({ reject: "NotAllowedError" })), { ok: false, reason: "passkey_blocked" });
  assert.deepEqual(await run(await fakeAssertion({ reject: "NotSupportedError" })), { ok: false, reason: "passkey_unsupported" });
  assert.deepEqual(await run(await fakeAssertion({ reject: "SecurityError" })), { ok: false, reason: "passkey_security" });
  // Not verified, another credential, another host: nothing is sent to the background.
  assert.deepEqual(await run(await fakeAssertion({ uv: false })), { ok: false, reason: "passkey_not_verified" });
  assert.deepEqual(await run(await fakeAssertion({ credential: filled(24, 9) })), { ok: false, reason: "passkey_other_credential" });
  assert.deepEqual(await run(await fakeAssertion({ host: "evil.example" })), { ok: false, reason: "passkey_bad_answer" });
  // A result of the wrong size is the same plain answer as a key that does not open the vault.
  assert.deepEqual(await run(await fakeAssertion({ output: filled(31, 1) })), { ok: false, reason: "passkey_unlock_failed" });
  assert.deepEqual(asked, []);
  for (const reason of ["passkey_blocked", "passkey_cancelled", "passkey_failed", "passkey_not_verified", "passkey_other_credential", "passkey_security", "passkey_unlock_failed", "passkey_unsupported", "prf_failed", "prf_unavailable", "method_removed", "network", "signed_out", "attack_warning"]) {
    assert.match(passkeyErrorKey(reason), /^(?:passkey|session)\.error\./, reason);
  }
  assert.equal(passkeyErrorKey("something_else"), "session.error.unknown");
});

test("the_window_flow_reads_the_options_and_refuses_what_it_cannot_use", async () => {
  const { load } = await pkg();
  const { createUnlockWindowFlow } = await load("pages/unlockWindowFlow.mjs");
  const make = async (/** @type {any} */ reply) => createUnlockWindowFlow(async () => reply, { getAssertion: async () => null, deps: await flowDeps() });
  const good = await (await make({ ok: true, rp_id: HOST, credentials: [{ id: b64u(PASSKEY.credential), salt: b64u(PASSKEY.salt) }] })).options();
  assert.equal(good.ok, true);
  assert.equal(good.offer.rpId, HOST);
  assert.deepEqual(good.offer.credentials[0].id, PASSKEY.credential);
  assert.deepEqual((await (await make({ ok: false, reason: "network" })).options()), { ok: false, reason: "network" });
  assert.deepEqual((await (await make({ ok: true, rp_id: HOST, credentials: [] })).options()), { ok: false, reason: "prf_unavailable" });
  assert.deepEqual((await (await make(null)).options()), { ok: false, reason: "passkey_failed" });
  // The real protocol: the reply is checked against the schema on its way.
  const raw = encode("prf_options", { ok: true, rp_id: HOST, credentials: [{ id: b64u(PASSKEY.credential), salt: b64u(PASSKEY.salt) }] }, { reply: true, id: "a" });
  assert.equal(decode(raw, UI_TYPES, { reply: true }).type, "prf_options");
  assert.throws(() => encode("prf_options", { ok: true, rp_id: HOST, credentials: [{ id: "not base64!", salt: b64u(PASSKEY.salt) }] }, { reply: true, id: "a" }));
  assert.throws(() => encode("prf_unlock", { credential_id: "AQID", prf_output: "short" }, { id: "a" }));
});

// ------------------------------------------------------------------------------------------ the flag

test("prf_messages_are_refused_with_unlock_off", async () => {
  const env = makeRoot();
  try {
    const options = { root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, manifest: "mv2" };
    const { pathToFileURL } = await import("node:url");
    for (const [name, variant, features] of /** @type {const} */ ([["release", "release", undefined], ["test-off", "test", ["save"]]])) {
      const built = await build({ ...options, out: join(env.out, name), variant, ...(features ? { features: [...features] } : {}) });
      assert.equal(built.files.has(WINDOW_PAGE), false, `${name}: no window page`);
      assert.equal(built.files.has("pages/unlockWindow.mjs"), false);
      assert.equal(built.files.has("pages/unlockWindowFlow.mjs"), false);
      const handler = (await import(pathToFileURL(join(built.dir, "background", "handlers", "unlock.handler.mjs")).href)).default;
      assert.ok(["prf_options", "prf_unlock", "prf_window"].every((type) => handler.types.includes(type)), "the types are the handler's, which refuses them");
      const w = await prfWorld();
      for (const type of ["prf_options", "prf_unlock", "prf_window"]) {
        let refused = null;
        try {
          await handler.handle({ credential_id: "x", prf_output: "y" }, {
            channel: "ui", type, sender: extensionPageSender(w.fake, WINDOW_PAGE), runtime: w.fake.runtime, state: () => "locked",
            call: async () => ({ ok: true }), lock: async () => {},
          });
        } catch (error) {
          refused = /** @type {any} */ (error)?.code;
        }
        assert.equal(refused, "not_available", `${name}: ${type}`);
      }
      // No WebAuthn call anywhere in the package, and nothing that would make one.
      for (const [path, bytes] of built.files) {
        if (!/\.(?:mjs|js|html)$/.test(path) || path.startsWith("wasm") || path.includes("test-only")) continue;
        assert.equal(/credentials\s*\.\s*(?:get|create)\b/.test(bytes.toString("utf8")), false, `${name}: ${path}`);
      }
    }
  } finally {
    env.cleanup();
  }
});

test("the_popup_offers_a_passkey_only_when_the_server_and_the_account_have_one", async () => {
  const { load } = await pkg();
  const { createPopupFlow } = await load("pages/popupFlow.mjs");
  /** @type {string[]} */
  const asked = [];
  /** @param {Record<string, any>} answers */
  const flowWith = (answers) =>
    createPopupFlow(async (/** @type {string} */ type) => {
      asked.push(type);
      const reply = answers[type];
      if (reply instanceof Error) throw reply;
      return reply;
    });
  const policy = (/** @type {boolean} */ enabled) => ({
    pin: { allowed: true, after_restart: true, min_length: 6, set: false, failures_left: 0, wait_ms: 0, offline_ok: false },
    prf: { enabled, count: 0 },
  });
  assert.equal(await flowWith({ unlock_policy: policy(true), prf_options: { ok: true, rp_id: HOST, credentials: [{ id: "AQID", salt: "a".repeat(43) }] } }).passkeyOffer(), true);
  assert.equal(await flowWith({ unlock_policy: policy(false), prf_options: { ok: true, rp_id: HOST, credentials: [{ id: "AQID", salt: "a".repeat(43) }] } }).passkeyOffer(), false);
  assert.deepEqual(asked.slice(-1), ["unlock_policy"], "the server's rule says no: the list is not even asked for");
  assert.equal(await flowWith({ unlock_policy: policy(true), prf_options: { ok: false, reason: "network" } }).passkeyOffer(), false);
  assert.equal(await flowWith({ unlock_policy: policy(true), prf_options: { ok: true, rp_id: HOST, credentials: [] } }).passkeyOffer(), false);
  assert.equal(await flowWith({ unlock_policy: policy(true), prf_options: new Error("refused") }).passkeyOffer(), false);
  assert.equal(await flowWith({ prf_window: { ok: true } }).openPasskeyWindow(), true);
  assert.equal(await flowWith({ prf_window: { ok: false, reason: "prf_unavailable" } }).openPasskeyWindow(), false);
  assert.equal(await flowWith({ prf_window: new Error("refused") }).openPasskeyWindow(), false);
});

test("the_texts_of_the_passkey_unlock_exist_in_en_and_nb_and_each_is_used", async () => {
  const { extensionRoot } = await import("./buildHelpers.mjs");
  const read = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "passkey.json"), "utf8"));
  const [en, nb] = [read("en"), read("nb")];
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  for (const key of Object.keys(en)) assert.notEqual(en[key], nb[key], key);
  const { PASSKEY_REASONS } = await (await pkg()).load("pages/unlockWindowFlow.mjs");
  // Every reason the window can show has a text, and every text is one the pages ask for.
  for (const reason of PASSKEY_REASONS) assert.ok(en[`passkey.error.${reason}`] && nb[`passkey.error.${reason}`], reason);
  const asked = new Set();
  for (const file of ["unlockWindow.mjs", "popup.mjs", "unlockWindowFlow.mjs"]) {
    const text = readFileSync(join(extensionRoot, "src", "pages", file), "utf8");
    for (const [, key] of text.matchAll(/["'`](passkey\.[a-z_.]+)["'`]/g)) asked.add(key);
  }
  for (const reason of PASSKEY_REASONS) asked.add(`passkey.error.${reason}`);
  for (const key of asked) if (!key.endsWith(".error.")) assert.ok(en[key], `en: ${key}`);
  for (const key of Object.keys(en)) assert.ok(asked.has(key), `unused: ${key}`);
  // The help for a fast failure is the web vault's: another provider, macOS with no provider, Windows Hello not set up.
  assert.match(en["passkey.blocked.other_manager"], /Another password manager/);
  assert.match(en["passkey.blocked.mac"], /AutoFill & Passwords/);
  assert.match(en["passkey.blocked.windows"], /Windows Hello/);
});

test("the_origin_of_an_extension_page_is_computed_from_its_id_and_checked_exactly", async () => {
  // Firefox 150 and later writes moz-extension:// and the SHA-256 of the extension id (each hex nibble as a letter a to p) into
  // the client data of an extension page. The value below was captured from a real Firefox run of the test build.
  const { load } = await pkg();
  const { extensionOrigin } = await load("pages/unlockWindowFlow.mjs");
  const { evaluateOneOf } = await load("shared/flows/passkeyAnswer.mjs");
  const { createHash } = await import("node:crypto");
  const sha256 = async (/** @type {Uint8Array} */ data) => Uint8Array.from(createHash("sha256").update(data).digest());
  const captured = "moz-extension://loihkokpllkcdpkkahglfeikpjenbcbemfmfjlnbkpdgfmgjpjhplhbkfhmfeaan";
  assert.equal(await extensionOrigin("ferret-test@hedgerow.tools", sha256), captured);
  const release = await extensionOrigin("ferret@hedgerow.tools", sha256);
  assert.match(release, /^moz-extension:[/][/][a-p]{64}$/);
  assert.notEqual(release, captured);
  // The check is the exact string: the same origin passes, another one (a web page, another extension) does not.
  const deps = await flowDeps();
  const evaluate = async (/** @type {string} */ writes, /** @type {string} */ expected) => {
    const fake = await fakeAssertion({ origin: writes });
    return evaluateOneOf({ rpId: HOST, credentials: [{ id: PASSKEY.credential, salt: PASSKEY.salt }], getAssertion: fake.getAssertion }, { ...deps, origin: expected }).then(
      () => "ok",
      (/** @type {any} */ error) => error.code,
    );
  };
  assert.equal(await evaluate(captured, captured), "ok");
  assert.equal(await evaluate(release, captured), "passkey_bad_answer");
  assert.equal(await evaluate("https://evil.example", captured), "passkey_bad_answer");
});

test("a_refusal_of_the_checks_after_a_passkey_unlock_deletes_the_pin_but_a_wrong_key_does_not", async () => {
  const { makeBlob } = await import("./localUnlockHelpers.mjs");
  const withPin = async () => {
    const w = await lockedWorld();
    await w.pinStore.save(SERVER, ACCOUNT, makeBlob({ minLength: 6 }), { location: "disk", acknowledged: true });
    assert.equal((await w.pinStore.status(SERVER, ACCOUNT)).set, true);
    return w;
  };
  // What the server shows disagrees with what this device pinned: the vault locks and the PIN is deleted.
  for (const [name, cause] of /** @type {Array<[string, (w: any) => void]>} */ ([
    ["the list differs from the manifest", (w) => { w.state.methodsCheck = () => { throw coded("method_list_changed"); }; }],
    ["the account key is not the pinned one", (w) => { w.state.pkA = filled(32, 99); }],
    ["the key epoch is ahead", (w) => { w.state.vkEpoch = 2; }],
  ])) {
    const w = await withPin();
    cause(w);
    assert.deepEqual(await w.unlock(), { ok: false, reason: "attack_warning" }, name);
    assert.equal(w.coreHost.state(), "locked", name);
    assert.equal((await w.pinStore.status(SERVER, ACCOUNT)).set, false, `${name}: the PIN is deleted`);
  }
  // A passkey that is only wrong, removed or not offered says nothing about the server: the PIN stays.
  const w = await withPin();
  assert.deepEqual(await w.unlock({ prf_output: b64u(filled(32, 1)) }), { ok: false, reason: "prf_failed" });
  assert.deepEqual(await w.unlock({ credential_id: b64u(filled(24, 5)) }), { ok: false, reason: "prf_failed" });
  w.state.online = false;
  assert.deepEqual(await w.unlock(), { ok: false, reason: "network" });
  w.state.online = true;
  w.state.prfEnabled = false;
  assert.deepEqual(await w.unlock(), { ok: false, reason: "prf_unavailable" });
  assert.equal((await w.pinStore.status(SERVER, ACCOUNT)).set, true, "the PIN is still there");
});
