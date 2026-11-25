// The registration of the passkey scripts (background/passkeyRegistry.mjs), the background's side of the bridge
// (background/passkeyRequests.mjs), the way a report of the bridge goes through the router, and the generated module through
// which the background reaches the feature (design document § 9.2 and § 10.8).
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createPasskeyRegistry, PASSKEY_BRIDGE_FILE, PASSKEY_MAIN_FILE, PASSKEY_SETTING_KEY, passkeyScripts, SERVER_KEY, serverPattern,
} from "../../src/background/passkeyRegistry.mjs";
import { createPasskeyRequests, PASSKEY_EVENT_OP } from "../../src/background/passkeyRequests.mjs";
import { PASSKEY_SCRIPT_IDS } from "../../src/background/passkeyCleanup.mjs";
import { readFileSync } from "node:fs";
import { CORE_OPS } from "../../src/background/coreHost.mjs";
import { LOCK_EXEMPT } from "../../src/background/lock.mjs";
import { createRouter, PASSKEY_OP } from "../../src/background/router.mjs";
import { CAPTURE_ORIGINS } from "../../src/shared/captureConfig.mjs";
import { decode, encode, PUSH_TYPES } from "../../src/shared/protocol.mjs";
import { PASSKEY_GEN_FILE, passkeysModule } from "../../scripts/build.mjs";

/**
 * A browser with the three things the registration follows, and the scripts it holds.
 * @param {{ on?: boolean, permission?: boolean, server?: string | null, reportWorld?: boolean }} [o]
 */
function browserWith({ on = false, permission = false, server = null, reportWorld = true } = {}) {
  /** @type {Map<string, Record<string, unknown>>} */
  const held = new Map();
  /** @type {Record<string, unknown>} */
  const storage = { ...(on ? { [PASSKEY_SETTING_KEY]: true } : {}), ...(server ? { [SERVER_KEY]: server } : {}) };
  const calls = { registered: 0, unregistered: 0 };
  const state = { permission };
  return {
    held,
    storage,
    calls,
    state,
    scripting: {
      registerContentScripts: async (/** @type {Array<Record<string, unknown>>} */ scripts) => {
        calls.registered += 1;
        for (const s of scripts) {
          if (held.has(/** @type {string} */ (s.id))) throw new Error(`Content script with id "${s.id}" is already registered.`);
        }
        for (const s of scripts) {
          const copy = structuredClone(s);
          if (!reportWorld) delete copy.world;
          held.set(/** @type {string} */ (s.id), copy);
        }
      },
      unregisterContentScripts: async (/** @type {{ ids: string[] }} */ filter) => {
        calls.unregistered += 1;
        for (const id of filter.ids) if (!held.has(id)) throw new Error(`Nonexistent script ID '${id}'`);
        for (const id of filter.ids) held.delete(id);
      },
      getRegisteredContentScripts: async (/** @type {{ ids: string[] }} */ filter) => [...held.values()].filter((s) => filter.ids.includes(/** @type {string} */ (s.id))),
    },
    permissions: { contains: async (/** @type {{ origins: string[] }} */ wanted) => state.permission && wanted.origins.every((o) => o === "https://*/*") },
    storageLocal: {
      get: async (/** @type {string | string[]} */ keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((k) => k in storage).map((k) => [k, storage[k]])),
      set: async (/** @type {Record<string, unknown>} */ items) => void Object.assign(storage, items),
    },
  };
}

test("registration_follows_permission_setting_and_sign_in", async () => {
  // Every combination: registered exactly when all three hold.
  for (const on of [false, true]) {
    for (const permission of [false, true]) {
      for (const server of [null, "https://vault.example"]) {
        const b = browserWith({ on, permission, server });
        const registry = createPasskeyRegistry({ ...b, release: false });
        const status = await registry.reconcile();
        const want = on && permission && server !== null;
        assert.equal(status.registered, want, JSON.stringify({ on, permission, server }));
        assert.deepEqual([...b.held.keys()].sort(), want ? [...PASSKEY_SCRIPT_IDS].sort() : [], JSON.stringify({ on, permission, server }));
        // The setting goes off when the permission is gone (a later grant for saving passwords does not bring it back).
        if (on && !permission) assert.equal(b.storage[PASSKEY_SETTING_KEY], false);
      }
    }
  }

  const b = browserWith({ on: true, permission: true, server: "https://vault.example" });
  const registry = createPasskeyRegistry({ ...b, release: false });
  await registry.reconcile();
  // The definitions: the page's own world and the isolated world, every https page and frame, at document_start, kept across sessions.
  const main = /** @type {any} */ (b.held.get("ferret-passkey-main"));
  const bridge = /** @type {any} */ (b.held.get("ferret-passkey-bridge"));
  assert.equal(main.world, "MAIN");
  assert.equal(bridge.world, undefined, "the bridge runs in the isolated world");
  for (const s of [main, bridge]) {
    assert.deepEqual(s.matches, ["https://*/*"]);
    assert.equal(s.allFrames, true);
    assert.equal(s.runAt, "document_start");
    assert.equal(s.persistAcrossSessions, true);
  }
  assert.deepEqual(main.js, [PASSKEY_MAIN_FILE]);
  assert.deepEqual(bridge.js, [PASSKEY_BRIDGE_FILE]);
  // The same permission as saving passwords, no other.
  assert.deepEqual(main.matches, [...CAPTURE_ORIGINS]);
  // A second start with the current registration leaves it alone (no moment without the scripts).
  const before = { ...b.calls };
  await registry.reconcile();
  assert.deepEqual(b.calls, before);
  // A browser that does not report the world registers again (it cannot tell the registration is the current one).
  const quiet = browserWith({ on: true, permission: true, server: "https://vault.example", reportWorld: false });
  const quietRegistry = createPasskeyRegistry({ ...quiet, release: false });
  await quietRegistry.reconcile();
  await quietRegistry.reconcile();
  assert.equal(quiet.calls.registered, 2);

  // Sign-out: the scripts go, the setting stays.
  delete b.storage[SERVER_KEY];
  assert.equal(await registry.onStorageChanged({ [SERVER_KEY]: { oldValue: "https://vault.example" } }, "local"), true);
  assert.deepEqual([...b.held.keys()], []);
  assert.equal(b.storage[PASSKEY_SETTING_KEY], true);
  // Sign-in at another server: registered again, with that server left out.
  b.storage[SERVER_KEY] = "https://other.example:8443";
  await registry.onStorageChanged({ [SERVER_KEY]: { newValue: "https://other.example:8443" } }, "local");
  assert.deepEqual(/** @type {any} */ (b.held.get("ferret-passkey-main")).excludeMatches, ["https://other.example/*"]);
  // A change of another key or another area is not a reason.
  assert.equal(await registry.onStorageChanged({ lock_seconds: { newValue: 60 } }, "local"), false);
  assert.equal(await registry.onStorageChanged({ [SERVER_KEY]: {} }, "session"), false);
  // The setting off: the scripts go.
  b.storage[PASSKEY_SETTING_KEY] = false;
  await registry.onStorageChanged({ [PASSKEY_SETTING_KEY]: { newValue: false } }, "local");
  assert.deepEqual([...b.held.keys()], []);
  // enable checks the permission itself.
  b.state.permission = false;
  assert.deepEqual(await registry.enable(), { ok: false, reason: "permission_missing" });
  assert.deepEqual([...b.held.keys()], []);
  // The permission alone turns nothing on; with the setting on, its grant registers.
  b.state.permission = true;
  b.storage[PASSKEY_SETTING_KEY] = true;
  assert.equal(await registry.onPermissionAdded({ origins: ["https://*/*"] }), true);
  assert.equal(b.held.size, 2);
  assert.equal(await registry.onPermissionAdded({ origins: ["https://vault.example/*"] }), false);
  b.storage[PASSKEY_SETTING_KEY] = false;
  await registry.reconcile();
  assert.deepEqual(await registry.enable(), { ok: true });
  assert.equal(b.held.size, 2);
  // The permission taken back: the scripts and the setting go.
  b.state.permission = false;
  assert.equal(await registry.onPermissionRemoved({ origins: ["https://*/*"] }), true);
  assert.deepEqual([...b.held.keys()], []);
  assert.equal(b.storage[PASSKEY_SETTING_KEY], false);
  assert.equal(await registry.onPermissionRemoved({ origins: ["https://vault.example/*"] }), false);
  // disable: off, and the permission stays (saving passwords may use it).
  b.state.permission = true;
  await registry.enable();
  await registry.disable();
  assert.deepEqual([...b.held.keys()], []);
  assert.equal(b.state.permission, true);
  // A left-over registration of another shape (an older build) is replaced, not kept.
  const old = browserWith({ on: true, permission: true, server: "https://vault.example" });
  old.held.set("ferret-passkey-main", { id: "ferret-passkey-main", js: ["content/old.js"], matches: ["https://*/*"], world: "MAIN" });
  await createPasskeyRegistry({ ...old, release: false }).reconcile();
  assert.deepEqual(/** @type {any} */ (old.held.get("ferret-passkey-main")).js, [PASSKEY_MAIN_FILE]);
  // The session keeps the server under the key the registry reads.
  // (session.mjs needs the shared modules of the web vault, which only a build brings, so its source is read.)
  const session = readFileSync(new URL("../../src/background/session.mjs", import.meta.url), "utf8");
  assert.match(session, new RegExp(`export const SERVER_KEY = "${SERVER_KEY}";`));
});

test("the_override_is_off_on_ferret_servers_and_extension_pages", () => {
  // The signed-in server's host, every port of it (a match pattern has no port).
  assert.equal(serverPattern("https://vault.example"), "https://vault.example/*");
  assert.equal(serverPattern("https://vault.example:8443"), "https://vault.example/*");
  assert.equal(serverPattern("http://vault.example"), null);
  assert.equal(serverPattern("not a url"), null);
  const [main, bridge] = passkeyScripts({ server: "https://vault.example", release: false });
  for (const s of [main, bridge]) {
    assert.deepEqual(s.excludeMatches, ["https://vault.example/*"]);
    // Only web pages: nothing of the extension (moz-extension:), no http, no file.
    assert.deepEqual(s.matches, ["https://*/*"]);
  }
  // A release also leaves localhost to the browser; the test variant keeps https://localhost for its fixtures.
  const [released] = passkeyScripts({ server: "https://vault.example", release: true });
  assert.deepEqual(released.excludeMatches, ["https://localhost/*", "https://vault.example/*"]);
});

test("the_answer_goes_only_to_the_frame_and_document_that_asked", async () => {
  /** @type {Array<{ tabId: number, raw: string, options: unknown }>} */
  const pushed = [];
  const requests = createPasskeyRequests({ tabs: { sendMessage: async (tabId, raw, options) => void pushed.push({ tabId, raw: /** @type {string} */ (raw), options }) } });
  const sender = { tabId: 4, frameId: 17179869185, documentId: "doc-1", url: "https://rp.example/" };
  const id = "a".repeat(32);
  await requests.ops[PASSKEY_EVENT_OP].run(null, { type: "passkey_request", sender, body: { request_id: id } });
  assert.equal(pushed.length, 1);
  assert.deepEqual(pushed[0].options, { frameId: 17179869185, documentId: "doc-1" });
  assert.equal(pushed[0].tabId, 4);
  // Until the broker decides, the browser answers: a handover of the bridge's own id.
  assert.deepEqual(decode(pushed[0].raw, PUSH_TYPES).body, { request_id: id, once: false });
  // Without a document id there is no answer at all (it could reach another document of the frame).
  await requests.ops[PASSKEY_EVENT_OP].run(null, { type: "passkey_request", sender: { tabId: 4, frameId: 0, url: "https://rp.example/" }, body: { request_id: id } });
  assert.equal(pushed.length, 1);
  // Another provider in a tab is remembered for the tab, until it closes.
  await requests.ops[PASSKEY_EVENT_OP].run(null, { type: "passkey_foreign", sender, body: {} });
  assert.equal(requests.foreignIn(4), true);
  requests.onTabRemoved(4);
  assert.equal(requests.foreignIn(4), false);
  assert.equal(PASSKEY_EVENT_OP, PASSKEY_OP);
  assert.ok(CORE_OPS.includes(PASSKEY_EVENT_OP));
});

test("a_report_of_the_bridge_reaches_the_passkey_operation_with_the_browsers_sender_while_locked", async () => {
  /** @type {Array<{ op: string, args: any }>} */
  const calls = [];
  const runtime = { id: "ferret-test@hedgerow.tools", getURL: (/** @type {string} */ p) => `moz-extension://x/${p}` };
  // The handler of the package hands the body to `ctx.passkey` (its refusal with the feature off is features.test.mjs's); this
  // stand-in does the same, without the generated features module a unit test has no build for.
  const handler = { types: ["passkey_request", "passkey_abort", "passkey_foreign", "passkey_ping"], channel: /** @type {const} */ ("content"), handle: (/** @type {unknown} */ body, /** @type {any} */ ctx) => ctx.passkey(body) };
  const router = createRouter({
    runtime,
    lock: { checkOrLock: async (/** @type {string} */ type) => LOCK_EXEMPT.includes(type), touch: () => {}, setSeconds: async () => {}, getSeconds: async () => 900 },
    coreHost: { call: async (op, args) => void calls.push({ op, args }), lock: async () => {}, state: () => "locked" },
    handlers: [handler],
  });
  const sender = { id: runtime.id, tab: { id: 3 }, frameId: 0, url: "https://rp.example/login", origin: "https://rp.example", documentId: "d-1" };
  const id = "b".repeat(32);
  const body = { request_id: id, kind: "get", mediation: "optional", get: { challenge: "AAAA", allow_credentials: [], hints: [], extensions: {} }, activation: true, policy: null };
  await router.onMessage(encode("passkey_request", body), sender);
  await router.onMessage(encode("passkey_ping", { request_ids: [id] }), sender);
  assert.deepEqual(calls.map((c) => [c.op, c.args.type]), [[PASSKEY_OP, "passkey_request"], [PASSKEY_OP, "passkey_ping"]], "taken while the vault is locked");
  assert.deepEqual(calls[0].args.sender, { tabId: 3, frameId: 0, documentId: "d-1", url: "https://rp.example/login" });
  assert.equal(calls[0].args.body.request_id, id);
  // A page's message with a key the schema does not have (an origin, say) is refused before anything happens.
  await router.onMessage(JSON.stringify({ v: 1, id: "x1", type: "passkey_request", body: { ...body, origin: "https://bank.example" } }), sender);
  assert.equal(calls.length, 2);
  // Not from a content script of this extension: nothing.
  await router.onMessage(encode("passkey_abort", { request_id: id }), { ...sender, id: "other" });
  assert.equal(calls.length, 2);
});

test("the_background_reaches_the_feature_only_through_the_generated_module", () => {
  assert.equal(PASSKEY_GEN_FILE, "background/passkeys.gen.mjs");
  const on = passkeysModule(["passkeys", "save"], new Map());
  assert.match(on, /export \{ createPasskeyRegistry \} from "\.\/passkeyRegistry\.mjs";/);
  assert.match(on, /export \{ createPasskeyRequests \} from "\.\/passkeyRequests\.mjs";/);
  const off = passkeysModule(["save", "unlock"], new Map());
  assert.doesNotMatch(off, /import|from/);
  assert.match(off, /export const createPasskeyRegistry = null;/);
  assert.match(off, /export const createPasskeyRequests = null;/);
  assert.throws(() => passkeysModule([], new Map([[PASSKEY_GEN_FILE, Buffer.from("")]])), /generated by the build/);
});
