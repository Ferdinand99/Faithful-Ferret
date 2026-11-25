// The one permission for https pages, shared by saving passwords and the passkeys (background/httpsAccess.mjs, design document § 9.2
// and § 10.9): a grant never switches a feature on by itself, and turning one feature off takes the permission back only when the
// other does not need it.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createCaptureRegistry } from "../../src/background/captureRegistry.mjs";
import { createHttpsAccess, HTTPS_ORIGINS, HTTPS_USERS, PENDING_KEY, PENDING_MS } from "../../src/background/httpsAccess.mjs";
import { createPasskeyRegistry, PASSKEY_ORIGINS, PASSKEY_SETTING_KEY, SERVER_KEY } from "../../src/background/passkeyRegistry.mjs";
import { CAPTURE_ORIGINS } from "../../src/shared/captureConfig.mjs";

const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

/**
 * A browser with the permission, the storage and the scripts, and the two registries made over it as the background makes them:
 * one shared `access`, each registry listening for the permission events.
 * @param {{ features?: Record<string, boolean>, signedIn?: boolean }} [o]
 */
function world({ features = { save: true, passkeys: true }, signedIn = true } = {}) {
  /** @type {Record<string, unknown>} */
  const storage = signedIn ? { [SERVER_KEY]: "https://vault.example" } : {};
  const state = { granted: false, now: 10_000_000, removes: 0, requests: 0 };
  /** @type {Map<string, any>} */
  const held = new Map();
  const storageLocal = {
    get: async (/** @type {string | string[]} */ keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((k) => k in storage).map((k) => [k, structuredClone(storage[k])])),
    set: async (/** @type {Record<string, unknown>} */ items) => void Object.assign(storage, structuredClone(items)),
  };
  /** @type {Array<(added: any) => void>} */
  const onAdded = [];
  /** @type {Array<(removed: any) => void>} */
  const onRemoved = [];
  const permissions = {
    contains: async (/** @type {{ origins: string[] }} */ w) => state.granted && w.origins.every((o) => o === "https://*/*"),
    // The page's own call: the browser tells the listeners only when something was added.
    request: async (/** @type {{ origins: string[] }} */ w) => {
      state.requests += 1;
      if (!state.granted) {
        state.granted = true;
        for (const fn of onAdded) fn({ origins: w.origins });
      }
      return true;
    },
    remove: async (/** @type {{ origins: string[] }} */ w) => {
      state.removes += 1;
      if (!state.granted) return false;
      state.granted = false;
      for (const fn of onRemoved) fn({ origins: w.origins });
      return true;
    },
  };
  const scripting = {
    registerContentScripts: async (/** @type {any[]} */ list) => void list.forEach((s) => held.set(s.id, structuredClone(s))),
    unregisterContentScripts: async (/** @type {{ ids: string[] }} */ f) => void f.ids.forEach((id) => held.delete(id)),
    getRegisteredContentScripts: async (/** @type {{ ids: string[] }} */ f) => [...held.values()].filter((s) => f.ids.includes(s.id)),
  };
  const access = createHttpsAccess({ permissions, storageLocal, now: () => state.now, features });
  const capture = createCaptureRegistry({ scripting, permissions, storageLocal, access });
  const passkeys = createPasskeyRegistry({ scripting, permissions, storageLocal, release: false, access });
  // As main.mjs and captureHost.mjs wire them: both registries hear every event of the permission.
  onAdded.push((added) => void capture.onAdded(added), (added) => void passkeys.onPermissionAdded(added));
  onRemoved.push((removed) => void capture.onRemoved(removed), (removed) => void passkeys.onPermissionRemoved(removed));
  const settle = async () => {
    for (let i = 0; i < 12; i += 1) await new Promise((r) => setImmediate(r));
  };
  /**
   * What a feature's switch does in its click: mark, ask the browser, then (the page's second step) `enable`.
   * @param {"capture" | "passkeys"} which @param {{ pageSurvives?: boolean }} [o] `pageSurvives` false: the prompt closed the page that asked
   */
  const turnOn = async (which, { pageSurvives = true } = {}) => {
    const registry = which === "capture" ? capture : passkeys;
    await registry.markPending();
    await permissions.request({ origins: [...HTTPS_ORIGINS] });
    await settle();
    if (pageSurvives) return registry.enable();
    return null;
  };
  return { storage, state, held, access, capture, passkeys, permissions, turnOn, settle, onAdded, onRemoved };
}

const captureOn = (/** @type {ReturnType<typeof world>} */ w) => w.storage.offer_to_save === true;
const passkeysOn = (/** @type {ReturnType<typeof world>} */ w) => w.storage[PASSKEY_SETTING_KEY] === true;

test("the_https_permission_is_shared_and_never_switches_the_other_feature", async () => {
  // Both features ask for the same pattern, and there is one.
  assert.deepEqual([...CAPTURE_ORIGINS], [...PASSKEY_ORIGINS]);
  assert.deepEqual([...HTTPS_ORIGINS], [...CAPTURE_ORIGINS]);

  // 1. Passkeys on: the permission is granted, and saving passwords stays off (no capture script in any page).
  const w = world();
  assert.deepEqual(await w.turnOn("passkeys"), { ok: true });
  assert.equal(passkeysOn(w), true);
  assert.equal(captureOn(w), false, "saving passwords was not switched on by the grant");
  assert.equal(w.held.has("ferret-capture"), false, "no capture script");
  assert.equal(w.held.has("ferret-passkey-main"), true);
  assert.equal((await w.capture.status()).on, false);

  // 2. Saving passwords on as well: the permission is there already, nothing more is asked of the browser's prompt.
  assert.deepEqual(await w.turnOn("capture"), { ok: true });
  assert.equal(captureOn(w), true);
  assert.equal(passkeysOn(w), true);

  // 3. Saving passwords off: the permission stays (the passkeys need it), and the passkeys stay on.
  await w.capture.disable();
  await w.settle();
  assert.equal(captureOn(w), false);
  assert.equal(w.state.granted, true, "the permission is kept while the passkeys are on");
  assert.equal(w.state.removes, 0);
  assert.equal(passkeysOn(w), true);
  assert.equal(w.held.has("ferret-passkey-main"), true, "the passkey scripts are still registered");
  assert.equal(w.held.has("ferret-capture"), false);

  // 4. Saving passwords on again, then the passkeys off: the permission stays for saving passwords.
  await w.turnOn("capture");
  await w.passkeys.disable();
  await w.settle();
  assert.equal(passkeysOn(w), false);
  assert.equal(captureOn(w), true);
  assert.equal(w.state.granted, true, "the permission is kept while saving passwords is on");
  assert.equal(w.held.has("ferret-passkey-main"), false);
  assert.equal(w.held.has("ferret-capture"), true);

  // 5. The last one off takes the permission back.
  await w.capture.disable();
  await w.settle();
  assert.equal(w.state.granted, false);
  assert.equal(captureOn(w), false);
  assert.equal(passkeysOn(w), false);

  // 6. A revoke from outside (the browser's add-on page) turns both off.
  await w.turnOn("capture");
  await w.turnOn("passkeys");
  assert.equal(captureOn(w) && passkeysOn(w), true);
  await w.permissions.remove({ origins: [...HTTPS_ORIGINS] });
  await w.settle();
  assert.equal(captureOn(w), false);
  assert.equal(passkeysOn(w), false);
  assert.equal(w.held.size, 0, "no script is registered");
});

test("a_grant_nobody_marked_switches_nothing_on_and_a_marked_one_is_finished_when_the_page_is_gone", async () => {
  // A grant from anywhere else (the browser's add-on page, the other feature's switch, a test): neither feature turns on.
  const w = world();
  await w.permissions.request({ origins: [...HTTPS_ORIGINS] });
  await w.settle();
  assert.equal(captureOn(w), false);
  assert.equal(passkeysOn(w), false);
  assert.equal(w.held.size, 0);
  assert.equal(await w.capture.onAdded({ origins: [...HTTPS_ORIGINS] }), false);
  assert.equal(await w.passkeys.onPermissionAdded({ origins: [...HTTPS_ORIGINS] }), true, "the registry looked at its setting, and changed nothing");
  assert.equal(passkeysOn(w), false);

  // The switch marked the grant and the prompt closed the page (Firefox closes a popup when the prompt opens): the grant finishes it.
  const a = world();
  await a.turnOn("passkeys", { pageSurvives: false });
  assert.equal(passkeysOn(a), true, "the passkeys finished their own turn-on");
  assert.equal(captureOn(a), false, "and only theirs");
  assert.equal(a.held.has("ferret-passkey-main"), true);
  const b = world();
  await b.turnOn("capture", { pageSurvives: false });
  assert.equal(captureOn(b), true);
  assert.equal(passkeysOn(b), false);

  // The mark is the feature's own: a mark of the passkeys does not let saving passwords finish a grant.
  const c = world();
  await c.passkeys.markPending();
  await c.permissions.request({ origins: [...HTTPS_ORIGINS] });
  await c.settle();
  assert.equal(passkeysOn(c), true);
  assert.equal(captureOn(c), false);

  // The latest click wins: a mark of the passkeys that was never cleared (the popup closed under the prompt that was refused) does not
  // let a later grant for saving passwords switch the passkeys on too.
  const e = world();
  await e.passkeys.markPending();
  await e.capture.markPending();
  await e.permissions.request({ origins: [...HTTPS_ORIGINS] });
  await e.settle();
  assert.equal(captureOn(e), true);
  assert.equal(passkeysOn(e), false, "the older mark was dropped by the newer one");
  const f = world();
  await f.capture.markPending();
  await f.passkeys.markPending();
  await f.permissions.request({ origins: [...HTTPS_ORIGINS] });
  await f.settle();
  assert.equal(passkeysOn(f), true);
  assert.equal(captureOn(f), false);

  // A refused prompt: the page clears its mark, so a later grant from elsewhere finishes nothing.
  const d = world();
  await d.capture.markPending();
  await d.capture.clearPending();
  await d.permissions.request({ origins: [...HTTPS_ORIGINS] });
  await d.settle();
  assert.equal(captureOn(d), false);
});

test("the_mark_is_used_once_ends_after_two_minutes_and_belongs_to_one_feature", async () => {
  const w = world();
  assert.equal(PENDING_MS, 120_000);
  assert.equal(await w.access.takePending("passkeys"), false, "nothing marked");
  await w.access.markPending("passkeys");
  assert.equal(await w.access.takePending("save"), false, "another feature's mark");
  assert.equal(await w.access.takePending("passkeys"), true);
  assert.equal(await w.access.takePending("passkeys"), false, "used once");
  await w.access.markPending("save");
  await w.access.markPending("passkeys");
  w.state.now += PENDING_MS;
  assert.equal(await w.access.takePending("save"), false, "ended");
  assert.equal(await w.access.takePending("passkeys"), false);
  // A mark that is longer than its time (a clock that moved back) is not one; a name that is no feature is refused.
  w.storage[PENDING_KEY] = { save: w.state.now + 10 * PENDING_MS, other: w.state.now + 5 };
  assert.equal(await w.access.takePending("save"), false);
  assert.equal(await w.access.markPending("other"), false);
  assert.equal(await w.access.takePending("other"), false);
  assert.deepEqual(Object.keys(HTTPS_USERS).sort(), ["passkeys", "save"]);
});

test("a_feature_that_the_build_lacks_does_not_keep_the_permission", async () => {
  // A build without the passkeys: a left-over "on" in storage does not keep the permission when saving passwords goes off.
  const w = world({ features: { save: true, passkeys: false } });
  w.storage[PASSKEY_SETTING_KEY] = true;
  await w.turnOn("capture");
  assert.equal(await w.access.neededBesides("save"), false);
  await w.capture.disable();
  await w.settle();
  assert.equal(w.state.granted, false);
  // And when the storage cannot be read, the permission is kept (the person can take it back in the browser).
  const x = world();
  await x.turnOn("capture");
  const failing = createHttpsAccess({
    permissions: x.permissions,
    storageLocal: { get: async () => Promise.reject(new Error("no")), set: async () => {} },
    now: () => x.state.now,
  });
  assert.deepEqual(await failing.release("save"), { removed: false });
  assert.equal(x.state.granted, true);
  // A permissions API without `remove` leaves it alone.
  const bare = createHttpsAccess({ permissions: {}, storageLocal: x.permissions ? { get: async () => ({}), set: async () => {} } : /** @type {any} */ (null) });
  assert.deepEqual(await bare.release("save"), { removed: true });
});

test("no_page_removes_the_permission_and_only_the_registries_write_their_settings", () => {
  // The page never takes the permission back itself (it is shared): nothing under pages/ calls permissions.remove.
  /** @param {string} dir @returns {string[]} */
  const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
  const files = walk(src).filter((f) => /\.mjs$/.test(f));
  const rel = (/** @type {string} */ f) => f.slice(src.length + 1).replace(/\\/g, "/");
  const removers = files.filter((f) => /permissions\.remove\b/.test(readFileSync(f, "utf8"))).map(rel).sort();
  assert.deepEqual(removers.filter((p) => p.startsWith("pages/")), [], "no page removes a permission");
  assert.deepEqual(removers, ["background/httpsAccess.mjs", "background/main.mjs", "background/sync.mjs"], "the feature registries never remove it themselves: httpsAccess does, once it knows nobody else needs it");
  // Only the passkey registry writes the setting "use_passkeys" (the settings go through `enable` and `disable`).
  const writers = files.filter((f) => /\[PASSKEY_SETTING_KEY\]\s*:|\buse_passkeys\s*:/.test(readFileSync(f, "utf8"))).map(rel).sort();
  assert.deepEqual(writers, ["background/passkeyRegistry.mjs"]);
});
