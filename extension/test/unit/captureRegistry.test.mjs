// The registration of the capture script (captureRegistry.mjs): registered
// exactly when the permission for https pages is granted and the setting is on,
// reconciled at every start, and gone when the permission is taken back.
import assert from "node:assert/strict";
import { test } from "node:test";
import { NEVER_KEY, SETTING_KEY, createCaptureRegistry, createNeverList, listedHost } from "../../src/background/captureRegistry.mjs";
import { CAPTURE_ORIGINS, CAPTURE_SCRIPT_FILE, CAPTURE_SCRIPT_ID, MAX_NEVER } from "../../src/shared/captureConfig.mjs";

/**
 * A browser's scripting, permissions and storage over memory.
 * @param {{ granted?: boolean, stored?: Record<string, unknown>, registered?: boolean, failRegister?: boolean }} [start]
 */
function browserWorld({ granted = false, stored = {}, registered = false, failRegister = false } = {}) {
  const state = { granted, registered, failRegister, calls: /** @type {string[]} */ ([]), definitions: /** @type {any[]} */ ([]) };
  /** @type {Record<string, unknown>} */
  const data = { ...stored };
  const scripting = {
    registerContentScripts: async (/** @type {any[]} */ scripts) => {
      state.calls.push("register");
      if (state.failRegister) throw new Error("no");
      if (state.registered) throw new Error("Duplicate script ID");
      state.registered = true;
      state.definitions.push(...scripts);
    },
    unregisterContentScripts: async () => {
      state.calls.push("unregister");
      state.registered = false;
    },
    // What the browser reports: the definition it was given, or (a registration left from before) just the id.
    getRegisteredContentScripts: async () => (state.registered ? [state.definitions.at(-1) ?? { id: CAPTURE_SCRIPT_ID }] : []),
  };
  const permissions = {
    contains: async (/** @type {{ origins: string[] }} */ wanted) => state.granted && wanted.origins.every((o) => CAPTURE_ORIGINS.includes(o)),
    remove: async (/** @type {{ origins: string[] }} */ gone) => {
      state.calls.push("permission remove");
      const had = state.granted;
      if (gone.origins.every((o) => CAPTURE_ORIGINS.includes(o))) state.granted = false;
      return had;
    },
  };
  const storageLocal = {
    get: async (/** @type {string} */ key) => (key in data ? { [key]: data[key] } : {}),
    set: async (/** @type {Record<string, unknown>} */ items) => void Object.assign(data, items),
  };
  /** @type {string[]} */
  const off = [];
  const registry = createCaptureRegistry({ scripting, permissions, storageLocal, onOff: (reason) => off.push(reason) });
  return { state, data, registry, off, scripting, permissions, storageLocal };
}

test("capture_is_off_by_default", async () => {
  const w = browserWorld();
  assert.deepEqual(await w.registry.reconcile(), { on: false, permission: false, registered: false });
  assert.equal(SETTING_KEY in w.data, false);
  assert.deepEqual(await w.registry.status(), { on: false, permission: false, registered: false });
  // Nothing was registered and no setting was written: a new install has no capture script anywhere.
  assert.equal(w.state.calls.includes("register"), false);
  // The permission alone, with the setting never turned on, registers nothing either.
  const granted = browserWorld({ granted: true });
  assert.deepEqual(await granted.registry.reconcile(), { on: false, permission: true, registered: false });
  assert.equal(granted.state.registered, false);
});

test("capture_registers_only_after_the_https_grant_and_unregisters_when_it_is_removed", async () => {
  const w = browserWorld();
  // Turning it on without the permission does nothing.
  assert.deepEqual(await w.registry.enable(), { ok: false, reason: "permission_missing" });
  assert.equal(w.state.registered, false);
  assert.equal(w.data[SETTING_KEY], undefined);
  // The page asked the browser and got it: the script is registered with the definition of the design.
  w.state.granted = true;
  assert.deepEqual(await w.registry.enable(), { ok: true });
  assert.equal(w.state.registered, true);
  assert.equal(w.data[SETTING_KEY], true);
  assert.deepEqual(w.state.definitions, [
    { id: CAPTURE_SCRIPT_ID, js: [CAPTURE_SCRIPT_FILE], matches: ["https://*/*"], allFrames: true, runAt: "document_idle", persistAcrossSessions: true },
  ]);
  assert.equal("matchOriginAsFallback" in w.state.definitions[0], false);
  assert.deepEqual(await w.registry.status(), { on: true, permission: true, registered: true });

  // The browser tells that the permission was taken back: the script goes and the setting goes off.
  w.state.granted = false;
  assert.equal(await w.registry.onRemoved({ origins: ["https://*/*"] }), true);
  assert.equal(w.state.registered, false);
  assert.equal(w.data[SETTING_KEY], false);
  assert.deepEqual(w.off, ["permission_removed"]);
  // Another permission leaves it alone.
  const other = browserWorld({ granted: true });
  await other.registry.enable();
  assert.equal(await other.registry.onRemoved({ origins: ["https://vault.example.net/*"] }), false);
  assert.equal(other.state.registered, true);
  assert.equal(await other.registry.onRemoved(undefined), false);

  // Turning it off takes the script away and says so.
  assert.deepEqual(await other.registry.disable(), { ok: true });
  assert.equal(other.state.registered, false);
  assert.equal(other.data[SETTING_KEY], false);
  assert.deepEqual(other.off, ["capture_off"]);
  // A script the browser cannot register leaves capture off.
  const broken = browserWorld({ granted: true, failRegister: true });
  assert.deepEqual(await broken.registry.enable(), { ok: false, reason: "register_failed" });
  assert.equal(broken.data[SETTING_KEY], undefined);
  assert.equal(broken.state.registered, false);
});

test("registration_permission_and_setting_are_reconciled_on_every_start", async () => {
  // setting, permission, registered: what is true after the start
  /** @type {Array<[boolean, boolean, boolean, { on: boolean, registered: boolean }]>} */
  const cases = [
    [false, false, false, { on: false, registered: false }],
    [false, false, true, { on: false, registered: false }],
    [false, true, false, { on: false, registered: false }],
    [false, true, true, { on: false, registered: false }],
    [true, false, false, { on: false, registered: false }],
    [true, false, true, { on: false, registered: false }],
    [true, true, false, { on: true, registered: true }],
    [true, true, true, { on: true, registered: true }],
  ];
  for (const [setting, permission, registered, expected] of cases) {
    const w = browserWorld({ granted: permission, registered, stored: setting ? { [SETTING_KEY]: true } : {} });
    const name = `setting ${setting}, permission ${permission}, registered ${registered}`;
    const outcome = await w.registry.reconcile();
    assert.equal(outcome.on, expected.on, name);
    assert.equal(outcome.registered, expected.registered, name);
    assert.equal(w.state.registered, expected.registered, name);
    // The setting goes off when the permission is gone, and is never turned on by a start.
    assert.equal(w.data[SETTING_KEY] === true, expected.on, name);
  }
  // A script left by an older version is replaced, so the definition is the current one.
  const old = browserWorld({ granted: true, registered: true, stored: { [SETTING_KEY]: true } });
  await old.registry.reconcile();
  assert.equal(old.state.definitions.length, 1);
  // A storage that cannot be read means off.
  const broken = browserWorld({ granted: true });
  broken.storageLocal.get = async () => {
    throw new Error("storage failed");
  };
  assert.equal((await broken.registry.reconcile()).on, false);
  assert.equal(broken.state.registered, false);
});

test("a_start_leaves_the_current_registration_alone_and_replaces_a_stale_one", async () => {
  const w = browserWorld({ granted: true });
  await w.registry.enable();
  assert.deepEqual(w.state.calls, ["register"]);
  // Every later start finds the current definition: nothing is taken away and put back.
  for (let start = 0; start < 3; start += 1) assert.deepEqual(await w.registry.reconcile(), { on: true, permission: true, registered: true });
  assert.deepEqual(w.state.calls, ["register"], "three starts, no unregister and no register");
  // The browser may report the file without the slash in front: still the current definition.
  const held = w.state.definitions.at(-1);
  w.state.definitions[w.state.definitions.length - 1] = { ...held, js: [CAPTURE_SCRIPT_FILE.replace(/^\//, "")] };
  await w.registry.reconcile();
  assert.deepEqual(w.state.calls, ["register"], "a leading slash is the same file");
  // Defaults a browser may report are the same registration.
  for (const same of [{ world: "ISOLATED" }, { excludeMatches: [] }, { matchOriginAsFallback: false }]) {
    const v = browserWorld({ granted: true });
    await v.registry.enable();
    v.state.definitions[v.state.definitions.length - 1] = { ...v.state.definitions.at(-1), ...same };
    v.state.calls.length = 0;
    await v.registry.reconcile();
    assert.deepEqual(v.state.calls, [], `kept: ${JSON.stringify(same)}`);
  }
  // A registration of an earlier version (another file, no frames, another run time, not kept across sessions) is replaced.
  for (const stale of [{ js: ["content/old.js"] }, { allFrames: false }, { runAt: "document_start" }, { persistAcrossSessions: false }, { matches: ["https://example.net/*"] }, { excludeMatches: ["https://vault.example.net/*"] }, { matchOriginAsFallback: true }, { world: "MAIN" }, { css: ["x.css"] }, {}]) {
    const v = browserWorld({ granted: true });
    await v.registry.enable();
    v.state.definitions[v.state.definitions.length - 1] = Object.keys(stale).length === 0 ? { id: CAPTURE_SCRIPT_ID } : { ...v.state.definitions.at(-1), ...stale };
    v.state.calls.length = 0;
    await v.registry.reconcile();
    assert.deepEqual(v.state.calls, ["unregister", "register"], `replaced: ${JSON.stringify(stale)}`);
    assert.deepEqual(v.state.definitions.at(-1)?.js, [CAPTURE_SCRIPT_FILE], `the current definition again: ${JSON.stringify(stale)}`);
  }
});

test("the_never_list_keeps_a_label_at_most_500_hosts_and_reads_only_hosts", async () => {
  assert.equal(listedHost(" Login.Example.NET. "), "login.example.net");
  for (const bad of ["", "a b", "http://x.example", "x.example/path", "x@example", 5, null, undefined, "a".repeat(254)]) assert.equal(listedHost(bad), null, String(bad));
  /** @type {Record<string, unknown>} */
  const data = { [NEVER_KEY]: ["b.example.net", "garbage value", 7, "a.example.net", "b.example.net"] };
  const writes = /** @type {Array<Record<string, unknown>>} */ ([]);
  const list = createNeverList({
    storageLocal: { get: async (key) => ({ [key]: data[key] }), set: async (items) => void writes.push(items) },
  });
  assert.deepEqual(await list.list(), ["a.example.net", "b.example.net"]);
  await list.remove("a.example.net");
  assert.deepEqual(writes.at(-1), { [NEVER_KEY]: ["b.example.net"] });
  for (let i = 0; i < MAX_NEVER + 20; i += 1) await list.add(`h${i}.example.net`);
  assert.equal((await list.list()).length, MAX_NEVER);
  assert.equal(await list.has(`h${MAX_NEVER + 19}.example.net`), true);
  assert.equal(await list.has("h0.example.net"), false, "the newest win");
  // A storage that fails still keeps the choice for this session.
  const failing = createNeverList({ storageLocal: { get: async () => Promise.reject(new Error("x")), set: async () => Promise.reject(new Error("x")) } });
  await failing.add("x.example.net");
  assert.equal(await failing.has("x.example.net"), true);
});

test("a_grant_that_lands_after_the_popup_closed_turns_capture_on_and_a_second_enable_registers_nothing_twice", async () => {
  const w = browserWorld();
  // A grant nobody marked (the passkeys' switch, the browser's add-on page) switches nothing on: the permission is shared.
  w.state.granted = true;
  assert.equal(await w.registry.onAdded({ origins: ["https://*/*"] }), false);
  assert.equal(w.state.registered, false);
  assert.equal(SETTING_KEY in w.data, false);
  // Firefox closed the popup that asked; the user said yes in the prompt: the switch marked its grant, the browser tells the
  // background, which finishes it (once: the mark is used up).
  await w.registry.markPending();
  assert.equal(await w.registry.onAdded({ origins: ["https://*/*"] }), true);
  assert.equal(await w.registry.onAdded({ origins: ["https://*/*"] }), false, "the mark was used");
  assert.equal(w.state.registered, true);
  assert.equal(w.data[SETTING_KEY], true);
  assert.deepEqual(await w.registry.status(), { on: true, permission: true, registered: true });
  // The popup that is still open (no prompt, or a browser that does not close it) sends its own enable: the script is not registered again.
  w.state.calls.length = 0;
  assert.deepEqual(await w.registry.enable(), { ok: true });
  assert.equal(w.state.calls.includes("register"), false, "a script that is registered with the current definition is left alone");
  assert.equal(w.state.calls.includes("unregister"), false);
  assert.equal(w.state.definitions.length, 1);
  // The same two in the other order.
  const other = browserWorld({ granted: true });
  await other.registry.markPending();
  assert.deepEqual(await other.registry.enable(), { ok: true });
  other.state.calls.length = 0;
  assert.equal(await other.registry.onAdded({ origins: ["https://*/*"] }), false, "the page's own enable finished it and used the mark");
  assert.deepEqual(other.state.calls, []);
  assert.equal(other.state.definitions.length, 1);
  // Another grant (the origin of a server or a frame), none at all, or a grant the browser does not hold now: nothing is switched on.
  for (const added of [{ origins: ["https://vault.example.test/*"] }, { origins: [] }, {}, undefined]) {
    const none = browserWorld({ granted: true });
    await none.registry.markPending();
    assert.equal(await none.registry.onAdded(/** @type {any} */ (added)), false);
    assert.equal(none.state.registered, false);
    assert.equal(SETTING_KEY in none.data, false);
  }
  const gone = browserWorld({ granted: false });
  await gone.registry.markPending();
  assert.equal(await gone.registry.onAdded({ origins: ["https://*/*"] }), false, "the permission is checked, not believed");
  assert.equal(gone.state.registered, false);
});

test("turning_it_off_takes_the_permission_back_in_the_background_and_a_start_never_does", async () => {
  const w = browserWorld({ granted: true });
  assert.deepEqual(await w.registry.enable(), { ok: true });
  w.state.calls.length = 0;
  // No page is involved: the background switches capture off and removes the access itself.
  assert.deepEqual(await w.registry.disable(), { ok: true });
  assert.equal(w.state.registered, false);
  assert.equal(w.data[SETTING_KEY], false);
  assert.equal(w.state.granted, false);
  assert.deepEqual(w.state.calls.filter((c) => c !== "unregister"), ["permission remove"]);
  assert.deepEqual(w.off, ["capture_off"]);
  // The browser's own news of the removal finds nothing left to switch off.
  assert.equal(await w.registry.onRemoved({ origins: ["https://*/*"] }), true);
  assert.deepEqual(w.off, ["capture_off"]);
  // A permission that cannot be removed does not make "off" fail.
  const stuck = browserWorld({ granted: true });
  await stuck.registry.enable();
  stuck.permissions.remove = async () => {
    throw new Error("no");
  };
  assert.deepEqual(await stuck.registry.disable(), { ok: true });
  assert.equal(stuck.data[SETTING_KEY], false);
  // A start (reconcile) with the permission there and the setting off leaves the grant alone, and registers nothing.
  const start = browserWorld({ granted: true });
  assert.deepEqual(await start.registry.reconcile(), { on: false, permission: true, registered: false });
  assert.equal(start.state.granted, true);
  assert.equal(start.state.calls.includes("permission remove"), false);
});
