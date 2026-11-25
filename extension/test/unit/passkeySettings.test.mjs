// The settings of the passkey provider (background/passkeySettings.mjs and its handler): the switch (through the registry), the
// "never" list per site, the recent-unlock choice (design document § 9.3 and § 9.4).
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHttpsAccess } from "../../src/background/httpsAccess.mjs";
import { PASSKEY_NEVER_KEY, createPasskeyNever } from "../../src/background/passkeyNever.mjs";
import { createPasskeyRegistry, PASSKEY_RECENT_UNLOCK_KEY, PASSKEY_SETTING_KEY, SERVER_KEY } from "../../src/background/passkeyRegistry.mjs";
import { createPasskeySettings, PASSKEY_SETTINGS_OP, recentUnlockOn } from "../../src/background/passkeySettings.mjs";
import { MAX_NEVER } from "../../src/shared/captureConfig.mjs";
import { decode, encode, UI_TYPES } from "../../src/shared/protocol.mjs";

/** @param {{ signedIn?: boolean, permission?: boolean, never?: string[] }} [o] */
function world({ signedIn = true, permission = true, never = [] } = {}) {
  /** @type {Record<string, unknown>} */
  const storage = { ...(signedIn ? { [SERVER_KEY]: "https://vault.example" } : {}), ...(never.length > 0 ? { [PASSKEY_NEVER_KEY]: never } : {}) };
  const state = { permission, removes: 0 };
  /** @type {Map<string, any>} */
  const held = new Map();
  const storageLocal = {
    get: async (/** @type {string | string[]} */ keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((k) => k in storage).map((k) => [k, structuredClone(storage[k])])),
    set: async (/** @type {Record<string, unknown>} */ items) => void Object.assign(storage, structuredClone(items)),
  };
  const permissions = {
    contains: async () => state.permission,
    remove: async () => {
      state.removes += 1;
      state.permission = false;
      return true;
    },
  };
  const scripting = {
    registerContentScripts: async (/** @type {any[]} */ list) => void list.forEach((s) => held.set(s.id, structuredClone(s))),
    unregisterContentScripts: async (/** @type {{ ids: string[] }} */ f) => void f.ids.forEach((id) => held.delete(id)),
    getRegisteredContentScripts: async (/** @type {{ ids: string[] }} */ f) => [...held.values()].filter((s) => f.ids.includes(s.id)),
  };
  const access = createHttpsAccess({ permissions, storageLocal, features: { save: true, passkeys: true } });
  const registry = createPasskeyRegistry({ scripting, permissions, storageLocal, release: false, access });
  const never_ = createPasskeyNever({ storageLocal });
  const settings = createPasskeySettings({ registry, never: never_, storageLocal });
  return { storage, state, held, registry, never: never_, settings, ask: (/** @type {Record<string, unknown>} */ body = {}) => /** @type {Promise<any>} */ (settings.run(body)) };
}

test("the_never_list_is_per_host_editable_and_capped_at_500", async () => {
  const w = world({ never: ["bank.example", "shop.example"] });
  // It lists the RP IDs, sorted, as the core keeps them.
  assert.deepEqual((await w.ask()).never, ["bank.example", "shop.example"]);
  // One site is taken off; the others stay.
  assert.deepEqual((await w.ask({ never_remove: "bank.example" })).never, ["shop.example"]);
  assert.deepEqual(w.storage[PASSKEY_NEVER_KEY], ["shop.example"]);
  // A site that is not on the list changes nothing; a text that is no host is not a site.
  assert.deepEqual((await w.ask({ never_remove: "other.example" })).never, ["shop.example"]);
  assert.deepEqual((await w.ask({ never_remove: "not a host!" })).never, ["shop.example"]);
  // The window adds (the settings never do); a private window's choice is in memory only, and the list shows it all the same.
  await w.never.add("a.example");
  await w.never.add("priv.example", { incognito: true });
  assert.deepEqual((await w.ask()).never, ["a.example", "priv.example", "shop.example"]);
  assert.deepEqual(w.storage[PASSKEY_NEVER_KEY], ["shop.example", "a.example"], "the private one never reached the disk");
  // Remove all empties it, the private choice too.
  assert.deepEqual((await w.ask({ never_clear: true })).never, []);
  assert.deepEqual(w.storage[PASSKEY_NEVER_KEY], []);
  // At most 500: the newest wins, the oldest goes.
  assert.equal(MAX_NEVER, 500);
  for (let i = 0; i < 503; i += 1) await w.never.add(`site${i}.example`);
  const list = (await w.ask()).never;
  assert.equal(list.length, 500);
  assert.equal(list.includes("site0.example"), false);
  assert.equal(list.includes("site2.example"), false);
  assert.equal(list.includes("site3.example"), true);
  assert.equal(list.includes("site502.example"), true);
  assert.equal(/** @type {string[]} */ (w.storage[PASSKEY_NEVER_KEY]).length, 500);
  // A page of another list is not read into this one: the list is the feature's own key.
  assert.equal(PASSKEY_NEVER_KEY, "passkey_never");
});

test("turning_ferret_off_unregisters_the_scripts", async () => {
  const w = world();
  const on = await w.ask({ enable: true });
  assert.equal(on.ok, true);
  assert.equal(on.on, true);
  assert.deepEqual([...w.held.keys()].sort(), ["ferret-passkey-bridge", "ferret-passkey-main"], "turning it on registers both scripts");
  assert.equal(w.storage[PASSKEY_SETTING_KEY], true);
  // Off: the setting, the scripts and (nothing else needs it) the permission go.
  const off = await w.ask({ enable: false });
  assert.equal(off.ok, true);
  assert.equal(off.on, false);
  assert.deepEqual([...w.held.keys()], []);
  assert.equal(w.storage[PASSKEY_SETTING_KEY], false);
  assert.equal(w.state.permission, false);
  // What stays: the person's own choices (the list and the recent-unlock choice); a later turn-on finds them again.
  await w.never.add("keep.example");
  await w.ask({ recent_unlock: false });
  await w.ask({ enable: false });
  assert.deepEqual((await w.ask()).never, ["keep.example"]);
  assert.equal((await w.ask()).recent_unlock, false);
  // Turning on without the permission does nothing and says so; with the permission it works.
  assert.deepEqual({ ...(await w.ask({ enable: true })), never: undefined, recent_unlock: undefined }, { ok: false, reason: "permission_missing", on: false, permission: false, signed_in: true, never: undefined, recent_unlock: undefined });
  assert.deepEqual([...w.held.keys()], []);
  w.state.permission = true;
  assert.equal((await w.ask({ enable: true })).ok, true);
  assert.equal(w.held.size, 2);
  // Signed out: the setting is on, the scripts wait for the sign-in, and the page is told.
  const out = world({ signedIn: false });
  const state = await out.ask({ enable: true });
  assert.equal(state.on, true);
  assert.equal(state.signed_in, false);
  assert.equal(out.held.size, 0);
});

test("the_recent_unlock_setting_is_on_by_default_and_can_be_turned_off", async () => {
  const w = world();
  assert.equal(await recentUnlockOn(w.storage ? { get: async (/** @type {string} */ k) => (k in w.storage ? { [k]: w.storage[k] } : {}) } : /** @type {any} */ (null)), true, "nothing stored: on");
  assert.equal((await w.ask()).recent_unlock, true);
  assert.equal((await w.ask({ recent_unlock: false })).recent_unlock, false);
  assert.equal(w.storage[PASSKEY_RECENT_UNLOCK_KEY], false);
  assert.equal(await recentUnlockOn({ get: async () => ({ [PASSKEY_RECENT_UNLOCK_KEY]: false }) }), false);
  assert.equal((await w.ask({ recent_unlock: true })).recent_unlock, true);
  // Only `false` turns it off; anything else that is stored (a damaged value) leaves the default.
  assert.equal(await recentUnlockOn({ get: async () => ({ [PASSKEY_RECENT_UNLOCK_KEY]: "no" }) }), true);
  // A read that fails does not give the five minutes (the person may have turned them off).
  assert.equal(await recentUnlockOn({ get: async () => Promise.reject(new Error("no")) }), false);
  assert.equal(PASSKEY_RECENT_UNLOCK_KEY, "passkey_recent_unlock");
  // Turning the feature off does not touch the choice.
  await w.ask({ recent_unlock: false });
  await w.ask({ enable: false });
  assert.equal((await w.ask()).recent_unlock, false);
});

test("the_switch_marks_its_grant_and_the_settings_reply_says_what_is_true", async () => {
  // The page marks before it asks the browser; the grant that follows (the page may be gone by then) is finished by the registry.
  const w = world({ permission: false });
  assert.equal((await w.ask({ pending: true })).on, false, "a mark turns nothing on");
  w.state.permission = true;
  assert.equal(await w.registry.onPermissionAdded({ origins: ["https://*/*"] }), true);
  assert.equal(w.storage[PASSKEY_SETTING_KEY], true);
  assert.equal(w.held.size, 2);
  // A page that was refused clears its mark: a later grant from elsewhere turns nothing on.
  const x = world({ permission: false });
  await x.ask({ pending: true });
  await x.ask({ pending: false });
  x.state.permission = true;
  await x.registry.onPermissionAdded({ origins: ["https://*/*"] });
  assert.notEqual(x.storage[PASSKEY_SETTING_KEY], true);
  assert.equal(x.held.size, 0);
  // The reply has exactly the fields the page reads, and the page's request is checked against the protocol.
  const reply = await w.ask();
  assert.deepEqual(Object.keys(reply).sort(), ["never", "ok", "on", "permission", "recent_unlock", "signed_in"]);
  for (const body of [{}, { enable: true }, { pending: false }, { never_remove: "a.example" }, { never_clear: true }, { recent_unlock: false }]) {
    assert.doesNotThrow(() => encode("passkey_settings", body), JSON.stringify(body));
  }
  assert.throws(() => encode("passkey_settings", { enable: "yes" }));
  assert.throws(() => encode("passkey_settings", { never_remove: "" }));
  assert.doesNotThrow(() => encode("passkey_settings", reply, { reply: true }));
  assert.deepEqual(decode(encode("passkey_settings", { enable: true }), UI_TYPES).body, { enable: true });
  assert.equal(PASSKEY_SETTINGS_OP, "passkey_settings");
});

test("a_build_without_the_feature_removes_the_switch_and_keeps_the_persons_choices", async () => {
  const { removePasskeyScripts, PASSKEY_SWITCH_KEY } = await import("../../src/background/passkeyCleanup.mjs");
  assert.equal(PASSKEY_SWITCH_KEY, PASSKEY_SETTING_KEY, "the cleanup names the same key as the registry");
  /** @type {Record<string, unknown>} */
  const storage = { [PASSKEY_SETTING_KEY]: true, [PASSKEY_NEVER_KEY]: ["keep.example"], [PASSKEY_RECENT_UNLOCK_KEY]: false, offer_to_save: true };
  const storageLocal = { remove: async (/** @type {string} */ key) => void delete storage[key] };
  const scripting = { getRegisteredContentScripts: async () => [], unregisterContentScripts: async () => {} };
  assert.equal(await removePasskeyScripts(scripting, storageLocal), true);
  assert.equal(PASSKEY_SETTING_KEY in storage, false, "the switch is gone, so a later build does not start by itself");
  assert.deepEqual(storage[PASSKEY_NEVER_KEY], ["keep.example"]);
  assert.equal(storage[PASSKEY_RECENT_UNLOCK_KEY], false);
  assert.equal(storage.offer_to_save, true, "another feature's setting is not touched");
  // It never throws, whatever the storage does, and still removes the scripts.
  assert.equal(await removePasskeyScripts(scripting, { remove: async () => Promise.reject(new Error("no")) }), true);
  assert.equal(await removePasskeyScripts(scripting, /** @type {any} */ ({ remove: () => { throw new Error("no"); } })), true);
  assert.equal(await removePasskeyScripts(scripting), true, "the old call with scripts only still works");
});
