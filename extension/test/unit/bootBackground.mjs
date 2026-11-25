// Loads the built background page of a package against a fake `browser`, as the browser would: for the tests that
// check what a package does when its entry runs (arch.test.mjs, features.test.mjs).
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createFakeBrowser } from "./fakeBrowser.mjs";

/**
 * Loads the built `main.mjs` of a package against a fake `browser` and returns
 * what it registered.
 *
 * @param {string} dir the unpacked package
 * @param {{ scripting?: any }} [overrides] parts of the fake `browser` that a test replaces (`scripting`, to see what the
 *   background registers or removes at start)
 */
export async function boot(dir, overrides = {}) {
  const fake = createFakeBrowser();
  /** @type {Array<(port: any) => void>} */
  const onConnect = [];
  /** @type {Array<(message: unknown, sender: unknown) => unknown>} */
  const onMessage = [];
  const counts = { alarm: 0, idle: 0, command: 0, menuClick: 0 };
  /** @type {any[]} */
  const menuItems = [];
  /** @type {Map<string, unknown>} */
  const session = new Map([["lock_at", Date.now() + 600_000]]);
  /** @type {any} */ (globalThis).browser = {
    action: { openPopup: async () => {} },
    commands: { onCommand: { addListener: () => { counts.command += 1; } } },
    menus: {
      create: (/** @type {any} */ item) => { menuItems.push(item); },
      remove: async () => {},
      onClicked: { addListener: () => { counts.menuClick += 1; } },
    },
    scripting: overrides.scripting ?? { executeScript: async () => [], getRegisteredContentScripts: async () => [], registerContentScripts: async () => {}, unregisterContentScripts: async () => {} },
    webNavigation: {
      getFrame: async () => null,
      getAllFrames: async () => [],
      onCommitted: { addListener() {} },
      onCompleted: { addListener() {} },
      onHistoryStateUpdated: { addListener() {} },
    },
    tabs: { get: async () => ({ incognito: false }), onRemoved: { addListener() {} } },
    permissions: { contains: async () => false, onRemoved: { addListener() {} } },
    runtime: {
      ...fake.runtime,
      getManifest: () => ({ manifest_version: 3, browser_specific_settings: { gecko: { id: fake.runtime.id } } }),
      onConnect: { addListener: (/** @type {any} */ fn) => onConnect.push(fn) },
      onMessage: { addListener: (/** @type {any} */ fn) => onMessage.push(fn) },
      onSuspend: { addListener() {} },
      onSuspendCanceled: { addListener() {} },
    },
    alarms: { create() {}, clear() {}, get: async () => undefined, onAlarm: { addListener: () => { counts.alarm += 1; } } },
    idle: { onStateChanged: { addListener: () => { counts.idle += 1; } } },
    storage: {
      local: new Proxy({}, { get: () => async () => ({}) }),
      session: {
        get: async (/** @type {string} */ key) => (session.has(key) ? { [key]: session.get(key) } : {}),
        set: async (/** @type {Record<string, unknown>} */ items) => { for (const [k, v] of Object.entries(items)) session.set(k, v); },
        remove: async (/** @type {string} */ key) => { session.delete(key); },
      },
    },
  };
  // Node's own fetch puts its dispatcher on globalThis on first use; the page reads its catalogs with fetch, so
  // that happens here first and is not counted as the background's.
  await fetch(fake.runtime.getURL("locales.en.json")).catch(() => {});
  const before = Reflect.ownKeys(globalThis);
  await import(pathToFileURL(join(dir, "background", "main.mjs")).href);
  await new Promise((resolve) => setTimeout(resolve, 10));
  return { fake, onConnect, onMessage, counts, menuItems, session, before };
}
