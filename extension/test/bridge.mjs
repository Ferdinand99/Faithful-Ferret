// The test bridge: an extension page that only the test variant ships (dist/test/
// bridge.html). The browser tests open it in a tab to reach extension APIs from
// the harness, and it records what a real shortcut and a real menu click did.
//
// It is a page of the extension, so it has the extension's privileges; that is why
// it exists only in the test build, never in a release (the release check refuses
// test/ paths). `invoke` answers only for the API calls listed below.

/** Calls the harness may make through `invoke`. */
const ALLOWED = {
  "storage.local.get": (/** @type {any[]} */ args) => browser.storage.local.get(...args),
  "storage.local.set": (/** @type {any[]} */ args) => browser.storage.local.set(args[0]),
  "storage.local.clear": () => browser.storage.local.clear(),
  "runtime.getManifest": () => browser.runtime.getManifest(),
  "runtime.getURL": (/** @type {any[]} */ args) => browser.runtime.getURL(args[0]),
  "runtime.getPlatformInfo": () => browser.runtime.getPlatformInfo(),
  "permissions.getAll": () => browser.permissions.getAll(),
  "tabs.query": (/** @type {any[]} */ args) => browser.tabs.query(args[0] ?? {}),
  // What the toolbar button shows on one tab (the badge of the offers).
  "action.getBadgeText": (/** @type {any[]} */ args) => (browser.action ?? browser.browserAction).getBadgeText({ tabId: args[0]?.tab_id }),
  // What the offers store of the background holds for a tab: the offers' metadata and the SHA-256 of each
  // password, never a password. A build without saving passwords has no store, and says there is nothing to read.
  offers_peek: (/** @type {any[]} */ args) => testCore("offers_peek", { tab_id: args[0]?.tab_id, session: freshSession(), ...(args[0]?.clear === true ? { clear: true } : {}) }).catch(() => ({ available: false, offers: [] })),
};

/** A popup session of the bridge's own: the offers it is told of are the ones it reads. */
function freshSession() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * One operation of the test build's core port (the test build's own ops: this page is one of the extension's top-level
 * pages, which the port accepts).
 * @param {string} op @param {Record<string, unknown>} args
 * @returns {Promise<any>}
 */
function testCore(op, args) {
  return new Promise((resolve, reject) => {
    const port = browser.runtime.connect({ name: "ferret-test-core" });
    const timer = setTimeout(() => {
      port.disconnect();
      reject(new Error(`bridge: ${op} did not answer`));
    }, 30_000);
    port.onMessage.addListener((/** @type {any} */ reply) => {
      clearTimeout(timer);
      port.disconnect();
      if (reply?.ok === true) resolve(reply.value);
      else reject(new Error(`bridge: ${op}: ${reply?.code}`));
    });
    port.postMessage({ id: "1", op, args });
  });
}

/** What the registered command and the menu item saw. @type {Record<string, unknown>[]} */
const events = [];

// Same value as TEST_MENU_ITEM_ID in scripts/lib/testIds.mjs (a unit test holds them equal).
const MENU_ID = "ferret-test-menu-item";
const MENU_TITLE = "Ferret test menu item";

/** What a tab object shows. Without the tabs permission, `url` is there only under activeTab. @param {browser.tabs.Tab | undefined} tab */
function describeTab(tab) {
  return { tabId: tab?.id ?? null, tabUrl: tab?.url ?? null };
}

browser.commands.onCommand.addListener((name, tab) => {
  events.push({ kind: "command", name, ...describeTab(tab) });
});

browser.menus.onClicked.addListener((info, tab) => {
  events.push({ kind: "menu", menuItemId: info.menuItemId, frameId: info.frameId ?? null, ...describeTab(tab) });
});

// Created here, not in the background: nothing but this page needs the item.
browser.menus.create({ id: MENU_ID, title: MENU_TITLE, contexts: ["editable"] });

/**
 * @param {string} api
 * @param {string} [argsJson] the arguments as a JSON list, so a caller in another compartment passes a plain string
 * @returns {Promise<string>} the result as JSON
 */
async function invoke(api, argsJson = "[]") {
  if (!Object.hasOwn(ALLOWED, api)) throw new Error(`bridge: ${api} is not allowed`);
  const args = JSON.parse(argsJson);
  if (!Array.isArray(args)) throw new Error("bridge: the arguments must be a list");
  const result = await ALLOWED[/** @type {keyof typeof ALLOWED} */ (api)](args);
  return JSON.stringify(result ?? null);
}

Object.defineProperty(globalThis, "ferretBridge", {
  value: Object.freeze({
    menuTitle: MENU_TITLE,
    invoke,
    /** @returns {string} the recorded events as JSON */
    events: () => JSON.stringify(events),
    clearEvents: () => { events.length = 0; },
  }),
});
document.documentElement.dataset.ready = "1";
