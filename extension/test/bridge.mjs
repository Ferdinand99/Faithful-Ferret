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
  // What the browser's add-on page does when the person takes the access back (the spec for the shared https permission).
  "permissions.remove": (/** @type {any[]} */ args) => browser.permissions.remove(args[0]),
  "tabs.query": (/** @type {any[]} */ args) => browser.tabs.query(args[0] ?? {}),
  // What the toolbar button shows on one tab (the badge of the offers).
  "action.getBadgeText": (/** @type {any[]} */ args) => (browser.action ?? browser.browserAction).getBadgeText({ tabId: args[0]?.tab_id }),
  // What the offers store of the background holds for a tab: the offers' metadata and the SHA-256 of each
  // password, never a password. A build without saving passwords has no store, and says there is nothing to read.
  // A content script of the extension in the top frame of a tab, for the specs that treat one as hostile (66-unlock-adversarial):
  // the first sends every message of the unlock the way a content script can, the second reads what a content script can see of
  // the extension's storage. Each function is a fixed one of this file; the harness names it and gives its arguments.
  "content.unlock_flood": (/** @type {any[]} */ args) => runInTab(args[0].tab_id, unlockFloodProbe, args[0].messages),
  "content.unlock_storage": (/** @type {any[]} */ args) => runInTab(args[0].tab_id, unlockStorageProbe, args[0].record),
  offers_peek: (/** @type {any[]} */ args) => testCore("offers_peek", { tab_id: args[0]?.tab_id, session: freshSession(), ...(args[0]?.clear === true ? { clear: true } : {}) }).catch(() => ({ available: false, offers: [] })),
};

/**
 * Runs `func` as a content script in the top frame of a tab and returns its result. The tab needs the permission the real shortcut
 * gives (activeTab) or a host permission, as for the extension's own injections.
 * @param {number} tabId
 * @param {(argument: any) => unknown} func
 * @param {unknown} argument
 */
async function runInTab(tabId, func, argument) {
  const [injected] = await browser.scripting.executeScript({ target: { tabId, frameIds: [0] }, func, args: [argument] });
  return injected?.result ?? null;
}

/**
 * Content-script side: sends each message the ways a content script can (the object and the text the pages use, on a runtime
 * message and on the extension pages' port) and returns what came back. Nothing here may use a name of this file.
 * @param {Array<{ type: string, body: unknown }>} messages
 */
async function unlockFloodProbe(messages) {
  /** @type {{ replies: any[], port: any }} */
  const out = { replies: [], port: null };
  for (const [i, message] of messages.entries()) {
    const wire = { v: 1, id: `c${i}`, type: message.type, body: message.body };
    for (const payload of [wire, JSON.stringify(wire)]) {
      try {
        out.replies.push({ type: message.type, reply: (await browser.runtime.sendMessage(payload)) ?? null });
      } catch (error) {
        out.replies.push({ type: message.type, error: String(/** @type {any} */ (error)?.message ?? error).slice(0, 80) });
      }
    }
  }
  out.port = await new Promise((resolve) => {
    const port = browser.runtime.connect({ name: "ferret-ui" });
    /** @type {any[]} */
    const got = [];
    let disconnected = false;
    port.onMessage.addListener((raw) => got.push(raw));
    port.onDisconnect.addListener(() => {
      disconnected = true;
    });
    try {
      for (const [i, message] of messages.entries()) port.postMessage(JSON.stringify({ v: 1, id: `p${i}`, type: message.type, body: message.body }));
    } catch {
      // A closed port throws: that is the answer.
    }
    setTimeout(() => resolve({ got, disconnected }), 4000);
  });
  return out;
}

/**
 * Content-script side: what a content script can do with the extension's storage and databases. `record` is a key and a value
 * of the extension's session storage that the content script writes to the local storage, where it can.
 * @param {{ key: string, value: unknown }} record
 */
async function unlockStorageProbe(record) {
  const brief = (/** @type {any} */ error) => `threw: ${String(error?.message ?? error).slice(0, 60)}`;
  /** @type {Record<string, any>} */
  const out = { sessionArea: typeof (/** @type {any} */ (browser.storage).session), sessionRead: null, sessionWrite: null, databases: null, local: null };
  try {
    out.sessionRead = JSON.stringify(await /** @type {any} */ (browser.storage).session.get(null));
  } catch (error) {
    out.sessionRead = brief(error);
  }
  try {
    await /** @type {any} */ (browser.storage).session.set({ "ferretPin|forged": "x" });
    out.sessionWrite = "wrote";
  } catch (error) {
    out.sessionWrite = brief(error);
  }
  try {
    out.databases = (await indexedDB.databases()).map((d) => d.name);
  } catch (error) {
    out.databases = brief(error);
  }
  try {
    await browser.storage.local.set({ [record.key]: record.value });
    out.local = Object.keys(await browser.storage.local.get(null)).filter((k) => k.startsWith("ferretPin"));
  } catch (error) {
    out.local = brief(error);
  }
  return out;
}

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
