// What the adversarial specs (70-phishing, 71-clickjacking, 80-end-to-end) share:
// a Firefox with the extension signed in to the end-to-end stack, the test
// sites' entries in its vault (made with the sync engine, each with a user name
// and a password of the test's own making), the real popup in a window of its
// own about a page's tab, a UI port that stays open across steps (one popup
// session), and screenshots. Not a spec (run.sh picks up *.spec.mjs only).
//
// activeTab comes from a real shortcut on the page's tab (chrome context), as a
// person gives it. The account is the stack's one (the sign-in specs made it, or
// the first world makes it); before a world signs the extension in, it revokes
// the devices that earlier specs left in the account (their browsers are gone),
// so the run stays under the server's 20 devices per account.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ORIGINS } from "../fixtures/sites/index.mjs";
import { POPUP_URL, SLOW, extensionSignIn, helpers, start, webVaultAccount } from "./e2e.mjs";
import { EXTENSION_ORIGIN, TEST_SHORTCUT, fixtures, openBridge } from "./harness.mjs";
import { base32 } from "./totp.mjs";

const here = dirname(fileURLToPath(import.meta.url));

/** The English texts of the popup, as a person reads them. */
export const POPUP_TEXT = Object.freeze(JSON.parse(readFileSync(join(here, "..", "..", "src", "locales", "en", "popup.json"), "utf8")));

/** The user name of every entry. */
export const USERNAME = "ola";

/** The entries of the test sites, by the key of the sites' expectations that speaks of them (see pages.mjs). */
export const ENTRIES = Object.freeze({
  host: { name: "Host entry", url: "https://login.example.net/", matching: "host" },
  domain: { name: "Domain entry", url: "https://login.example.net/", matching: "domain" },
  http: { name: "Http entry", url: "http://login.example.net/", matching: "host" },
  loopback: { name: "Loopback entry", url: "http://127.0.0.1/", matching: "host" },
  github: { name: "Github entry", url: `https://${ORIGINS.ghA.host}/`, matching: "domain" },
});

/** @typedef {keyof typeof ENTRIES} EntryKey */

/**
 * Which entry each expectation of a site speaks of, as pairs of the outcome and the entry.
 * @param {any} site
 * @returns {Array<[string, EntryKey]>}
 */
export function expectationsOf(site) {
  const e = site.expect;
  /** @type {Array<[string, EntryKey]>} */
  const out = [];
  if (typeof e.outcome === "string") out.push([e.outcome, typeof e.entry === "string" && e.entry.includes("github") ? "github" : "host"]);
  if (typeof e.domain_entry === "string") out.push([e.domain_entry, "domain"]);
  if (typeof e.http_entry === "string") out.push([e.http_entry, site.origin === "loopback" ? "loopback" : "http"]);
  return out;
}

/** Where a screenshot goes: FERRET_SHOTS_DIR (the gate run hands it back), else a folder of the container's own. */
export function shotPath(/** @type {string} */ channel, /** @type {string} */ name) {
  const dir = join(process.env.FERRET_SHOTS_DIR ?? join(tmpdir(), "ferret-shots"), channel);
  mkdirSync(dir, { recursive: true });
  return join(dir, `${name.replace(/[^a-z0-9-]+/gi, "-")}.png`);
}

/**
 * In the selected tab's document: every input, also inside open shadow roots, with its id, type, value and the
 * test sites' marks. Frames are read by switching into them.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<Array<{ id: string, type: string, value: string, expect: string | null }>>}
 */
export function inputsOf(session) {
  return session.content(() => {
    /** @type {Array<{ id: string, type: string, value: string, expect: string | null }>} */
    const out = [];
    /** @param {Document | ShadowRoot} root */
    const walk = (root) => {
      for (const el of root.querySelectorAll("*")) {
        if (el instanceof HTMLInputElement) out.push({ id: el.id, type: el.type, value: el.value, expect: el.getAttribute("data-fixture-expect") });
        if (el.shadowRoot) walk(el.shadowRoot);
      }
    };
    walk(document);
    return out;
  });
}

/**
 * The documents of the selected tab that hold `value` in an input: "top" or the path of frame ids ("login-frame",
 * "login-frame>nested-blank"). Every frame is read, whatever its origin (WebDriver may enter any of them); a frame
 * that cannot be read is named with a "?" in front, so a test can tell it from one that holds nothing.
 * @param {import("./driver.mjs").Session} session
 * @param {string} value
 * @returns {Promise<string[]>}
 */
export async function documentsHolding(session, value) {
  /** @type {string[]} */
  const found = [];
  /** @param {string[]} path */
  const walk = async (path) => {
    const where = path.length === 0 ? "top" : path.join(">");
    try {
      if ((await inputsOf(session)).some((input) => input.value === value)) found.push(where);
    } catch {
      found.push(`?${where}`);
      return;
    }
    const names = /** @type {string[]} */ (await session.content(() => [...document.querySelectorAll("iframe, frame")].map((f, i) => f.id || f.getAttribute("name") || `#${i}`)));
    for (let i = 0; i < names.length; i += 1) {
      const frames = await session.findAll("iframe, frame");
      if (!frames[i]) continue;
      try {
        await session.switchToFrame(frames[i]);
      } catch {
        found.push(`?${[...path, names[i]].join(">")}`);
        continue;
      }
      try {
        await walk([...path, names[i]]);
      } finally {
        await session.switchToParentFrame();
      }
    }
  };
  await session.switchToTopFrame();
  await walk([]);
  return found;
}

/**
 * A Firefox signed in to the stack, with the entries made (names tagged with the channel and the time).
 * `grant`: ids of test sites (or page addresses, `https://...`) whose waiting frames get their host permission in the
 * grant tab, as a person gives it (a frame of another origin on the same site waits for it).
 * @param {"release" | "esr"} channel
 * @param {{ grant?: string[], entries?: Partial<typeof ENTRIES> }} [options]
 */
export async function world(channel, { grant = [], entries = ENTRIES } = {}) {
  const server = await fixtures();
  const session = await start(channel);
  const page = helpers(session);
  const account = await webVaultAccount(session, channel);
  const vaultTab = await session.windowHandle();
  await revokeLeftDevices(session);
  const bridgeTab = await session.newTab();
  await session.switchTo(bridgeTab);
  const signed = await extensionSignIn(session, account);
  assert.equal(signed.ok, true, `${channel}: ${signed.text}`);
  await session.navigate(POPUP_URL);
  await page.ready();
  await page.waitVisible('[data-role="sync"][data-state="idle"]', SLOW);
  const bridge = await openBridge(session);
  const pageTab = await session.newTab();
  await session.switchTo(pageTab);

  /** @template T @param {() => Promise<T>} body */
  const fromBridge = async (body) => {
    const back = await session.windowHandle();
    await session.switchTo(bridgeTab);
    try {
      return await body();
    } finally {
      await session.switchTo(back);
    }
  };

  /** One message on a port of its own, from the bridge (an extension page). @param {string} name @param {unknown} message */
  const ask = (name, message) =>
    fromBridge(async () => JSON.parse(await session.content((/** @type {string} */ portName, /** @type {string} */ text) => new Promise((resolve, reject) => {
      const port = browser.runtime.connect({ name: portName });
      const timer = setTimeout(() => reject(new Error(`${portName} did not answer`)), 120_000);
      port.onMessage.addListener((reply) => {
        clearTimeout(timer);
        port.disconnect();
        resolve(typeof reply === "string" ? reply : JSON.stringify(reply));
      });
      port.onDisconnect.addListener(() => reject(new Error(`${portName} hung up`)));
      port.postMessage(JSON.parse(text));
    }), name, JSON.stringify(message))));
  /** A core operation of the test build. @param {string} op @param {Record<string, unknown>} [args] */
  const core = async (op, args = {}) => {
    const reply = await ask("ferret-test-core", { id: "1", op, args });
    assert.equal(reply.ok, true, `${channel}: ${op}: ${reply.code}`);
    return reply.value;
  };

  /** The host's state and the vault's deadline, read from the test build's measure port (no UI message, no touch). */
  const lockState = async () => {
    const reply = await ask("ferret-test-measure", { id: "1", cmd: "state" });
    assert.equal(reply.ok, true, `${channel}: state: ${reply.code}`);
    return { core: String(reply.value.core), lockAt: typeof reply.value.lockAt === "number" ? reply.value.lockAt : null };
  };

  /** The ids and revisions of the vault's items, from the sync engine (the test build's measure port): what a write changes. */
  const vaultState = async () => {
    const reply = await ask("ferret-test-measure", { id: "1", cmd: "vault" });
    assert.equal(reply.ok, true, `${channel}: vault: ${reply.code}`);
    return reply.value;
  };

  // A UI port that stays open across steps: one popup session (a reference is good only on the port that got it).
  const ui = {
    async open() {
      await fromBridge(() => session.content(() => {
        const w = /** @type {any} */ (window);
        w.__ferretUi?.port.disconnect();
        const port = browser.runtime.connect({ name: "ferret-ui" });
        /** @type {Record<string, (reply: any) => void>} */
        const waiting = {};
        port.onMessage.addListener((raw) => {
          const reply = JSON.parse(raw);
          waiting[reply.id]?.(reply);
          delete waiting[reply.id];
        });
        let n = 0;
        w.__ferretUi = {
          port,
          ask: (/** @type {string} */ type, /** @type {any} */ body) => new Promise((resolve, reject) => {
            n += 1;
            const id = `u${n}`;
            const timer = setTimeout(() => reject(new Error(`${type} did not answer`)), 120_000);
            waiting[id] = (reply) => {
              clearTimeout(timer);
              resolve(reply);
            };
            port.postMessage(JSON.stringify({ v: 1, id, type, body }));
          }),
        };
        return true;
      }));
    },
    /** @param {string} type @param {Record<string, unknown>} body @returns {Promise<{ type: string, body: any }>} */
    async ask(type, body) {
      const raw = await fromBridge(() => session.content(
        (/** @type {string} */ t, /** @type {string} */ b) => /** @type {any} */ (window).__ferretUi.ask(t, JSON.parse(b)).then((/** @type {any} */ r) => JSON.stringify(r)),
        type,
        JSON.stringify(body),
      ));
      return JSON.parse(raw);
    },
    /** The reply's body, which must be of the asked type. @param {string} type @param {Record<string, unknown>} body */
    async body(type, body) {
      const reply = await ui.ask(type, body);
      assert.equal(reply.type, type, `${channel}: ${type}: ${JSON.stringify(reply.body)}`);
      return reply.body;
    },
    async close() {
      await fromBridge(() => session.content(() => {
        /** @type {any} */ (window).__ferretUi?.port.disconnect();
        /** @type {any} */ (window).__ferretUi = null;
        return true;
      }));
    },
  };

  /**
   * Presses the real shortcut on the page the tab shows (activeTab) and returns the tab's id. The permission lasts for the
   * page it was given on: a person who has gone on to another page presses it again there.
   * @param {string} url the address, for the messages
   */
  const grant = async (url) => {
    await session.switchTo(pageTab);
    await fromBridge(() => bridge.clearEvents());
    // The shortcut goes to the tab the browser window shows, which is not always the one WebDriver drives (closing a
    // popup window selects another tab): make the page's tab the shown one of the front window first.
    await session.switchTo(pageTab);
    const address = await session.currentUrl();
    await session.waitFor(() => session.chrome((/** @type {string} */ want) => {
      const front = /** @type {any} */ (globalThis).Services.wm.getMostRecentWindow("navigator:browser");
      return front?.gBrowser?.selectedBrowser?.currentURI?.spec === want;
    }, address), 10_000, `the page's tab is the shown one (${address})`);
    await session.pressShortcut(TEST_SHORTCUT);
    const command = await session.waitFor(async () => (await fromBridge(() => bridge.events())).find((e) => e.kind === "command"), 15_000, "the command event");
    // The shortcut gives activeTab: the command's tab then carries its address. Without it the extension cannot see
    // the page at all, and every row would read as "nothing offered"; that is a failure of the run, said here.
    assert.ok(typeof command.tabUrl === "string" && /^https?:/.test(command.tabUrl), `${channel}: the shortcut on ${url} gave no activeTab (${JSON.stringify(command)})`);
    return /** @type {number} */ (command.tabId);
  };

  /**
   * Loads a page in the page tab and presses the real shortcut there (activeTab). Returns the tab's id.
   * @param {string} url
   */
  const visit = async (url) => {
    await session.switchTo(pageTab);
    await session.navigate(url);
    await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, url);
    return grant(url);
  };

  // The entries, with the sync engine of the extension (the release writes no items).
  const tag = `${channel}-${randomBytes(3).toString("hex")}`;
  /** @type {Record<string, string>} */
  const named = {};
  /** @type {Record<string, string>} */
  const passwords = {};
  /** The one-time-code secrets (base32) of the entries that ask for one (`totp: true`), made up per run. @type {Record<string, string>} */
  const totps = {};
  for (const [key, entry] of Object.entries(entries)) {
    if (!entry) continue;
    named[key] = `${entry.name} ${tag}`;
    passwords[key] = `Pw-${key}-${randomBytes(6).toString("hex")}`;
    const { totp, ...rest } = /** @type {Record<string, unknown>} */ (entry);
    if (totp === true) totps[key] = base32(randomBytes(20));
    await core("item_probe", { ...rest, name: named[key], username: USERNAME, password: passwords[key], ...(totps[key] ? { totp: `otpauth://totp/${encodeURIComponent(named[key])}?secret=${totps[key]}` } : {}) });
  }
  const keyOf = (/** @type {string} */ name) => /** @type {EntryKey | undefined} */ (Object.keys(named).find((k) => named[k] === name));
  if (named.host) {
    // The engine has them once the login page is offered the host entry.
    const tabId = await visit(server.siteUrl("login"));
    await ui.open();
    await session.waitFor(async () => (await ui.body("candidates", { tab_id: tabId })).handles.some((/** @type {any} */ h) => h.name === named.host), 30_000, "the new entries");
    await ui.close();
  }

  // Host permissions, given in the grant tab with a click, as a person does: for each site named in `grant`, the
  // frames its list says wait for their permission (the grant tab takes only an origin that a list named).
  /** @type {string[]} */
  const origins = [];
  for (const siteId of grant) {
    const tabId = await visit(siteId.startsWith("https://") ? siteId : server.siteUrl(siteId));
    await ui.open();
    const waiting = await ui.body("candidates", { tab_id: tabId });
    await ui.close();
    for (const g of waiting.grant) if (!origins.includes(g.origin)) origins.push(g.origin);
  }
  for (const origin of origins) {
    const grantTab = await session.newTab();
    await session.switchTo(grantTab);
    await session.navigate(`${EXTENSION_ORIGIN}/pages/grant.html?${new URLSearchParams({ origin })}`);
    await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 20_000, "the grant tab");
    // The grant tab asks only for an origin that a list named in the last minutes: the page's list names it.
    const [allow] = await session.findAll('[data-role="grant-allow"]');
    assert.ok(allow, `${channel}: the grant tab offers ${origin}`);
    await session.click(allow);
    await session.waitFor(() => session.content(() => document.querySelector('[data-role="grant-status"]')?.getAttribute("data-outcome") === "granted"), 20_000, "the grant");
    await session.closeTab();
    await session.switchTo(pageTab);
  }

  /**
   * The real popup in a window of its own about a tab (as a popped-out popup), once its list is built.
   * @param {number} tabId
   */
  const popup = async (tabId) => {
    const handle = await session.newWindow();
    await session.switchTo(handle);
    await session.navigate(`${POPUP_URL}?tab=${tabId}`);
    await page.ready();
    await page.waitVisible('[data-role="unlocked-view"]', SLOW);
    await session.waitFor(() => session.content(() => document.querySelector('[data-role="all"], [data-role="results"]') !== null), SLOW, "the popup's list");
    const view = {
      handle,
      /** The suggestions for the page, as the popup shows them. */
      suggestions: () => session.content(() => [...document.querySelectorAll('[data-role="suggestion"]')].map((row) => ({
        name: row.querySelector('[data-role="row-name"]')?.textContent?.trim() ?? "",
        insecure: row.querySelector('[data-role="insecure"]') !== null,
      }))),
      /** The host line above the suggestions ("" when there are none). */
      host: () => session.content(() => document.querySelector('[data-role="page-host"]')?.textContent?.trim() ?? ""),
      text: () => session.content(() => document.body.innerText),
      html: () => session.content(() => document.documentElement.outerHTML),
      /** @param {string} name */
      shot: (name) => session.screenshot(shotPath(channel, name)),
      /**
       * "Fill" on the suggestion with this name (twice on an unencrypted page: "Fill anyway"); the toast's text.
       * @param {string} name
       */
      fill: async (name) => {
        const marked = await session.content((/** @type {string} */ wanted) => {
          for (const old of document.querySelectorAll("[data-e2e-row]")) old.removeAttribute("data-e2e-row");
          const row = [...document.querySelectorAll('[data-role="suggestion"]')].find((r) => r.querySelector('[data-role="row-name"]')?.textContent?.trim() === wanted);
          if (!row) return null;
          row.setAttribute("data-e2e-row", "1");
          return { insecure: row.querySelector('[data-role="insecure"]') !== null };
        }, name);
        assert.ok(marked, `${channel}: the popup suggests ${name}`);
        await page.click('[data-e2e-row] [data-role="fill"]');
        if (marked.insecure) {
          assert.equal(await page.text('[data-e2e-row] [data-role="fill"]'), POPUP_TEXT["popup.row.fill_anyway"], `${channel}: one click more on an unencrypted page`);
          await page.click('[data-e2e-row] [data-role="fill"]');
        }
        await page.waitVisible('[data-role="toast"]', 30_000);
        return page.text('[data-role="toast"]');
      },
      close: async () => {
        await session.switchTo(handle);
        await session.closeTab();
        await session.switchTo(pageTab);
      },
    };
    return view;
  };

  /** Closes the session; the device is revoked by the next world (or the next run's stack is a new one). */
  const quit = () => session.quit();

  return { session, page, server, account, vaultTab, bridgeTab, pageTab, bridge, fromBridge, core, lockState, vaultState, ui, visit, grant, popup, named, passwords, totps, keyOf, tag, origins, quit };
}

/**
 * In the web vault's tab (signed in): revokes every device of the account (not the browsers). The sessions of the
 * specs that made them have ended; this keeps the account under the server's limit of 20 devices.
 * @param {import("./driver.mjs").Session} session
 */
export async function revokeLeftDevices(session) {
  const result = await session.content(async () => {
    const headers = { "Ferret-Protocol": "1" };
    const listed = await fetch("/api/auth/devices", { headers, cache: "no-store" });
    if (!listed.ok) return { ok: false, status: listed.status, revoked: 0 };
    const { devices } = await listed.json();
    let revoked = 0;
    for (const device of devices) {
      if (device.kind !== "device") continue;
      const gone = await fetch(`/api/auth/devices/${device.id}`, { method: "DELETE", headers });
      if (!gone.ok) return { ok: false, status: gone.status, revoked };
      revoked += 1;
    }
    return { ok: true, status: 200, revoked };
  });
  assert.equal(result.ok, true, `revoking the devices left in the account: ${JSON.stringify(result)}`);
  return result.revoked;
}

/**
 * The text the system clipboard holds (chrome context; the headless clipboard of Firefox is in the browser), or ""
 * when it holds no text.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<string>}
 */
export function clipboardText(session) {
  return session.chrome(() => {
    const C = /** @type {any} */ (globalThis).Components;
    const services = /** @type {any} */ (globalThis).Services;
    const transfer = C.classes["@mozilla.org/widget/transferable;1"].createInstance(C.interfaces.nsITransferable);
    transfer.init(null);
    transfer.addDataFlavor("text/plain");
    services.clipboard.getData(transfer, C.interfaces.nsIClipboard.kGlobalClipboard);
    const data = {};
    try {
      transfer.getTransferData("text/plain", data);
    } catch {
      return "";
    }
    const value = /** @type {any} */ (data).value;
    return value ? value.QueryInterface(C.interfaces.nsISupportsString).data : "";
  });
}
