// The extension end to end against the end-to-end stack (run by the e2e mode of
// the Firefox runner), with the web vault in a second browser:
//
// - Sign in in the extension (Firefox); a login made in the web vault in
//   Chromium (Playwright, through the stack's browser server) shows in the
//   extension; "Fill" puts it into the test site's sign-in page; "Lock" locks
//   and the master password opens it again; the extension's device is revoked
//   in the web vault in Chromium, and the extension is signed out.
// - The stack's malicious server: `replay_old` (an old version of an item) and
//   `hide` (an item left out of a full listing) each give their warning in the
//   popup, and every item the extension holds stays.
// - A background that the browser ended comes back locked, and the popup asks
//   for the master password only.
// - A copied password leaves the clipboard after 30 seconds, also when the
//   vault is locked right after the copy, and a later copy is not cleared by
//   the alarm of an earlier one (the system clipboard, read in the chrome
//   context). A user name copied from a row's copy menu, opened and moved
//   through with real keys, leaves the clipboard after 30 seconds too.
// - The real popup (the toolbar's panel, opened by the fill shortcut on a page
//   with two matches) and a popped-out window keep their header and their foot
//   inside the window, with a list too long for it: only the list scrolls.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { DEVICE_NAME, POPUP_URL, SLOW, VAULT_URL, helpers, pace } from "./e2e.mjs";
import { ENTRIES, POPUP_TEXT, USERNAME, clipboardText, shotPath, world } from "./adversary.mjs";
import { TEST_ADDON_ID, channels, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const here = dirname(fileURLToPath(import.meta.url));
/** How long a sync warning may take: the edit, the hint, a read of the feed and the popup's next look. */
const WARNED = 90_000;
/** The clipboard is cleared 30 s after a copy; the browser's alarm may fire a little late. */
const CLEARED_WITHIN_MS = 40_000;
/** The shortcut of the fill command (manifest/parts/commands.json). */
const FILL_SHORTCUT = "Alt+Shift+L";
/** The tallest popup Firefox shows (ExtensionPopups.sys.mjs asks the page for its size up to 600 pixels). */
const POPUP_MAX_HEIGHT = 600;
/** WebDriver's keys. */
const KEY = Object.freeze({ enter: String.fromCharCode(0xe007), space: String.fromCharCode(0xe00d), escape: String.fromCharCode(0xe00c), down: String.fromCharCode(0xe015), up: String.fromCharCode(0xe013) });

/** @param {number} ms */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The extension's own text of a sync warning (its English catalog). @param {string} code */
function warningText(code) {
  const catalog = JSON.parse(readFileSync(join(here, "..", "..", "src", "locales", "en", "sync.json"), "utf8"));
  return catalog[`sync.warning.${code}`];
}

/**
 * Switches the malicious server of the stack to a mode (web/test/e2e-stack/evil/modes.mjs).
 * @param {string} mode @param {Record<string, unknown>} [params]
 */
async function evil(mode, params = {}) {
  const base = process.env.FERRET_E2E_EVIL_URL ?? "";
  assert.ok(base, "FERRET_E2E_EVIL_URL is not set (run the specs in the e2e mode of the Firefox runner)");
  const response = await fetch(`${base}/mode`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...params, mode }) });
  assert.equal(response.ok, true, `the malicious server answered ${response.status} for ${mode}: ${await response.text()}`);
}

/**
 * The rows the extension holds (ids and revisions only), read through an extension page of the current tab.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<Array<{ itemId: string, rev: number }>>}
 */
function extensionRows(session) {
  return session.content(() => new Promise((resolve, reject) => {
    const open = indexedDB.open("ferret");
    open.onupgradeneeded = () => open.transaction?.abort();
    open.onerror = () => (open.error?.name === "AbortError" ? resolve([]) : reject(open.error));
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("rows")) {
        db.close();
        resolve([]);
        return;
      }
      const all = db.transaction(["rows"], "readonly").objectStore("rows").getAll();
      all.onerror = () => reject(all.error);
      all.onsuccess = () => {
        resolve(all.result.map((row) => ({ itemId: row.itemId, rev: row.rev })));
        db.close();
      };
    };
  }));
}

/** The web vault's steps in Firefox (its tab must be shown). */
const firefoxVault = {
  /** @param {ReturnType<typeof helpers>} page @param {import("./driver.mjs").Session} session @param {string} name */
  async create(page, session, name) {
    await page.click('[data-role="nav-items"]');
    await page.waitVisible('[data-role="new-item"]');
    await page.click('[data-role="new-item"]');
    await page.waitVisible('[data-role="edit-form"]');
    await page.type('[data-role="name"]', name);
    await page.type('[data-role="username"]', "evil-user");
    await page.click('[data-role="save"]');
    await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the saved item");
    const id = /#\/items\/([0-9a-f]{32})/.exec(await session.currentUrl())?.[1];
    assert.ok(id, "the item page names the item");
    return id;
  },
  /** Renames the item the web vault shows. @param {ReturnType<typeof helpers>} page @param {import("./driver.mjs").Session} session @param {string} name */
  async rename(page, session, name) {
    await page.click('[data-role="edit"]');
    await page.waitVisible('[data-role="edit-form"]');
    await page.paste('[data-role="name"]', name);
    await page.click('[data-role="save"]');
    await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the renamed item");
  },
  /** The top of the server's feed, read with the web vault's session. @param {import("./driver.mjs").Session} session */
  latestSeq: (session) => session.content(async () => {
    const response = await fetch("/api/sync/changes?since=0&limit=1", { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
    return (await response.json()).latest_seq;
  }),
};

/** Opens the popup in a tab of the extension's own (no page: the vault's list), once it has built itself. */
async function popupTab(/** @type {Awaited<ReturnType<typeof world>>} */ w) {
  const tab = await w.session.newTab();
  await w.session.switchTo(tab);
  await w.session.navigate(POPUP_URL);
  await w.page.ready();
  return tab;
}

test("sign_in_see_the_web_vault_login_fill_lock_unlock_and_a_revoke_signs_the_extension_out", async () => {
  const ws = process.env.FERRET_E2E_CHROMIUM_WS ?? "";
  assert.ok(ws, "FERRET_E2E_CHROMIUM_WS is not set (scripts/lanbox-ext.sh e2e starts the stack's Chromium)");
  // The client of the stack's browser server: playwright-core from web/package-lock.json, in the stack's volume.
  const client = "/pw/node_modules/playwright-core/index.mjs";
  const { chromium } = await import(client);
  for (const channel of channels()) {
    const w = await world(channel, { entries: {} });
    const browser = await chromium.connect(ws, { timeout: 60_000 });
    try {
      const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
      const vault = await context.newPage();
      const tag = randomBytes(4).toString("hex");
      const name = `E2E-login-${channel}-${tag}`;
      const username = `e2e-${tag}@fixture.example`;
      const password = `Whole-way-${tag}-battery-staple`;
      const loginUrl = w.server.siteUrl("login");

      // The extension is signed in (the world did it, in its own tab); its popup is open on the vault.
      const ext = await popupTab(w);
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);

      // The web vault in Chromium: sign in, and make a login for the test site's page.
      await vault.goto(`${VAULT_URL}/vault/login`);
      await vault.locator('[data-role="email"]').fill(w.account.email);
      await vault.locator('[data-role="password"]').click();
      await vault.locator('[data-role="password"]').fill(w.account.password);
      await vault.locator('[data-role="sk-question"]').waitFor({ timeout: 30_000 });
      await vault.locator('[data-role="sk-yes"]').click();
      await vault.locator('[data-role="sk-code"]').fill(w.account.secretKey);
      await vault.locator('[data-role="credentials"] [data-role="submit"]').click();
      await vault.locator('[data-role="list"]').waitFor({ timeout: SLOW });
      await vault.locator('[data-role="nav-items"]').click();
      await vault.locator('[data-role="new-item"]').click();
      await vault.locator('[data-role="edit-form"]').waitFor();
      await vault.locator('[data-role="name"]').fill(name);
      await vault.locator('[data-role="username"]').fill(username);
      await vault.locator('[data-role="password"]').fill(password);
      await vault.locator('[data-role="url"]').fill(loginUrl);
      await vault.locator('[data-role="save"]').click();
      await vault.locator('[data-role="item"] h1', { hasText: name }).waitFor({ timeout: 30_000 });
      await vault.screenshot({ path: shotPath(channel, "80-chromium-web-vault-login") });
      const itemId = /#\/items\/([0-9a-f]{32})/.exec(vault.url())?.[1];
      assert.ok(itemId, `${channel}: the web vault names the item (${vault.url()})`);
      // The server has it (the web vault's own feed, read in Chromium with its session).
      const serverHas = () => vault.evaluate(async (/** @type {string} */ wanted) => {
        let since = 0;
        for (let page = 0; page < 50; page += 1) {
          const response = await fetch(`/api/sync/changes?since=${since}&limit=500`, { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
          if (!response.ok) return false;
          const feed = await response.json();
          if (feed.changes.some((/** @type {any} */ c) => c.id === wanted)) return true;
          if (!feed.has_more || feed.changes.length === 0) return false;
          since = feed.changes[feed.changes.length - 1].seq;
        }
        return false;
      }, itemId);
      await w.session.waitFor(serverHas, 60_000, `${channel}: the server has the login made in Chromium`);

      // The extension has it: its list, searched by the login's name.
      await w.session.switchTo(ext);
      await w.session.waitFor(async () => {
        await w.session.navigate(POPUP_URL);
        await w.page.ready();
        await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
        await w.page.type('[data-role="search"]', name);
        await sleep(1_500);
        return w.session.content((/** @type {string} */ wanted) => [...document.querySelectorAll('[data-role="row-name"]')].some((n) => n.textContent?.trim() === wanted), name);
      }, SLOW, `${channel}: the login in the extension's list`);
      await w.session.screenshot(shotPath(channel, "80-extension-has-the-login"));

      // "Fill" on the test site's page.
      const tabId = await w.visit(loginUrl);
      const view = await w.popup(tabId);
      try {
        await view.shot("80-popup-on-the-login-page");
        assert.equal(await view.fill(name), POPUP_TEXT["popup.filled"], channel);
        assert.equal((await view.html()).includes(password), false, `${channel}: the popup never had the password`);
      } finally {
        await view.close();
      }
      const values = await w.session.content(() => ({
        user: /** @type {HTMLInputElement} */ (document.getElementById("login-user")).value,
        pass: /** @type {HTMLInputElement} */ (document.getElementById("login-pass")).value,
      }));
      assert.deepEqual(values, { user: username, pass: password }, channel);

      // Lock, and open it again with the master password.
      await w.session.switchTo(ext);
      await w.session.navigate(POPUP_URL);
      await w.page.ready();
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      await w.page.click('[data-role="lock"]');
      await w.page.waitVisible('[data-role="locked-view"]');
      await w.session.screenshot(shotPath(channel, "80-locked"));
      await w.page.type('[data-role="password"]', w.account.password);
      await pace();
      await w.page.click('[data-role="unlock"]');
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);

      // The web vault in Chromium revokes the extension's device (the only one: the world revoked the others).
      await vault.evaluate(() => { location.hash = "#/devices"; });
      await vault.locator('[data-role="devices-list"]').waitFor({ timeout: 30_000 });
      const devices = await vault.evaluate(async () => {
        const response = await fetch("/api/auth/devices", { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
        return (await response.json()).devices;
      });
      const ours = devices.filter((/** @type {any} */ d) => d.kind === "device" && d.name === DEVICE_NAME);
      assert.equal(ours.length, 1, `${channel}: one device of the extension (${JSON.stringify(devices)})`);
      const row = vault.locator('[data-role="devices-row"][data-kind="device"]', { hasText: DEVICE_NAME });
      await row.locator('[data-role="devices-revoke"]').click();
      await vault.locator('[data-role="dialog-confirm"]').click();
      await vault.locator('[data-role="devices-done"]').waitFor({ timeout: 30_000 });
      await vault.screenshot({ path: shotPath(channel, "80-chromium-device-revoked") });

      // The extension is signed out.
      await w.session.switchTo(ext);
      await w.session.waitFor(async () => {
        await w.session.navigate(POPUP_URL);
        await w.page.ready();
        return w.page.visible('[data-role="signed-out-view"]');
      }, SLOW, `${channel}: the extension is signed out`);
      await w.session.screenshot(shotPath(channel, "80-signed-out"));
      await context.close();
    } finally {
      await browser.close().catch(() => {});
      await w.quit();
    }
  }
});

test("the_evil_server_modes_replay_old_and_hide_warn_in_the_popup_and_nothing_local_is_lost", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { entries: {} });
    try {
      const ext = await popupTab(w);
      await w.page.waitVisible('[data-role="sync"][data-state="idle"][data-live="live"]', SLOW);
      const rows = async () => {
        await w.session.switchTo(w.bridgeTab);
        try {
          return await extensionRows(w.session);
        } finally {
          await w.session.switchTo(ext);
        }
      };
      /** The popup's warning with this code, once it shows. @param {string} code */
      const warned = async (code) => {
        const css = `[data-role="sync-warning"][data-code="${code}"]`;
        await w.session.waitFor(async () => {
          await w.session.navigate(POPUP_URL);
          await w.page.ready();
          await w.session.waitFor(() => w.page.visible('[data-role="sync"]'), 10_000, "the sync part");
          return w.page.visible(css);
        }, WARNED, `${channel}: the warning ${code}`);
        assert.equal(await w.page.text(css), warningText(code), `${channel}: ${code} in the extension's words`);
        await w.session.screenshot(shotPath(channel, `80-evil-${code}`));
      };

      // replay_old: the server sends the first version of an item whenever it changes.
      await w.session.switchTo(w.vaultTab);
      const name = `Ext-replay-${channel}-${randomBytes(4).toString("hex")}`;
      const replayed = await firefoxVault.create(w.page, w.session, name);
      await firefoxVault.rename(w.page, w.session, `${name}-2`);
      await w.session.switchTo(ext);
      await w.session.waitFor(async () => (await rows()).some((r) => r.itemId === replayed && r.rev === 2), 60_000, "the second version in the extension");
      const held = new Set((await rows()).map((r) => r.itemId));
      await evil("replay_old", { id: replayed });
      try {
        await w.session.switchTo(w.vaultTab);
        await firefoxVault.rename(w.page, w.session, `${name}-3`);
        await w.session.switchTo(ext);
        await warned("rev_lower_than_local");
        const kept = (await rows()).find((r) => r.itemId === replayed);
        assert.ok(kept && kept.rev >= 2, `${channel}: the extension kept a version it had (${JSON.stringify(kept)})`);
      } finally {
        await evil("honest");
      }

      // hide: the server says the extension's place in the feed is too old (a full listing) and leaves one item out of it.
      await w.session.switchTo(w.vaultTab);
      const hiddenName = `Ext-hidden-${channel}-${randomBytes(4).toString("hex")}`;
      const pokeName = `Ext-poke-${channel}-${randomBytes(4).toString("hex")}`;
      const hidden = await firefoxVault.create(w.page, w.session, hiddenName);
      await firefoxVault.create(w.page, w.session, pokeName);
      await w.session.switchTo(ext);
      await w.session.waitFor(async () => (await rows()).some((r) => r.itemId === hidden), 60_000, "the item to hide in the extension");
      for (const r of await rows()) held.add(r.itemId);
      await w.session.switchTo(w.vaultTab);
      const top = await firefoxVault.latestSeq(w.session);
      await evil("gone", { min_valid_since: top + 1, hide: hidden });
      try {
        await firefoxVault.rename(w.page, w.session, `${pokeName}-b`);
        await w.session.switchTo(ext);
        await warned("server_hid_item");
      } finally {
        await evil("honest");
      }
      // Nothing the extension held is gone.
      const now = new Set((await rows()).map((r) => r.itemId));
      assert.deepEqual([...held].filter((id) => !now.has(id)), [], `${channel}: every item the extension held is still there`);
      assert.ok(now.has(hidden), `${channel}: the hidden item is kept`);
    } finally {
      await w.quit();
    }
  }
});

test("a_killed_background_comes_back_locked_and_the_popup_asks_only_for_the_password", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { entries: {} });
    try {
      await popupTab(w);
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      // The browser ends the background the way the Terminate button of about:debugging does.
      const state = await w.session.terminateBackground(TEST_ADDON_ID);
      assert.notEqual(state, "running", `${channel}: the background was ended (${state})`);
      await w.session.navigate(POPUP_URL);
      await w.page.ready();
      await w.page.waitVisible('[data-role="locked-view"]', SLOW);
      await w.session.screenshot(shotPath(channel, "80-after-a-killed-background"));
      assert.equal(await w.page.visible('[data-role="password"]'), true, `${channel}: the master password is asked for`);
      for (const role of ["email", "sk-code", "qr-text", "server"]) {
        assert.equal(await w.page.visible(`[data-role="${role}"]`), false, `${channel}: no ${role} field`);
      }
      assert.equal(await w.page.visible('[data-role="lock"]'), false, `${channel}: no lock button on a locked vault`);
      // The master password alone opens it: the device and its tokens outlived the background.
      await w.page.type('[data-role="password"]', w.account.password);
      await pace();
      await w.page.click('[data-role="unlock"]');
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
    } finally {
      await w.quit();
    }
  }
});

test("a_copied_password_leaves_the_clipboard_after_30_seconds", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { entries: { host: ENTRIES.host, domain: ENTRIES.domain } });
    try {
      await popupTab(w);
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      /** Copies an entry's password from the popup's list (found by a search), as a person does. @param {"host" | "domain"} key */
      const copy = async (key) => {
        await w.session.navigate(POPUP_URL);
        await w.page.ready();
        await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
        await w.page.type('[data-role="search"]', w.named[key]);
        const marked = await w.session.waitFor(() => w.session.content((/** @type {string} */ wanted) => {
          const row = [...document.querySelectorAll('[data-role="results"] [data-role="item-row"]')].find((r) => r.querySelector('[data-role="row-name"]')?.textContent?.trim() === wanted);
          if (!row) return false;
          for (const old of document.querySelectorAll("[data-e2e-copy]")) old.removeAttribute("data-e2e-copy");
          row.setAttribute("data-e2e-copy", "1");
          return true;
        }, w.named[key]), 30_000, `the row of ${key}`);
        assert.equal(marked, true);
        await w.page.click('[data-e2e-copy] [data-role="copy"]');
        await w.page.waitVisible('[data-e2e-copy] [data-role="copy-menu"]', 5_000);
        await w.page.click('[data-e2e-copy] [data-role="copy-password"]');
        await w.page.waitVisible('[data-role="toast"]', 20_000);
        assert.equal(await w.page.text('[data-role="toast"]'), POPUP_TEXT["popup.copied.password"], `${channel}: copied`);
        return Date.now();
      };
      /** Waits until the clipboard holds no text; how long after `since` that was. @param {number} since */
      const clearedAfter = async (since) => {
        await w.session.waitFor(async () => (await clipboardText(w.session)) === "", CLEARED_WITHIN_MS + 5_000, `${channel}: the clipboard is cleared`);
        return Date.now() - since;
      };

      // One copy: the password is on the clipboard, and gone after 30 seconds.
      let at = await copy("host");
      assert.equal(await clipboardText(w.session), w.passwords.host, `${channel}: the clipboard has the password`);
      let took = await clearedAfter(at);
      console.log(`# ${channel}: the clipboard was cleared ${took} ms after the copy`);
      assert.ok(took >= 25_000 && took <= CLEARED_WITHIN_MS, `${channel}: cleared after ${took} ms (30 s wanted)`);

      // A second copy 10 seconds later: the first copy's alarm leaves it alone, its own clears it.
      at = await copy("host");
      await sleep(10_000);
      const second = await copy("domain");
      assert.equal(await clipboardText(w.session), w.passwords.domain, channel);
      await sleep(Math.max(0, at + 34_000 - Date.now()));
      assert.equal(await clipboardText(w.session), w.passwords.domain, `${channel}: the first copy's alarm did not clear the second copy`);
      took = await clearedAfter(second);
      assert.ok(took <= CLEARED_WITHIN_MS, `${channel}: the second copy was cleared after ${took} ms`);

      // A copy, then "Lock" at once: still cleared, while locked.
      at = await copy("host");
      await w.page.click('[data-role="lock"]');
      await w.page.waitVisible('[data-role="locked-view"]');
      assert.equal(await clipboardText(w.session), w.passwords.host, channel);
      took = await clearedAfter(at);
      assert.ok(took <= CLEARED_WITHIN_MS, `${channel}: cleared ${took} ms after the copy, while locked`);
      await w.session.screenshot(shotPath(channel, "80-clipboard-cleared-while-locked"));
    } finally {
      await w.quit();
    }
  }
});

test("a_copied_user_name_leaves_the_clipboard_after_30_seconds_and_the_copy_menu_works_with_the_keyboard", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { entries: { host: ENTRIES.host } });
    try {
      await popupTab(w);
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      await w.page.type('[data-role="search"]', w.named.host);
      const marked = await w.session.waitFor(() => w.session.content((/** @type {string} */ wanted) => {
        const row = [...document.querySelectorAll('[data-role="results"] [data-role="item-row"]')].find((r) => r.querySelector('[data-role="row-name"]')?.textContent?.trim() === wanted);
        if (!row) return false;
        row.setAttribute("data-e2e-copy", "1");
        return true;
      }, w.named.host), 30_000, "the row of the entry");
      assert.equal(marked, true);
      /** The row's copy menu as the page shows it, and which control of the row has the focus. */
      const menu = () => w.session.content(() => {
        const row = /** @type {HTMLElement} */ (document.querySelector("[data-e2e-copy]"));
        const list = /** @type {HTMLElement} */ (row.querySelector('[data-role="copy-menu"]'));
        return {
          open: !list.hidden && list.getClientRects().length > 0,
          expanded: row.querySelector('[data-role="copy"]')?.getAttribute("aria-expanded") ?? null,
          entries: [...list.querySelectorAll('[role="menuitem"]')].map((i) => i.textContent?.trim() ?? ""),
          focus: row.contains(document.activeElement) ? document.activeElement?.getAttribute("data-role") ?? null : null,
        };
      });
      /** Real keys on a control of the row. @param {string} role @param {string} keys */
      const press = async (role, keys) => {
        const [control] = await w.session.findAll(`[data-e2e-copy] [data-role="${role}"]`);
        assert.ok(control, role);
        await w.session.type(control, keys);
      };
      /** Waits for the menu to be open (or closed) with the focus on `focus`. @param {boolean} open @param {string} focus */
      const expect = (open, focus) => w.session.waitFor(async () => {
        const now = await menu();
        return now.open === open && now.focus === focus ? now : null;
      }, 5_000, `${channel}: the copy menu ${open ? "open" : "closed"} with the focus on ${focus}`);

      // Enter on the button opens the menu at its first entry: the user name, then the password.
      await press("copy", KEY.enter);
      const opened = await expect(true, "copy-username");
      assert.deepEqual(opened.entries, [POPUP_TEXT["popup.row.copy_username"], POPUP_TEXT["popup.row.copy_password"]], channel);
      assert.equal(opened.expanded, "true");
      // The arrows move, Escape closes it and the focus is back on the button.
      await press("copy-username", KEY.down);
      await expect(true, "copy-password");
      await press("copy-password", KEY.up);
      await expect(true, "copy-username");
      await press("copy-username", KEY.escape);
      assert.equal((await expect(false, "copy")).expanded, "false");
      assert.equal(await clipboardText(w.session), "", `${channel}: nothing was copied`);
      // Space opens it again, and Enter on "Copy user name" copies the user name.
      await press("copy", KEY.space);
      await expect(true, "copy-username");
      await press("copy-username", KEY.enter);
      await expect(false, "copy");
      await w.page.waitVisible('[data-role="toast"]', 20_000);
      assert.equal(await w.page.text('[data-role="toast"]'), POPUP_TEXT["popup.copied.username"], `${channel}: copied`);
      const at = Date.now();
      assert.equal(await clipboardText(w.session), USERNAME, `${channel}: the clipboard has the user name`);
      await w.session.waitFor(async () => (await clipboardText(w.session)) === "", CLEARED_WITHIN_MS + 5_000, `${channel}: the clipboard is cleared`);
      const took = Date.now() - at;
      console.log(`# ${channel}: the user name left the clipboard ${took} ms after the copy`);
      assert.ok(took >= 25_000 && took <= CLEARED_WITHIN_MS, `${channel}: cleared after ${took} ms (30 s wanted)`);
    } finally {
      await w.quit();
    }
  }
});

test("the_real_popup_keeps_its_header_and_foot_inside_the_window_and_scrolls_only_its_list", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { entries: { host: ENTRIES.host, domain: ENTRIES.domain } });
    try {
      // Two entries match the sign-in page, so the fill shortcut opens the toolbar's popup instead of filling.
      const tabId = await w.visit(w.server.siteUrl("login"));
      await w.session.pressShortcut(FILL_SHORTCUT);

      /**
       * The layout of the popup's page: the toolbar's panel, or the popped-out window about the page's tab. With
       * `stretch`, the page first gets a list far longer than the window, and an account and a server name far wider
       * than it. Null until the page shows its list.
       * @param {"panel" | "window"} where @param {boolean} stretch
       */
      const layout = (where, stretch) => w.fromBridge(() => w.session.content((/** @type {string} */ kind, /** @type {boolean} */ longer) => {
        const views = kind === "panel"
          ? browser.extension.getViews({ type: "popup" })
          : browser.extension.getViews({ type: "tab" }).filter((v) => v.location.pathname.endsWith("/pages/popup.html") && v.location.search.startsWith("?tab="));
        const view = /** @type {Window | undefined} */ (views[0]);
        if (!view) return null;
        const d = view.document;
        const list = d.querySelector('[data-role="list"]');
        const rows = d.querySelector('[data-role="all-rows"]');
        const first = rows?.querySelector('[data-role="item-row"]');
        if (d.body.dataset.ready !== "1" || !d.querySelector('[data-role="unlocked-view"]') || !list || !rows || !first) return null;
        if (longer && !d.body.hasAttribute("data-e2e-stretched")) {
          for (let i = 0; i < 40; i += 1) rows.append(first.cloneNode(true));
          const account = /** @type {HTMLElement} */ (d.querySelector('[data-role="account"]'));
          const host = /** @type {HTMLElement} */ (d.querySelector('[data-role="server-host"]'));
          account.textContent = `${"a-very-long-account-name.".repeat(8)}@example.net`;
          host.textContent = `${"a-long-server-label.".repeat(8)}example.net`;
          d.body.setAttribute("data-e2e-stretched", "1");
        }
        /** @param {string} css */
        const box = (css) => {
          const r = /** @type {Element} */ (d.querySelector(css)).getBoundingClientRect();
          return { top: r.top, bottom: r.bottom, left: r.left, right: r.right };
        };
        return {
          views: views.length,
          width: view.innerWidth,
          height: view.innerHeight,
          pageHeight: d.documentElement.scrollHeight,
          windowed: d.body.classList.contains("ff-windowed"),
          header: box(".ff-bar"),
          foot: box(".ff-foot"),
          account: box('[data-role="account"]'),
          host: box('[data-role="server-host"]'),
          list: { ...box('[data-role="list"]'), client: list.clientHeight, scroll: list.scrollHeight },
        };
      }, where, stretch));
      /** The layout once Firefox has sized the popup (the same twice in a row). @param {"panel" | "window"} where @param {boolean} stretch */
      const settled = async (where, stretch) => {
        /** @type {any} */
        let last = null;
        return w.session.waitFor(async () => {
          const now = await layout(where, stretch);
          const same = now !== null && last !== null && JSON.stringify(now) === JSON.stringify(last);
          last = now;
          return same ? now : null;
        }, SLOW, `${channel}: the ${where}'s layout`);
      };
      /** @param {any} l @param {string} what */
      const whole = (l, what) => {
        const detail = `${channel}, ${what}: ${JSON.stringify(l)}`;
        assert.ok(l.height >= 300, detail);
        assert.ok(l.header.top >= -0.5, `the header starts inside the window: ${detail}`);
        assert.ok(l.foot.bottom <= l.height + 0.5, `the foot ends inside the window: ${detail}`);
        assert.ok(l.foot.top >= l.list.bottom - 0.5, `the foot is below the list: ${detail}`);
        assert.ok(l.pageHeight <= l.height + 0.5, `the page itself does not scroll: ${detail}`);
        for (const part of [l.account, l.host]) assert.ok(part.left >= -0.5 && part.right <= l.width + 0.5, `the foot's text stays inside the window: ${detail}`);
        assert.ok(l.account.right <= l.host.left + 0.5, `the account and the server do not overlap: ${detail}`);
      };

      // The toolbar's panel: as tall as Firefox lets a popup be, with the header and the foot whole.
      const panel = await settled("panel", false);
      assert.equal(panel.views, 1, `${channel}: one popup`);
      assert.equal(panel.windowed, false, channel);
      assert.ok(panel.height <= POPUP_MAX_HEIGHT, `${channel}: the panel is ${panel.height} pixels tall`);
      whole(panel, "the panel");
      // A list far longer than the panel, and names far wider: the list scrolls, the rest stays where it was.
      const full = await settled("panel", true);
      whole(full, "the panel with a long list");
      assert.ok(full.list.scroll > full.list.client, `${channel}: the list scrolls (${full.list.scroll} > ${full.list.client})`);
      assert.equal(full.height, panel.height, `${channel}: the panel keeps its height`);
      assert.equal(full.foot.bottom, panel.foot.bottom, `${channel}: the foot stays where it was`);
      console.log(`# ${channel}: panel ${full.width}x${full.height}, foot ${full.foot.top}-${full.foot.bottom}`);

      // The popped-out window (the pop-out button's own size) takes the window's height.
      const opened = await w.fromBridge(() => w.session.content(async (/** @type {number} */ id) => {
        const made = await browser.windows.create({ url: browser.runtime.getURL(`pages/popup.html?tab=${id}`), type: "popup", width: 380, height: 620 });
        return made.id;
      }, tabId));
      try {
        const windowed = await settled("window", true);
        assert.equal(windowed.windowed, true, channel);
        whole(windowed, "the popped-out window");
        assert.ok(windowed.list.scroll > windowed.list.client, `${channel}: the window's list scrolls`);
      } finally {
        await w.fromBridge(() => w.session.content((/** @type {number} */ id) => browser.windows.remove(id).then(() => true), opened));
      }
    } finally {
      await w.quit();
    }
  }
});
