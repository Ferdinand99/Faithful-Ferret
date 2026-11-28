// A second account (invited by the first) uses the extension against the end-to-end stack (run by the e2e mode of the
// Firefox runner), with nothing of the extension changed: one account per browser profile, as before.
//
// - The first account (the administrator of the stack) makes an invitation on the Users page and a second person
//   joins with it, in Chromium (Playwright, through the stack's browser server). The administrator's fresh password
//   check goes through the vault's re-authentication page there.
// - In a Firefox profile of its own the second account signs in to the web vault and to the extension, its entry for
//   the test site is filled in on the sign-in page, and a login it makes in the web vault reaches the extension. A
//   login the first account makes for the same page is never offered, and no row of the first account is in the
//   extension.
// - The extension's device is listed for the second account only: the first account's list of devices does not have
//   it.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { ADMIN_URL, DEVICE_NAME, POPUP_URL, SLOW, VAULT_URL, knownAccount, pace, start, webVaultAccount } from "./e2e.mjs";
import { ENTRIES, POPUP_TEXT, USERNAME, shotPath, world } from "./adversary.mjs";
import { channels, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const ACCOUNTS = "/settings/accounts";
/** The second account of the stack, kept for the next channel's process (as e2e.mjs keeps the first). */
const SECOND_FILE = join(tmpdir(), "ferret-ext-e2e-second-account.json");
/** The extension's device id of the second account in the last run, for the list of devices. */
const DEVICE_FILE = join(tmpdir(), "ferret-ext-e2e-second-device.json");

/** @param {number} ms */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** @typedef {{ email: string, password: string, secretKey: string, qrText: string }} Account */

/** The stack's browser server (Chromium), through the client in the stack's volume. */
async function chromiumBrowser() {
  const ws = process.env.FERRET_E2E_CHROMIUM_WS ?? "";
  assert.ok(ws, "FERRET_E2E_CHROMIUM_WS is not set (scripts/lanbox-ext.sh e2e starts the stack's Chromium)");
  const { chromium } = await import("/pw/node_modules/playwright-core/index.mjs");
  return chromium.connect(ws, { timeout: 60_000 });
}

/**
 * Fills the vault's sign-in form that `page` shows (a browser that has not seen the account), and sends it.
 * @param {any} page @param {Account} account
 */
async function fillSignIn(page, account) {
  const credentials = page.locator('[data-role="credentials"]');
  await credentials.waitFor({ timeout: 30_000 });
  await page.locator('[data-role="email"]').fill(account.email);
  await page.locator('[data-role="password"]').click();
  await page.locator('[data-role="password"]').fill(account.password);
  await page.locator('[data-role="sk-question"]').waitFor({ timeout: 30_000 });
  await page.locator('[data-role="sk-yes"]').click();
  await page.locator('[data-role="sk-code"]').fill(account.secretKey);
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
}

/** The web vault of `account` in a new page of `context`, signed in, on its list. @param {any} context @param {Account} account */
async function vaultOf(context, account) {
  const page = await context.newPage();
  await page.goto(`${VAULT_URL}/vault/login`);
  await fillSignIn(page, account);
  await page.locator('[data-role="list"]').waitFor({ timeout: SLOW });
  return page;
}

/**
 * The first account makes an invitation on the Users page (signing in through the hand-over and confirming its
 * password, as the page asks) and the second person joins with it, each in a context of its own. Kept in a file.
 * @param {Account} admin
 * @returns {Promise<Account>}
 */
async function makeSecondAccount(admin) {
  const browser = await chromiumBrowser();
  try {
    const adminContext = await browser.newContext();
    const users = await adminContext.newPage();
    await users.goto(`${ADMIN_URL}${ACCOUNTS}`);
    await fillSignIn(users, admin);
    const atUsers = (/** @type {URL} */ url) => url.origin === ADMIN_URL && url.pathname === ACCOUNTS;
    await users.waitForURL(atUsers, { timeout: SLOW });
    const make = users.locator('form[action="/settings/accounts/invites"] button[type="submit"]');
    if ((await make.count()) === 0) {
      await users.locator('a[href^="/vault/reauth"]').first().click();
      const credentials = users.locator('[data-role="credentials"]');
      await credentials.waitFor({ timeout: 30_000 });
      await credentials.locator('[data-role="password"]').fill(admin.password);
      await pace();
      await credentials.locator('[data-role="submit"]').click();
      await users.waitForURL(atUsers, { timeout: SLOW });
    }
    await make.click();
    const link = ((await users.locator("#created-invite").textContent({ timeout: 30_000 })) ?? "").trim();
    assert.match(link, /^https:\/\/[^/]+\/vault\/setup#invite=[0-9A-Za-z]{43}$/, "the link the page shows");
    await adminContext.close();

    const tag = randomBytes(5).toString("hex");
    const person = { email: `second-${tag}@e2e.example.test`, password: `Second-${tag}-horse-battery`, secretKey: "", qrText: "" };
    const joinContext = await browser.newContext();
    const page = await joinContext.newPage();
    await page.goto(link);
    await page.locator('[data-role="setup-form"]').waitFor({ timeout: 30_000 });
    assert.equal(await page.locator('[data-role="setup-token"]').count(), 0, "the join form has no setup-token field");
    await page.locator('[data-role="email"]').fill(person.email);
    await page.locator('[data-role="password"]').fill(person.password);
    await page.locator('[data-role="password-repeat"]').fill(person.password);
    await page.locator('[data-role="setup-form"] [data-role="submit"]').click();
    await page.locator('[data-role="sheet-page"]').waitFor({ timeout: SLOW });
    const recoveryKey = ((await page.locator('[data-role="sheet-recovery-key"]').textContent()) ?? "").trim();
    person.secretKey = ((await page.locator('[data-role="sheet-secret-key"]').textContent()) ?? "").trim();
    person.qrText = ((await page.locator('[data-role="sheet-qr"]').textContent()) ?? "").trim();
    assert.ok(recoveryKey.length > 10 && person.secretKey.length > 10 && person.qrText.startsWith("ferret-setup:"), "the sheet");
    await page.locator('[data-role="rk-typed"]').fill(recoveryKey);
    await page.locator('[data-role="sk-typed"]').fill(person.secretKey);
    await page.locator('[data-role="confirm"]').click();
    await page.locator('[data-role="open-vault"]').waitFor({ timeout: SLOW });
    await joinContext.close();
    writeFileSync(SECOND_FILE, JSON.stringify(person));
    return person;
  } finally {
    await browser.close().catch(() => {});
  }
}

/** The first account of the stack (made in a profile of its own when no spec made it yet) and the second. @param {"release" | "esr"} channel */
async function theTwoAccounts(channel) {
  let first = knownAccount();
  if (first === null) {
    const session = await start(channel);
    try {
      first = await webVaultAccount(session, channel);
    } finally {
      await session.quit();
    }
  }
  const admin = /** @type {Account} */ (first);
  /** @type {Account} */
  const second = existsSync(SECOND_FILE) ? JSON.parse(readFileSync(SECOND_FILE, "utf8")) : await makeSecondAccount(admin);
  return { first: admin, second };
}

/** A page's answer to a GET of the vault's API with its own session. @param {any} page @param {string} path */
const apiGet = (page, path) => page.evaluate(async (/** @type {string} */ p) => {
  const response = await fetch(p, { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
  return { status: response.status, body: await response.text() };
}, path);

/** Every id in the feed of the page's session. @param {any} page */
const feedIds = (page) => page.evaluate(async () => {
  const ids = [];
  let since = 0;
  for (let n = 0; n < 50; n += 1) {
    const response = await fetch(`/api/sync/changes?since=${since}&limit=500`, { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
    const feed = await response.json();
    ids.push(...feed.changes.map((/** @type {any} */ c) => c.id));
    if (!feed.has_more || feed.changes.length === 0) break;
    since = feed.changes[feed.changes.length - 1].seq;
  }
  return ids;
});

/**
 * Makes a login in the web vault of `page` and returns its id.
 * @param {any} page @param {{ name: string, username: string, password: string, url: string }} login
 */
async function makeLogin(page, login) {
  await page.locator('[data-role="nav-items"]').click();
  await page.locator('[data-role="new-item"]').click();
  await page.locator('[data-role="edit-form"]').waitFor();
  await page.locator('[data-role="name"]').fill(login.name);
  await page.locator('[data-role="username"]').fill(login.username);
  await page.locator('[data-role="password"]').fill(login.password);
  await page.locator('[data-role="url"]').fill(login.url);
  await page.locator('[data-role="save"]').click();
  await page.locator('[data-role="item"] h1', { hasText: login.name }).waitFor({ timeout: 30_000 });
  const id = /#\/items\/([0-9a-f]{32})/.exec(page.url())?.[1];
  assert.ok(id, `the web vault names the item (${page.url()})`);
  // On the server.
  for (let n = 0; n < 60 && !(await feedIds(page)).includes(id); n += 1) await sleep(1_000);
  assert.ok((await feedIds(page)).includes(id), "the server has the login");
  return id;
}

test("a_second_account_signs_in_syncs_and_fills_in_its_own_profile", async () => {
  for (const channel of channels()) {
    const { first, second } = await theTwoAccounts(channel);
    // A profile of the second account: the web vault and the extension signed in with it, its entry for the test site.
    const w = await world(channel, { entries: { host: ENTRIES.host }, account: second });
    const browser = await chromiumBrowser();
    try {
      assert.equal(w.account.email, second.email);
      const tag = randomBytes(4).toString("hex");
      const loginUrl = w.server.siteUrl("login");

      // The first account makes a login for the same page, in its own vault.
      const firstContext = await browser.newContext();
      const firstVault = await vaultOf(firstContext, first);
      const firstName = `First-${channel}-${tag}`;
      const firstId = await makeLogin(firstVault, { name: firstName, username: `first-${tag}`, password: `First-pw-${tag}`, url: loginUrl });

      // The second account makes a login in its web vault: it reaches the extension.
      const secondContext = await browser.newContext();
      const secondVault = await vaultOf(secondContext, second);
      const secondName = `Second-${channel}-${tag}`;
      const secondPassword = `Second-pw-${tag}`;
      const secondId = await makeLogin(secondVault, { name: secondName, username: `second-${tag}`, password: secondPassword, url: loginUrl });
      assert.equal((await feedIds(secondVault)).includes(firstId), false, `${channel}: the second account's feed has no row of the first`);
      assert.equal((await feedIds(firstVault)).includes(secondId), false, `${channel}: the first account's feed has no row of the second`);
      const ext = await w.session.newTab();
      await w.session.switchTo(ext);
      await w.session.waitFor(async () => {
        await w.session.navigate(POPUP_URL);
        await w.page.ready();
        await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
        await w.page.type('[data-role="search"]', secondName);
        await sleep(1_500);
        return w.session.content((/** @type {string} */ wanted) => [...document.querySelectorAll('[data-role="row-name"]')].some((n) => n.textContent?.trim() === wanted), secondName);
      }, SLOW, `${channel}: the second account's login in the extension's list`);
      assert.equal(await w.page.text('[data-role="account"]'), second.email, `${channel}: the extension is the second account's`);

      // On the test site's page: the second account's entries are offered, the first account's login never is.
      const tabId = await w.visit(loginUrl);
      const view = await w.popup(tabId);
      try {
        const names = (await view.suggestions()).map((s) => s.name);
        assert.ok(names.includes(w.named.host), `${channel}: the entry is offered (${names.join(", ")})`);
        assert.ok(names.includes(secondName), `${channel}: the web vault's login is offered (${names.join(", ")})`);
        assert.equal(names.includes(firstName), false, `${channel}: the first account's login is not offered`);
        await view.shot("76-popup-of-the-second-account");
        assert.equal(await view.fill(w.named.host), POPUP_TEXT["popup.filled"], channel);
      } finally {
        await view.close();
      }
      const values = await w.session.content(() => ({
        user: /** @type {HTMLInputElement} */ (document.getElementById("login-user")).value,
        pass: /** @type {HTMLInputElement} */ (document.getElementById("login-pass")).value,
      }));
      assert.deepEqual(values, { user: USERNAME, pass: w.passwords.host }, channel);

      // The extension holds rows of the second account only.
      const held = await w.fromBridge(() => w.session.content(() => new Promise((resolve, reject) => {
        const open = indexedDB.open("ferret");
        open.onupgradeneeded = () => open.transaction?.abort();
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const db = open.result;
          const all = db.transaction(["rows"], "readonly").objectStore("rows").getAllKeys();
          all.onerror = () => reject(all.error);
          all.onsuccess = () => {
            resolve(all.result.map((key) => (Array.isArray(key) ? key.map(String) : [String(key)])));
            db.close();
          };
        };
      })));
      const keys = /** @type {string[][]} */ (held);
      assert.ok(keys.some((key) => key.includes(secondId)), `${channel}: the extension holds the second account's login`);
      assert.equal(keys.some((key) => key.includes(firstId)), false, `${channel}: no row of the first account`);

      // The device the extension signed in as, for the next test.
      const listed = JSON.parse((await apiGet(secondVault, "/api/auth/devices")).body).devices;
      const ours = listed.filter((/** @type {any} */ d) => d.kind === "device" && d.name === DEVICE_NAME);
      assert.equal(ours.length, 1, `${channel}: one device of the extension (${JSON.stringify(listed)})`);
      writeFileSync(DEVICE_FILE, JSON.stringify({ id: ours[0].id }));
      await w.session.screenshot(shotPath(channel, "76-second-account-filled"));
      await firstContext.close();
      await secondContext.close();
    } finally {
      await browser.close().catch(() => {});
      await w.quit();
    }
  }
});

test("its_device_is_listed_for_it_only", async () => {
  for (const channel of channels()) {
    const { first, second } = await theTwoAccounts(channel);
    assert.ok(existsSync(DEVICE_FILE), "the first test of this file signed the extension in as the second account");
    const { id } = JSON.parse(readFileSync(DEVICE_FILE, "utf8"));
    const browser = await chromiumBrowser();
    try {
      const secondContext = await browser.newContext();
      const secondVault = await vaultOf(secondContext, second);
      const own = await apiGet(secondVault, "/api/auth/devices");
      assert.equal(own.status, 200, own.body);
      assert.ok(JSON.parse(own.body).devices.some((/** @type {any} */ d) => d.id === id && d.kind === "device"), `${channel}: the second account lists its extension`);
      // The web vault's page of devices shows it too.
      await secondVault.evaluate(() => { location.hash = "#/devices"; });
      await secondVault.locator('[data-role="devices-row"][data-kind="device"]', { hasText: DEVICE_NAME }).first().waitFor({ timeout: 30_000 });

      const firstContext = await browser.newContext();
      const firstVault = await vaultOf(firstContext, first);
      const theirs = await apiGet(firstVault, "/api/auth/devices");
      assert.equal(theirs.status, 200, theirs.body);
      assert.equal(theirs.body.includes(id), false, `${channel}: the first account's list does not have the second account's device`);
      // Nor can the first account revoke it.
      const revoke = await firstVault.evaluate(async (/** @type {string} */ device) => {
        const response = await fetch(`/api/auth/devices/${device}`, { method: "DELETE", headers: { "Ferret-Protocol": "1" } });
        return response.status;
      }, id);
      assert.equal(revoke, 404, `${channel}: another account's device is unknown`);
      const still = await apiGet(secondVault, "/api/auth/devices");
      assert.ok(JSON.parse(still.body).devices.some((/** @type {any} */ d) => d.id === id), `${channel}: the device is still the second account's`);
      await firstContext.close();
      await secondContext.close();
    } finally {
      await browser.close().catch(() => {});
    }
  }
});
