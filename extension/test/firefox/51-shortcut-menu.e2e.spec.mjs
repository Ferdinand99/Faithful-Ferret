// The keyboard shortcut and the context menu fill a login in a real Firefox
// against the end-to-end stack: a login made in the web vault (with the address
// of the fixture's sign-in page) reaches the extension through the sync, a real
// Alt+Shift+L on the page fills both fields, and so does a real click on "Fill
// with Ferret" on the password field after the page is loaded again. Neither
// opens the popup, since exactly one login matches.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, extensionSignIn, helpers, start, webVaultAccount } from "./e2e.mjs";
import { channels, fixtures, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/** The shortcut of the fill command (manifest/parts/commands.json) and the menu item's title. */
const FILL_SHORTCUT = "Alt+Shift+L";
const MENU_LABEL = "Fill with Ferret";
/** @type {Record<string, string>} */
const OWN_HOST = { release: "second.fixture.test", esr: "login.example.org" };

test("shortcut_and_menu_each_fill_the_fixture_login", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const server = await fixtures();
      // A host of its own per channel: the stack's one account keeps the logins of the other specs and of the other
      // channel, and a second match would (rightly) open the popup instead of filling.
      const loginUrl = server.url(OWN_HOST[channel] ?? "second.fixture.test", "/static/login.html");
      const page = helpers(session);
      const tag = randomBytes(4).toString("hex");
      const name = `Shortcut-login-${tag}`;
      const username = `bob-${tag}@fixture.example`;
      const password = `Shortcut-${tag}-correct-horse`;

      // The login, made in the web vault.
      const account = await webVaultAccount(session, channel);
      await page.click('[data-role="nav-items"]');
      await page.waitVisible('[data-role="new-item"]');
      await page.click('[data-role="new-item"]');
      await page.waitVisible('[data-role="edit-form"]');
      await page.type('[data-role="name"]', name);
      await page.type('[data-role="username"]', username);
      await page.type('[data-role="password"]', password);
      await page.type('[data-role="url"]', loginUrl);
      await page.click('[data-role="save"]');
      await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the saved item");

      // The extension signs in, syncs, and its list has the login.
      const extensionTab = await session.newTab();
      await session.switchTo(extensionTab);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await session.navigate(POPUP_URL);
      await page.ready();
      await session.waitFor(
        () => session.content((/** @type {string} */ wanted) => [...document.querySelectorAll('[data-role="row-name"]')].some((n) => n.textContent?.includes(wanted)), name),
        SLOW,
        "the login in the extension's list",
      );
      const popups = async () => {
        await session.switchTo(extensionTab);
        try {
          return await session.content(() => browser.extension.getViews({ type: "popup" }).length);
        } finally {
          await session.switchTo(pageTab);
        }
      };

      // The page, and a real shortcut on its tab: one login matches, so it is filled.
      const pageTab = await session.newTab();
      await session.switchTo(pageTab);
      await session.navigate(loginUrl);
      await session.waitFor(() => session.findAll("#password").then((found) => found.length === 1), 10_000, "the sign-in form");
      const value = (/** @type {string} */ id) => session.content((/** @type {string} */ field) => /** @type {HTMLInputElement} */ (document.getElementById(field)).value, id);
      await session.pressShortcut(FILL_SHORTCUT);
      await session.waitFor(async () => (await value("password")) === password, 20_000, `${channel}: the shortcut's fill`);
      assert.equal(await value("username"), username, channel);
      assert.equal(await popups(), 0, `${channel}: no popup for one match`);

      // The page again, empty, and a real click on the menu item on the password field.
      await session.navigate(loginUrl);
      await session.waitFor(async () => (await session.findAll("#password")).length === 1 && (await value("password")) === "", 10_000, "the sign-in form again");
      await session.clickContextMenuItem(MENU_LABEL, "#password");
      await session.waitFor(async () => (await value("password")) === password, 20_000, `${channel}: the menu's fill`);
      assert.equal(await value("username"), username, channel);
      assert.equal(await popups(), 0, `${channel}: no popup for one match`);
    } finally {
      await session.quit();
    }
  }
});
