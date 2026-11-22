// "Fill" from the popup in a real Firefox against the end-to-end stack: a login
// made in the web vault (with the address of the fixture's sign-in page)
// reaches the extension through the sync, the popup offers it for that page,
// and a click on "Fill" puts the user name and the password into the page. The
// values go from the background to the page's frame; the popup shows neither.
//
// activeTab comes from a real shortcut on the page's tab (chrome context). The
// popup runs in a window of its own that names that tab (`?tab=`), as a popped
// out popup does. The page's candidates come from the test build's stand-in for
// the page matching (the core's `match_page` for the top frame).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, extensionSignIn, helpers, start, webVaultAccount } from "./e2e.mjs";
import { TEST_COMMAND, TEST_SHORTCUT, channels, fixtures, openBridge, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

test("click_fills_the_fixture_login", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const server = await fixtures();
      const loginUrl = server.url(server.hosts[0], "/static/login.html");
      const page = helpers(session);
      const tag = randomBytes(4).toString("hex");
      const name = `Fixture-login-${tag}`;
      const username = `alice-${tag}@fixture.example`;
      const password = `Fill-me-${tag}-correct-horse`;

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
      const bridge = await openBridge(session);

      // The page, and a real shortcut on its tab: Firefox grants activeTab for it.
      const pageTab = await session.newTab();
      await session.switchTo(pageTab);
      await session.navigate(loginUrl);
      await session.waitFor(() => session.findAll("#username").then((found) => found.length === 1), 10_000, "the sign-in form");
      await session.pressShortcut(TEST_SHORTCUT);
      await session.switchTo(extensionTab);
      const command = await session.waitFor(async () => (await bridge.events()).find((e) => e.kind === "command"), 10_000, "the command event");
      assert.equal(command.name, TEST_COMMAND);
      assert.equal(command.tabUrl, loginUrl, `${channel}: activeTab was granted`);

      // The popup, in a window of its own, about that tab.
      const popupWindow = await session.newWindow();
      await session.switchTo(popupWindow);
      await session.navigate(`${POPUP_URL}?tab=${command.tabId}`);
      await page.ready();
      await page.waitVisible('[data-role="suggestion"]', SLOW);
      // The stack's one account keeps the logins of the other channel too: this run's login is the row with its name.
      const marked = await session.waitFor(() => session.content((/** @type {string} */ wanted) => {
        const row = [...document.querySelectorAll('[data-role="suggestion"]')].find((r) => r.querySelector('[data-role="row-name"]')?.textContent?.trim() === wanted);
        if (!row) return false;
        row.setAttribute("data-e2e-this-run", "1");
        return true;
      }, name), SLOW, "this run's suggestion");
      assert.equal(marked, true);
      assert.equal(await page.text('[data-e2e-this-run] [data-role="row-user"]'), username);
      await page.click('[data-e2e-this-run] [data-role="fill"]');
      await page.waitVisible('[data-role="toast"]', 20_000);
      assert.equal(await page.text('[data-role="toast"]'), "Filled in.", channel);
      // The popup never had the password.
      const shown = await session.content(() => document.documentElement.outerHTML);
      assert.equal(shown.includes(password), false, `${channel}: the popup shows no password`);

      // The page has both values.
      await session.switchTo(pageTab);
      const value = (/** @type {string} */ id) => session.content((/** @type {string} */ field) => /** @type {HTMLInputElement} */ (document.getElementById(field)).value, id);
      assert.equal(await value("username"), username, channel);
      assert.equal(await value("password"), password, channel);
    } finally {
      await session.quit();
    }
  }
});
