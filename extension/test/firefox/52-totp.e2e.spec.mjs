// The one-time code of a login in the popup, in a real Firefox against the end-to-end stack: an item with a one-time-code
// secret reaches the extension through the sync, the popup's view of it shows the live code (the same code an RFC 6238
// reference gives for the clock), "Copy" says the clipboard is cleared, and "Fill the code" puts the code into the page's
// one-time-code field. After the sign-in of the same item is filled, the popup offers the code on the page that follows.
// A row of the search result offers "Copy one-time code" in its copy menu when its item holds a code, and copies it.
//
// The item is made with the test build's probe (the web vault's edit form is another change), with a secret of this run's
// making. The popup runs in a window of its own that names the tab (`?tab=`), as a popped-out popup does; activeTab comes
// from a real shortcut on the page's tab.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, extensionSignIn, helpers, start, webVaultAccount } from "./e2e.mjs";
import { TEST_SHORTCUT, channels, fixtures, openBridge, stopFixtures } from "./harness.mjs";
import { base32, recentCodes } from "./totp.mjs";

after(() => stopFixtures());

test("the_popup_shows_copies_and_fills_the_one_time_code_and_offers_it_after_the_sign_in", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const server = await fixtures();
      const host = server.hosts[0];
      const loginUrl = server.url(host, "/static/login.html");
      const codeUrl = server.url(host, "/otp-single-de/");
      const page = helpers(session);
      const tag = randomBytes(4).toString("hex");
      const name = `Totp-login-${tag}`;
      const username = `alice-${tag}@fixture.example`;
      const password = `Fill-me-${tag}-correct-horse`;
      const secret = base32(randomBytes(20));

      const account = await webVaultAccount(session, channel);
      const extensionTab = await session.newTab();
      await session.switchTo(extensionTab);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await session.navigate(POPUP_URL);
      await page.ready();
      await page.waitVisible('[data-role="sync"][data-state="idle"]', SLOW);
      const bridge = await openBridge(session);

      /** One core operation of the test build, asked from the bridge tab. @param {string} op @param {Record<string, unknown>} args */
      const core = async (op, args) => {
        const reply = JSON.parse(
          await session.content((/** @type {string} */ text) => new Promise((resolve, reject) => {
            const port = browser.runtime.connect({ name: "ferret-test-core" });
            const timer = setTimeout(() => reject(new Error("the test core did not answer")), 120_000);
            port.onMessage.addListener((answer) => {
              clearTimeout(timer);
              port.disconnect();
              resolve(typeof answer === "string" ? answer : JSON.stringify(answer));
            });
            port.postMessage(JSON.parse(text));
          }), JSON.stringify({ id: "1", op, args })),
        );
        assert.equal(reply.ok, true, `${channel}: ${op}: ${reply.code}`);
        return reply.value;
      };
      await core("item_probe", { name, url: server.url(host, "/"), matching: "host", username, password, totp: `otpauth://totp/${encodeURIComponent(name)}?secret=${secret}` });

      const pageTab = await session.newTab();
      /** Opens `url` in the page's tab, presses the shortcut there (activeTab) and returns the tab's id. @param {string} url */
      const visit = async (url) => {
        await session.switchTo(extensionTab);
        await bridge.clearEvents();
        await session.switchTo(pageTab);
        await session.navigate(url);
        await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, url);
        await session.pressShortcut(TEST_SHORTCUT);
        await session.switchTo(extensionTab);
        const command = await session.waitFor(async () => (await bridge.events()).find((e) => e.kind === "command"), 15_000, "the command event");
        return /** @type {number} */ (command.tabId);
      };
      /** The popup in a window of its own, about the tab; the row of this run's item is marked. @param {number} tabId */
      const popupFor = async (tabId) => {
        const popupWindow = await session.newWindow();
        await session.switchTo(popupWindow);
        await session.navigate(`${POPUP_URL}?tab=${tabId}`);
        await page.ready();
        await page.waitVisible('[data-role="suggestion"]', SLOW);
        await session.waitFor(
          () => session.content((/** @type {string} */ wanted) => {
            const row = [...document.querySelectorAll('[data-role="suggestion"]')].find((r) => r.querySelector('[data-role="row-name"]')?.textContent?.trim() === wanted);
            if (!row) return false;
            (row.closest('[data-role="suggestion-next"]') ?? row).setAttribute("data-e2e-this-run", "1");
            return true;
          }, name),
          SLOW,
          "this run's suggestion",
        );
        return popupWindow;
      };
      /** The digits of the code on show. */
      const shownCode = async () => (await page.text('[data-role="totp-code"]')).replace(/\s/g, "");

      // ---- the item's view: the live code, the countdown, copy and fill, on a page with a one-time-code field.
      const codeTab = await visit(codeUrl);
      await popupFor(codeTab);
      // No code card under the row: the page was not signed in with Ferret here.
      assert.equal(await page.visible('[data-role="suggestion-next"]'), false, `${channel}: no offer before a sign-in was filled`);
      await page.click('[data-e2e-this-run] [data-role="more"]');
      await page.click('[data-e2e-this-run] [data-role="menu-view"]');
      await page.waitVisible('[data-role="totp-card"]');
      await session.waitFor(async () => /^[0-9]{6}$/.test(await shownCode()), 20_000, "the code");
      const first = await shownCode();
      assert.ok(recentCodes(secret).includes(first), `${channel}: the popup shows the RFC 6238 code of the secret`);
      assert.match(await page.text('[data-role="totp-left"]'), /^Changes in [0-9]+ s$/);
      // The countdown runs.
      const left = await page.text('[data-role="totp-left"]');
      await session.waitFor(async () => (await page.text('[data-role="totp-left"]')) !== left, 5_000, "the countdown");
      // Copy says that the clipboard is cleared.
      await page.click('[data-role="totp-copy"]');
      await page.waitVisible('[data-role="toast"]', 20_000);
      assert.match(await page.text('[data-role="toast"]'), /^One-time code copied\. Ferret clears the clipboard after 30 seconds/);
      // Fill puts the code into the page's field. The note of the copy covers the foot of the list until it ends.
      await session.waitFor(async () => !(await page.visible('[data-role="toast"]')), 20_000, "the copy note to end");
      await page.click('[data-role="totp-fill"]');
      await session.waitFor(async () => (await page.text('[data-role="toast"]')) === "Code filled in.", 20_000, "the fill note");
      // The popup never had the secret.
      const shown = await session.content(() => document.documentElement.outerHTML);
      assert.equal(shown.includes(secret), false, `${channel}: the popup does not hold the secret`);
      assert.equal(shown.includes(password), false, `${channel}: the popup does not hold the password`);
      await session.switchTo(pageTab);
      const value = (/** @type {string} */ id) => session.content((/** @type {string} */ field) => /** @type {HTMLInputElement} */ (document.getElementById(field)).value, id);
      assert.ok(recentCodes(secret).includes(await value("code")), `${channel}: the field got the code`);

      // ---- after the sign-in is filled, the page that follows is offered the code.
      const loginTab = await visit(loginUrl);
      await popupFor(loginTab);
      await page.click('[data-e2e-this-run] [data-role="fill"]');
      await session.waitFor(async () => (await page.text('[data-role="toast"]')) === "Filled in.", 20_000, "the sign-in fill note");
      await session.switchTo(pageTab);
      assert.equal(await value("username"), username, channel);
      assert.equal(await value("password"), password, channel);

      // The next step of the same tab: a page that asks for the code.
      const nextTab = await visit(codeUrl);
      await popupFor(nextTab);
      await page.waitVisible('[data-e2e-this-run][data-role="suggestion-next"] [data-role="totp-card"]', SLOW);
      await session.waitFor(async () => /^[0-9]{6}$/.test(await shownCode()), 20_000, "the offered code");
      assert.ok(recentCodes(secret).includes(await shownCode()), `${channel}: the offered code is the secret's`);
      await page.click('[data-e2e-this-run] [data-role="totp-fill"]');
      await session.waitFor(async () => (await page.text('[data-role="toast"]')) === "Code filled in.", 20_000, "the code fill note");
      await session.switchTo(pageTab);
      assert.ok(recentCodes(secret).includes(await value("code")), `${channel}: the next step got the code`);

      // ---- a row of the search result: its copy menu offers the code for the item that holds one, and only for it.
      const plainName = `Plain-login-${tag}`;
      await session.switchTo(extensionTab);
      await core("item_probe", { name: plainName, url: server.url(host, "/"), matching: "host", username: `bob-${tag}@fixture.example`, password: `Plain-${tag}-correct-horse` });
      await popupFor(await visit(codeUrl));
      await page.type('[data-role="search"]', tag);
      /** Marks the rows of the two items (the list draws its rows again when the sync brings a change). @param {string[]} wanted */
      const markRows = (wanted) =>
        session.content((/** @type {string[]} */ names) => {
          const rows = [...document.querySelectorAll('[data-role="item-row"]')];
          const found = names.map((w) => rows.find((r) => r.querySelector('[data-role="row-name"]')?.textContent?.trim() === w));
          found.forEach((r, i) => r?.setAttribute("data-e2e-row", String(i)));
          return found.every(Boolean);
        }, wanted);
      /** Opens the copy menu of a marked row (0: the item with a code, 1: the one without) and waits for it to show. @param {number} at */
      const openCopyMenu = (at) =>
        session.waitFor(
          async () => {
            if (!(await markRows([name, plainName]))) return false;
            const shown = `[data-e2e-row="${at}"] [data-role="copy-password"]`;
            if (!(await page.visible(shown))) await page.click(`[data-e2e-row="${at}"] [data-role="copy"]`);
            return page.visible(shown);
          },
          SLOW,
          `the copy menu of row ${at}`,
        );
      // The row of the item without a code has no entry for it.
      await openCopyMenu(1);
      assert.equal(await page.visible('[data-e2e-row="1"] [data-role="copy-totp"]'), false, `${channel}: no code entry for an item without a code`);
      // The row of the item with a code copies it.
      await openCopyMenu(0);
      assert.equal(await page.visible('[data-e2e-row="0"] [data-role="copy-totp"]'), true, `${channel}: the code entry for an item with a code`);
      await page.click('[data-e2e-row="0"] [data-role="copy-totp"]');
      await page.waitVisible('[data-role="toast"]', 20_000);
      assert.match(await page.text('[data-role="toast"]'), /^One-time code copied\. Ferret clears the clipboard after 30 seconds/);
    } finally {
      await session.quit();
    }
  }
});
