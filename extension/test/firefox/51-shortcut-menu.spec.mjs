// The keyboard shortcut and the context menu in real Firefox (chrome context, so
// the shortcut is a real key press and the menu click a real click, and Firefox
// grants activeTab for each): the menu has one fixed item on editable fields,
// and both open the popup when nothing can be filled, while the vault is
// locked and while it is open with no match. The fill itself, which needs a
// synced vault, is in 51-shortcut-menu.e2e.spec.mjs.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { ABOUT_URL, TEST_ADDON_ID, channels, fixtures, launch, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/** The shortcut of the fill command (manifest/parts/commands.json). */
const FILL_SHORTCUT = "Alt+Shift+L";
const MENU_LABEL = "Fill with Ferret";

test("the_menu_has_one_fixed_item_and_the_shortcut_and_the_menu_open_the_popup_when_nothing_can_be_filled", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      // An extension page of our own to look from (not the bridge: its test menu item would join ours in a submenu).
      const homeTab = await session.windowHandle();
      await session.navigate(ABOUT_URL);
      await session.waitFor(() => session.content(() => document.readyState === "complete"), 20_000, "the about page");

      const url = server.url(server.hosts[0], "/static/login.html");
      const pageTab = await session.newTab();
      await session.switchTo(pageTab);
      await session.navigate(url);
      await session.waitFor(() => session.findAll("#password").then((found) => found.length === 1), 10_000, "the sign-in form");

      /** Runs `body` in the extension's own tab and comes back to the page. @template T @param {() => Promise<T>} body */
      const fromHome = async (body) => {
        await session.switchTo(homeTab);
        try {
          return await body();
        } finally {
          await session.switchTo(pageTab);
        }
      };
      const popups = () => fromHome(() => session.content(() => browser.extension.getViews({ type: "popup" }).length));
      const closePopups = () => fromHome(() => session.content(() => {
        for (const view of browser.extension.getViews({ type: "popup" })) view.close();
        return true;
      }));
      /** Waits for the popup, then closes it. @param {string} what */
      const expectPopup = async (what) => {
        await session.waitFor(async () => (await popups()) === 1, 10_000, `${channel}: the popup after ${what}`);
        await closePopups();
        await session.waitFor(async () => (await popups()) === 0, 10_000, "the popup to close");
      };
      const value = (/** @type {string} */ id) => session.content((/** @type {string} */ field) => document.getElementById(field).value, id);

      // One item of ours, on a password field and on a user name field, with the fixed title: never a name.
      for (const target of ["#password", "#username"]) {
        const items = await session.contextMenuItems(target);
        const ours = items.filter((i) => typeof i.id === "string" && i.id.includes("ferret-fill"));
        assert.deepEqual(ours.map((i) => i.label), [MENU_LABEL], `${channel}: ${target}: ${JSON.stringify(items)}`);
        assert.equal(ours[0].nested, false, "a top-level item, not a submenu");
      }

      // Locked: the shortcut opens the popup (which asks for the master password), and so does the menu.
      assert.equal(await popups(), 0);
      await session.pressShortcut(FILL_SHORTCUT);
      await expectPopup("the shortcut while locked");
      await session.clickContextMenuItem(MENU_LABEL, "#password");
      await expectPopup("the menu while locked");

      // Open, with no match for the page: both open the popup after the page matching.
      const opened = await fromHome(() => session.content(() => new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-test-core" });
        const timer = setTimeout(() => reject(new Error("the core port did not answer")), 20_000);
        port.onMessage.addListener((reply) => {
          clearTimeout(timer);
          port.disconnect();
          resolve(JSON.stringify(reply));
        });
        port.postMessage({ id: "1", op: "measure_open" });
      })));
      assert.equal(JSON.parse(opened).ok, true, `${channel}: the test build opened its vault: ${opened}`);
      await session.pressShortcut(FILL_SHORTCUT);
      await expectPopup("the shortcut with no match");
      await session.clickContextMenuItem(MENU_LABEL, "#password");
      await expectPopup("the menu with no match");
      assert.equal(await value("password"), "", "nothing was filled");
      assert.equal(await value("username"), "");
    } finally {
      await session.quit();
    }
  }
});
