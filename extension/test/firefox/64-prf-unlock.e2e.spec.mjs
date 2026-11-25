// Unlocking with a passkey in the extension, in real Firefox against the end-to-end stack (run by `scripts/lanbox-ext.sh e2e`):
// a real server, the real background with its handlers and the real core, and Firefox's own virtual authenticator (WebDriver's
// Web Authentication extension, on the soft token) that evaluates the PRF. The passkey is made where it is made for real, in
// the web vault's page "Unlock methods" on the vault's exact host; the extension then opens its locked vault with it: the
// popup offers the button, the button opens the unlock window in a window of its own (a popup cannot make the call: it closes
// when the system's dialog takes the focus), one press makes the one WebAuthn call, and the vault opens. One credential
// serves the web vault and the extension: the extension asks for the passkey on the vault's host, which it has the host
// permission for.
//
// The virtual authenticator answers with the same PRF value for every credential, so "another key gives another result" is not
// something this spec can show; the unit tests do it (a key that does not open the wrap is one plain failure).
//
// The stack must be fresh (`e2e-up`), as for the other end-to-end specs; the account is the one the first channel made.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, VAULT_HOST, extensionSignIn, helpers, pace, webVaultAccount } from "./e2e.mjs";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, channels, launch, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const UNLOCK_WINDOW_URL = `${EXTENSION_ORIGIN}/pages/unlockWindow.html`;
const NAME = "Virtual passkey";

/**
 * One request over the UI port of the extension page the current tab shows.
 * @param {import("./driver.mjs").Session} session
 * @param {string} type @param {unknown} body
 * @returns {Promise<any>} the reply body
 */
function ask(session, type, body) {
  return session.content(
    (/** @type {string} */ kind, /** @type {unknown} */ payload) =>
      new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-ui" });
        const timer = setTimeout(() => reject(new Error("the UI port did not answer")), 170_000);
        port.onMessage.addListener((raw) => {
          const message = JSON.parse(typeof raw === "string" ? raw : JSON.stringify(raw));
          clearTimeout(timer);
          port.disconnect();
          resolve(message.body);
        });
        port.onDisconnect.addListener(() => reject(new Error("the UI port hung up")));
        port.postMessage(JSON.stringify({ v: 1, id: "a1", type: kind, body: payload }));
      }),
    type,
    body,
  );
}

/**
 * Makes the account's passkey in the web vault (the account is signed in there), and returns to a blank page.
 * @param {import("./driver.mjs").Session} session
 * @param {{ password: string }} account
 */
async function addPasskey(session, account) {
  const page = helpers(session);
  await session.content(() => {
    location.hash = "#/unlock-methods";
  });
  await page.waitVisible('[data-role="methods-page"]', SLOW);
  await page.waitVisible('[data-role="methods-empty"]', SLOW);
  await pace();
  await page.click('[data-role="methods-add"]');
  // The page asks for the master password again when the last check is older than a minute.
  const asked = await page.waitAny(['[data-role="reauth-dialog"]', '[data-role="methods-name-form"]'], SLOW);
  if (asked === '[data-role="reauth-dialog"]') {
    await page.type('[data-role="reauth-password"]', account.password);
    await pace();
    await page.click('[data-role="reauth-confirm"]');
  }
  await page.waitVisible('[data-role="methods-name-form"]', SLOW);
  await page.type('[data-role="methods-name-input"]', NAME);
  await page.click('[data-role="methods-create"]');
  await page.waitVisible('[data-role="methods-confirm"]', SLOW);
  await page.click('[data-role="methods-confirm"]');
  await page.waitVisible('[data-role="methods-done"]', SLOW);
}

test("prf_unlock_after_lock_in_release_and_esr", async () => {
  for (const channel of channels()) {
    // The soft token answers the virtual authenticator; the default profile uses the USB token, which a container has none of.
    const session = await launch({
      channel,
      prefs: { "security.webauth.webauthn_enable_softtoken": true, "security.webauth.webauthn_enable_usbtoken": false },
    });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      await session.addVirtualAuthenticator();
      const account = await webVaultAccount(session, channel);
      await addPasskey(session, account);

      // The extension signs in as a device, then locks.
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await ask(session, "lock", {});
      assert.equal((await ask(session, "state", {})).state, "locked", channel);

      // The locked popup offers the passkey (the account has one and the server allows them).
      const popup = helpers(session);
      await session.navigate(POPUP_URL);
      await popup.ready();
      await popup.waitVisible('[data-role="unlock-passkey"]', SLOW);
      // The popup is a page of the extension that no passkey call can come from: it asks for the window and the window is the
      // only page that may send the result.
      const refused = await ask(session, "prf_unlock", { credential_id: "AQID", prf_output: "a".repeat(43) });
      assert.equal(refused.reason, "not_available", `${channel}: ${JSON.stringify(refused)}`);
      assert.equal((await ask(session, "state", {})).state, "locked", channel);

      // The button opens the window in a window of its own.
      const before = await session.windowHandles();
      await popup.click('[data-role="unlock-passkey"]');
      const opened = await session.waitFor(async () => {
        const now = await session.windowHandles();
        return now.find((handle) => !before.includes(handle)) ?? null;
      }, 30_000, "the unlock window");
      await session.switchTo(opened);
      await session.waitFor(async () => (await session.currentUrl()) === UNLOCK_WINDOW_URL, 30_000, "the unlock window to load");
      const win = helpers(session);
      await win.waitVisible('[data-role="passkey-unlock"]', SLOW);
      assert.equal(await win.text('[data-role="passkey-host"]'), `Unlock ${VAULT_HOST} with a passkey.`, channel);

      // One press: the one WebAuthn call, the 32 bytes to the background in one message, and the vault is open.
      await win.click('[data-role="passkey-unlock"]');
      await session.waitFor(
        async () => (await session.content(() => document.body?.dataset.done === "1" || document.querySelector('[data-role="passkey-error"]') !== null)) === true,
        SLOW,
        "the end of the passkey unlock",
      );
      const error = await session.content(() => document.querySelector('[data-role="passkey-error"]')?.textContent ?? "");
      assert.equal(error, "", `${channel}: the passkey unlock said: ${error}`);
      assert.equal((await ask(session, "state", {})).state, "unlocked", channel);

      // The window closes by itself.
      await session.waitFor(async () => !(await session.windowHandles()).includes(opened), 30_000, "the window to close");
      const [first] = await session.windowHandles();
      await session.switchTo(first);

      // A second time, straight from the window page in a tab: lock, press, open. The list is read again each time.
      await ask(session, "lock", {});
      await session.navigate(UNLOCK_WINDOW_URL);
      await helpers(session).ready().catch(() => {});
      await helpers(session).waitVisible('[data-role="passkey-unlock"]', SLOW);
      await helpers(session).click('[data-role="passkey-unlock"]');
      await session.waitFor(async () => (await session.content(() => document.body?.dataset.done === "1")) === true, SLOW, "the second passkey unlock");
      assert.equal((await ask(session, "state", {})).state, "unlocked", channel);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 6 });
