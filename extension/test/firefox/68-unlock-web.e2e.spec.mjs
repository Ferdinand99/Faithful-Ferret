// The web vault's passkey unlock methods in real Firefox, and the whole of the unlock in one run (run by
// `scripts/lanbox-ext.sh e2e`). The web vault's own specs drive Chromium, whose virtual authenticator Playwright can reach;
// Playwright's Firefox has no such thing, so the Firefox side of the same page is driven here through geckodriver, whose Web
// Authentication extension adds a virtual authenticator that evaluates the PRF (as 64 does for the extension).
//
//  - `the_web_vault_unlock_methods_page_works_in_firefox`: the page "Unlock methods" lists, adds and removes a passkey; while the
//    session lives, a reload leaves the vault locked and the unlock page offers the passkey, one press opens the vault with no
//    password sign-in; after a lock the same; a removed passkey is not offered.
//  - `full_u3_flow_end_to_end`: one account, one Firefox. A passkey is made in the web vault; the extension signs in, sets a PIN
//    on disk and unlocks with it; the extension unlocks with the passkey in the unlock window; the passkey is removed in the web
//    vault and the extension no longer offers it while the PIN still works; and neither the PIN nor what the passkey gave (read
//    again from the web vault page, which is the only other place that can ask for it) is in any file of the browser's profile.
//
// The stack must be fresh (`e2e-up`), as for the other end-to-end specs; the account is the one the first channel made.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, VAULT_URL, extensionSignIn, helpers, pace, webVaultAccount } from "./e2e.mjs";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, channels, launch, stopFixtures } from "./harness.mjs";
import { SENTINEL_PREFIX, addPasskey, ask, onBridge, pinPlaces, scanFolder, setPin } from "./unlock.mjs";

after(() => stopFixtures());

const UNLOCK_WINDOW_URL = `${EXTENSION_ORIGIN}/pages/unlockWindow.html`;
const PIN = `${SENTINEL_PREFIX}web-flow-æøå`;

/** The soft token answers the virtual authenticator; the default profile uses the USB token, which a container has none of. */
const SOFT_TOKEN = { "security.webauth.webauthn_enable_softtoken": true, "security.webauth.webauthn_enable_usbtoken": false };

/** @typedef {import("./driver.mjs").Session} Session */

/** Reloads the web vault page the tab shows. @param {Session} session */
async function reload(session) {
  await session.content(() => location.reload());
}

/** The master password dialog, when the page asks for it. @param {Session} session @param {{ password: string }} account */
async function answerReauth(session, account) {
  const page = helpers(session);
  await page.type('[data-role="reauth-password"]', account.password);
  await pace();
  await page.click('[data-role="reauth-confirm"]');
}

/**
 * The passkey methods the server lists, from the page's own session.
 * @param {Session} session
 * @returns {Promise<Array<Record<string, any>>>}
 */
async function serverPasskeys(session) {
  const raw = await session.content(async (/** @type {string} */ url) => {
    const response = await fetch(`${url}/api/vault/unlock-methods`, { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
    return JSON.stringify({ status: response.status, body: await response.json() });
  }, VAULT_URL);
  const { status, body } = JSON.parse(raw);
  assert.equal(status, 200, "the list of methods");
  return body.methods.filter((/** @type {any} */ method) => method.method_type === 3);
}

/** Removes the account's passkeys on the page "Unlock methods" (the page is open). @param {Session} session @param {{ password: string }} account */
async function removePasskeys(session, account) {
  const page = helpers(session);
  const count = async () => (await session.findAll('[data-role="methods-row"]')).length;
  for (let left = await count(); left > 0; left = await count()) {
    await page.click('[data-role="methods-remove"]');
    await page.waitVisible('[data-role="dialog-confirm"]', SLOW);
    await page.click('[data-role="dialog-confirm"]');
    const next = await page.waitAny(['[data-role="reauth-dialog"]', '[data-role="methods-done"]'], SLOW);
    if (next === '[data-role="reauth-dialog"]') await answerReauth(session, account);
    await session.waitFor(async () => (await count()) < left, SLOW, "the removal");
  }
}

test("the_web_vault_unlock_methods_page_works_in_firefox", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel, prefs: SOFT_TOKEN });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      await session.addVirtualAuthenticator();
      const account = await webVaultAccount(session, channel);
      const page = helpers(session);
      const name = `Firefox passkey ${channel}`;
      await addPasskey(session, account, name);

      // The list shows the passkey, by the name that only the sealed manifest holds, and the server lists one method.
      await session.content(() => {
        location.hash = "#/unlock-methods";
      });
      await page.waitVisible('[data-role="methods-page"]', SLOW);
      await session.waitFor(async () => (await session.findAll('[data-role="methods-row"]')).length === 1, SLOW, "the one passkey");
      assert.equal(await page.text('[data-role="methods-row"] [data-role="methods-row-name"]'), name, channel);
      const listed = await serverPasskeys(session);
      assert.equal(listed.length, 1, `${channel}: the server lists one passkey`);
      assert.ok(!JSON.stringify(listed).includes(name), `${channel}: the name is not in what the server holds`);

      // A reload: the vault is closed, the session on the server is still good, and the unlock page offers the passkey.
      await reload(session);
      await page.waitVisible('[data-role="unlock"][data-mode="session"]', SLOW);
      await page.waitVisible('[data-role="passkey-unlock"]', SLOW);
      await page.click('[data-role="passkey-unlock"]');
      await page.waitVisible('[data-role="methods-page"]', SLOW);
      await session.waitFor(async () => (await session.findAll('[data-role="methods-row"]')).length === 1, SLOW, "the passkey after the unlock");
      assert.equal(await page.text('[data-role="methods-row"] [data-role="methods-row-name"]'), name, `${channel}: the vault is open: the sealed name reads`);

      // A lock without a reload: the same offer, the same press.
      await page.click('[data-role="account-menu-button"]');
      await page.click('[data-role="lock"]');
      await page.waitVisible('[data-role="unlock"][data-mode="session"]', SLOW);
      await page.waitVisible('[data-role="passkey-unlock"]', SLOW);
      await page.click('[data-role="passkey-unlock"]');
      await session.waitFor(async () => (await page.visible('[data-role="methods-page"]')) || (await page.visible('[data-role="list"]')), SLOW, "the vault after the second press");

      // Removing the passkey: it is gone from the server, and the unlock page no longer offers it.
      await session.content(() => {
        location.hash = "#/unlock-methods";
      });
      await page.waitVisible('[data-role="methods-page"]', SLOW);
      await session.waitFor(async () => (await session.findAll('[data-role="methods-row"]')).length === 1, SLOW, "the passkey to remove");
      await removePasskeys(session, account);
      assert.deepEqual(await serverPasskeys(session), [], `${channel}: the server lists none`);
      await reload(session);
      await page.waitVisible('[data-role="unlock"][data-mode="session"]', SLOW);
      await page.waitVisible('[data-role="password"]', SLOW);
      assert.equal(await page.visible('[data-role="passkey-unlock"]'), false, `${channel}: a removed passkey is not offered`);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 8 });

test("full_u3_flow_end_to_end", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel, prefs: SOFT_TOKEN });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      await session.addVirtualAuthenticator();
      const account = await webVaultAccount(session, channel);
      const webTab = await session.windowHandle();
      await addPasskey(session, account, `Flow passkey ${channel}`);

      // The extension, in a tab of its own: sign in, a PIN on disk, a lock and an unlock with the PIN.
      const extTab = await session.newTab();
      await session.switchTo(extTab);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await onBridge(session);
      await setPin(session, account, PIN, "disk");
      assert.equal((await pinPlaces(session)).disk, true, channel);
      await ask(session, "lock", {});
      const withPin = await ask(session, "pin_unlock", { pin: PIN });
      assert.equal(withPin.ok, true, `${channel}: ${JSON.stringify(withPin)}`);

      // Locked again: the popup offers the passkey beside the PIN, the button opens the unlock window, one press opens the vault.
      await ask(session, "lock", {});
      const popup = helpers(session);
      await session.navigate(POPUP_URL);
      await popup.ready();
      await popup.waitVisible('[data-role="unlock-passkey"]', SLOW);
      const before = await session.windowHandles();
      await popup.click('[data-role="unlock-passkey"]');
      const opened = await session.waitFor(async () => (await session.windowHandles()).find((handle) => !before.includes(handle)) ?? null, 30_000, "the unlock window");
      await session.switchTo(opened);
      await session.waitFor(async () => (await session.currentUrl()) === UNLOCK_WINDOW_URL, 30_000, "the unlock window to load");
      const win = helpers(session);
      await win.waitVisible('[data-role="passkey-unlock"]', SLOW);
      await win.click('[data-role="passkey-unlock"]');
      await session.waitFor(
        async () => (await session.content(() => document.body?.dataset.done === "1" || document.querySelector('[data-role="passkey-error"]') !== null)) === true,
        SLOW,
        "the end of the passkey unlock",
      );
      assert.equal(await session.content(() => document.querySelector('[data-role="passkey-error"]')?.textContent ?? ""), "", `${channel}: the passkey unlock said something`);
      await session.waitFor(async () => !(await session.windowHandles()).includes(opened), 30_000, "the window to close");
      await session.switchTo(extTab);
      await onBridge(session);
      assert.equal((await ask(session, "state", {})).state, "unlocked", `${channel}: the passkey opened the vault`);

      // What the passkey gave for its salt, asked for again from the web vault's page (the only other place that can), is nowhere on disk.
      await session.switchTo(webTab);
      const output = await prfOutputOf(session);
      assert.equal(output.length, 32, `${channel}: the passkey gives 32 bytes`);

      // The passkey is removed in the web vault: the extension locks, no longer offers it, and the PIN still opens the vault.
      await session.content(() => {
        location.hash = "#/unlock-methods";
      });
      await helpers(session).waitVisible('[data-role="methods-page"]', SLOW);
      await session.waitFor(async () => (await session.findAll('[data-role="methods-row"]')).length === 1, SLOW, "the passkey to remove");
      await removePasskeys(session, account);
      await session.switchTo(extTab);
      await ask(session, "lock", {});
      const options = await ask(session, "prf_options", {});
      assert.deepEqual([options.ok, options.credentials], [true, []], `${channel}: the server lists no passkey any more: ${JSON.stringify(options)}`);
      await session.navigate(POPUP_URL);
      await popup.ready();
      await session.waitFor(async () => (await popup.visible('[data-role="unlock-form"]')) || (await popup.visible('[data-role="pin-unlock-form"]')), SLOW, "the locked popup");
      assert.equal(await popup.visible('[data-role="unlock-passkey"]'), false, `${channel}: the removed passkey is not offered`);
      await onBridge(session);
      const again = await ask(session, "pin_unlock", { pin: PIN });
      assert.equal(again.ok, true, `${channel}: the PIN still opens the vault: ${JSON.stringify(again)}`);

      // No file of the profile holds the PIN or the passkey's output.
      const leaked = scanFolder(session.profileDir, [PIN, PIN.normalize("NFKD"), output]);
      assert.deepEqual(leaked, [], `${channel}: the PIN or the passkey's output is in a file of the profile`);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 10 });

/**
 * What the passkey gives for its first listed salt, asked for from the web vault's page by a press (a call needs a user gesture).
 * @param {Session} session
 * @returns {Promise<Uint8Array>}
 */
async function prfOutputOf(session) {
  const text = await session.content(async (/** @type {string} */ url) => {
    const response = await fetch(`${url}/api/vault/unlock-methods`, { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
    const { methods } = await response.json();
    const method = methods.find((/** @type {any} */ m) => m.method_type === 3);
    const unb64 = (/** @type {string} */ value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const button = document.createElement("button");
    button.id = "prf-probe";
    button.textContent = "probe";
    button.style.cssText = "position:fixed;top:0;left:0;z-index:99999";
    document.body.append(button);
    /** @type {any} */ (window).prfProbe = null;
    button.addEventListener("click", async () => {
      try {
        const credentialId = unb64(method.credential_id);
        const got = /** @type {any} */ (await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId: location.hostname,
            allowCredentials: [{ type: "public-key", id: credentialId }],
            userVerification: "required",
            extensions: { prf: { evalByCredential: { [method.credential_id]: { first: unb64(method.prf_salt) } } } },
          },
        }));
        const results = got.getClientExtensionResults().prf?.results?.first;
        /** @type {any} */ (window).prfProbe = results ? Array.from(new Uint8Array(results)) : [];
      } catch (error) {
        /** @type {any} */ (window).prfProbe = `error: ${String(/** @type {any} */ (error)?.message ?? error)}`;
      }
    });
    return "ready";
  }, VAULT_URL);
  assert.equal(text, "ready");
  const page = helpers(session);
  await page.click("#prf-probe");
  const got = await session.waitFor(async () => session.content(() => /** @type {any} */ (window).prfProbe), 60_000, "the passkey's answer");
  assert.ok(Array.isArray(got), `the passkey's output: ${got}`);
  await session.content(() => document.getElementById("prf-probe")?.remove());
  return Uint8Array.from(got);
}
