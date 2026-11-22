// The sign-in of the extension against the end-to-end stack (run by
// `scripts/lanbox-ext.sh e2e`): a real server, the real core and a real Firefox.
//
// The first channel makes the stack's first account the way a person does (the
// setup link of the admin origin, the web vault's form, the emergency sheet)
// and keeps its e-mail, master password, secret key and sheet text in a file
// for the next channel's process. The stack must be fresh (`e2e-up`).
//
// The server limits sign-in starts per account and address, and an unlock of
// the extension starts one too, so the tests pace their starts (as the web
// vault's scenarios do) instead of turning the limit off.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { DEVICE_NAME, POPUP_URL, SLOW, VAULT_HOST, extensionSignIn, helpers, knownAccount, pace, start, webVaultAccount } from "./e2e.mjs";
import { channels, openBridge, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/** The server key in a setup text as hex. @param {string} text */
function keyHex(text) {
  const value = new URLSearchParams(text.slice(text.indexOf("?") + 1)).get("o");
  assert.ok(value, "the setup text has a server key");
  return /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : Buffer.from(value, "base64url").toString("hex");
}

/**
 * What the extension has pinned (read through the test bridge, a page of the same origin).
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<Array<{ server_public_key: string }>>}
 */
async function pinnedRecords(session) {
  await openBridge(session);
  return session.content(() => new Promise((resolve, reject) => {
    const open = indexedDB.open("ferret");
    // Never make the database here: the background makes it with its own version and stores.
    open.onupgradeneeded = () => open.transaction?.abort();
    open.onerror = () => (open.error?.name === "AbortError" ? resolve([]) : reject(open.error));
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("pinned")) {
        db.close();
        resolve([]);
        return;
      }
      const all = db.transaction(["pinned"], "readonly").objectStore("pinned").getAll();
      all.onerror = () => reject(all.error);
      all.onsuccess = () => {
        const hex = (/** @type {Uint8Array} */ b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
        resolve(all.result.map((row) => ({ server_public_key: hex(row.record.server_public_key) })));
        db.close();
      };
    };
  }));
}

// ------------------------------------------------------------------- tests

test("sign_in_against_the_e2e_stack_opens_the_vault_and_unlock_after_lock_needs_only_the_password", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      // Without the sheet: the first sign-in trusts the server the first time.
      const signedIn = await extensionSignIn(session, { ...account, qrText: "" });
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      assert.ok(signedIn.text.includes(account.email) && signedIn.text.includes(VAULT_HOST), `${channel}: ${signedIn.text}`);

      // The popup: the open vault, with the lock button in the header.
      const page = helpers(session);
      await session.navigate(POPUP_URL);
      await page.ready();
      await page.waitVisible('[data-role="unlocked-view"]');
      assert.equal(await page.visible('[data-role="lock"]'), true, channel);
      assert.equal(await page.text('[data-role="account"]'), account.email);
      assert.equal(await page.text('[data-role="server-host"]'), VAULT_HOST);

      // The lock button locks, and the popup shows the unlock view: the master password only.
      await page.click('[data-role="lock"]');
      await page.waitVisible('[data-role="locked-view"]');
      assert.equal(await page.visible('[data-role="lock"]'), false, `${channel}: no lock button on a locked vault`);
      assert.equal(await page.visible('[data-role="password"]'), true, channel);
      for (const role of ["email", "sk-code", "qr-text", "server"]) assert.equal(await page.visible(`[data-role="${role}"]`), false, `${channel}: ${role}`);

      // A wrong password is refused and leaves it locked; the right one opens it.
      await page.type('[data-role="password"]', `${account.password}-wrong`);
      await pace();
      await page.click('[data-role="unlock"]');
      await page.waitVisible('[data-role="locked-view"] [data-role="error"]', SLOW);
      assert.match(await page.text('[data-role="error"]'), /could not be opened/i, channel);
      await page.type('[data-role="password"]', account.password);
      await pace();
      await page.click('[data-role="unlock"]');
      await page.waitVisible('[data-role="unlocked-view"]', SLOW);
      assert.equal(await page.text('[data-role="account"]'), account.email);

      // A reload of the popup asks the background: still open.
      await session.navigate(POPUP_URL);
      await page.ready();
      await page.waitVisible('[data-role="unlocked-view"]');
    } finally {
      await session.quit();
    }
  }
});

test("the_device_appears_with_the_extension_name", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const vaultTab = await session.windowHandle();
      const extensionTab = await session.newTab();
      await session.switchTo(extensionTab);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await session.switchTo(vaultTab);
      // The web vault's list of devices (its own session cookie).
      const listed = await session.content(async () => {
        const response = await fetch("/api/auth/devices", { headers: { "Ferret-Protocol": "1" } });
        return { status: response.status, body: await response.text() };
      });
      assert.equal(listed.status, 200, `${channel}: ${listed.body}`);
      const devices = JSON.parse(listed.body).devices.filter((/** @type {any} */ d) => d.kind === "device");
      assert.ok(devices.some((/** @type {any} */ d) => d.name === DEVICE_NAME && d.platform === "linux"), `${channel}: ${JSON.stringify(devices)}`);
    } finally {
      await session.quit();
    }
  }
});

test("wrong_password_and_unknown_email_give_the_same_message", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = knownAccount() ?? (await webVaultAccount(session, channel));
      const wrong = await extensionSignIn(session, { ...account, password: `${account.password}-wrong` });
      const unknown = await extensionSignIn(session, { ...account, email: `nobody-${randomBytes(4).toString("hex")}@e2e.example.test` });
      assert.equal(wrong.ok, false, channel);
      assert.equal(unknown.ok, false, channel);
      assert.equal(unknown.text, wrong.text, `${channel}: the two refusals read the same`);
      assert.match(wrong.text, /could not be opened/i, channel);
    } finally {
      await session.quit();
    }
  }
});

test("a_pasted_sheet_qr_pins_the_server_key_and_a_different_server_key_is_refused", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = knownAccount() ?? (await webVaultAccount(session, channel));
      const original = keyHex(account.qrText);
      const flipped = (original[0] === "0" ? "1" : "0") + original.slice(1);
      const forged = account.qrText.replace(/([?&]o=)[^&]+/, (_, lead) => `${lead}${flipped}`);
      assert.notEqual(forged, account.qrText);

      // A sheet with another server key: refused, and nothing is pinned.
      const refused = await extensionSignIn(session, { ...account, qrText: forged });
      assert.equal(refused.ok, false, channel);
      assert.match(refused.text, /different identity than the one on your emergency sheet/i, channel);
      assert.deepEqual(await pinnedRecords(session), [], `${channel}: nothing was pinned`);

      // The real sheet: the sign-in pins the server key the sheet states.
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      const pinned = await pinnedRecords(session);
      assert.equal(pinned.length, 1, channel);
      assert.equal(pinned[0].server_public_key, original, `${channel}: the pinned server key is the sheet's`);
    } finally {
      await session.quit();
    }
  }
});
