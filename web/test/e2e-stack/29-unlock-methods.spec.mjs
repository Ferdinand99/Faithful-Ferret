// A passkey as an unlock method, with the real server and the real core, in Chromium with a virtual authenticator that can
// evaluate the PRF. The page asks for the master password again, makes the passkey on the vault's exact host and uses it once,
// and the server holds the wrap, the credential id, the salt and the AAGUID; the name stays inside the sealed manifest, which
// shows after a lock and an unlock. Removing the method asks for the password once more and leaves the server with none.
//
// The other browsers have no virtual authenticator that the tests can drive, so the file runs in Chromium only.
import { addNeedle, expect, lockNow, newDevice, noViolations, openList, pace, remember, secrets, SLOW, test, unlockWith, useAccount, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  useAccount();
});

/** @param {import("@playwright/test").Page} page */
const methodsPage = (page) => page.locator('[data-role="methods-page"]');
/** @param {import("@playwright/test").Page} page */
const rows = (page) => page.locator('[data-role="methods-row"]');

/**
 * Answers the master password dialog when it opens (the page asks again when the last check is older than a minute).
 * @param {import("@playwright/test").Page} page
 */
async function answerReauth(page) {
  const dialog = page.locator('[data-role="reauth-dialog"]');
  await expect(dialog).toBeVisible({ timeout: 30_000 });
  await dialog.locator('[data-role="reauth-password"]').fill(secrets.password);
  await pace();
  await dialog.locator('[data-role="reauth-confirm"]').click();
  await expect(dialog).toHaveCount(0, { timeout: SLOW });
}

/**
 * The passkey methods the server lists, from the page's own session.
 * @param {import("@playwright/test").Page} page
 */
async function serverPasskeys(page) {
  const answer = await page.request.get(`${vaultUrl}/api/vault/unlock-methods`);
  expect(answer.status()).toBe(200);
  const list = await answer.json();
  return /** @type {any[]} */ (list.methods).filter((method) => method.method_type === 3);
}

test("add_lock_and_unlock_with_a_prf_method_then_remove_it", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "the virtual authenticator is Chromium's");
  test.setTimeout(900_000);
  const device = await newDevice(browser);
  const { context, page } = device;
  try {
    // A passkey that can evaluate the PRF and verifies the user, on this browser only.
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
      },
    });

    // What the page sends to the server for the methods, to see that the name is not in it.
    const name = `Passkey-${Date.now().toString(36)}-name`;
    addNeedle("passkey name", name);
    /** @type {string[]} */
    const bodies = [];
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (request.method() !== "GET" && url.pathname.startsWith("/api/vault/unlock-methods")) bodies.push(`${request.method()} ${url.pathname} ${request.postData() ?? ""}`);
    });

    await page.evaluate(() => {
      location.hash = "#/unlock-methods";
    });
    await expect(methodsPage(page)).toBeVisible({ timeout: 30_000 });
    // The page is in the account menu now that the server offers passkeys.
    await page.evaluate(() => {
      location.hash = "#/account";
    });
    await expect(page.locator('[data-role="account-link"][data-path="/unlock-methods"]')).toBeVisible({ timeout: 30_000 });
    await page.evaluate(() => {
      location.hash = "#/unlock-methods";
    });
    await expect(methodsPage(page)).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('[data-role="methods-empty"]')).toBeVisible({ timeout: 30_000 });
    expect(await serverPasskeys(page)).toEqual([]);
    // What a passkey does and does not do is said before one is added.
    await expect(page.locator('[data-role="methods-what-still"]')).toContainText("master password and your recovery key still work");
    await expect(page.locator('[data-role="methods-what-host"]')).toContainText(new URL(vaultUrl).hostname);

    // ---- Add: the password again, the name, the passkey, the passkey once more.
    await pace();
    await page.locator('[data-role="methods-add"]').click();
    await answerReauth(page);
    const form = page.locator('[data-role="methods-name-form"]');
    await expect(form).toBeVisible({ timeout: 30_000 });
    await form.locator('[data-role="methods-name-input"]').fill(name);
    await form.locator('[data-role="methods-create"]').click();
    const confirm = page.locator('[data-role="methods-confirm"]');
    await expect(confirm).toBeVisible({ timeout: 30_000 });
    // Nothing has been sent: the passkey is made and not yet used.
    expect(bodies, "nothing is sent before the passkey has been used").toEqual([]);
    await confirm.click();
    await expect(page.locator('[data-role="methods-done"]')).toBeVisible({ timeout: SLOW });
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page).first().locator('[data-role="methods-row-name"]')).toHaveText(name);
    // A virtual authenticator is not backup eligible: the list says "This device only".
    await expect(rows(page).first().locator('[data-role="methods-kind"]')).toHaveText("This device only");
    await expect(rows(page).first().locator('[data-role="methods-aaguid"]')).toBeVisible();

    // The server holds the wrap and the ids, in the hex of the core; the name is nowhere in what was sent.
    const stored = await serverPasskeys(page);
    expect(stored).toHaveLength(1);
    expect(stored[0].credential_id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(stored[0].prf_salt).toHaveLength(43);
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatch(/^POST \/api\/vault\/unlock-methods \{"method_type":3,"method_id":"[0-9a-f]{32}",/);
    expect(bodies[0]).toContain('"aaguid":"');
    expect(bodies.join("\n")).not.toContain(name);
    remember();

    // ---- Lock and unlock with the master password: the method is still there, with its name from the sealed manifest.
    await lockNow(page);
    await expect(page.locator('[data-role="unlock-form"]')).toBeVisible({ timeout: 30_000 });
    await unlockWith(page, secrets.password);
    await openList(page);
    await page.evaluate(() => {
      location.hash = "#/unlock-methods";
    });
    await expect(rows(page)).toHaveCount(1, { timeout: SLOW });
    await expect(rows(page).first().locator('[data-role="methods-row-name"]')).toHaveText(name);

    // ---- Remove: asked first, the password again when the last check has run out, and the server has none left.
    await rows(page).first().locator('[data-role="methods-remove"]').click();
    await expect(page.locator('[data-role="dialog"]')).toContainText(name);
    await page.locator('[data-role="dialog-confirm"]').click();
    const done = page.locator('[data-role="methods-done"]');
    const dialog = page.locator('[data-role="reauth-dialog"]');
    await expect(done.or(dialog)).toBeVisible({ timeout: SLOW });
    if (await dialog.isVisible()) await answerReauth(page);
    await expect(done).toBeVisible({ timeout: SLOW });
    await expect(done).toContainText("was removed");
    await expect(rows(page)).toHaveCount(0);
    expect(await serverPasskeys(page)).toEqual([]);
    expect(bodies.filter((body) => body.startsWith("DELETE "))).toHaveLength(1);
    expect(bodies.join("\n")).not.toContain(name);
  } finally {
    await context.close();
  }
});
