// Opening the vault with a passkey while the vault session lives, with the real server and the real core, in Chromium with
// a virtual authenticator that can evaluate the PRF. A passkey is added on the methods page (the master password again, the
// name, the passkey made and used once); the page is reloaded, so the vault is closed while the session on the server is
// still good; the Unlock page offers the passkey, and one click opens the vault without a password sign-in. When the session
// has ended the page asks for the master password as before and offers no passkey. A removed passkey is not offered.
//
// The other browsers have no virtual authenticator that the tests can drive, so the file runs in Chromium only.
import { API_HEADERS, expect, lockNow, newDevice, noViolations, openList, pace, remember, secrets, SLOW, test, unlockWith, untilStartAccepted, useAccount, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  useAccount();
});

/** @param {import("@playwright/test").Page} page */
const sessionUnlock = (page) => page.locator('[data-role="unlock"][data-mode="session"]');
/** @param {import("@playwright/test").Page} page */
const passkeyButton = (page) => page.locator('[data-role="passkey-unlock"]');

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

test("reload_and_unlock_with_the_passkey", async ({ browser, browserName }) => {
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

    // ---- Add a passkey on the methods page.
    const name = `Unlock-${Date.now().toString(36)}`;
    await page.evaluate(() => {
      location.hash = "#/unlock-methods";
    });
    await expect(page.locator('[data-role="methods-page"]')).toBeVisible({ timeout: 30_000 });
    await pace();
    await page.locator('[data-role="methods-add"]').click();
    await answerReauth(page);
    const form = page.locator('[data-role="methods-name-form"]');
    await expect(form).toBeVisible({ timeout: 30_000 });
    await form.locator('[data-role="methods-name-input"]').fill(name);
    await form.locator('[data-role="methods-create"]').click();
    await expect(page.locator('[data-role="methods-confirm"]')).toBeVisible({ timeout: 30_000 });
    await page.locator('[data-role="methods-confirm"]').click();
    await expect(page.locator('[data-role="methods-done"]')).toBeVisible({ timeout: SLOW });
    expect(await serverPasskeys(page)).toHaveLength(1);
    remember();

    // ---- Reload: the vault is closed, the session on the server is still good. The page offers the passkey and the password.
    /** @type {string[]} */
    const requests = [];
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (url.pathname.startsWith("/api/")) requests.push(`${request.method()} ${url.pathname}`);
    });
    await page.reload();
    await expect(sessionUnlock(page)).toBeVisible({ timeout: 30_000 });
    await expect(passkeyButton(page)).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('[data-role="password"]')).toBeVisible();
    // Showing the offer asked nothing of the passkey and signed nobody in.
    expect(requests.filter((r) => r.includes("/opaque/"))).toEqual([]);

    // ---- One click opens the vault: no master password, no password sign-in.
    requests.length = 0;
    await passkeyButton(page).click();
    // The page that was open when it was reloaded (the methods page) comes back, now with the vault open.
    await expect(page.locator('[data-role="methods-page"]')).toBeVisible({ timeout: SLOW });
    await expect(sessionUnlock(page)).toHaveCount(0);
    expect(requests.filter((r) => r.includes("/opaque/")), "no password sign-in ran").toEqual([]);
    expect(requests).toContain("GET /api/vault/unlock-methods");
    expect(requests.filter((r) => r.startsWith("POST ") && r.includes("/api/vault/unlock-methods")), "nothing was written to the methods").toEqual([]);
    // The vault is really open: the methods page reads the sealed manifest, which needs the vault key.
    await expect(page.locator('[data-role="methods-row"]')).toHaveCount(1, { timeout: SLOW });
    await expect(page.locator('[data-role="methods-row"] [data-role="methods-row-name"]')).toHaveText(name);

    // ---- Locked again (no reload): the same offer, the same click.
    await lockNow(page);
    await expect(sessionUnlock(page)).toBeVisible({ timeout: 30_000 });
    await expect(passkeyButton(page)).toBeVisible({ timeout: 30_000 });
    await passkeyButton(page).click();
    await expect(page.locator('[data-role="list"], [data-role="methods-page"]').first()).toBeVisible({ timeout: SLOW });
    await openList(page);

    // ---- The session ends: the page asks for the master password as before, and offers no passkey.
    expect((await context.request.post(`${vaultUrl}/api/auth/logout`, { headers: API_HEADERS })).status()).toBe(204);
    await page.reload();
    const remembered = page.locator('[data-role="unlock"][data-mode="remembered"]');
    await expect(remembered).toBeVisible({ timeout: 30_000 });
    await expect(passkeyButton(page)).toHaveCount(0);
    await untilStartAccepted(context, () => unlockWith(page, secrets.password));
    await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });

    // ---- A removed passkey is not offered.
    await page.evaluate(() => {
      location.hash = "#/unlock-methods";
    });
    await expect(page.locator('[data-role="methods-row"]')).toHaveCount(1, { timeout: SLOW });
    await page.locator('[data-role="methods-row"] [data-role="methods-remove"]').click();
    await page.locator('[data-role="dialog-confirm"]').click();
    const done = page.locator('[data-role="methods-done"]');
    await expect(page.locator('[data-role="methods-done"]:not([hidden]), [data-role="reauth-dialog"]')).toBeVisible({ timeout: SLOW });
    if (await page.locator('[data-role="reauth-dialog"]').isVisible()) await answerReauth(page);
    await expect(done).toContainText("was removed", { timeout: SLOW });
    expect(await serverPasskeys(page)).toEqual([]);
    await page.reload();
    await expect(sessionUnlock(page)).toBeVisible({ timeout: 30_000 });
    await expect(passkeyButton(page)).toHaveCount(0);
    await expect(page.locator('[data-role="password"]')).toBeVisible();
  } finally {
    await context.close();
  }
});
