// After the first sign-in on a browser, an ended server session asks for the master password only ("Unlock"): the
// remembered e-mail is shown read only, and the password runs a full sign-in with the secret key this browser keeps. A
// wrong password renews nothing; an explicit sign-out, or "Not you?", brings the full sign-in page back for good.
import {
  API_HEADERS, createItem, expect, findRows, freshContext, newDevice, pace, readStores, requireAccount, secrets, signInOn, signOutOn, SLOW, test,
  unlockWith, untilStartAccepted, vaultUrl,
} from "./support.mjs";

/** The page's "Unlock" for an ended session. @param {import("@playwright/test").Page} page */
const unlockPage = (page) => page.locator('[data-role="unlock"][data-mode="remembered"]');

/** What this browser keeps in its settings: the device id and the remembered account (keys and values). @param {import("@playwright/test").Page} page */
async function settingsOf(page) {
  const stores = await readStores(page);
  const keys = /** @type {any[]} */ (stores.settings?.keys ?? []);
  const values = /** @type {any[]} */ (stores.settings?.values ?? []);
  return Object.fromEntries(keys.map((key, i) => [String(key), values[i]]));
}

/** The vault session cookie of a context, or undefined. @param {import("@playwright/test").BrowserContext} context */
const sessionCookie = async (context) => (await context.cookies(vaultUrl)).find((c) => c.name === "__Host-ferret_sid");

test("after_the_session_ends_the_vault_asks_for_the_password_only", async ({ browser }) => {
  test.setTimeout(400_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  const name = `Unlock-${Date.now()}`;
  await createItem(page, { name, username: "unlock-user" });

  // This browser remembers the account by its id alone: no new setting holds the e-mail.
  const settings = await settingsOf(page);
  const markers = Object.entries(settings).filter(([key]) => key.startsWith("signin.remembered."));
  expect(markers).toHaveLength(1);
  expect(markers[0][1]).toMatch(/^[0-9a-f]{32}$/);
  expect(JSON.stringify(settings)).not.toContain(secrets.email);

  // The server ends the session (as at its idle or absolute limit, or a sign-out elsewhere), and the page is loaded again.
  expect((await context.request.post(`${vaultUrl}/api/auth/logout`, { headers: API_HEADERS })).status()).toBe(204);
  expect((await context.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);
  await page.reload();
  await expect(unlockPage(page)).toBeVisible({ timeout: 30_000 });
  const email = unlockPage(page).locator('[data-role="remembered-email"]');
  await expect(email).toHaveValue(secrets.email);
  await expect(email).toHaveAttribute("readonly", "");
  await expect(unlockPage(page).locator('[data-role="not-you"]')).toBeVisible();
  // The password only: no field for the e-mail, no secret key question, no secret key field.
  for (const role of ["email", "sk-question", "sk-code", "secret-key"]) await expect(page.locator(`[data-role="${role}"]`)).toHaveCount(0);
  // The sign-in page says the same.
  await page.goto(`${vaultUrl}/vault/login`);
  await expect(unlockPage(page)).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-role="credentials"]')).toHaveCount(0);

  // A wrong password: the sign-in page's message, the page stays, and nothing is renewed (no proof is posted, no session).
  /** @type {string[]} */
  const finishes = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/auth/opaque/login/finish") finishes.push(request.method());
  });
  await untilStartAccepted(context, () => unlockWith(page, `${secrets.password}-wrong`));
  const error = unlockPage(page).locator('[data-role="error"]');
  await expect(error).toBeVisible({ timeout: SLOW });
  await expect(error).toContainText(/could not be opened/i);
  await expect(error).toContainText(/master password/i);
  expect(finishes, "the proof of a wrong password never reaches the server").toEqual([]);
  expect(await sessionCookie(context), "no session was made").toBeUndefined();
  expect((await context.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);
  await expect(unlockPage(page)).toBeVisible();
  await expect(unlockPage(page).locator('[data-role="password"]')).toHaveValue("");

  // The right password: a full sign-in behind the page, and the vault opens with its items.
  await untilStartAccepted(context, () => unlockWith(page, secrets.password));
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
  await expect(await findRows(page, name)).toHaveCount(1, { timeout: 30_000 });
  expect(finishes, "one sign-in proof was posted").toEqual(["POST"]);
  expect((await context.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);

  // An explicit sign-out: the full sign-in page, also after a reload. The pinned record stays; the marker goes.
  await signOutOn(page);
  await expect(page.locator('[data-role="credentials"]')).toBeVisible();
  await page.reload();
  await expect(page.locator('[data-role="email"]')).toBeVisible({ timeout: 30_000 });
  await expect(unlockPage(page)).toHaveCount(0);
  const after = await readStores(page);
  expect(after.pinned.count, "the pinned record stays").toBeGreaterThan(0);
  expect(Object.keys(await settingsOf(page)).filter((key) => key.startsWith("signin.remembered.")), "the account is forgotten").toEqual([]);
  await context.close();
});

test("a_revoked_browser_unlocks_with_the_password_and_not_you_brings_the_sign_in_page_back", async ({ browser }) => {
  test.setTimeout(500_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  const deviceId = (await settingsOf(page)).device_id;
  expect(deviceId).toMatch(/^[0-9a-f]{32}$/);

  // Another browser of the account revokes this one from the list of devices: its sessions end on the server.
  const other = await newDevice(browser);
  const revoked = await other.context.request.delete(`${vaultUrl}/api/auth/devices/${deviceId}`, { headers: API_HEADERS });
  expect(revoked.status()).toBeLessThan(300);
  expect((await context.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);
  await other.context.close();

  // The server keeps nothing that tells a browser it was revoked: "Unlock", and a full sign-in with the password.
  await page.reload();
  await expect(unlockPage(page)).toBeVisible({ timeout: 30_000 });
  await untilStartAccepted(context, () => unlockWith(page, secrets.password));
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
  expect((await context.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);

  // "Not you? Sign out" on the Unlock page: the full sign-in page, for good.
  expect((await context.request.post(`${vaultUrl}/api/auth/logout`, { headers: API_HEADERS })).status()).toBe(204);
  await page.reload();
  await expect(unlockPage(page)).toBeVisible({ timeout: 30_000 });
  await unlockPage(page).locator('[data-role="not-you"]').click();
  await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-role="email"]')).toBeVisible();
  await page.reload();
  await expect(page.locator('[data-role="email"]')).toBeVisible({ timeout: 30_000 });
  expect((await readStores(page)).pinned.count, "the pinned record stays").toBeGreaterThan(0);
  await pace();
  await context.close();
});
