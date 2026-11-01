// Scenario 2: sign out and sign in again on a fresh browser context. A new
// device is asked the secret key question, pins the account and seals the key; a
// device that knows the account asks for the password only.
import { bodyText, expect, freshContext, pace, readStores, requireAccount, secrets, signInOn, signOutOn, SLOW, test, vaultUrl } from "./support.mjs";

test("sign_out_and_sign_in_again_on_a_fresh_browser_context", async ({ browser }) => {
  test.setTimeout(300_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();

  // A device that has never seen the account: the secret key question, the first use.
  await page.goto(`${vaultUrl}/vault/login`);
  await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
  await page.locator('[data-role="email"]').fill(secrets.email);
  await page.locator('[data-role="email"]').blur();
  await expect(page.locator('[data-role="sk-question"]')).toBeVisible();
  const before = await readStores(page);
  expect(before.pinned.count).toBe(0);
  expect(before.device_secrets.count).toBe(0);

  // A wrong password is one plain refusal and leaves nothing on the device.
  await page.locator('[data-role="password"]').fill(`${secrets.password}-wrong`);
  await page.locator('[data-role="sk-yes"]').check();
  await page.locator('[data-role="sk-code"]').fill(secrets.secretKey);
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="credentials"] ~ [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect((await readStores(page)).pinned.count).toBe(0);

  // The right password: signed in, the account is pinned, and the secret key is sealed on the device.
  await signInOn(page);
  const stores = await readStores(page);
  expect(stores.pinned.count).toBe(1);
  expect(stores.device_secrets.count).toBe(1);
  const pinned = stores.pinned.values[0].record;
  expect(typeof pinned.server_url).toBe("string");
  expect(pinned.sk_bit).toBe(true);
  // The sealed key is sealed: the secret key's text is nowhere in what the device keeps.
  const dump = JSON.stringify(stores);
  expect(dump).not.toContain(secrets.secretKey);
  expect(dump).not.toContain(secrets.secretKey.replaceAll("-", ""));
  expect(dump).not.toContain(secrets.password);

  // Sign out: the session ends, the device keeps its record of the account.
  await signOutOn(page);
  expect((await readStores(page)).pinned.count).toBe(1);
  expect((await page.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);

  // The same device again: the account is known, the key is remembered, the password is enough.
  await page.locator('[data-role="email"]').fill(secrets.email);
  await page.locator('[data-role="email"]').blur();
  await expect(page.locator('[data-role="sk-remembered"]')).toBeVisible();
  await expect(page.locator('[data-role="sk-question"]')).toBeHidden();
  await expect(page.locator('[data-role="sk-code"]')).toBeHidden();
  await page.locator('[data-role="password"]').fill(secrets.password);
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
  expect((await page.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);
  expect(await bodyText(page)).not.toContain(secrets.password);

  // Another fresh context is a new device and is asked again.
  const second = await freshContext(browser);
  const other = await second.newPage();
  await other.goto(`${vaultUrl}/vault/login`);
  await other.locator('[data-role="email"]').fill(secrets.email);
  await other.locator('[data-role="email"]').blur();
  await expect(other.locator('[data-role="sk-question"]')).toBeVisible();
  await second.close();
  await context.close();
});
