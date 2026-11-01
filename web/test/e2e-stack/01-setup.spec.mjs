// Scenario 1: the first administrator makes the account by the path the owner
// takes: the setup link on the admin origin, the form on the vault origin, the
// emergency sheet, and the keys typed back before anything is uploaded.
import { adminUrl, bodyText, confirmSheet, expect, fillSetup, freshContext, memory, readSheet, remember, secrets, setupToken, SLOW, test, vaultUrl } from "./support.mjs";

test("setup_creates_the_first_account_and_requires_typing_rk_and_sk", async ({ page, browser }) => {
  test.setTimeout(300_000);
  const finishes = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/auth/opaque/register/finish")) finishes.push(r.url());
  });

  // The link from the admin origin lands on the vault origin, and the token is not left in the address.
  await page.goto(`${adminUrl}/setup?token=${setupToken}`);
  await expect(page.locator('[data-role="setup-page"]')).toBeVisible({ timeout: 20_000 });
  expect(new URL(page.url()).origin).toBe(vaultUrl);
  expect(page.url()).not.toContain(setupToken);
  await expect(page.locator('[data-role="token-received"]')).toBeVisible();

  await fillSetup(page, { token: null });
  const keys = await readSheet(page);
  expect(keys.recoveryKey.length).toBeGreaterThan(10);
  expect(keys.secretKey.length).toBeGreaterThan(10);
  secrets.recoveryKey = keys.recoveryKey;
  secrets.secretKey = keys.secretKey;
  remember();

  // Nothing has been uploaded yet: the sheet is shown first.
  expect(finishes).toEqual([]);

  // A wrong recovery key is refused, and so is a wrong secret key; still nothing is uploaded.
  await page.locator('[data-role="rk-typed"]').fill(keys.recoveryKey.slice(0, -1) + (keys.recoveryKey.endsWith("A") ? "B" : "A"));
  await page.locator('[data-role="sk-typed"]').fill(keys.secretKey);
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="sheet-page"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(finishes).toEqual([]);
  await page.locator('[data-role="rk-typed"]').fill(keys.recoveryKey);
  await page.locator('[data-role="sk-typed"]').fill(keys.secretKey.slice(0, -1) + (keys.secretKey.endsWith("A") ? "B" : "A"));
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="sheet-page"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(finishes).toEqual([]);

  // Both typed back right: the account is uploaded and the sheet leaves the page.
  await confirmSheet(page, keys);
  expect(finishes.length).toBe(1);
  const after = await bodyText(page);
  expect(after).not.toContain(keys.recoveryKey);
  expect(after).not.toContain(keys.secretKey);
  expect(page.url()).not.toContain(setupToken);

  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  expect((await memory(page)).engine).toBe(true);

  // A second setup is refused: there is a first administrator now.
  const other = await freshContext(browser);
  const second = await other.newPage();
  await second.goto(`${vaultUrl}/vault/setup#token=${setupToken}`);
  await expect(second.locator('[data-role="setup-page"]')).toBeVisible({ timeout: 20_000 });
  await second.locator('[data-role="email"]').fill("second@e2e.example.test");
  await second.locator('[data-role="password"]').fill(secrets.password);
  await second.locator('[data-role="password-repeat"]').fill(secrets.password);
  await second.locator('[data-role="setup-form"] [data-role="submit"]').click();
  await expect(second.locator('[data-role="setup-page"] [data-role="error"]')).toContainText("first administrator already exists", { timeout: SLOW });
  await other.close();
});
