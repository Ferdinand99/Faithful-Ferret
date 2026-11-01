// Scenario 5: locking removes every secret from the page and from memory, ends
// the worker that held the keys, and a password alone opens the vault again.
import { bodyText, createItem, expect, freshContext, memory, pace, recordWorkers, requireAccount, secrets, signInOn, signOutOn, SLOW, tamperPinnedServerKey, test, unlockWith, workers } from "./support.mjs";

test("lock_and_unlock_roundtrip", async ({ browser }) => {
  test.setTimeout(400_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await recordWorkers(page);
  await signInOn(page);
  const name = `Lock-${secrets.itemTitle}`;
  const password = `${secrets.itemPassword}-lock`;
  await createItem(page, { name, username: secrets.itemUsername, password, notes: secrets.itemNotes });

  // Reveal a password, so that it is on the page when the lock comes.
  const row = page.locator('[data-role="field"]', { hasText: "Password" });
  await row.locator('[data-role="reveal"]').click();
  await expect(row.locator('[data-role="value"]')).toHaveText(password);
  expect(await bodyText(page)).toContain(password);
  const open = await memory(page);
  expect(open.engine).toBe(true);
  expect(open.items).toBeGreaterThan(0);
  expect((await workers(page)).filter((w) => !w.ended).length).toBeGreaterThan(0);

  await page.locator('[data-role="lock"]').click();
  await expect(page.locator('[data-role="unlock"]')).toBeVisible({ timeout: 20_000 });

  // No secret is left in the page: not the revealed password, not the name, not the user name.
  const text = await bodyText(page);
  for (const secret of [password, name, secrets.itemUsername, secrets.itemNotes, secrets.password]) {
    expect(text, "the page after the lock").not.toContain(secret);
  }
  // Nothing in memory: no engine and no item summary; the worker that held the keys has been ended.
  expect(await memory(page)).toEqual({ engine: false, items: 0 });
  expect((await workers(page)).filter((w) => !w.ended)).toEqual([]);

  // A wrong password does not open it and shows a plain message.
  await unlockWith(page, `${secrets.password}-wrong`);
  await expect(page.locator('[data-role="unlock"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(await memory(page)).toEqual({ engine: false, items: 0 });

  // The password alone opens it (the device keeps the secret key), and the item is there.
  await expect(page.locator('[data-role="secret-key"]')).toHaveCount(0);
  await unlockWith(page, secrets.password);
  await expect(page.locator('[data-role="item"] h1')).toContainText(name, { timeout: SLOW });
  expect((await memory(page)).engine).toBe(true);
  // The revealed value did not come back: it is hidden again.
  expect(await bodyText(page)).not.toContain(password);
  await context.close();
});

test("tampered_pinned_server_key_is_loud", async ({ browser }) => {
  test.setTimeout(300_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  await signOutOn(page);

  // The stored record of the server's identity is changed behind the page's back.
  expect(await tamperPinnedServerKey(page)).toBe(1);

  await page.locator('[data-role="email"]').fill(secrets.email);
  await page.locator('[data-role="email"]').blur();
  await page.locator('[data-role="password"]').fill(secrets.password);
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
  const error = page.locator('[data-role="credentials"] ~ [data-role="error"]');
  await expect(error).toBeVisible({ timeout: SLOW });
  // The warning about the server's identity, not "wrong password".
  await expect(error).toContainText("different identity");
  await expect(error).not.toContainText("Check the e-mail, the master password");
  await expect(page.locator('[data-role="list"]')).toHaveCount(0);
  await context.close();
});
