// "Forget this server": the device drops what it keeps for the account (the saved items, the record of what the server
// showed before, the remembered secret key), the other tabs of the browser lock, and the next sign-in counts as the first
// one on this device, with the secret key asked for. Nothing on the server is deleted.
import { createItem, expect, freshContext, readStores, rowsNamed, secrets, shot, signInHere, signInOn, test, unlockWith, useAccount, vaultUrl, noViolations } from "./support.mjs";

noViolations();

test("forget_server_removes_the_local_data_tells_other_tabs_and_the_next_sign_in_is_first_use", async ({ browser }) => {
  test.setTimeout(600_000);
  useAccount();
  const context = await freshContext(browser);
  try {
    const first = await context.newPage();
    await signInOn(first);
    const name = `Forget-${Date.now()}`;
    await createItem(first, { name, username: "forget-user" });
    // The device keeps the account's data: the items, the record of what the server showed, the remembered secret key.
    const before = await readStores(first);
    expect(before.rows.count, "the device holds the items").toBeGreaterThan(0);
    expect(before.pinned.count, "the device holds the pinned account").toBeGreaterThan(0);
    expect(before.device_secrets.count, "the device remembers the secret key").toBeGreaterThan(0);
    expect(before.sync_state?.count ?? 0, "the device holds the record of what the server showed").toBeGreaterThan(0);

    // A second tab of the same browser has the vault open.
    const second = await context.newPage();
    await second.goto(`${vaultUrl}/vault/#/items`);
    await unlockWith(second, secrets.password);
    await expect(second.locator('[data-role="list"]')).toBeVisible({ timeout: 90_000 });
    await expect(rowsNamed(second, name)).toHaveCount(1, { timeout: 30_000 });

    // Forget, from the first tab, with the question first.
    await first.evaluate(() => {
      window.location.hash = "#/forget";
    });
    await expect(first.locator('[data-role="forget-page"]')).toBeVisible();
    await shot(first, "16-forget-the-page");
    await first.locator('[data-role="forget-start"]').click();
    await expect(first.locator('[data-role="dialog-confirm"]')).toBeVisible();
    await shot(first, "16-forget-the-question");
    await first.locator('[data-role="dialog-confirm"]').click();
    // The tab that forgot ends on the sign-in page. (It should show the page that says what was forgotten first: see the
    // test below that is marked fixme.)
    await expect(first.locator('[data-role="credentials"]')).toBeVisible({ timeout: 60_000 });
    await shot(first, "16-forget-done");

    // The other tab locked and shows no items.
    await expect(second.locator('[data-role="list"]')).toHaveCount(0, { timeout: 30_000 });
    await expect(second.locator('[data-role="unlock"], [data-role="credentials"], [data-role="account-page"]').first()).toBeVisible();
    await shot(second, "16-forget-the-other-tab");

    // Nothing of the account is left on this device.
    const after = await readStores(first);
    for (const store of ["rows", "outbox", "pinned", "device_secrets", "sync_state", "trash"]) {
      expect(/** @type {any} */ (after)[store]?.count ?? 0, `${store} is empty after forgetting`).toBe(0);
    }

    // The next sign-in is the first one here: the secret key is asked for again, and the server's items come back.
    await first.goto(`${vaultUrl}/vault/login`);
    await expect(first.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
    await first.locator('[data-role="email"]').fill(secrets.email);
    await first.locator('[data-role="email"]').blur();
    await expect(first.locator('[data-role="sk-question"]')).toBeVisible({ timeout: 15_000 });
    await expect(first.locator('[data-role="sk-remembered"]')).toBeHidden();
    await shot(first, "16-forget-next-sign-in-is-first-use");
    await signInHere(first);
    await expect(rowsNamed(first, name)).toHaveCount(1, { timeout: 30_000 });
  } finally {
    await context.close();
  }
});

// Known fault, found by this run (task-37-report.md, "Forget this server: the confirmation page is replaced"): the tab that
// forgets locks itself through its own listener for the message it sends to the other tabs, so the page that says what was
// forgotten is replaced by the sign-in page within a few milliseconds and the person never reads it. Nothing is lost by it:
// the data is gone and the sign-in is first use, as the test above shows.
test.fixme("forget_shows_what_was_forgotten_on_the_tab_that_forgot", async ({ browser }) => {
  useAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  await page.evaluate(() => {
    window.location.hash = "#/forget";
  });
  await page.locator('[data-role="forget-start"]').click();
  await page.locator('[data-role="dialog-confirm"]').click();
  await expect(page.locator('[data-role="forget-done"]')).toBeVisible({ timeout: 10_000 });
  await context.close();
});
