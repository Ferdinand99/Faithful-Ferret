// An item goes through its whole life in the interface: make, view,
// change, delete. A deleted item does not come back after a reload.
import { bodyText, createItem, expect, freshContext, openList, requireAccount, rowsNamed, secrets, signInOn, SLOW, test, unlockWith } from "./support.mjs";

test("crud_item_roundtrip_in_the_ui", async ({ browser }) => {
  test.setTimeout(400_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);

  // Make.
  await createItem(page, {
    name: secrets.itemTitle,
    username: secrets.itemUsername,
    password: secrets.itemPassword,
    url: secrets.itemUrl,
    notes: secrets.itemNotes,
  });

  // View: the user name shows, the password and the notes are hidden until asked for.
  const passwordRow = page.locator('[data-role="field"]', { hasText: "Password" });
  await expect(page.locator('[data-role="item"]')).toContainText(secrets.itemUsername);
  expect(await bodyText(page)).not.toContain(secrets.itemPassword);
  expect(await bodyText(page)).not.toContain(secrets.itemNotes);
  await passwordRow.locator('[data-role="reveal"]').click();
  await expect(passwordRow.locator('[data-role="value"]')).toHaveText(secrets.itemPassword);
  await passwordRow.locator('[data-role="reveal"]').click();
  await expect(passwordRow.locator('[data-role="value"]')).not.toHaveText(secrets.itemPassword);
  expect(await bodyText(page)).not.toContain(secrets.itemPassword);
  await expect(page.locator('[data-role="urls"]')).toContainText(secrets.itemUrl);

  // The list shows it.
  await openList(page);
  await expect(rowsNamed(page, secrets.itemTitle)).toHaveCount(1);

  // Change: a new name and a new password; the password field starts empty.
  await rowsNamed(page, secrets.itemTitle).locator('[data-role="item-link"]').click();
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  await expect(page.locator('[data-role="password"]')).toHaveValue("");
  await expect(page.locator('[data-role="name"]')).toHaveValue(secrets.itemTitle);
  const renamed = `${secrets.itemTitle}-edited`;
  const newPassword = `${secrets.itemPassword}-new`;
  await page.locator('[data-role="name"]').fill(renamed);
  await page.locator('[data-role="password"]').fill(newPassword);
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(renamed, { timeout: 30_000 });
  const again = page.locator('[data-role="field"]', { hasText: "Password" });
  await again.locator('[data-role="reveal"]').click();
  await expect(again.locator('[data-role="value"]')).toHaveText(newPassword);

  // The change is on the server: the sync status settles with nothing waiting.
  await expect(page.locator('[data-role="sync-status"]')).toHaveAttribute("data-state", "idle", { timeout: 30_000 });

  // A reload ends the page's keys: the vault asks for the password (the secret key is remembered).
  await page.reload();
  await expect(page.locator('[data-role="unlock"]')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-role="secret-key"]')).toHaveCount(0);
  await unlockWith(page, secrets.password);
  await expect(page.locator('[data-role="item"] h1')).toContainText(renamed, { timeout: SLOW });

  // Delete: confirmed in a dialog; the item is gone from the list.
  await page.locator('[data-role="delete"]').click();
  await expect(page.locator('[data-role="dialog"]')).toBeVisible();
  await page.locator('[data-role="dialog-cancel"]').click();
  await expect(page.locator('[data-role="dialog"]')).toHaveCount(0);
  await page.locator('[data-role="delete"]').click();
  await page.locator('[data-role="dialog-confirm"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  await expect(rowsNamed(page, renamed)).toHaveCount(0);
  await expect(page.locator('[data-role="sync-status"]')).toHaveAttribute("data-state", "idle", { timeout: 30_000 });

  // After a reload and a fresh sign-in on another device it has not come back.
  await page.reload();
  await unlockWith(page, secrets.password);
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
  await expect(rowsNamed(page, renamed)).toHaveCount(0);
  const other = await freshContext(browser);
  const second = await other.newPage();
  await signInOn(second);
  await expect(rowsNamed(second, renamed)).toHaveCount(0);
  await expect(rowsNamed(second, secrets.itemTitle)).toHaveCount(0);
  await other.close();
  await context.close();
});
