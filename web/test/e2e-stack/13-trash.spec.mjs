// Deleting moves an item to the local trash (30 days, on every device that sees the deletion), and restoring brings it
// back everywhere. A deletion against an edit made offline is a conflict, not a loss.
import { createItem, editItem, expect, newDevice, noViolations, openItem, openList, rowsNamed, shot, synced, test, useAccount } from "./support.mjs";

const SEEN = 15_000;

test.describe.configure({ mode: "serial" });
noViolations();

/** @type {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} */
let a;
/** @type {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} */
let b;

test.beforeAll(async ({ browser }) => {
  test.setTimeout(400_000);
  useAccount();
  a = await newDevice(browser);
  b = await newDevice(browser);
});

test.afterAll(async () => {
  await a?.context.close();
  await b?.context.close();
});

/** @param {import("@playwright/test").Page} page */
async function openTrash(page) {
  await openList(page);
  await page.locator('[data-role="trash-link"]').click();
  await expect(page.locator('[data-role="trash"]')).toBeVisible();
}

/** @param {import("@playwright/test").Page} page @param {string} name */
const trashed = (page, name) => page.locator('[data-role="trash-item"]', { hasText: name });

/** @param {import("@playwright/test").Page} page @param {string} name */
async function deleteItem(page, name) {
  await openItem(page, name);
  await page.locator('[data-role="delete"]').click();
  await page.locator('[data-role="dialog-confirm"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
}

test("delete_moves_to_the_trash_and_restore_brings_it_back_in_both_browsers", async () => {
  test.setTimeout(400_000);
  const name = `Trash-${Date.now()}`;
  await createItem(a.page, { name, username: "trash-user", notes: "to the trash and back" });
  await openList(b.page);
  await expect(rowsNamed(b.page, name)).toHaveCount(1, { timeout: SEEN });

  await deleteItem(a.page, name);
  await expect(rowsNamed(a.page, name)).toHaveCount(0);
  await expect(rowsNamed(b.page, name)).toHaveCount(0, { timeout: SEEN });

  // Both devices keep the deleted item in the trash, by name.
  await openTrash(a.page);
  await expect(trashed(a.page, name)).toHaveCount(1);
  await shot(a.page, "13-trash-after-delete");
  await openTrash(b.page);
  await expect(trashed(b.page, name)).toHaveCount(1, { timeout: SEEN });

  // Restore on A: the item is back on A, and B shows it again and no longer has it in the trash.
  await trashed(a.page, name).locator('[data-role="restore"]').click();
  await expect(trashed(a.page, name)).toHaveCount(0, { timeout: 30_000 });
  await openList(a.page);
  await expect(rowsNamed(a.page, name)).toHaveCount(1, { timeout: 30_000 });
  await synced(a.page);
  await openList(b.page);
  await expect(rowsNamed(b.page, name)).toHaveCount(1, { timeout: SEEN });
  await openItem(b.page, name);
  await expect(b.page.locator('[data-role="item"]')).toContainText("trash-user");
  await openTrash(b.page);
  await expect(trashed(b.page, name)).toHaveCount(0);
  await shot(b.page, "13-trash-restored-on-the-other-device");
});

test("delete_against_an_offline_edit_gives_a_deleted_conflict", async () => {
  test.setTimeout(400_000);
  const base = `Deleted-conflict-${Date.now()}`;
  await createItem(a.page, { name: base, username: "base-user" });
  await openList(b.page);
  await expect(rowsNamed(b.page, base)).toHaveCount(1, { timeout: SEEN });
  await synced(b.page);

  // B edits offline; A deletes; B comes back.
  await b.context.setOffline(true);
  await editItem(b.page, base, { name: `${base}-B`, username: "b-user" });
  await deleteItem(a.page, base);
  await synced(a.page);
  await b.context.setOffline(false);
  await openList(b.page);
  await expect(b.page.locator('[data-role="conflict-note"]')).toBeVisible({ timeout: 60_000 });
  await b.page.locator('[data-role="first-conflict"]').click();
  await expect(b.page.locator('[data-role="conflict"]')).toBeVisible();
  await expect(b.page.locator('[data-role="side"][data-side="server"] [data-role="deleted"]')).toBeVisible();
  await expect(b.page.locator('[data-role="side"][data-side="local"] [data-role="name"]')).toHaveText(`${base}-B`);
  await shot(b.page, "13-trash-deleted-conflict");

  // Nothing was lost: B chooses to bring its version back, and it is back on both devices.
  await b.page.locator('[data-role="keep-mine"]').click();
  await b.page.locator('[data-role="dialog-confirm"]').click();
  await expect(b.page.locator('[data-role="item"] h1')).toContainText(`${base}-B`, { timeout: 30_000 });
  await openList(a.page);
  await expect(rowsNamed(a.page, `${base}-B`)).toHaveCount(1, { timeout: SEEN });
  await openItem(a.page, `${base}-B`);
  await expect(a.page.locator('[data-role="item"]')).toContainText("b-user");
});
