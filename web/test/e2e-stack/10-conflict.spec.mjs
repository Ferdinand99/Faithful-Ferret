// Two devices of one account change the same item while one is offline. When it is back, it shows the two versions
// field by field, and the choice (keep mine, keep the server's) holds on both devices. Nothing is merged, and the version
// that is not kept is dropped on purpose and for good, not by accident.
import { createItem, editItem, expect, noViolations, newDevice, openItem, openList, rowsNamed, shot, synced, test, useAccount } from "./support.mjs";

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

/**
 * Both devices hold the item; B goes offline and changes it; A changes it too, and A's change reaches the server; B comes
 * back. Returns with B on the conflict view of the item.
 * @param {string} base
 */
async function makeConflict(base) {
  await createItem(a.page, { name: base, username: "base-user", notes: "base-notes" });
  await openList(b.page);
  await expect(rowsNamed(b.page, base)).toHaveCount(1, { timeout: SEEN });
  await synced(b.page);

  await b.context.setOffline(true);
  await editItem(b.page, base, { name: `${base}-B`, username: "b-user" });

  await editItem(a.page, base, { name: `${base}-A`, notes: "a-notes" });
  await synced(a.page);

  await b.context.setOffline(false);
  await openList(b.page);
  await expect(b.page.locator('[data-role="conflict-note"]')).toBeVisible({ timeout: 60_000 });
  await b.page.locator('[data-role="first-conflict"]').click();
  await expect(b.page.locator('[data-role="conflict"]')).toBeVisible();
}

test("edit_same_item_in_two_browsers_shows_a_field_by_field_conflict_and_keep_mine_wins_everywhere", async () => {
  test.setTimeout(400_000);
  const base = `Conflict-mine-${Date.now()}`;
  await makeConflict(base);

  // Two versions, each with its name; the fields are compared one by one.
  await expect(b.page.locator('[data-role="side"][data-side="local"] [data-role="name"]')).toHaveText(`${base}-B`);
  await expect(b.page.locator('[data-role="side"][data-side="server"] [data-role="name"]')).toHaveText(`${base}-A`);
  await expect(b.page.locator('[data-role="conflict-field"][data-same="differs"]').first()).toBeVisible();
  await expect(b.page.locator('[data-role="conflict-field"]').locator('[data-role="status-word"]').first()).toBeVisible();
  await shot(b.page, "10-conflict-two-versions");

  await b.page.locator('[data-role="keep-mine"]').click();
  await shot(b.page, "10-conflict-keep-mine-question");
  await b.page.locator('[data-role="dialog-confirm"]').click();

  // B shows its own version, and so does A.
  await expect(b.page.locator('[data-role="item"] h1')).toContainText(`${base}-B`, { timeout: 30_000 });
  await openList(b.page);
  await expect(b.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
  await openList(a.page);
  await expect(rowsNamed(a.page, `${base}-B`)).toHaveCount(1, { timeout: SEEN });
  await expect(rowsNamed(a.page, `${base}-A`)).toHaveCount(0);
  await expect(a.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
  await openItem(a.page, `${base}-B`);
  await expect(a.page.locator('[data-role="item"]')).toContainText("b-user");
  await shot(a.page, "10-conflict-keep-mine-on-the-other-device");
});

test("keep_theirs_drops_the_local_change_everywhere", async () => {
  test.setTimeout(400_000);
  const base = `Conflict-theirs-${Date.now()}`;
  await makeConflict(base);

  await b.page.locator('[data-role="keep-theirs"]').click();
  await b.page.locator('[data-role="dialog-confirm"]').click();

  // B shows the server's version; B's change is gone, and A is as it was.
  await expect(b.page.locator('[data-role="item"] h1')).toContainText(`${base}-A`, { timeout: 30_000 });
  await openList(b.page);
  await expect(rowsNamed(b.page, `${base}-A`)).toHaveCount(1);
  await expect(rowsNamed(b.page, `${base}-B`)).toHaveCount(0);
  await expect(b.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
  await synced(b.page);
  await openList(a.page);
  await expect(rowsNamed(a.page, `${base}-A`)).toHaveCount(1);
  await expect(rowsNamed(a.page, `${base}-B`)).toHaveCount(0);
  await openItem(a.page, `${base}-A`);
  await expect(a.page.locator('[data-role="item"]')).toContainText("base-user");
  await shot(b.page, "10-conflict-keep-theirs");
});
