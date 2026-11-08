// A restored server. The host script takes a snapshot of the server's data and puts it back with a higher restore number,
// while the two browsers stay open (scripts/lanbox-ferret-e2e-gate.sh m2 watches for the requests this file makes with
// `hostStep`). Both browsers say the server was restored and offer to accept the older state. The first to accept sends
// what the server lost without a conflict, over rows nobody changed since; the second gets a conflict where the first
// wrote. A write saved while the server is restored is refused by the server, and nothing lands in silence.
import { createItem, editItem, evilNow, existsHost, expect, feedOf, hostStep, itemIdOf, newDevice, noViolations, openItem, openList, putCheckpointOnTop, rowsNamed, serverRev, shot, synced, syncBanner, test, useAccount } from "./support.mjs";

const SEEN = 20_000;
const WARNED = 150_000;

test.describe.configure({ mode: "serial" });
noViolations();

/** @typedef {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} Device */
/** @type {Device} */
let a;
/** @type {Device} */
let b;

test.beforeAll(async ({ browser }) => {
  test.setTimeout(400_000);
  test.skip(!existsHost(), "needs the host script (scripts/lanbox-ferret-e2e-gate.sh m2)");
  useAccount();
  a = await newDevice(browser);
  b = await newDevice(browser);
});

test.afterAll(async () => {
  await a?.context.close();
  await b?.context.close();
});

/** @param {import("@playwright/test").Page} page */
async function openRestoredPage(page) {
  await syncBanner(page, "server_restored").locator('[data-action="see_what_happened"]').click();
  await expect(page.locator('[data-role="restored"]')).toBeVisible();
  await expect(page.locator('[data-role="restored-preview"]')).toBeVisible({ timeout: 60_000 });
}

/**
 * Accepts the older state on the page that shows it.
 * @param {import("@playwright/test").Page} page
 */
async function accept(page) {
  await page.locator('[data-role="restored-word"]').fill("accept");
  await page.locator('[data-role="restored-accept"]').click();
  await expect(page.locator('[data-role="restored-done"]')).toBeVisible({ timeout: 120_000 });
}

test("a_restored_server_offers_accept_older_state_in_both_browsers_and_overwrites_nothing", async ({ browser }) => {
  test.setTimeout(1_500_000);
  const tag = Date.now();
  const untouched = `Restore-untouched-${tag}`;
  const quiet = `Restore-quiet-${tag}`;
  const bonly = `Restore-bonly-${tag}`;
  for (const name of [untouched, quiet, bonly]) await createItem(a.page, { name, username: "before-the-backup" });
  await openList(b.page);
  for (const name of [untouched, quiet, bonly]) await expect(rowsNamed(b.page, name)).toHaveCount(1, { timeout: SEEN });
  await synced(a.page);
  await synced(b.page);

  // A checkpoint on top of the feed goes up before the snapshot: the clock of the server moves ten minutes on, and a new
  // device, which has not uploaded one yet, makes it.
  await hostStep("clock-600");
  await putCheckpointOnTop(browser);
  await hostStep("snapshot");

  // After the snapshot each browser changes an item (and sees the other's change). All of it will be lost by the restore.
  await editItem(a.page, quiet, { name: `${quiet}-a`, username: "after-the-backup-a" });
  await editItem(b.page, bonly, { name: `${bonly}-b`, username: "after-the-backup-b" });
  await openList(a.page);
  await expect(rowsNamed(a.page, `${bonly}-b`)).toHaveCount(1, { timeout: SEEN });
  await openList(b.page);
  await expect(rowsNamed(b.page, `${quiet}-a`)).toHaveCount(1, { timeout: SEEN });
  await synced(a.page);
  await synced(b.page);

  await hostStep("restore");

  // Both browsers say that the server was restored, and nothing is gone from either list.
  await expect(syncBanner(a.page, "server_restored")).toBeVisible({ timeout: WARNED });
  await expect(syncBanner(b.page, "server_restored")).toBeVisible({ timeout: WARNED });
  await shot(a.page, "15-restored-banner-a");
  await shot(b.page, "15-restored-banner-b");
  await openList(a.page);
  await expect(rowsNamed(a.page, `${quiet}-a`)).toHaveCount(1);
  await expect(rowsNamed(a.page, `${bonly}-b`)).toHaveCount(1);

  // The first browser accepts. What the server lost goes out again over rows that nobody changed since the restore, and
  // there is no conflict.
  await openRestoredPage(a.page);
  await expect(a.page.locator('[data-role="preview-reupload"]')).toContainText("2");
  await expect(a.page.locator('[data-role="preview-conflicts"]')).toContainText("0");
  await shot(a.page, "15-restored-preview-a");
  await accept(a.page);
  await expect(a.page.locator('[data-role="restored-done"]')).toContainText("2");
  await expect(a.page.locator('[data-role="restored-conflicts"]')).toHaveCount(0);
  await shot(a.page, "15-restored-accepted-a");
  await openList(a.page);
  await expect(a.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
  await expect(rowsNamed(a.page, `${quiet}-a`)).toHaveCount(1);
  await expect(rowsNamed(a.page, `${bonly}-b`)).toHaveCount(1);
  await synced(a.page, 90_000);
  const quietId = await itemIdOf(a.page, `${quiet}-a`);
  await expect.poll(async () => serverRev(a.context, quietId), { timeout: 60_000, message: "A's version is on the server again" }).toBeGreaterThan(1);

  // The second browser accepts. A wrote after the restore, so every item A sent gives a conflict here, and nothing that
  // nobody changed does. Nothing of A's is overwritten.
  await openRestoredPage(b.page);
  await expect(b.page.locator('[data-role="preview-conflicts"]')).toContainText("2");
  await shot(b.page, "15-restored-preview-b");
  await accept(b.page);
  await expect(b.page.locator('[data-role="restored-conflicts"]')).toBeVisible();
  await shot(b.page, "15-restored-accepted-b");
  await openList(b.page);
  await expect(b.page.locator('[data-role="conflict-note"]')).toBeVisible();
  await expect(b.page.locator('[data-role="conflict-note"]')).toContainText("2");
  await expect(rowsNamed(b.page, untouched)).toHaveCount(1);
  await shot(b.page, "15-restored-conflicts-in-the-list-b");
  // The conflict shows both versions.
  await b.page.locator('[data-role="first-conflict"]').click();
  await expect(b.page.locator('[data-role="conflict"]')).toBeVisible();
  await expect(b.page.locator('[data-role="side"]')).toHaveCount(2);
  await shot(b.page, "15-restored-conflict-view-b");
  // Settling both with the server's version leaves the two browsers the same.
  for (let left = 2; left > 0; left -= 1) {
    await b.page.locator('[data-role="keep-theirs"]').click();
    await b.page.locator('[data-role="dialog-confirm"]').click();
    await expect(b.page.locator('[data-role="item"] h1')).toBeVisible({ timeout: 30_000 });
    await openList(b.page);
    if (left > 1) await b.page.locator('[data-role="first-conflict"]').click();
  }
  await expect(b.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
  await openList(a.page);
  await expect(rowsNamed(a.page, `${quiet}-a`)).toHaveCount(1);
  await expect(rowsNamed(b.page, `${quiet}-a`)).toHaveCount(1);
  await expect(rowsNamed(b.page, `${bonly}-b`)).toHaveCount(1);
});

test("a_write_saved_during_a_restore_is_refused_and_the_banner_appears", async () => {
  test.setTimeout(1_200_000);
  const tag = Date.now();
  const target = `Refused-${tag}`;
  const lower = `Refused-lower-${tag}`;
  await createItem(a.page, { name: target, username: "before" });
  await openList(b.page);
  await expect(rowsNamed(b.page, target)).toHaveCount(1, { timeout: SEEN });
  await synced(a.page);
  await synced(b.page);
  await hostStep("snapshot");
  // Something the restore will take away, which both browsers have seen: the restore will look older than what they know.
  await createItem(a.page, { name: lower });
  await openList(b.page);
  await expect(rowsNamed(b.page, lower)).toHaveCount(1, { timeout: SEEN });
  await synced(b.page);
  const id = await itemIdOf(b.page, target);
  const rev = await serverRev(b.context, id);

  // B is open and cannot read: it does not hear that the server is restored. It can still write.
  await b.page.route(/\/api\/sync\/(events|changes|checkpoint)|\/api\/sync\/items\?/, (route) => route.abort("failed"));
  await hostStep("restore");
  const epochAfter = (await feedOf(b.context)).restore_epoch;
  const refused = b.page.waitForResponse((r) => r.request().method() === "PUT" && r.url().includes("/api/sync/items/"));
  await editItem(b.page, target, { name: `${target}-saved-during-restore`, username: "after" });
  // The answer to the write: 409, and the reason is the restore number.
  const answer = await refused;
  expect(answer.status()).toBe(409);
  expect((await answer.json()).error).toBe("restore_epoch_changed");

  // The server refused it for the restore number, and it did not land: the row is as it was.
  await b.page.waitForTimeout(5_000);
  expect(await serverRev(b.context, id), "the write did not land").toBe(rev);
  expect(epochAfter, "the server was restored").toBeGreaterThan(0);
  await expect(rowsNamed(b.page, `${target}-saved-during-restore`)).toHaveCount(1);

  // B can read again and says so: the server was restored, and the write is kept and waits.
  await b.page.unroute(/\/api\/sync\/(events|changes|checkpoint)|\/api\/sync\/items\?/);
  await b.page.evaluate(() => window.dispatchEvent(new Event("online")));
  await b.page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(syncBanner(b.page, "server_restored")).toBeVisible({ timeout: WARNED });
  await shot(b.page, "15-restored-write-refused");
  expect(await serverRev(b.context, id), "still not on the server").toBe(rev);
  await expect(rowsNamed(b.page, `${target}-saved-during-restore`)).toHaveCount(1);
});
