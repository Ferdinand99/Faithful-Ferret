// A write made offline is saved once when the browser is online again, even when the server stored the first try and
// the answer never arrived (the same write is sent again with the same key, and the server says it has it already).
import { createItem, expect, feedOf, newDevice, noViolations, openList, rowsNamed, shot, synced, test, useAccount } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  useAccount();
});

test("an_offline_write_is_saved_once_when_the_browser_is_online_again", async ({ browser }) => {
  test.setTimeout(500_000);
  const a = await newDevice(browser);
  const b = await newDevice(browser);
  try {
    await openList(a.page);
    await synced(b.page);
    const rowsBefore = (await feedOf(b.context)).changes.length;

    // B loses its network and writes. The write is saved on the device and the screen says that it is waiting.
    const name = `Offline-once-${Date.now()}`;
    await b.context.setOffline(true);
    await createItem(b.page, { name, username: "offline-user", notes: "written offline" });
    await expect(b.page.locator('[data-role="sync-status"]')).not.toHaveAttribute("data-state", "idle", { timeout: 30_000 });
    await shot(b.page, "12-offline-waiting");
    await expect(rowsNamed(a.page, name)).toHaveCount(0);

    // The network is back, but the first answer is lost: the server stores the write and the browser never hears of it.
    let lost = 0;
    await b.page.route("**/api/sync/items/*", async (route) => {
      if (route.request().method() === "PUT" && lost === 0) {
        lost += 1;
        await route.fetch();
        await route.abort("failed");
      } else {
        await route.continue();
      }
    });
    await b.context.setOffline(false);
    await b.page.evaluate(() => window.dispatchEvent(new Event("online")));

    // A has it, once. B has finished and holds one row, and the server holds one new row.
    await openList(a.page);
    await expect(rowsNamed(a.page, name)).toHaveCount(1, { timeout: 90_000 });
    await synced(b.page, 90_000);
    expect(lost, "the first answer was lost").toBe(1);
    await openList(b.page);
    await expect(rowsNamed(b.page, name)).toHaveCount(1);
    await b.page.waitForTimeout(3_000);
    await expect(rowsNamed(a.page, name)).toHaveCount(1);
    await expect(b.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
    await expect(a.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
    expect((await feedOf(b.context)).changes.length, "the server holds one new row").toBe(rowsBefore + 1);
    await shot(b.page, "12-offline-saved-once");
  } finally {
    await a.context.close();
    await b.context.close();
  }
});
