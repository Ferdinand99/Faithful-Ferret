// Live updates: a change in one browser shows in the other within two seconds, the event stream is closed by the server
// when the session ends, and a third tab of the same browser (the server gives a device two streams) falls back to
// reading now and then without breaking the sync or the record of what the server showed before.
import { createItem, expect, newDevice, noViolations, openList, rowsNamed, shot, synced, test, unlockWith, secrets, useAccount, vaultUrl, signOutOn } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

/** @param {import("@playwright/test").Page} page */
const live = (page) => page.locator('[data-role="live-status"]');

test.beforeAll(() => {
  useAccount();
});

test("a_change_in_one_browser_shows_in_the_other_within_2_seconds", async ({ browser }) => {
  test.setTimeout(400_000);
  const a = await newDevice(browser);
  const b = await newDevice(browser);
  try {
    await expect(live(a.page)).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    await expect(live(b.page)).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    await openList(b.page);
    await synced(b.page);
    await synced(a.page);

    for (const name of [`Live-one-${Date.now()}`, `Live-two-${Date.now()}`]) {
      // The clock starts when the server has the write, not when the form was sent.
      const stored = a.page.waitForResponse((r) => r.request().method() === "PUT" && r.url().includes("/api/sync/items/"));
      await createItem(a.page, { name, username: "live-user" });
      expect((await stored).status()).toBe(200);
      const from = Date.now();
      await expect(rowsNamed(b.page, name)).toHaveCount(1, { timeout: 2_000 });
      expect(Date.now() - from, "the other browser shows it within 2 seconds").toBeLessThan(2_000);
      await openList(a.page);
    }
    await shot(b.page, "11-live-the-other-browser");
  } finally {
    await a.context.close();
    await b.context.close();
  }
});

test("the_events_stream_closes_on_sign_out", async ({ browser }) => {
  test.setTimeout(400_000);
  const { context, page } = await newDevice(browser);
  try {
    await expect(live(page)).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    // Another tab of the same browser signs out: the session of this tab is over.
    const other = await context.newPage();
    await signOutOn(other);
    // The server closes the stream with the end of the session: this tab's channel stops, and it does not come back.
    await expect(live(page)).not.toHaveAttribute("data-state", "live", { timeout: 10_000 });
    await shot(page, "11-live-signed-out");
    await page.waitForTimeout(3_000);
    await expect(live(page)).not.toHaveAttribute("data-state", "live");
    // No session, no stream: the server refuses a new one.
    const response = await context.request.get(`${vaultUrl}/api/sync/events`, { headers: { "Ferret-Protocol": "1" } });
    expect(response.status()).toBe(401);
  } finally {
    await context.close();
  }
});

test("a_third_tab_falls_back_without_breaking_sync_or_lowering_a_floor", async ({ browser }) => {
  test.setTimeout(600_000);
  const { context, page: first } = await newDevice(browser);
  try {
    // A second and a third tab of the same browser: the server keeps two streams per device.
    const tab = async () => {
      const page = await context.newPage();
      // The address of the first tab: a signed-in browser asks for the password there.
      await page.goto(`${vaultUrl}/vault/#/items`);
      await unlockWith(page, secrets.password);
      await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 90_000 });
      return page;
    };
    const second = await tab();
    await expect(live(first)).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    await expect(live(second)).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    const third = await tab();
    // The third stream is refused, tried again a few times and then given up: the tab says so.
    await expect(live(third)).toHaveAttribute("data-state", "fallback", { timeout: 240_000 });
    await shot(third, "11-live-third-tab-fallback");

    // The sync goes on in every tab. A change in the first tab reaches the second by its stream.
    const fromFirst = `Third-first-${Date.now()}`;
    await openList(first);
    await createItem(first, { name: fromFirst });
    await openList(second);
    await expect(rowsNamed(second, fromFirst)).toHaveCount(1, { timeout: 15_000 });
    // The third tab reads when it is shown again.
    await openList(third);
    await third.evaluate(() => window.dispatchEvent(new Event("focus")));
    await expect(rowsNamed(third, fromFirst)).toHaveCount(1, { timeout: 30_000 });
    // And its own change is saved and reaches the others.
    const fromThird = `Third-own-${Date.now()}`;
    await createItem(third, { name: fromThird });
    await synced(third);
    await openList(first);
    await expect(rowsNamed(first, fromThird)).toHaveCount(1, { timeout: 15_000 });
    await openList(second);
    await expect(rowsNamed(second, fromThird)).toHaveCount(1, { timeout: 15_000 });

    // Three engines wrote the record of what the server showed, and none of them lowered it: no tab shows a warning.
    for (const page of [first, second, third]) {
      await expect(page.locator('[data-role="sync-banner"]')).toHaveCount(0);
      await expect(page.locator('[data-role="sync-status"]')).not.toHaveAttribute("data-state", "halted");
    }
  } finally {
    await context.close();
  }
});
