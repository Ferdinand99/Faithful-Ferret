// One tab runs the sync of a browser. A second tab of the same browser shows "The vault is open in another tab" with the
// button "Use here", opens no stream and asks the server for nothing; the button moves the vault to the tab where it is
// pressed (the other tab is asked to stop and shows the notice), and a write that was waiting in the first tab is sent from
// the second, once. When the first tab does not answer, the lock is taken after about three seconds.
import { bodyText, createItem, expect, freshContext, newDevice, noViolations, openList, readStores, rowsNamed, secrets, shot, signInOn, synced, test, unlockWith, useAccount, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  useAccount();
});

/** @param {import("@playwright/test").Page} page */
const notice = (page) => page.locator('[data-role="standby"]');
/** @param {import("@playwright/test").Page} page */
const list = (page) => page.locator('[data-role="list"]');

/**
 * Opens the vault in a second tab of the browser and unlocks it. The tab does not get the vault: it shows the notice.
 * @param {import("@playwright/test").BrowserContext} context
 */
async function secondTab(context) {
  const page = await context.newPage();
  await page.goto(`${vaultUrl}/vault/#/items`);
  await unlockWith(page, secrets.password);
  return page;
}

/** The owner locks that this browser holds now (all tabs hold the same origin's locks). @param {import("@playwright/test").Page} page */
const ownerLocks = (page) =>
  page.evaluate(async () => (await navigator.locks.query()).held?.filter((lock) => String(lock.name).startsWith("ferret-sync-owner:")).length ?? 0);

test("a_second_tab_shows_the_notice_and_use_here_moves_the_vault_without_losing_a_write", async ({ browser }) => {
  test.setTimeout(600_000);
  const { context, page: first } = await newDevice(browser);
  try {
    await expect(first.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    const before = `Owner-first-${Date.now()}`;
    await createItem(first, { name: before, username: "owner-user" });
    await synced(first);
    await openList(first);
    expect(await ownerLocks(first), "one tab holds the vault").toBe(1);

    // A second tab: it asks the server for nothing, shows no item, and says where the vault is.
    const asked = /** @type {string[]} */ ([]);
    const second = await context.newPage();
    second.on("request", (request) => {
      if (new URL(request.url()).pathname.startsWith("/api/sync/")) asked.push(`${request.method()} ${new URL(request.url()).pathname}`);
    });
    await second.goto(`${vaultUrl}/vault/#/items`);
    await unlockWith(second, secrets.password);
    await expect(notice(second)).toBeVisible({ timeout: 90_000 });
    await expect(notice(second).locator("h1")).toHaveText("The vault is open in another tab");
    await expect(second.locator('[data-role="use-here"]')).toHaveText("Use here");
    await expect(list(second)).toHaveCount(0);
    await expect(second.locator('[data-role="shell"]')).toHaveCount(0);
    expect(await bodyText(second), "no vault data in the tab").not.toContain(before);
    expect(asked, "the tab on standby asked the server for nothing").toEqual([]);
    expect(await ownerLocks(second), "still one tab holds the vault").toBe(1);
    expect((await readStores(second)).outbox.count, "nothing is queued by a tab that has no engine").toBe(0);
    await shot(second, "17-owner-the-notice");

    // Nothing sticks out at 360 px, and the notice does not grow when the button is pressed.
    await second.setViewportSize({ width: 360, height: 740 });
    expect(await second.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), "no sideways scroll at 360 px").toBe(true);
    const box = await notice(second).boundingBox();
    expect(box && box.width <= 360, "the notice fits the page").toBe(true);
    await second.setViewportSize({ width: 1280, height: 800 });

    // The first tab writes while the network is gone: the write waits in the browser's outbox.
    const queued = `Owner-queued-${Date.now()}`;
    await context.setOffline(true);
    await createItem(first, { name: queued, username: "owner-user" });
    await expect.poll(async () => (await readStores(first)).outbox.count, { timeout: 30_000 }).toBeGreaterThan(0);

    // "Use here" in the second tab: the first is asked, stops and shows the notice; the vault is here.
    const keyboard = second.locator('[data-role="use-here"]');
    await keyboard.focus();
    await second.keyboard.press("Enter");
    await expect(list(second)).toBeVisible({ timeout: 30_000 });
    await expect(notice(first)).toBeVisible({ timeout: 30_000 });
    await expect(list(first)).toHaveCount(0);
    expect(await bodyText(first), "the tab that gave the vault up shows none of it").not.toContain(queued);
    expect(await ownerLocks(second), "one tab holds the vault, now the second").toBe(1);
    await expect(rowsNamed(second, before)).toHaveCount(1);
    await expect(rowsNamed(second, queued)).toHaveCount(1);
    await shot(first, "17-owner-the-first-tab-after-use-here");
    await shot(second, "17-owner-the-vault-moved");

    // The network is back: the write leaves from the second tab, once.
    await context.setOffline(false);
    await second.evaluate(() => window.dispatchEvent(new Event("online")));
    await synced(second, 90_000);
    const other = await newDevice(browser);
    try {
      await expect(rowsNamed(other.page, queued)).toHaveCount(1, { timeout: 60_000 });
      await expect(rowsNamed(other.page, before)).toHaveCount(1);
    } finally {
      await other.context.close();
    }

    // And back: "Use here" in the first tab.
    await first.locator('[data-role="use-here"]').click();
    // The tab shows the screen it was on (the page of the item it made last), now with the vault again.
    await expect(first.locator('[data-role="shell"]')).toBeVisible({ timeout: 30_000 });
    await expect(notice(first)).toHaveCount(0);
    await expect(notice(second)).toBeVisible({ timeout: 30_000 });
    await openList(first);
    expect(await ownerLocks(first)).toBe(1);
    await expect(rowsNamed(first, queued)).toHaveCount(1);
    await synced(first);
    // Neither tab shows a warning.
    await expect(first.locator('[data-role="sync-banner"]')).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test("use_here_takes_the_vault_after_about_three_seconds_when_the_other_tab_does_not_answer", async ({ browser }) => {
  test.setTimeout(400_000);
  const context = await freshContext(browser);
  // A tab that cannot be told anything: its owner channel hears nothing while the flag is set.
  await context.addInitScript(() => {
    const Native = window.BroadcastChannel;
    window.BroadcastChannel = /** @type {any} */ (class extends Native {
      /** @param {string} name */
      constructor(name) {
        super(name);
        if (!String(name).startsWith("ferret-sync-owner:")) return;
        const add = this.addEventListener.bind(this);
        this.addEventListener = /** @type {any} */ ((/** @type {string} */ type, /** @type {any} */ fn, /** @type {any} */ options) =>
          add(type, (/** @type {any} */ event) => {
            if (!(/** @type {any} */ (window).__deaf)) fn(event);
          }, options));
      }
    });
  });
  try {
    const first = await context.newPage();
    await signInOn(first);
    const name = `Owner-steal-${Date.now()}`;
    await createItem(first, { name, username: "owner-user" });
    await synced(first);
    const second = await secondTab(context);
    await expect(notice(second)).toBeVisible({ timeout: 90_000 });

    await first.evaluate(() => {
      /** @type {any} */ (window).__deaf = true;
    });
    const from = Date.now();
    await second.locator('[data-role="use-here"]').click();
    await expect(second.locator('[data-role="use-here"]')).toHaveAttribute("aria-busy", "true");
    await expect(list(second)).toBeVisible({ timeout: 30_000 });
    const took = Date.now() - from;
    expect(took, "the other tab was given about three seconds").toBeGreaterThanOrEqual(2_500);
    await expect(notice(first)).toBeVisible({ timeout: 30_000 });
    expect(await ownerLocks(second), "one tab holds the vault").toBe(1);
    await expect(rowsNamed(second, name)).toHaveCount(1);
    await shot(second, "17-owner-taken-after-three-seconds");
  } finally {
    await context.close();
  }
});
