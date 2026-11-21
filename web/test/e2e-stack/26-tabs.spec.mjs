// Two and three tabs of one browser, with the real server. A tab that holds unsaved text is asked before the vault moves, and its
// form comes back whole; locking the tab that holds the vault hands it to the tab that waits, and a tab that is out of view does not
// take it; a tab that does not answer is warned about, and a waiting tab that nobody sees does not stand in the way. The last
// scenario puts a copy of the server's data back over a server that has purged the tombstones the copy still holds.
import { addNeedle, createItem, expect, feedOf, freshContext, hostStep, itemIdOf, leave, newDevice, noViolations, openItem, openList, putCheckpointOnTop, readStores, rowsNamed, secrets, serverRev, signInHere, signInOn, SLOW, synced, test, unlockWith, untilStartAccepted, useAccount, vaultUrl } from "./support.mjs";

// The scenarios do not depend on each other (each makes its own browsers), so one that fails does not skip the rest.
noViolations();

test.beforeAll(() => {
  useAccount();
});

/** @param {import("@playwright/test").Page} page */
const notice = (page) => page.locator('[data-role="standby"]');
/** @param {import("@playwright/test").Page} page */
const list = (page) => page.locator('[data-role="list"]');

/**
 * Unlocks the vault in a tab. The server's limit counts the sign-ins and unlocks of the earlier scenarios too, which this process does not
 * know of: when it says so, the wait it names is taken and the form is sent again (see untilStartAccepted).
 * @param {import("@playwright/test").Page} page @param {import("@playwright/test").Locator} done what shows when the unlock has worked
 */
async function unlockPatiently(page, done) {
  await untilStartAccepted(page.context(), () => unlockWith(page, secrets.password));
  await done.waitFor({ timeout: SLOW }).catch(() => {});
}

/**
 * Opens the vault in another tab of the browser and unlocks it: the tab shows the notice that the vault is open elsewhere.
 * @param {import("@playwright/test").BrowserContext} context
 */
async function waitingTab(context) {
  const page = await context.newPage();
  await page.goto(`${vaultUrl}/vault/#/items`);
  await unlockPatiently(page, notice(page));
  await expect(notice(page)).toBeVisible({ timeout: 90_000 });
  return page;
}

/** The locks of the vault that this browser holds now (all tabs hold the same origin's locks). @param {import("@playwright/test").Page} page */
const locksHeld = (page) =>
  page.evaluate(async () => (await navigator.locks.query()).held?.filter((lock) => String(lock.name).startsWith("ferret-sync-owner:")).length ?? 0);

/**
 * Makes the tab say that it is out of view (the way a tab behind another one, or a minimised window, does), or in view again.
 * @param {import("@playwright/test").Page} page @param {boolean} hidden
 */
async function setHidden(page, hidden) {
  await page.evaluate((hide) => {
    if (hide) {
      Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
      Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
    } else {
      // @ts-ignore: removes the made-up properties, so the real ones show again
      delete document.visibilityState;
      // @ts-ignore
      delete document.hidden;
    }
    document.dispatchEvent(new Event("visibilitychange"));
  }, hidden);
}

/**
 * The restore number the server shows now. The last page of the feed is asked for (a cursor at the end), so that a vault of more than
 * a page, or a feed whose floor has moved (410 for an old cursor), does not matter.
 * @param {import("@playwright/test").BrowserContext} context
 */
async function restoreEpochOf(context) {
  const response = await context.request.get(`${vaultUrl}/api/sync/changes?since=9007199254740991&limit=1`, { headers: { "Ferret-Protocol": "1" } });
  if (response.status() !== 200) throw new Error(`the change feed answered ${response.status()}`);
  return (await response.json()).restore_epoch;
}

test("use_here_with_an_unsaved_edit_warns_first", async ({ browser }) => {
  test.setTimeout(900_000);
  const { context, page: first } = await newDevice(browser);
  try {
    await expect(first.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    // A form with text in it that is not saved.
    const name = `Tabs-draft-${Date.now()}`;
    const password = `Draft-pw-${Date.now()}-x!`;
    await first.locator('[data-role="nav-new"]').click();
    await expect(first.locator('[data-role="edit-form"]')).toBeVisible();
    await first.locator('[data-role="name"]').fill(name);
    await first.locator('[data-role="username"]').fill("draft-user");
    await first.locator('[data-role="password"]').fill(password);

    const second = await waitingTab(context);
    /** @type {string[]} */
    const sentFromFirst = [];
    first.on("request", (request) => {
      if (new URL(request.url()).pathname.startsWith("/api/sync/") && request.method() !== "GET") sentFromFirst.push(`${request.method()} ${new URL(request.url()).pathname}`);
    });

    // "Use here": the first tab is asked, says it has unsaved text, and the second tab warns before anything moves.
    await second.locator('[data-role="use-here"]').click();
    await expect(second.locator('[data-role="warning"]')).toBeVisible({ timeout: 30_000 });
    await expect(second.locator('[data-role="warning"]')).toContainText(/not saved/i);
    expect(await locksHeld(second), "nothing moved yet").toBe(1);
    await expect(first.locator('[data-role="edit-form"]')).toBeVisible();
    // Cancel keeps things as they were; the button asks again.
    await second.locator('[data-role="warning-cancel"]').click();
    await expect(second.locator('[data-role="warning"]')).toBeHidden();
    await second.locator('[data-role="use-here"]').click();
    await expect(second.locator('[data-role="warning"]')).toBeVisible({ timeout: 30_000 });
    await second.locator('[data-role="use-here-anyway"]').click();
    await expect(list(second)).toBeVisible({ timeout: 60_000 });
    expect(await locksHeld(second), "the vault is in the second tab now").toBe(1);

    // The first tab keeps the form on the screen, read-only, with every character that was typed, and offers to take the vault back.
    await expect(notice(first)).toBeVisible({ timeout: 30_000 });
    await expect(first.locator('[data-role="take-back"]')).toBeVisible();
    await expect(first.locator('[data-role="name"]')).toHaveValue(name);
    await expect(first.locator('[data-role="name"]')).toHaveAttribute("readonly", "");
    await expect(first.locator('[data-role="password"]')).toHaveValue(password);
    expect(sentFromFirst, "the first tab sent nothing while its form was kept").toEqual([]);
    expect((await readStores(first)).outbox.count, "the unsaved text is not in the outbox").toBe(0);

    // "Take back": the vault comes to the first tab (the second has no unsaved text, so it is not asked twice), the form is
    // editable again with the same text, and saving it writes the item once.
    await first.locator('[data-role="take-back"]').click();
    await expect(notice(second)).toBeVisible({ timeout: 60_000 });
    await expect(first.locator('[data-role="edit-form"]')).toBeVisible({ timeout: 60_000 });
    // The page settles (the screen is built again under the new engine), then the form is the one that was kept: editable, with
    // every character that was typed.
    await first.waitForTimeout(2_000);
    await expect(first.locator('[data-role="name"]')).toHaveValue(name);
    await expect(first.locator('[data-role="name"]')).not.toHaveAttribute("readonly", "");
    await expect(first.locator('[data-role="password"]')).toHaveValue(password);
    expect(await locksHeld(first), "one tab holds the vault, the first").toBe(1);
    await first.locator('[data-role="save"]').click();
    await expect(first.locator('[data-role="item"] h1')).toContainText(name, { timeout: 60_000 });
    await synced(first);
    await openList(first);
    const id = await itemIdOf(first, name);
    await expect.poll(() => serverRev(context, id), { timeout: 60_000, message: "the item is on the server" }).toBe(1);
    expect((await feedOf(context)).changes.filter((change) => change.id === id), "once").toHaveLength(1);
    addNeedle("tab draft password", password);
  } finally {
    await context.close();
  }
});

test("locking_the_owner_tab_hands_over_to_the_other", async ({ browser }) => {
  test.setTimeout(900_000);
  const { context, page: holder } = await newDevice(browser);
  try {
    await expect(holder.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    // B waits first, C second; C is then out of view (a tab behind others).
    const b = await waitingTab(context);
    const c = await waitingTab(context);
    await setHidden(c, true);
    await b.bringToFront();
    expect(await locksHeld(holder)).toBe(1);

    // The tab that holds the vault locks: the tab in view that waits gets the vault, and starts its engine; the hidden one does not.
    await holder.locator('[data-role="lock"]').click();
    await expect(list(b)).toBeVisible({ timeout: 90_000 });
    await expect(b.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "live", { timeout: 60_000 });
    await expect(notice(c)).toBeVisible();
    await expect(list(c)).toHaveCount(0);
    expect(await locksHeld(b), "one tab holds the vault").toBe(1);

    // C comes into view while B holds the vault: it still waits.
    await setHidden(c, false);
    await c.bringToFront();
    await c.waitForTimeout(3_000);
    await expect(notice(c)).toBeVisible();
    expect(await locksHeld(c), "still one").toBe(1);

    // B locks: C starts. No tab ever held two locks.
    await b.locator('[data-role="lock"]').click();
    await expect(list(c)).toBeVisible({ timeout: 90_000 });
    await expect(c.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "live", { timeout: 60_000 });
    expect(await locksHeld(c), "one tab holds the vault, the last").toBe(1);
    await expect(c.locator('[data-role="sync-banner"]')).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test("a_tab_that_does_not_answer_is_warned_about_and_a_hidden_tab_at_the_head_of_the_queue_does_not_stand_in_the_way", async ({ browser }) => {
  test.setTimeout(900_000);
  const context = await freshContext(browser);
  // A tab that cannot be told anything: its channel for the vault hears nothing while the flag is set.
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
    const holder = await context.newPage();
    await signInOn(holder);
    const name = `Tabs-deaf-${Date.now()}`;
    await createItem(holder, { name, username: "deaf-user" });
    await synced(holder);
    // The tab at the head of the queue is out of view (it is behind the others); the one in view comes after it.
    const head = await waitingTab(context);
    await setHidden(head, true);
    const visible = await waitingTab(context);
    await visible.bringToFront();
    await holder.evaluate(() => {
      /** @type {any} */ (window).__deaf = true;
    });

    const from = Date.now();
    await visible.locator('[data-role="use-here"]').click();
    await expect(visible.locator('[data-role="warning"]')).toBeVisible({ timeout: 30_000 });
    await expect(visible.locator('[data-role="warning"]')).toContainText(/did not answer/i);
    await visible.locator('[data-role="use-here-anyway"]').click();
    // The vault is the visible tab's after about three seconds, although a tab stands first in the queue.
    await expect(list(visible)).toBeVisible({ timeout: 60_000 });
    expect(Date.now() - from, "the other tab was given about three seconds").toBeGreaterThanOrEqual(2_500);
    await expect(rowsNamed(visible, name)).toHaveCount(1);
    await expect(notice(holder)).toBeVisible({ timeout: 30_000 });
    await expect(notice(head)).toBeVisible();
    expect(await locksHeld(visible), "one tab holds the vault").toBe(1);
  } finally {
    await context.close();
  }
});

test("a_restore_over_purged_tombstones_leaves_no_alarm_and_brings_nothing_back_to_life", async ({ browser }) => {
  test.setTimeout(2_700_000);
  // The server clock moves 401 days on in this test and is not set back: it is the last one of the run.
  const tag = Date.now().toString(36);
  const keep = `Purge-keep-${tag}`;
  const gone = `Purge-gone-${tag}`;
  const first = await newDevice(browser);
  await createItem(first.page, { name: keep, username: "kept" });
  await createItem(first.page, { name: gone, username: "deleted" });
  await synced(first.page);
  await openItem(first.page, gone);
  await first.page.locator('[data-role="delete"]').click();
  await first.page.locator('[data-role="dialog-confirm"]').click();
  await expect(list(first.page)).toBeVisible({ timeout: 30_000 });
  await synced(first.page);
  // A checkpoint on top of the feed (so the tombstone may be purged later) goes up from a new device; then a copy of the server's data
  // (the host stops the app, copies the data volume and starts the app again: what a backup holds, without the sets' own retention,
  // which would prune it once the clock is 401 days on).
  await putCheckpointOnTop(browser);
  await hostStep("snapshot");
  await first.context.close();

  // 401 days on: the sessions are over, and the next pass of the retention job purges the tombstone. A new browser signs in at the
  // new time and sees the feed floor move (a feed that starts before it is refused with 410).
  await hostStep("clock-34646400");
  const late = await newDevice(browser);
  await expect
    .poll(async () => (await late.context.request.get(`${vaultUrl}/api/sync/changes?since=1&limit=1`, { headers: { "Ferret-Protocol": "1" } })).status(), {
      timeout: 240_000,
      intervals: [5_000],
      message: "the retention job purges the old tombstone",
    })
    .toBe(410);
  await synced(late.page);
  await openList(late.page);
  await expect(rowsNamed(late.page, keep)).toHaveCount(1);
  await expect(rowsNamed(late.page, gone)).toHaveCount(0);

  // The copy from before the purge is put back with a higher restore number: the tombstone is on the server again, with the feed floor
  // of the copy.
  const epochSeen = await restoreEpochOf(late.context);
  await hostStep("restore");
  const fresh = await newDevice(browser);
  await expect(rowsNamed(fresh.page, keep)).toHaveCount(1, { timeout: 90_000 });
  await expect(rowsNamed(fresh.page, gone), "nothing the backup deleted comes back to life").toHaveCount(0);
  await synced(fresh.page, 90_000);
  // No warning about the feed, the checkpoint or a rollback: a new browser on a restored server has nothing to compare with.
  await expect(fresh.page.locator('[data-role="sync-banner"]')).toHaveCount(0);
  await expect(fresh.page.locator('[data-role="banner"][data-banner^="error:"]')).toHaveCount(0);
  await expect(fresh.page.locator('[data-role="banner"][data-banner^="warning:"]')).toHaveCount(0);
  // The browser that saw the purge was kept open across the restore: its session is over and it signs in again. The server shows a higher
  // restore number, and this browser holds nothing that the restored server lacks, so there is nothing to offer and nothing to alarm:
  // no banner about the feed, the checkpoint, a rollback or a restore, and the deleted item stays deleted.
  expect((await late.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the session from before the restore is over").toBe(401);
  await late.page.goto(`${vaultUrl}/vault/login`);
  await signInHere(late.page);
  await synced(late.page, 90_000);
  await late.page.waitForTimeout(10_000);
  expect(await restoreEpochOf(late.context), "the server shows a higher restore number").toBeGreaterThan(epochSeen);
  const codes = await late.page.locator('[data-role="sync-banner"]').evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-code")));
  expect(codes, "no alarm and no offer").toEqual([]);
  await expect(late.page.locator('[data-role="banner"][data-banner^="error:"]')).toHaveCount(0);
  await expect(late.page.locator('[data-role="banner"][data-banner^="warning:"]')).toHaveCount(0);
  await openList(late.page);
  await expect(rowsNamed(late.page, keep)).toHaveCount(1);
  await expect(rowsNamed(late.page, gone), "the deleted item stays deleted").toHaveCount(0);
  await late.context.close();
  const feed = await feedOf(fresh.context);
  expect(feed.changes.some((change) => change.deleted), "the restored server holds the tombstone again").toBe(true);
  expect(feed.restore_epoch).toBeGreaterThan(0);
  await fresh.context.close();

  // What the host script searches for in the data, the backup sets and the log at the end of the run.
  const standard = {
    "master password": secrets.password,
    "secret key": secrets.secretKey,
    "recovery key": secrets.recoveryKey,
    "setup qr text": secrets.qrText,
    ...secrets.needles,
  };
  leave("needles", Object.entries(standard).filter(([, value]) => typeof value === "string" && value.length >= 8).map(([name, value]) => ({ name, value })));
  leave("state", { email: secrets.email });
  leave("m3-26", { done: true });
});
