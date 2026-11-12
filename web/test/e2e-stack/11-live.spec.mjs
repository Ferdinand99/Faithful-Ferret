// Live updates: a change in one browser shows in the other within two seconds, the event stream is closed by the server
// when the session ends, and only the tab that runs the sync of a browser has a stream (the other tabs are on standby).
import { createItem, expect, newDevice, noViolations, openList, readStores, rowsNamed, shot, synced, test, unlockWith, secrets, useAccount, vaultUrl, signOutOn } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

/** @param {import("@playwright/test").Page} page */
const live = (page) => page.locator('[data-role="live-status"]');

test.beforeAll(() => {
  useAccount();
});

/**
 * What the device keeps of what the server showed before, read from the browser's store: how much the memory holds (it only
 * grows with the items seen) and the numbers that only go up.
 * @param {import("@playwright/test").Page} page
 */
async function memoryOfServer(page) {
  const record = (await readStores(page)).sync_state?.values?.[0];
  if (!record) throw new Error("the device keeps no record of what the server showed");
  return { memory: String(record.memory).length, restoreEpoch: record.restoreEpoch, verifiedSeq: record.verifiedSeq, uploadedSeq: record.uploadedSeq };
}

/**
 * Nothing was lowered between two readings: the memory is not smaller, and a number is not lower or gone.
 * @param {Awaited<ReturnType<typeof memoryOfServer>>} before @param {Awaited<ReturnType<typeof memoryOfServer>>} after @param {string} when
 */
function expectMonotonic(before, after, when) {
  expect(after.memory, `the memory is not smaller ${when}`).toBeGreaterThanOrEqual(before.memory);
  for (const key of /** @type {const} */ (["restoreEpoch", "verifiedSeq", "uploadedSeq"])) {
    if (before[key] === null) continue;
    expect(after[key], `${key} is not lower or gone ${when}`).not.toBeNull();
    expect(after[key], `${key} is not lower ${when}`).toBeGreaterThanOrEqual(before[key]);
  }
}

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

test("a_second_and_a_third_tab_open_no_stream_and_leave_the_record_of_the_server_alone", async ({ browser }) => {
  test.setTimeout(600_000);
  const { context, page: first } = await newDevice(browser);
  try {
    // Only the tab that runs the sync has a stream: the second and the third tab of the same browser are on standby.
    const tab = async () => {
      const page = await context.newPage();
      // The address of the first tab: a signed-in browser asks for the password there.
      await page.goto(`${vaultUrl}/vault/#/items`);
      await unlockWith(page, secrets.password);
      await expect(page.locator('[data-role="standby"]')).toBeVisible({ timeout: 90_000 });
      return page;
    };
    await expect(live(first)).toHaveAttribute("data-state", "live", { timeout: 30_000 });
    const recordOne = await memoryOfServer(first);
    const second = await tab();
    const third = await tab();
    // Neither tab has a live field or a list: they are not part of the sync.
    for (const page of [second, third]) {
      await expect(live(page)).toHaveCount(0);
      await expect(page.locator('[data-role="list"]')).toHaveCount(0);
    }
    await shot(third, "11-live-third-tab-standby");
    await expect(live(first)).toHaveAttribute("data-state", "live");

    // The sync goes on in the first tab, and the record of what the server showed is never lowered.
    const name = `Third-first-${Date.now()}`;
    await openList(first);
    await createItem(first, { name });
    await synced(first);
    expectMonotonic(recordOne, await memoryOfServer(first), "after two more tabs were opened and a change was made");
    await expect(first.locator('[data-role="sync-banner"]')).toHaveCount(0);
    await expect(first.locator('[data-role="sync-status"]')).not.toHaveAttribute("data-state", "halted");
  } finally {
    await context.close();
  }
});
