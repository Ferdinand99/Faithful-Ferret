// Signing out of the admin pages leaves nothing of them behind in the tab. htmx keeps a snapshot of
// each page it navigated away from in the admin origin's sessionStorage, and the kit's sign-out
// leads on to the vault origin, so nothing on the admin origin would load to drop that cache. The
// admin sign-out ends on a page of the admin origin that does (`/auth/signed-out`).
import { adminUrl, expect, freshContext, recordWorkers, requireAccount, signInHere, SLOW, test, vaultUrl } from "./support.mjs";

const CACHE_KEY = "htmx-history-cache";

/** What htmx has cached in the admin origin's sessionStorage in this tab (the page must be on that origin). @param {import("@playwright/test").Page} page */
const cachedPages = (page) =>
  page.evaluate((key) => {
    const raw = window.sessionStorage.getItem(key);
    return raw === null ? [] : JSON.parse(raw);
  }, CACHE_KEY);

test("admin_sign_out_empties_the_history_cache_and_back_shows_no_admin_page", async ({ browser }) => {
  test.setTimeout(300_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await recordWorkers(page);

  // Sign in through the hand-over and land on the admin pages.
  await page.goto(`${adminUrl}/settings/general`);
  await signInHere(page, { expectList: false });
  await page.waitForURL((url) => url.origin === adminUrl && url.pathname === "/settings/general", { timeout: SLOW });

  // Open another admin page by an htmx navigation (a boosted link): htmx snapshots the page it leaves.
  await page.locator('.settings-nav a[href="/settings/users"]').click();
  await expect(page.locator('.settings-nav a[href="/settings/users"][aria-current="page"]')).toBeVisible();
  expect(new URL(page.url()).pathname).toBe("/settings/users");
  // The control: the cache holds a signed-in page now, so the empty cache below is the sign-out's doing.
  const before = await cachedPages(page);
  expect(JSON.stringify(before)).toContain("/settings/general");

  // Sign out from the account menu.
  await page.locator('button.user-button').click();
  await page.locator('form[action="/logout"] button[type="submit"]').click();
  await page.waitForURL((url) => url.origin === adminUrl && url.pathname === "/auth/signed-out", { timeout: 30_000 });
  await expect(page.getByRole("heading", { name: "You are signed out" })).toBeVisible();
  await expect.poll(() => cachedPages(page), { timeout: 10_000 }).toEqual([]);
  expect(await page.evaluate((key) => window.sessionStorage.getItem(key), CACHE_KEY)).toBeNull();
  expect((await context.request.get(`${adminUrl}/api/auth/session`)).status()).toBe(401);

  // Back: the admin page that was open is not shown. The guard turns the request away to the vault
  // origin's sign-in (no-store keeps the browser from showing the old page). In Playwright's WebKit
  // a Back from here stayed on the signed-out page for the whole test (no navigation was seen), so
  // there the test only checks that no admin page shows.
  const webkit = browser.browserType().name() === "webkit";
  await page.evaluate(() => history.back());
  if (webkit) {
    // The report shows that this run checked less than the other two.
    test.info().annotations.push({
      type: "weaker-check",
      description: "WebKit: Back from the signed-out page did not navigate in Playwright, so the Back-to-vault-sign-in check was skipped; only that no admin page shows was checked.",
    });
    await page.waitForTimeout(5_000);
  } else {
    await page.waitForURL((url) => url.origin === vaultUrl, { timeout: 30_000 });
    await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
  }
  expect(await page.locator(".settings-nav, .topnav, .user-button, #user-menu").count()).toBe(0);
  const html = await page.content();
  expect(html).not.toContain("/settings/users");
  expect(html).not.toContain("/settings/general");

  // The cache of the admin origin is still empty (read from a page of that origin in this tab).
  await page.goto(`${adminUrl}/static/favicon.svg`);
  expect(await cachedPages(page)).toEqual([]);
  expect(await page.evaluate((key) => window.sessionStorage.getItem(key), CACHE_KEY)).toBeNull();

  await context.close();
});

test("a_session_that_ended_without_log_out_leaves_no_cache_after_the_next_hand_over_page_runs", async ({ browser }) => {
  // An expired or revoked session never passes the signed-out page. The hand-over page of the next
  // sign-in in the tab drops what the earlier session left in sessionStorage.
  const context = await freshContext(browser);
  const page = await context.newPage();
  // A page of the admin origin that is not the hand-over page, to put the old snapshot in this tab.
  await page.goto(`${adminUrl}/static/favicon.svg`);
  await page.evaluate((key) => {
    window.sessionStorage.setItem(key, JSON.stringify([{ url: "/settings/users", content: "private" }]));
    window.sessionStorage.setItem("unrelated", "kept");
  }, CACHE_KEY);
  expect(await cachedPages(page)).toHaveLength(1);

  // The hand-over page, with no code (a hand-over that comes later has one): its script runs and starts by clearing.
  await page.goto(`${adminUrl}/auth/handoff`);
  await expect(page.locator("#handoff-status")).toBeVisible();
  await expect.poll(() => page.evaluate((key) => window.sessionStorage.getItem(key), CACHE_KEY), { timeout: 10_000 }).toBeNull();
  expect(await page.evaluate(() => window.sessionStorage.getItem("unrelated"))).toBe("kept");

  await context.close();
});
