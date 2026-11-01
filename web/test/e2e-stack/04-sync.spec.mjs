// Scenario 4: two browsers on the same account see each other's changes within
// ten seconds (two contexts of one browser, and two different browsers), and
// signing out in one leaves the other signed in.
import { chromium, firefox, webkit } from "@playwright/test";
import { createItem, expect, freshContext, openList, requireAccount, rowsNamed, secrets, signInOn, signOutOn, test, vaultUrl } from "./support.mjs";

const SEEN = 10_000;

/** @param {import("@playwright/test").Page} page @param {string} name */
async function open(page, name) {
  await rowsNamed(page, name).locator('[data-role="item-link"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(name);
}

/**
 * Both sides change something and see the other's change.
 * @param {import("@playwright/test").Page} a
 * @param {import("@playwright/test").Page} b
 * @param {string} label
 */
async function exchange(a, b, label) {
  const first = `Sync-${label}-from-a`;
  const second = `Sync-${label}-from-b`;
  await createItem(a, { name: first, username: "a-user" });
  await openList(b);
  await expect(rowsNamed(b, first)).toHaveCount(1, { timeout: SEEN });
  await createItem(b, { name: second, username: "b-user" });
  await openList(a);
  await expect(rowsNamed(a, second)).toHaveCount(1, { timeout: SEEN });

  // A change to an item arrives too.
  await openList(b);
  await open(b, first);
  await b.locator('[data-role="edit"]').click();
  await b.locator('[data-role="name"]').fill(`${first}-edited`);
  await b.locator('[data-role="save"]').click();
  await expect(b.locator('[data-role="item"] h1')).toContainText(`${first}-edited`, { timeout: 30_000 });
  await openList(a);
  await expect(rowsNamed(a, `${first}-edited`)).toHaveCount(1, { timeout: SEEN });

  // So does a deletion.
  await open(a, second);
  await a.locator('[data-role="delete"]').click();
  await a.locator('[data-role="dialog-confirm"]').click();
  await expect(a.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  await openList(b);
  await expect(rowsNamed(b, second)).toHaveCount(0, { timeout: SEEN });
}

test("two_browsers_see_each_others_changes_within_10_seconds", async ({ browser }) => {
  test.setTimeout(600_000);
  requireAccount();

  // Two devices of the same browser.
  const one = await freshContext(browser);
  const two = await freshContext(browser);
  const a = await one.newPage();
  const b = await two.newPage();
  await signInOn(a);
  await signInOn(b);
  await exchange(a, b, "same");
  await one.close();
  await two.close();

  // Two different browsers: this one and the next of chromium, firefox, webkit.
  const kinds = { chromium, firefox, webkit };
  const mine = browser.browserType().name();
  const order = ["chromium", "firefox", "webkit"];
  const partner = order[(order.indexOf(mine) + 1) % order.length];
  const other = await kinds[partner].launch();
  try {
    const left = await freshContext(browser);
    const right = await freshContext(other);
    const p = await left.newPage();
    const q = await right.newPage();
    await signInOn(p);
    await signInOn(q);
    await exchange(p, q, `${mine}-${partner}`);
    await left.close();
    await right.close();
  } finally {
    await other.close();
  }
});

test("logging_out_in_one_browser_leaves_the_other_signed_in", async ({ browser }) => {
  test.setTimeout(400_000);
  requireAccount();
  const one = await freshContext(browser);
  const two = await freshContext(browser);
  const a = await one.newPage();
  const b = await two.newPage();
  await signInOn(a);
  await signInOn(b);
  expect((await a.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);
  expect((await b.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);

  await signOutOn(a);
  expect((await a.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);
  // The other browser is still signed in, and still syncs.
  expect((await b.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);
  await openList(b);
  const name = `Still-in-${secrets.itemTitle}`;
  await createItem(b, { name });
  await expect(b.locator('[data-role="sync-status"]')).toHaveAttribute("data-state", "idle", { timeout: 30_000 });
  // The data is on the server: a third device sees it.
  const three = await freshContext(browser);
  const c = await three.newPage();
  await signInOn(c);
  await expect(rowsNamed(c, name)).toHaveCount(1, { timeout: 10_000 });
  await one.close();
  await two.close();
  await three.close();
});
