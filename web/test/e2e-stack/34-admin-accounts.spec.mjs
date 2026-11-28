// The administrator acts on another account on the Users page, and the account sees it. A sign-in code that the
// administrator makes is in the account's log ("Activity") and is told at its next unlock, once, without the
// administrator's e-mail in the notice. Disabling the account and signing it out of every device end its open tabs
// and its device's tokens at once; while it is disabled it cannot sign in, and after it is enabled again it can.
//
// The steps that need a fresh check of the administrator's password (a sign-in code, enabling an account) run in a
// Chromium of their own in every project: Playwright's WebKit stops with an internal "Assertion error" on the
// redirect from the admin origin to the vault's password check (see accounts.mjs). Disabling and signing out need no
// fresh check (they take access away), so the administrator does them in the project's own browser, WebKit too.
// The account's own browser is always the project's.
import { accountRow, asConfirmedAdmin, joinedPerson, openUsersPage, rowAction, sessionOf } from "./accounts.mjs";
import { ApiError, changes, closeDevice, holdStream, signInDevice } from "./deviceClient.mjs";
import {
  expect, freshContext, lockNow, noViolations, openList, pace, requireAccount, secrets, signInHere, signInOn, SLOW, test, untilStartAccepted,
  vaultUrl,
} from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

/** @param {import("@playwright/test").Page} page */
const notice = (page) => page.locator('[data-role="account-notice"]');
/**
 * What an open vault shows once its session is over: the live updates stop because the server refuses the session
 * (or, after a sync that the server refused, the banner that says to sign in again).
 * @param {import("@playwright/test").Page} page
 */
const signInAgain = (page) =>
  page.locator('[data-role="live-status"][data-state="unauthorized"]').or(page.locator('[data-role="banner"][data-banner="unauthorized"]')).first();

/**
 * Locks the vault and opens it again with the master password (the session lives on).
 * @param {import("@playwright/test").Page} page @param {string} password
 */
async function lockAndUnlock(page, password) {
  await lockNow(page);
  await unlockHere(page, password);
}

/**
 * Opens the vault on an unlock page of a live session (a locked vault, or a new tab) with the master password.
 * @param {import("@playwright/test").Page} page @param {string} password
 */
async function unlockHere(page, password) {
  const unlock = page.locator('[data-role="unlock"][data-mode="session"]');
  await expect(unlock).toBeVisible({ timeout: 30_000 });
  await unlock.locator('[data-role="password"]').fill(password);
  await untilStartAccepted(page.context(), async () => {
    await pace();
    await unlock.locator('[data-role="submit"]').click();
  });
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
}

/** The status of the device's next read of the feed: 200, or the status it was refused with. @param {any} device */
async function feedStatus(device) {
  try {
    await changes(device);
    return 200;
  } catch (error) {
    return error instanceof ApiError ? error.status : -1;
  }
}

test("an_admin_code_shows_in_the_users_log_and_as_a_notice", async ({ browser }) => {
  test.setTimeout(900_000);
  requireAccount();
  const { person, context, page } = await joinedPerson(browser, "coded");
  // The account's own creation is where this browser starts: no notice for it.
  await page.waitForTimeout(2_000);
  await expect(notice(page)).toHaveCount(0);

  // The administrator makes a sign-in code for the account; the page shows it once, and the row says one is pending.
  const code = await asConfirmedAdmin(async (admin) => {
    await rowAction(admin, person.email, "sign-in-code");
    const shown = admin.locator("#created-sign-in-code");
    await expect(shown).toBeVisible({ timeout: 20_000 });
    await expect(accountRow(admin, person.email).locator('[data-col="code"]')).toBeVisible();
    return ((await shown.textContent()) ?? "").trim();
  });
  expect(code.length).toBeGreaterThan(6);

  // At the next unlock the account is told, with a way to the log. The notice names no e-mail and no code.
  await lockAndUnlock(page, person.password);
  await expect(notice(page)).toBeVisible({ timeout: 30_000 });
  await expect(notice(page).locator('[data-role="account-notice-text"]')).toContainText("An administrator made a sign-in code for your account");
  const said = await notice(page).innerText();
  expect(said).not.toContain(secrets.email);
  expect(said).not.toContain(code);

  // "Activity" lists it, newest first, with the administrator's e-mail, after the creation of the account.
  await notice(page).locator('[data-role="account-notice-link"]').click();
  await expect(page.locator('[data-role="activity-page"]')).toBeVisible({ timeout: 30_000 });
  const rows = page.locator('[data-role="activity-row"]');
  await expect(rows.first()).toHaveAttribute("data-kind", "sign_in_code_issued", { timeout: 30_000 });
  await expect(rows.first().locator('[data-role="activity-who"]')).toContainText(`By the administrator ${secrets.email}`);
  await expect(page.locator('[data-role="activity-row"][data-kind="account_created"]')).toHaveCount(1);
  expect(await page.locator('[data-role="activity-page"]').innerText()).not.toContain(code);
  await expect(notice(page)).toHaveCount(0);

  // Seen: the next unlock tells nothing.
  await openList(page);
  await lockAndUnlock(page, person.password);
  await page.waitForTimeout(3_000);
  await expect(notice(page)).toHaveCount(0);
  await context.close();
});

test("disable_and_sign_out_everywhere_end_the_users_tabs_and_devices", async ({ browser }) => {
  test.setTimeout(1_500_000);
  requireAccount();
  const { person, context, page } = await joinedPerson(browser, "ended");
  const credentials = { vaultUrl, email: person.email, password: person.password, secretKey: person.secretKey };
  // A second browser of the account (a session of its own; tabs of one browser share the session and run the sync in
  // one of them), and a device of hers with tokens (what the extension is) that holds its stream.
  const otherBrowser = await freshContext(browser);
  const tab = await otherBrowser.newPage();
  await signInOn(tab, { account: person });
  let device = await signInDevice(credentials);
  expect(await feedStatus(device)).toBe(200);
  let stream = await holdStream(device);

  // The administrator, in this project's browser, disables the account.
  const adminContext = await freshContext(browser);
  const admin = await adminContext.newPage();
  await openUsersPage(admin);
  await rowAction(admin, person.email, "disable");
  await expect(accountRow(admin, person.email).locator('[data-col="status"]')).toHaveText("Disabled", { timeout: 20_000 });

  // Both browsers say to sign in again; the device's tokens and stream are over.
  await expect(signInAgain(page)).toBeVisible({ timeout: 30_000 });
  await expect(signInAgain(tab)).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => stream.state.ended, { timeout: 30_000, message: "the device's stream ended" }).toBe(true);
  expect(await feedStatus(device)).toBe(401);
  expect(await sessionOf(context)).toBeNull();
  // While disabled, a sign-in does not open anything.
  await expect(signInDevice(credentials)).rejects.toThrow();
  closeDevice(device);

  // Enabled again (that needs the fresh check): she signs in again, in the browser and on the device.
  await asConfirmedAdmin(async (confirmed) => {
    await rowAction(confirmed, person.email, "enable");
    await expect(accountRow(confirmed, person.email).locator('[data-col="status"]')).toHaveText("Active", { timeout: 20_000 });
  });
  await otherBrowser.close();
  await page.goto(`${vaultUrl}/vault/login`);
  await signInHere(page, { account: person });
  device = await signInDevice(credentials);
  expect(await feedStatus(device)).toBe(200);
  stream = await holdStream(device);

  // Signed out of every device: the tab and the device are over again, the account stays active.
  await openUsersPage(admin);
  await rowAction(admin, person.email, "sign-out");
  await expect(accountRow(admin, person.email).locator('[data-col="status"]')).toHaveText("Active", { timeout: 20_000 });
  await expect(signInAgain(page)).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => stream.state.ended, { timeout: 30_000, message: "the device's stream ended" }).toBe(true);
  expect(await feedStatus(device)).toBe(401);
  closeDevice(device);

  // The next sign-in tells her what was done, and the log has all of it.
  await page.goto(`${vaultUrl}/vault/login`);
  await signInHere(page, { account: person });
  await expect(notice(page)).toBeVisible({ timeout: 30_000 });
  await expect(notice(page).locator('[data-role="account-notice-text"]')).toContainText("signed your account out of every device");
  await notice(page).locator('[data-role="account-notice-link"]').click();
  await expect(page.locator('[data-role="activity-row"]').first()).toHaveAttribute("data-kind", "signed_out_everywhere", { timeout: 30_000 });
  for (const kind of ["account_disabled", "account_enabled", "account_created"]) {
    await expect(page.locator(`[data-role="activity-row"][data-kind="${kind}"]`)).toHaveCount(1);
  }
  await adminContext.close();
  await context.close();
});
