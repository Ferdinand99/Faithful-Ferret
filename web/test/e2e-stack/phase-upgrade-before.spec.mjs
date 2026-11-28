// The first half of the upgrade drill (scripts/lanbox-ferret-test.sh upgrade-drill <tag>). The stack runs the published
// image of the release before (by digest), and this file gives it the first account with everything such an account
// holds: the account with its secret key, a login item, a folder, an item with a one-time password, an item in the trash,
// a changed PIN rule, a device with tokens (the extension's sign-in, through deviceClient.mjs) and a passkey unlock method
// made with a virtual authenticator. Then the host makes a backup set with that release and swaps the server's image for
// the candidate build of this branch on the same data volume, while this browser and the device stay open, as a
// person's browser and extension stay open while the server is upgraded. What only they can prove is checked after the
// swap, here: the device renews its token without a new sign-in, and the passkey method still opens the vault.
// phase-upgrade-after.spec.mjs follows in a fresh browser.
//
// The browser and the device live through the upgrade in this one run because neither can be carried to another run:
// Chromium's virtual authenticator keeps the PRF key of a passkey in memory only (the DevTools credential has no field for
// it, so a passkey put back in another browser gives no PRF output), and the device's DPoP key is a non-extractable key.
//
// Chromium only: the other browsers have no virtual authenticator that a test can drive.
import { changes, closeDevice, signInDevice } from "./deviceClient.mjs";
import {
  adminUrl, API_HEADERS, createItem, expect, findRows, freshContext, hostStep, leave, noViolations, openItem, openList, pace, secrets,
  setUpAccount, signInHere, SLOW, synced, test, totpReference, vaultUrl,
} from "./support.mjs";

test.skip(process.env.FERRET_E2E_PHASE !== "upgrade-before", "run by scripts/lanbox-ferret-test.sh upgrade-drill");
test.describe.configure({ mode: "serial" });
noViolations();

/** The secret of the one-time password (RFC 6238, appendix B). */
const TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/** The PIN rule the administrator sets on the release: a stricter one than the default (6 characters, after a restart). */
const RULE = { allowed: true, after_restart: false, min_length: 8 };
/** The id of the vault's manifest in the change feed (it is not an item). */
const MANIFEST_ID = "0".repeat(32);

const tag = secrets.itemTitle.split("-")[1] ?? "run";
/** The names of what the account holds besides the login item of the run. */
const names = {
  folder: `Folder-${tag}-upgrade`,
  totp: `Totp-${tag}-upgrade`,
  trashed: `Trashed-${tag}-upgrade`,
  passkey: `Passkey-${tag}-upgrade`,
};

/** The browser that makes the passkey method and stays open over the upgrade. */
/** @type {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} */
let kept;
/** The device with tokens, open over the upgrade too. @type {import("./deviceClient.mjs").Device} */
let device;
/** The item ids the device read before the upgrade. @type {string[]} */
let deviceSaw = [];

test.afterAll(async () => {
  if (device) closeDevice(device);
  await kept?.context.close();
});

/** @param {import("@playwright/test").Page} page */
const sessionUnlock = (page) => page.locator('[data-role="unlock"][data-mode="session"]');
/** @param {import("@playwright/test").Page} page */
const passkeyButton = (page) => page.locator('[data-role="passkey-unlock"]');

/**
 * Answers the master password dialog of the vault when it opens.
 * @param {import("@playwright/test").Page} page
 */
async function answerReauth(page) {
  const dialog = page.locator('[data-role="reauth-dialog"]');
  await expect(dialog).toBeVisible({ timeout: 30_000 });
  await dialog.locator('[data-role="reauth-password"]').fill(secrets.password);
  await pace();
  await dialog.locator('[data-role="reauth-confirm"]').click();
  await expect(dialog).toHaveCount(0, { timeout: SLOW });
}

/** The passkey methods the server lists, from the page's own session. @param {import("@playwright/test").Page} page */
async function serverPasskeys(page) {
  const answer = await page.request.get(`${vaultUrl}/api/vault/unlock-methods`);
  expect(answer.status()).toBe(200);
  return /** @type {any[]} */ ((await answer.json()).methods).filter((method) => method.method_type === 3);
}

/** The ids of the live items in a device's change feed (not the manifest, whose id is all zeros). @param {any} feed */
const liveIds = (feed) => /** @type {any[]} */ (feed.changes).filter((c) => !c.deleted && c.id !== MANIFEST_ID).map((c) => c.id).sort();

test("the_release_gets_an_account_with_everything_in_it", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium (its virtual authenticator)");
  test.setTimeout(900_000);
  const context = await freshContext(browser);
  const page = await context.newPage();
  kept = { context, page };
  await setUpAccount(page);

  // A login item, the item the other scenarios know by the run's title, in a folder.
  await createItem(page, { name: secrets.itemTitle, username: secrets.itemUsername, password: secrets.itemPassword, url: secrets.itemUrl, notes: secrets.itemNotes });
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  await page.locator('[data-role="folder-input"]').fill(names.folder);
  await page.locator('[data-role="folder-input"]').press("Enter");
  await expect(page.locator('[data-role="folder-picked-chip"]', { hasText: names.folder })).toBeVisible();
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="folder-chip"]', { hasText: names.folder })).toBeVisible({ timeout: 30_000 });

  // An item with a one-time password.
  await createItem(page, { name: names.totp, username: "totp-user" });
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  await page.locator('[data-role="totp"]').fill(TOTP_SECRET);
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(names.totp, { timeout: 30_000 });
  await expect(page.locator('[data-role="item-card"][data-card="totp"]')).toBeVisible();

  // An item in the trash.
  await createItem(page, { name: names.trashed, username: "trash-user" });
  await openItem(page, names.trashed);
  await page.locator('[data-role="delete"]').click();
  await page.locator('[data-role="dialog-confirm"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  await expect(await findRows(page, names.trashed)).toHaveCount(0);
  await openList(page);
  await page.locator('[data-role="trash-link"]').click();
  await expect(page.locator('[data-role="trash-item"]', { hasText: names.trashed })).toHaveCount(1, { timeout: 30_000 });
  await openList(page);
  await synced(page);

  leave("state", { ...secrets, upgrade: { names, totpSecret: TOTP_SECRET, rule: RULE } });
});

test("the_release_gets_a_stricter_pin_rule_on_the_admin_pages", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium");
  test.setTimeout(600_000);
  const context = await freshContext(browser);
  try {
    const page = await context.newPage();
    await page.goto(`${adminUrl}/settings/unlock`);
    if (new URL(page.url()).origin !== adminUrl) {
      await signInHere(page, { expectList: false });
      await page.waitForURL((url) => url.origin === adminUrl && url.pathname === "/settings/unlock", { timeout: SLOW });
    }
    const form = page.locator('form[method="post"]').filter({ has: page.locator('input[name="min_length"]') });
    await expect(form).toBeVisible({ timeout: 20_000 });
    await form.locator('input[name="pin_after_restart"]').uncheck({ force: true });
    await form.locator('input[name="min_length"]').fill(String(RULE.min_length));
    await form.locator('button[type="submit"]').click();
    // A stricter rule is announced first and saved when it is sent again with the confirmation in it.
    await expect(form.locator('input[name="confirm"]')).toHaveCount(1, { timeout: 20_000 });
    await form.locator('button[type="submit"]').click();
    await expect(form.locator('input[name="confirm"]')).toHaveCount(0, { timeout: 20_000 });
    const policy = await context.request.get(`${vaultUrl}/api/vault/policy`, { headers: API_HEADERS });
    expect(policy.status()).toBe(200);
    expect((await policy.json()).pin).toEqual(RULE);
  } finally {
    await context.close();
  }
});

test("the_release_gets_a_device_with_tokens_and_a_passkey_method", async ({ browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium (its virtual authenticator)");
  test.setTimeout(900_000);
  // The device: the extension's sign-in with the e-mail, the master password and the secret key.
  device = await signInDevice({ vaultUrl, email: secrets.email, password: secrets.password, secretKey: secrets.secretKey });
  deviceSaw = liveIds(await changes(device));
  expect(deviceSaw).toHaveLength(2);

  // The passkey method, on the methods page of the browser that stays open.
  const { context, page } = kept;
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
    },
  });
  await page.evaluate(() => {
    location.hash = "#/unlock-methods";
  });
  await expect(page.locator('[data-role="methods-page"]')).toBeVisible({ timeout: 30_000 });
  await pace();
  await page.locator('[data-role="methods-add"]').click();
  await answerReauth(page);
  const form = page.locator('[data-role="methods-name-form"]');
  await expect(form).toBeVisible({ timeout: 30_000 });
  await form.locator('[data-role="methods-name-input"]').fill(names.passkey);
  await form.locator('[data-role="methods-create"]').click();
  await expect(page.locator('[data-role="methods-confirm"]')).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-role="methods-confirm"]').click();
  await expect(page.locator('[data-role="methods-done"]')).toBeVisible({ timeout: SLOW });
  expect(await serverPasskeys(page)).toHaveLength(1);

  // It opens the vault on the release: reload, one click, no password sign-in.
  await page.reload();
  await expect(passkeyButton(page)).toBeVisible({ timeout: 30_000 });
  await passkeyButton(page).click();
  await expect(sessionUnlock(page)).toHaveCount(0, { timeout: SLOW });
  await openList(page);
  await expect(await findRows(page, secrets.itemTitle)).toHaveCount(1, { timeout: 30_000 });
});

test("the_host_makes_a_backup_with_the_release_and_upgrades_the_server", async ({ browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium");
  test.setTimeout(900_000);
  // A backup set of the release, as a server at home has before an upgrade.
  const set = await hostStep("backup");
  expect(set).toMatch(/^\d{8}T\d{6}Z$/);
  leave("backup", { set });
  // The image is swapped for the candidate on the same data; the browser and the device stay open.
  await hostStep("upgrade");
  // The vault session of the open browser is still there on the new build.
  await expect
    .poll(async () => (await kept.context.request.get(`${vaultUrl}/api/auth/session`, { headers: { "Ferret-Protocol": "1" } })).status(), { timeout: 60_000 })
    .toBe(200);
});

test("its_device_token_still_renews_without_a_new_sign_in", async ({ browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium");
  test.setTimeout(300_000);
  const refusedBefore = device.answers.length;
  // A renewal with the refresh token of the release, and a read with the new access token.
  await device.auth.refresh();
  expect(device.auth.state).toBe("ok");
  expect(liveIds(await changes(device))).toEqual(deviceSaw);
  expect(device.auth.state).toBe("ok");
  expect(device.answers.slice(refusedBefore), "nothing was refused").toEqual([]);
});

test("its_passkey_method_still_unlocks", async ({ browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium (its virtual authenticator)");
  test.setTimeout(600_000);
  const { page } = kept;
  /** @type {string[]} */
  const requests = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) requests.push(`${request.method()} ${url.pathname}`);
  });
  // A reload loads the web vault of the new build; the session of the release is still good, so it offers the passkey.
  await page.reload();
  await expect(sessionUnlock(page)).toBeVisible({ timeout: 30_000 });
  await expect(passkeyButton(page)).toBeVisible({ timeout: 30_000 });
  await passkeyButton(page).click();
  await expect(sessionUnlock(page)).toHaveCount(0, { timeout: SLOW });
  expect(requests.filter((r) => r.includes("/opaque/")), "no password sign-in ran").toEqual([]);
  await openList(page);
  await expect(await findRows(page, secrets.itemTitle)).toHaveCount(1, { timeout: 30_000 });
  // The one-time password is the one of the reference at the page's clock.
  await openItem(page, names.totp);
  const code = page.locator('[data-role="totp-code"]');
  await expect
    .poll(async () => (await code.innerText()).replace(/\s/g, "") === totpReference(TOTP_SECRET, Math.floor((await page.evaluate(() => Date.now())) / 1000)), { timeout: 30_000 })
    .toBe(true);
  expect(await serverPasskeys(page)).toHaveLength(1);
  // This browser's trash, which the new web vault reads from what the old one left, still has the deleted item.
  await openList(page);
  await page.locator('[data-role="trash-link"]').click();
  await expect(page.locator('[data-role="trash-item"]', { hasText: names.trashed })).toHaveCount(1, { timeout: 30_000 });
  leave("upgrade-before", { passkey: "unlocked", device: "renewed" });
});
