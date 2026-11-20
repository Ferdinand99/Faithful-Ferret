// The encrypted export and its import, with the real core. The export is a file the browser saves; it holds nothing in the clear and
// opens only with the export password. The reminder for a new export comes 30 days after the last one. The file imports into a
// fresh account on a server that was wiped: the same items, with the same fields, come back.
import { readFileSync } from "node:fs";
import { addNeedle, createItem, expect, freshContext, hostStep, leave, listNames, newDevice, noViolations, openItem, openList, pace, readStores, remember, requireAccount, secrets, setUpAccount, SLOW, synced, test, unlockWith, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  requireAccount();
});

/**
 * Fills the export form and runs the export; returns the file that the browser saved.
 * @param {import("@playwright/test").Page} page
 * @param {{ master: string, password: string, again?: string }} values
 */
async function exportTo(page, { master, password, again = password }) {
  await page.locator('[data-role="master-password"]').fill(master);
  await page.locator('[data-role="export-password"]').fill(password);
  await page.locator('[data-role="export-password-again"]').fill(again);
  const ack = page.locator('[data-role="readiness-ack"]');
  if (await ack.isVisible()) await ack.check();
  // An export asks the server for a fresh sign-in, which it limits; the limit is kept to.
  await pace();
  await page.locator('[data-role="encrypted-form"] [data-role="submit"]').click();
}

/** Opens the export page of an open vault and waits for its readiness check. @param {import("@playwright/test").Page} page */
async function openExportPage(page) {
  await page.evaluate(() => {
    location.hash = "#/export";
  });
  await expect(page.locator('[data-role="export-page"]')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-role="readiness-status"]')).not.toHaveText(/Checking/i, { timeout: 60_000 }).catch(() => {});
}

test("the_export_reminder_shows_after_30_days", async ({ browser }) => {
  test.setTimeout(900_000);
  const device = await newDevice(browser);
  const exportPassword = `Export-${Date.now().toString(36)}-horse-battery-staple`;
  addNeedle("reminder export password", exportPassword);
  await createItem(device.page, { name: `Reminder-${Date.now()}`, username: "reminder-user" });
  await synced(device.page);
  await openExportPage(device.page);
  await expect(device.page.locator('[data-role="export-last"]')).toContainText(/never|not/i);

  // An encrypted export, and the page says when it was made.
  const [download] = await Promise.all([device.page.waitForEvent("download", { timeout: SLOW }), exportTo(device.page, { master: secrets.password, password: exportPassword })]);
  expect(download.suggestedFilename()).toMatch(/^ferret-export-\d{4}-\d{2}-\d{2}\.ferretexport$/);
  await expect(device.page.locator('[data-role="encrypted-done"]')).toBeVisible({ timeout: SLOW });
  await device.page.close();

  // The same browser a month later: after 29 days there is no reminder, after 31 days there is, and "remind me later" keeps it away.
  const DAY = 86_400_000;
  /** @param {number} days */
  const lookIn = async (days) => {
    const page = await device.context.newPage();
    await page.clock.install({ time: new Date(Date.now() + days * DAY) });
    await page.goto(`${vaultUrl}/vault/#/items`);
    await expect(page.locator('[data-role="unlock"]')).toBeVisible({ timeout: 30_000 });
    await unlockWith(page, secrets.password);
    await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
    return page;
  };
  const early = await lookIn(29);
  await early.waitForTimeout(3_000);
  await expect(early.locator('[data-role="export-reminder"]')).toHaveCount(0);
  await early.close();

  const late = await lookIn(31);
  await expect(late.locator('[data-role="export-reminder"]')).toBeVisible({ timeout: 30_000 });
  await expect(late.locator('[data-role="export-reminder-link"]')).toHaveAttribute("href", "#/export");
  await late.locator('[data-role="export-reminder-later"]').click();
  await expect(late.locator('[data-role="export-reminder"]')).toHaveCount(0);
  // The date it is kept until is written to the browser's store before the page goes.
  await expect.poll(async () => JSON.stringify((await readStores(late)).settings.values), { timeout: 15_000 }).toMatch(/"snoozedUntil":\d+/);
  await late.close();

  // Snoozed: the next visit, a day later, is quiet; a week later it is back.
  const snoozed = await lookIn(32);
  await snoozed.waitForTimeout(3_000);
  await expect(snoozed.locator('[data-role="export-reminder"]')).toHaveCount(0);
  await snoozed.close();
  const back = await lookIn(40);
  await expect(back.locator('[data-role="export-reminder"]')).toBeVisible({ timeout: 30_000 });
  await back.close();
  await device.context.close();
});

test("an_encrypted_export_imports_into_a_fresh_account_on_a_wiped_server", async ({ browser }) => {
  test.setTimeout(1_800_000);
  const exportPassword = `Moved-${Date.now().toString(36)}-horse-battery-staple`;
  addNeedle("export password", exportPassword);

  // ---- The old account: three items with every kind of field the form has, and notes with non-ASCII text.
  const device = await newDevice(browser);
  const tag = Date.now().toString(36);
  const made = [
    { name: `Export-bank-${tag}`, username: `ada-${tag}`, password: `Pw-${tag}-one!`, url: `https://bank-${tag}.example.test/login`, notes: `Notes with æøå and a line\nbreak ${tag}` },
    { name: `Export-mail-${tag}`, username: `ada-${tag}@mail.example.test`, password: `Pw-${tag}-two?`, url: `https://mail-${tag}.example.test`, notes: "" },
    { name: `Export-note-${tag}`, username: "", password: "", url: "", notes: `Only a note ${tag}` },
  ];
  for (const item of made) await createItem(device.page, item);
  await synced(device.page);
  for (const item of made) {
    addNeedle(`item ${item.name}`, item.name);
    if (item.password) addNeedle(`password of ${item.name}`, item.password);
    if (item.notes) addNeedle(`notes of ${item.name}`, item.notes.split("\n")[0]);
  }
  await openList(device.page);
  const namesBefore = (await listNames(device.page)).sort();
  expect(namesBefore.length).toBeGreaterThanOrEqual(made.length);

  // ---- The export: the page refuses what the core refuses, then writes the file.
  await openExportPage(device.page);
  await exportTo(device.page, { master: secrets.password, password: "Short1!", again: "Short1!" });
  await expect(device.page.locator('[data-role="encrypted-form"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  await exportTo(device.page, { master: secrets.password, password: exportPassword, again: `${exportPassword}x` });
  await expect(device.page.locator('[data-role="encrypted-form"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  // The master password as the export password is refused: the file would open with the password that the server can be asked to test.
  await exportTo(device.page, { master: secrets.password, password: secrets.password });
  await expect(device.page.locator('[data-role="encrypted-form"] [data-role="error"]')).toBeVisible({ timeout: SLOW });

  const [download] = await Promise.all([device.page.waitForEvent("download", { timeout: SLOW }), exportTo(device.page, { master: secrets.password, password: exportPassword })]);
  await expect(device.page.locator('[data-role="encrypted-done"]')).toBeVisible({ timeout: SLOW });
  await expect(device.page.locator('[data-role="done-items"]')).toContainText(String(namesBefore.length));
  const bytes = readFileSync(/** @type {string} */ (await download.path()));
  expect(bytes.length).toBeGreaterThan(200);
  // Nothing of the vault is readable in the file: no name, no password, no note, no e-mail address, no key.
  const asText = bytes.toString("latin1") + bytes.toString("utf8");
  for (const item of made) {
    for (const value of [item.name, item.username, item.password, item.url, item.notes.split("\n")[0]]) {
      if (value) expect(asText, `the export file holds nothing readable of ${item.name}`).not.toContain(value);
    }
  }
  for (const secret of [secrets.email, secrets.password, exportPassword, secrets.secretKey, secrets.recoveryKey]) expect(asText).not.toContain(secret);
  await device.context.close();

  // ---- The server is wiped: a new, empty server with a new server key.
  await hostStep("reset");

  // ---- A new account on it, by the whole path.
  const tagB = Date.now().toString(36);
  secrets.email = `second-${tagB}@e2e.example.test`;
  secrets.password = `Fresh-${tagB}-horse-battery-staple`;
  secrets.secretKey = "";
  secrets.recoveryKey = "";
  secrets.qrText = "";
  remember();
  addNeedle("fresh account password", secrets.password);
  const setup = await freshContext(browser);
  const setupPage = await setup.newPage();
  await setUpAccount(setupPage);
  addNeedle("fresh account recovery key", secrets.recoveryKey);
  addNeedle("fresh account secret key", secrets.secretKey);
  expect((await listNames(setupPage)).length, "the new account is empty").toBe(0);

  // ---- The import: a wrong export password is refused and nothing is written; the right one brings every item back.
  await setupPage.evaluate(() => {
    location.hash = "#/import";
  });
  await expect(setupPage.locator('[data-role="import-page"]')).toBeVisible({ timeout: 30_000 });
  await setupPage.locator('[data-role="file"]').setInputFiles({ name: "moved.ferretexport", mimeType: "application/octet-stream", buffer: bytes });
  await expect(setupPage.locator('[data-role="preview"]')).toBeVisible({ timeout: 60_000 });
  await expect(setupPage.locator('[data-role="preview-kind"]')).toBeVisible();
  await expect(setupPage.locator('[data-role="preview-export"]')).toBeVisible();
  // An encrypted export has no plain file to delete afterwards.
  await expect(setupPage.locator('[data-role="plain-file-warning"]')).toHaveCount(0);
  const fill = async (/** @type {string} */ password) => {
    await setupPage.locator('[data-role="import-form"] [data-role="master-password"]').fill(secrets.password);
    await setupPage.locator('[data-role="import-form"] [data-role="export-password"]').fill(password);
  };
  await fill(`${exportPassword}-wrong`);
  await setupPage.locator('[data-role="import-form"] [data-role="submit"]').click();
  await expect(setupPage.locator('[data-role="import-form"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  await setupPage.evaluate(() => {
    location.hash = "#/";
  });
  await openList(setupPage);
  expect((await listNames(setupPage)).length, "a refused import wrote nothing").toBe(0);

  await setupPage.evaluate(() => {
    location.hash = "#/import";
  });
  await expect(setupPage.locator('[data-role="import-page"]')).toBeVisible({ timeout: 30_000 });
  if ((await setupPage.locator('[data-role="preview"]').count()) === 0 || !(await setupPage.locator('[data-role="preview"]').isVisible())) {
    await setupPage.locator('[data-role="file"]').setInputFiles({ name: "moved.ferretexport", mimeType: "application/octet-stream", buffer: bytes });
    await expect(setupPage.locator('[data-role="preview"]')).toBeVisible({ timeout: 60_000 });
  }
  await fill(exportPassword);
  await setupPage.locator('[data-role="import-form"] [data-role="submit"]').click();
  await expect(setupPage.locator('[data-role="done-items"]')).toContainText(String(namesBefore.length), { timeout: 300_000 });
  await synced(setupPage, 120_000);

  // The same items, with the same fields.
  await openList(setupPage);
  const namesAfter = (await listNames(setupPage)).sort();
  expect(namesAfter, "the same items come back").toEqual(namesBefore);
  for (const item of made) {
    await openItem(setupPage, item.name);
    if (item.username) await expect(setupPage.locator('[data-role="field"]', { hasText: "User name" }).locator('[data-role="value"]')).toHaveText(item.username);
    if (item.url) await expect(setupPage.locator('[data-role="urls"]')).toContainText(item.url);
    if (item.password) {
      const row = setupPage.locator('[data-role="field"]', { hasText: "Password" });
      await row.locator('[data-role="reveal"]').click();
      await expect(row.locator('[data-role="value"]')).toHaveText(item.password);
    }
    if (item.notes) {
      // The notes are shown on request.
      const row = setupPage.locator('[data-role="field"]', { hasText: "Notes" });
      await row.locator('[data-role="reveal"]').click();
      await expect(row.locator('[data-role="value"]')).toContainText(item.notes.split("\n")[0]);
    }
  }
  await setup.close();
  leave("m3-23", { items: namesBefore.length });
});
