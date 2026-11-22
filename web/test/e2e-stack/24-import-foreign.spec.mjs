// Import from other password managers, with the real core and the real server: a Bitwarden export (JSON and CSV), an AliasVault
// export (.avux and CSV), the preview of what a file holds, the refusals for files that are not good, a thousand items inside a time
// budget, and what an import window does when the account is changed under it.
import { request } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { addNeedle, bulkJson, freshRedeemWindow, hostStep, redeemCode, signInHere, chooseImportFile, expect, feedOf, leave, listNames, memory, newDevice, noViolations, openImport, openItem, openList, pace, readStores, remember, requireAccount, rowsNamed, runChosenImport, secrets, SLOW, startHeldImport, synced, test, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  requireAccount();
});

const fixture = (/** @type {string} */ path) => fileURLToPath(new URL(`../fixtures/import/${path}`, import.meta.url));

/** The time the thousand items may take, from the button to the last item sent (a made-up budget for the run, with slack for the slower browsers). */
const BUDGET_MS = 240_000;

/** @param {import("@playwright/test").Page} page */
const itemCount = async (page) => (await memory(page)).items;

test("bitwarden_json_and_csv_import_with_the_preview_counts", async ({ browser }) => {
  test.setTimeout(1_800_000);
  // The account of this run (the one the export was imported into, or the first one).
  const device = await newDevice(browser);
  const { page } = device;
  await synced(page);

  /** @type {{ file: string, kind: string, items: number, lines: string[] }[]} */
  const cases = [
    { file: "bitwarden/every-type.json", kind: "A Bitwarden export (JSON)", items: 8, lines: ["5 login(s)", "1 note(s)", "1 card(s)", "1 identity item(s)"] },
    { file: "bitwarden/small.json", kind: "A Bitwarden export (JSON)", items: 2, lines: ["1 login(s)", "1 note(s)"] },
    { file: "bitwarden/small.csv", kind: "A Bitwarden export (CSV)", items: 3, lines: ["2 login(s)", "1 note(s)"] },
    { file: "aliasvault/synthetic.avux", kind: "An AliasVault export (.avux)", items: 8, lines: ["6 login(s)", "1 note(s)", "1 card(s)"] },
    { file: "aliasvault/synthetic.csv", kind: "An AliasVault export (CSV)", items: 8, lines: ["6 login(s)", "1 note(s)", "1 card(s)"] },
  ];
  for (const one of cases) {
    const before = await itemCount(page);
    await openImport(page);
    await chooseImportFile(page, fixture(one.file));
    // The preview says what kind of file it is and how many items of each kind it holds, and that the file is not encrypted.
    await expect(page.locator('[data-role="preview-kind"]')).toHaveText(one.kind);
    await expect(page.locator('[data-role="preview-items"]')).toHaveText(`Items to import: ${one.items}.`);
    for (const line of one.lines) await expect(page.locator('[data-role="preview-counts"]').getByText(line, { exact: true })).toHaveCount(1);
    await expect(page.locator('[data-role="preview-room"]')).toContainText(`Your vault has ${before} item(s) and room for`);
    await expect(page.locator('[data-role="plain-file-warning"]')).toBeVisible();
    if (before > 0) await expect(page.locator('[data-role="not-empty"]')).toBeVisible();
    await runChosenImport(page, one.items);
    // After it: the page says to delete the plain file, and the vault holds the items.
    await expect(page.locator('[data-role="plain-file-after"]')).toBeVisible();
    await synced(page, 120_000);
    expect(await itemCount(page), `${one.file} added ${one.items} items`).toBe(before + one.items);
  }

  // A few of the fields, as the item pages show them: the first Bitwarden login and an AliasVault login.
  await openItem(page, "Every login field");
  await expect(page.locator('[data-role="field"]', { hasText: "alice@example.test" })).toBeVisible();
  const password = page.locator('[data-role="field"]', { hasText: "Password" }).first();
  await password.locator('[data-role="reveal"]').click();
  await expect(password.locator('[data-role="value"]')).toHaveText("synthetic-password-1");
  await expect(page.locator('[data-role="urls"]')).toContainText("https://exact.example.test/path");
  await openList(page);
  const names = await listNames(page);
  // A favourite shows its star in front of the name.
  const has = (/** @type {string} */ name) => names.some((shown) => shown === name || shown === `★${name}`);
  expect(has("Every login field")).toBe(true);
  expect(has("Mail login")).toBe(true);
  expect(has("A secure note")).toBe(true);
  addNeedle("imported password one", "synthetic-password-1");
  addNeedle("imported password two", "synthetic-password-2");
  // What the server holds is sealed: the page has no way to ask it for a name.
  const stores = await readStores(page);
  expect(stores.outbox.count).toBe(0);
  await device.context.close();
});

test("files_that_are_not_good_are_refused_and_nothing_is_imported", async ({ browser }) => {
  test.setTimeout(600_000);
  const device = await newDevice(browser);
  const { page } = device;
  const before = await itemCount(page);
  /** @type {[string, RegExp][]} */
  const refused = [
    ["bitwarden/encrypted.json", /encrypted/i],
    ["bitwarden/password-protected.json", /password|encrypted/i],
    ["bitwarden/hostile.json", /key that an export never has|not valid|refused/i],
    ["bitwarden/huge-depth.json", /nested too deeply/i],
    ["aliasvault/encrypted.avex", /encrypted|does not read/i],
  ];
  for (const [file, text] of refused) {
    await openImport(page);
    await page.locator('[data-role="file"]').setInputFiles(fixture(file));
    await expect(page.locator('[data-role="file-error"]')).toBeVisible({ timeout: 60_000 });
    await expect(page.locator('[data-role="file-error"]')).toContainText(text);
    await expect(page.locator('[data-role="preview"]')).toBeHidden();
  }
  // A ZIP file is said to be one.
  await openImport(page);
  await page.locator('[data-role="file"]').setInputFiles({ name: "bitwarden.zip", mimeType: "application/zip", buffer: Buffer.from("PK\u0003\u0004 not an export") });
  await expect(page.locator('[data-role="file-error"]')).toContainText(/ZIP/);
  expect(await itemCount(page), "refused files import nothing").toBe(before);
  await device.context.close();
});

test("an_import_of_1000_items_finishes_within_budget", async ({ browser }) => {
  test.setTimeout(1_800_000);
  const device = await newDevice(browser);
  const { page } = device;
  const tag = Date.now().toString(36);
  const before = await itemCount(page);
  const seqBefore = (await feedOf(device.context)).latest_seq;
  await openImport(page);
  await chooseImportFile(page, { name: "thousand.json", mimeType: "application/json", buffer: bulkJson(tag, 1000) });
  await expect(page.locator('[data-role="preview-items"]')).toHaveText("Items to import: 1000.");
  await page.locator('[data-role="import-form"] [data-role="master-password"]').fill(secrets.password);
  await pace();
  const started = Date.now();
  await page.locator('[data-role="import-form"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="done-items"]')).toHaveText("Items sent to the server: 1000.", { timeout: BUDGET_MS });
  await synced(page, BUDGET_MS);
  const took = Date.now() - started;
  test.info().annotations.push({ type: "import 1000 items", description: `${Math.round(took / 1000)} s` });
  expect(took, `a thousand items took ${Math.round(took / 1000)} s`).toBeLessThan(BUDGET_MS);
  // They are in the vault and on the server: the feed moved on by at least a thousand writes, and no write is waiting.
  expect(await itemCount(page)).toBe(before + 1000);
  const feed = await feedOf(device.context);
  expect(feed.latest_seq - seqBefore).toBeGreaterThanOrEqual(1000);
  expect((await readStores(page)).outbox.count).toBe(0);
  // A search finds one of them.
  await page.evaluate(() => {
    location.hash = "#/items";
  });
  await page.locator('[data-role="search"]').fill(`Bulk-${tag}-777`);
  await expect(rowsNamed(page, `Bulk-${tag}-777`)).toHaveCount(1, { timeout: 30_000 });
  await device.context.close();
});

test("a_password_change_while_an_import_window_is_open_leaves_the_dead_session_no_write_and_the_changing_session_its_own_window", async ({ browser }) => {
  test.setTimeout(2_400_000);
  const tag = Date.now().toString(36);

  // A window belongs to one device and stays open for its time (or until it is used up) even when its session is over; another
  // device cannot open one meanwhile. So the window of the session that keeps its session goes first and is used up, and the
  // window of the session that is ended comes last.
  // ---- The session that changes the password is the one that holds the window: its batches wait while the page changes the
  // password, and they go through afterwards.
  const changing = await newDevice(browser);
  await synced(changing.page);
  const seqBefore = (await feedOf(changing.context)).latest_seq;
  const own = await startHeldImport(changing.page, bulkJson(`own-${tag}`, 120));
  const again = `Window-again-${tag}-horse-battery-staple`;
  addNeedle("password changed in the importing session", again);
  await changing.page.evaluate(() => {
    location.hash = "#/password";
  });
  await expect(changing.page.locator('[data-role="password-page"]')).toBeVisible({ timeout: 30_000 });
  await changing.page.locator('[data-role="current-password"]').fill(secrets.password);
  await changing.page.locator('[data-role="new-password"]').fill(again);
  await changing.page.locator('[data-role="new-password-again"]').fill(again);
  await pace();
  await changing.page.locator('[data-role="password-form"] [data-role="submit"]').click();
  await expect(changing.page.locator('[data-role="password-done"]')).toBeVisible({ timeout: SLOW });
  secrets.password = again;
  remember();
  expect((await changing.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the session that changed the password lives").toBe(200);
  own.release();
  await expect.poll(async () => (await feedOf(changing.context)).latest_seq - seqBefore, { timeout: 300_000, message: "the import goes on in the session that changed the password" }).toBeGreaterThanOrEqual(120);
  await changing.page.evaluate(() => {
    location.hash = "#/items";
  });
  // A long list draws only the rows near the screen: a search finds the one that is wanted.
  await changing.page.locator('[data-role="search"]').fill(`Bulk-own-${tag}-77`);
  await expect(rowsNamed(changing.page, `Bulk-own-${tag}-77`)).toHaveCount(1, { timeout: 120_000 });
  await changing.context.close();

  // ---- The window of the session that is ended: another browser of the account changes the password while its batches wait.
  const dead = await newDevice(browser);
  const other = await newDevice(browser);
  await synced(dead.page);
  await synced(other.page);

  const held = await startHeldImport(dead.page, bulkJson(`dead-${tag}`, 300));
  const newPassword = `Window-${tag}-horse-battery-staple`;
  addNeedle("password changed under a window", newPassword);
  await other.page.evaluate(() => {
    location.hash = "#/password";
  });
  await expect(other.page.locator('[data-role="password-page"]')).toBeVisible({ timeout: 30_000 });
  await other.page.locator('[data-role="current-password"]').fill(secrets.password);
  await other.page.locator('[data-role="new-password"]').fill(newPassword);
  await other.page.locator('[data-role="new-password-again"]').fill(newPassword);
  await pace();
  await other.page.locator('[data-role="password-form"] [data-role="submit"]').click();
  await expect(other.page.locator('[data-role="password-done"]')).toBeVisible({ timeout: SLOW });
  secrets.password = newPassword;
  remember();
  expect((await dead.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the importing browser's session is over").toBe(401);
  const before = await feedOf(other.context);

  // The batches go out now: the server refuses them, and nothing of the import is written.
  held.release();
  await expect(dead.page.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "unauthorized", { timeout: 60_000 });
  await dead.page.waitForTimeout(10_000);
  const after = await feedOf(other.context);
  expect(after.latest_seq, "the ended session's window wrote nothing").toBe(before.latest_seq);
  expect(after.changes.filter((c) => !before.changes.some((b) => b.id === c.id)), "no new row").toEqual([]);

  // ---- The same with a recovery: a one-time code is redeemed (the kit's way of ending every other session) while the batches of an
  // import wait. The same browser signs in again (it replaces its own window), starts an import, and the code ends its session.
  await freshRedeemWindow();
  await dead.page.goto(`${vaultUrl}/vault/login`);
  await signInHere(dead.page);
  const heldAgain = await startHeldImport(dead.page, bulkJson(`recovery-${tag}`, 300));
  const beforeRecovery = await feedOf(other.context);
  const reset = await request.newContext({ ignoreHTTPSErrors: true });
  const redeemed = await redeemCode(reset, secrets.email, await hostStep(`code-${secrets.email}`));
  expect(redeemed.status(), "the code is redeemed").toBe(200);
  expect((await dead.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the importing browser's session is over").toBe(401);
  expect((await other.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "so is every other session").toBe(401);
  heldAgain.release();
  await dead.page.waitForTimeout(10_000);
  const checker = await newDevice(browser);
  const afterRecovery = await feedOf(checker.context);
  expect(afterRecovery.latest_seq, "the window of the session the code ended wrote nothing").toBe(beforeRecovery.latest_seq);
  expect(afterRecovery.changes.filter((c) => !beforeRecovery.changes.some((b) => b.id === c.id)), "no new row").toEqual([]);
  await reset.dispose();
  await checker.context.close();
  await dead.context.close();
  await other.context.close();
  leave("m3-24", { done: true });
});
