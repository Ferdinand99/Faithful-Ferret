// A new recovery key. The page asks for the master password again, shows the new key alone (page 2 of the sheet), and uploads it
// only after it has been typed back. A page that is hidden while the key is shown throws it away and sends nothing. After the
// renewal the old key opens nothing and the new one recovers the account; the server makes a backup set at once and tells the
// stand-in monitor about it, with a message that holds no name, no path and no secret.
import { addNeedle, createItem, expect, freshContext, hostStep, leave, monitorCalls, newDevice, noViolations, pace, pushToken, remember, requireAccount, findRows, secrets, SLOW, synced, test, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  requireAccount();
  if (secrets.qrText === "") throw new Error("no QR text: run 18-sheet.spec.mjs first");
});

/**
 * Opens the page for a new recovery key, starts the renewal and answers the question for the master password. Returns when the
 * sheet with the new key is shown.
 * @param {import("@playwright/test").Page} page
 */
async function startRenewal(page) {
  await page.evaluate(() => {
    location.hash = "#/recovery-key";
  });
  await expect(page.locator('[data-role="renew-page"]')).toBeVisible({ timeout: 30_000 });
  await pace();
  await page.locator('[data-role="renew-start"]').click();
  await expect(page.locator('[data-role="reauth-dialog"]')).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-role="reauth-password"]').fill(secrets.password);
  await page.locator('[data-role="reauth-confirm"]').click();
  await expect(page.locator('[data-role="renew-sheet"] [data-role="sheet-recovery-key"]')).toBeVisible({ timeout: SLOW });
}

test("a_hidden_tab_cancels_a_renewal_in_progress", async ({ browser }) => {
  test.setTimeout(600_000);
  const device = await newDevice(browser);
  const { page } = device;
  /** @type {string[]} */
  const writes = [];
  page.on("request", (request) => {
    if (request.method() !== "GET" && new URL(request.url()).pathname.startsWith("/api/vault/")) writes.push(`${request.method()} ${new URL(request.url()).pathname}`);
  });
  await startRenewal(page);
  const shown = ((await page.locator('[data-role="sheet-recovery-key"]').textContent()) ?? "").trim();
  expect(shown).toMatch(/^FFR1-/);
  // The tab goes out of view (another tab, another app): the new key is thrown away and nothing is sent.
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.locator('[data-role="renew-sheet"] [data-role="sheet-recovery-key"]')).toHaveCount(0);
  expect(await page.locator("body").innerText()).not.toContain(shown);
  expect(await page.evaluate(() => document.body.innerHTML)).not.toContain(shown);
  expect(writes, "a cancelled renewal sends nothing").toEqual([]);
  await device.context.close();
});

test("a_new_recovery_key_makes_the_old_one_useless_and_a_backup_follows", async ({ browser }) => {
  test.setTimeout(1_500_000);
  const device = await newDevice(browser);
  const { page } = device;
  const name = `Before-renewal-${Date.now()}`;
  await createItem(page, { name, username: "before-the-renewal" });
  await synced(page);
  const oldKey = secrets.recoveryKey;
  /** @type {string[]} */
  const writes = [];
  page.on("request", (request) => {
    if (request.method() !== "GET" && new URL(request.url()).pathname.startsWith("/api/vault/")) writes.push(`${request.method()} ${new URL(request.url()).pathname}`);
  });

  await startRenewal(page);
  const newKey = ((await page.locator('[data-role="sheet-recovery-key"]').textContent()) ?? "").trim();
  expect(newKey).toMatch(/^FFR1-/);
  expect(newKey, "the key is a new one").not.toBe(oldKey);
  addNeedle("renewed recovery key", newKey);
  // Only page 2 is made again; the page says that page 1 stays as it is.
  await expect(page.locator('[data-role="sheet-secret-key"]')).toHaveCount(0);
  await expect(page.locator('[data-role="page-one-unchanged"]')).toBeVisible();
  expect(writes, "nothing is uploaded before the key is typed back").toEqual([]);
  // A wrong key typed back is refused; nothing is uploaded.
  await page.locator('[data-role="rk-typed"]').fill(`${newKey.slice(0, -1)}${newKey.endsWith("A") ? "B" : "A"}`);
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="sheet-page"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(writes).toEqual([]);
  // The old key typed back is wrong too.
  await page.locator('[data-role="rk-typed"]').fill(oldKey);
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="sheet-page"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(writes).toEqual([]);

  const calls = await monitorCalls();
  await page.locator('[data-role="rk-typed"]').fill(newKey);
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="renew-done"]')).toBeVisible({ timeout: SLOW });
  const committed = Date.now();
  expect(writes.filter((w) => w === "PUT /api/vault/unlock-methods/recovery"), "the new key is uploaded once").toHaveLength(1);
  // What the page says: the old key is no longer good, a backup was asked for, and the old sheet is kept until a newer backup exists.
  await expect(page.locator('[data-role="renew-done-old-key"]')).toBeVisible();
  await expect(page.locator('[data-role="renew-done-backup"]')).toContainText(/backup/i);
  await expect(page.locator('[data-role="renew-keep-old"]')).toContainText(/backup/i);
  expect(await page.locator("body").innerText()).not.toContain(newKey);
  secrets.recoveryKey = newKey;
  remember();

  // ---- A backup follows: within the collection window and a poll the server has made a set, checked it and told the monitor.
  await expect
    .poll(async () => (await monitorCalls()).filter((call) => call.at > committed).length, { timeout: 240_000, intervals: [5_000], message: "the stand-in monitor is told about a backup after the renewal" })
    .toBeGreaterThan(0);
  expect((await monitorCalls()).length).toBeGreaterThan(calls.length);

  // ---- The old key is useless: a code and the old key on a new browser are refused before anything is uploaded.
  const code = await hostStep(`code-${secrets.email}`);
  const other = await freshContext(browser);
  const tried = await other.newPage();
  /** @type {string[]} */
  const triedCalls = [];
  tried.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/")) triedCalls.push(`${request.method()} ${path}`);
  });
  /** @type {number[]} */
  const redeemAnswers = [];
  tried.on("response", (response) => {
    if (new URL(response.url()).pathname === "/api/auth/redeem") redeemAnswers.push(response.status());
  });
  await tried.goto(`${vaultUrl}/vault/#/recover`);
  await expect(tried.locator('[data-role="recover-page"]')).toBeVisible({ timeout: 20_000 });
  const fill = async (/** @type {string} */ useCode, /** @type {string} */ rk, /** @type {string} */ password) => {
    await tried.locator('[data-role="email"]').fill(secrets.email);
    await tried.locator('[data-role="email"]').blur();
    await tried.locator('[data-role="code"]').fill(useCode);
    await tried.locator('[data-role="qr-text"]').fill(secrets.qrText);
    await tried.locator('[data-role="qr-read"]').click();
    await expect(tried.locator('[data-role="qr-shown"]')).toBeVisible({ timeout: 30_000 });
    await tried.locator('[data-role="qr-confirm"]').check();
    await tried.locator('[data-role="sk-code"]').fill(secrets.secretKey);
    await tried.locator('[data-role="rk-code"]').fill(rk);
    await tried.locator('[data-role="new-password"]').fill(password);
    await tried.locator('[data-role="new-password-again"]').fill(password);
  };
  await fill(code, oldKey, `Never-${Date.now().toString(36)}-horse-battery-staple`);
  await tried.locator('[data-role="recover-form"] [data-role="submit"]').click();
  // The code was good and was redeemed; it is the old recovery key that is refused, before anything is uploaded.
  await expect(tried.locator('[data-role="recover-page"] [data-role="error"]')).toContainText(/recovery key does not open this account/i, { timeout: SLOW });
  expect(redeemAnswers, "the code was redeemed").toEqual([200]);
  await expect(tried.locator('[data-role="sheet-page"]')).toHaveCount(0);
  expect(triedCalls.filter((c) => c === "POST /api/vault/recover"), "the old key never gets as far as an upload").toEqual([]);
  await other.close();

  // ---- The new key recovers the account (a new code: the first one may have been spent by the refused try).
  const third = await freshContext(browser);
  const recovered = await third.newPage();
  const nextPassword = `After-renewal-${Date.now().toString(36)}-horse-battery-staple`;
  addNeedle("password after the renewal", nextPassword);
  await recovered.goto(`${vaultUrl}/vault/#/recover`);
  await expect(recovered.locator('[data-role="recover-page"]')).toBeVisible({ timeout: 20_000 });
  const code2 = await hostStep(`code-${secrets.email}`);
  await recovered.locator('[data-role="email"]').fill(secrets.email);
  await recovered.locator('[data-role="email"]').blur();
  await recovered.locator('[data-role="code"]').fill(code2);
  await recovered.locator('[data-role="qr-text"]').fill(secrets.qrText);
  await recovered.locator('[data-role="qr-read"]').click();
  await expect(recovered.locator('[data-role="qr-shown"]')).toBeVisible({ timeout: 30_000 });
  await recovered.locator('[data-role="qr-confirm"]').check();
  await recovered.locator('[data-role="sk-code"]').fill(secrets.secretKey);
  await recovered.locator('[data-role="rk-code"]').fill(newKey);
  await recovered.locator('[data-role="new-password"]').fill(nextPassword);
  await recovered.locator('[data-role="new-password-again"]').fill(nextPassword);
  await recovered.locator('[data-role="recover-form"] [data-role="submit"]').click();
  await expect(recovered.locator('[data-role="sheet-page"]')).toBeVisible({ timeout: SLOW });
  const nextKey = ((await recovered.locator('[data-role="sheet-recovery-key"]').textContent()) ?? "").trim();
  addNeedle("recovery key after the renewal", nextKey);
  await recovered.locator('[data-role="rk-typed"]').fill(nextKey);
  await recovered.locator('[data-role="confirm"]').click();
  await expect(recovered.locator('[data-role="recover-done"]')).toBeVisible({ timeout: 300_000 });
  secrets.password = nextPassword;
  secrets.recoveryKey = nextKey;
  remember();
  await recovered.locator('[data-role="open-vault"]').click();
  await expect(recovered.locator('[data-role="list"]')).toBeVisible({ timeout: 60_000 });
  await expect((await findRows(recovered, name))).toHaveCount(1, { timeout: 60_000 });
  await third.close();
  await device.context.close();
  leave("m3-22", { done: true });
});

test("every_good_backup_pushes_to_the_stand_in_monitor_without_a_secret", async () => {
  test.setTimeout(300_000);
  // The server has made sets after the changes above; each good one was told to the monitor, and every call is the same fixed message.
  await expect.poll(async () => (await monitorCalls()).length, { timeout: 240_000, intervals: [5_000] }).toBeGreaterThan(0);
  const calls = await monitorCalls();
  expect(pushToken.length, "the run knows the token of the push address").toBeGreaterThanOrEqual(16);
  for (const call of calls) {
    expect(call.method).toBe("GET");
    expect(call.path === `/api/push/${pushToken}`, "the path is the address the server was given").toBe(true);
    // Two values, and nothing of the server in them: no name, no path, no count, no key.
    expect(call.query).toBe("?status=up&msg=backup+ok");
    // No cookie, no authorization, no referring page: the secret path goes to the monitor's host and nowhere else.
    expect(Object.keys(call.headers).sort(), "only the client's name is sent").toEqual(["user-agent"]);
    expect(call.headers["user-agent"]).not.toMatch(/(secret|password|email|@)/i);
  }
  // The monitor has been told about each set once: as many calls as sets the server made (nothing in this run has made a set
  // with the command yet, and the command never tells the monitor). A set that is being made when this runs is waited for.
  await expect
    .poll(async () => Number(await hostStep("set-count")) - (await monitorCalls()).length, { timeout: 180_000, intervals: [10_000], message: "one call for each set" })
    .toBe(0);
  expect(Number(await hostStep("set-count")), "the server made sets").toBeGreaterThan(0);
  addNeedle("push token", pushToken);
  leave("m3-22-b", { calls: calls.length });
});
