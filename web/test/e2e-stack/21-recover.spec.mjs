// "Forgot the master password": the account is recovered on a new browser with a one-time sign-in code (made on the server by
// the host script, the way an administrator does it), both pages of the sheet (the text of the QR code and the secret key from
// page 1, the recovery key from page 2) and a new password. The old password is never asked for; the new recovery key is
// shown alone and has to be typed back before anything is uploaded; the old recovery key opens nothing afterwards.
import { request } from "@playwright/test";
import { addNeedle, adminUrl, freshRedeemWindow, redeemCode, expect, freshContext, hostStep, leave, newDevice, noViolations, openList, pace, readStores, remember, requireAccount, rowsNamed, secrets, SLOW, test, vaultUrl, createItem, synced } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  requireAccount();
  if (secrets.qrText === "") throw new Error("no QR text: run 18-sheet.spec.mjs first");
});

/**
 * Opens the recovery page of the vault on a fresh page and fills in everything but the new password's submit.
 * @param {import("@playwright/test").Page} page
 * @param {{ code: string, rk: string, newPassword: string }} values
 */
async function fillRecover(page, { code, rk, newPassword }) {
  await page.locator('[data-role="email"]').fill(secrets.email);
  await page.locator('[data-role="email"]').blur();
  await page.locator('[data-role="code"]').fill(code);
  await page.locator('[data-role="qr-text"]').fill(secrets.qrText);
  await page.locator('[data-role="qr-read"]').click();
  await expect(page.locator('[data-role="qr-shown"]')).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-role="qr-confirm"]').check();
  // The sheet says that the account has a secret key, and the page asks for it (this browser does not hold it).
  await expect(page.locator('[data-role="sk-code"]')).toBeVisible();
  await page.locator('[data-role="sk-code"]').fill(secrets.secretKey);
  await page.locator('[data-role="rk-code"]').fill(rk);
  await page.locator('[data-role="new-password"]').fill(newPassword);
  await page.locator('[data-role="new-password-again"]').fill(newPassword);
}

test("recover_on_a_new_browser_with_a_one_time_code_and_both_pages_of_the_sheet", async ({ browser }) => {
  test.setTimeout(1_200_000);
  const oldPassword = secrets.password;
  const oldRecoveryKey = secrets.recoveryKey;
  const newPassword = `Recovered-${Date.now().toString(36)}-horse-battery-staple`;
  addNeedle("recovered password", newPassword);

  // A browser that is signed in before the recovery: its session ends with it.
  const witness = await newDevice(browser);
  const name = `Before-recover-${Date.now()}`;
  await createItem(witness.page, { name, username: "before-the-recovery" });
  await synced(witness.page);
  expect((await witness.page.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);

  // The code: made on the server, as an administrator who forgot the master password does.
  const code = await hostStep(`code-${secrets.email}`);
  expect(code, "the host made a code").toMatch(/\S{6,}/);

  // ---- A new browser: the link on the sign-in page leads to the recovery page.
  const context = await freshContext(browser);
  const page = await context.newPage();
  /** @type {string[]} */
  const calls = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/")) calls.push(`${request.method()} ${path}`);
  });
  await page.goto(`${vaultUrl}/vault/login`);
  await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
  await page.locator('[data-role="recover-link"]').click();
  await expect(page.locator('[data-role="recover-page"]')).toBeVisible({ timeout: 20_000 });
  expect(new URL(page.url()).hash).toBe("#/recover");
  await expect(page.locator('[data-role="new-browser"]')).toBeVisible();
  // The old password is not asked for: there is no such field, and the page does not mention one.
  await expect(page.locator('[data-role="current-password"]')).toHaveCount(0);
  expect(await page.locator('[data-role="recover-page"]').innerText()).not.toMatch(/(current|old|forgotten) (master )?password/i);

  await fillRecover(page, { code, rk: oldRecoveryKey, newPassword });
  // A typo in the recovery key is caught before anything is sent (here: before the code is even used).
  const callsBefore = calls.length;
  await page.locator('[data-role="rk-code"]').fill(`${oldRecoveryKey.slice(0, -1)}${oldRecoveryKey.endsWith("A") ? "B" : "A"}`);
  await page.locator('[data-role="recover-form"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="recover-page"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(calls.slice(callsBefore).filter((c) => c.includes("/api/auth/redeem") || c.includes("/api/vault/recover")), "a mistyped key sends nothing").toEqual([]);

  // The right key: the page emptied the code, the keys and the passwords when the form was sent, so they are typed again. The code
  // was not used by the try with the typo: the code is redeemed now, the new sheet is shown alone, and nothing is uploaded until
  // its key is typed back.
  await page.locator('[data-role="code"]').fill(code);
  await page.locator('[data-role="sk-code"]').fill(secrets.secretKey);
  await page.locator('[data-role="rk-code"]').fill(oldRecoveryKey);
  await page.locator('[data-role="new-password"]').fill(newPassword);
  await page.locator('[data-role="new-password-again"]').fill(newPassword);
  await page.locator('[data-role="recover-form"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="sheet-page"]')).toBeVisible({ timeout: SLOW });
  await expect(page.locator('[data-role="sheet-recovery-key"]')).toBeVisible();
  // Only page 2: the recovery key; page 1 does not change.
  await expect(page.locator('[data-role="sheet-secret-key"]')).toHaveCount(0);
  await expect(page.locator('[data-role="page-one-unchanged"]')).toBeVisible();
  const newRecoveryKey = ((await page.locator('[data-role="sheet-recovery-key"]').textContent()) ?? "").trim();
  expect(newRecoveryKey).toMatch(/^FFR1-/);
  expect(newRecoveryKey, "the recovery key is a new one").not.toBe(oldRecoveryKey);
  addNeedle("recovered recovery key", newRecoveryKey);
  expect(calls.filter((c) => c === "POST /api/vault/recover"), "nothing is uploaded before the new key is typed back").toEqual([]);

  // A wrong key typed back is refused and still nothing is uploaded; the right one goes on.
  await page.locator('[data-role="rk-typed"]').fill(`${newRecoveryKey.slice(0, -1)}${newRecoveryKey.endsWith("A") ? "B" : "A"}`);
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="sheet-page"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(calls.filter((c) => c === "POST /api/vault/recover")).toEqual([]);
  await page.locator('[data-role="rk-typed"]').fill(newRecoveryKey);
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="recover-done"]')).toBeVisible({ timeout: 300_000 });
  await expect(page.locator('[data-role="done-signed-in"]')).toBeVisible();
  // The old password is not asked for at any point: the first sign-in of this browser comes after the upload, with the new one.
  const upload = calls.indexOf("POST /api/vault/recover");
  const firstSignIn = calls.indexOf("POST /api/auth/opaque/login/start");
  expect(upload, "the recovery was uploaded").toBeGreaterThan(-1);
  expect(firstSignIn === -1 || firstSignIn > upload, "no sign-in with a password comes before the recovery").toBe(true);
  secrets.password = newPassword;
  secrets.recoveryKey = newRecoveryKey;
  remember();
  expect(await page.locator("body").innerText()).not.toContain(newRecoveryKey);

  // The vault is open on the new browser and the item from before is there.
  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 60_000 });
  await expect(rowsNamed(page, name)).toHaveCount(1, { timeout: 60_000 });
  const stores = await readStores(page);
  expect(stores.pinned.count, "this browser pinned the account").toBe(1);

  // Every other session of the account is over, and the old password does not sign in any more.
  expect((await witness.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the other browser is signed out").toBe(401);
  await witness.context.close();

  // ---- The old recovery key is useless: a second code, a new browser, the old key.
  const second = await hostStep(`code-${secrets.email}`);
  const again = await freshContext(browser);
  const tried = await again.newPage();
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
  await fillRecover(tried, { code: second, rk: oldRecoveryKey, newPassword: `Other-${Date.now().toString(36)}-horse-battery-staple` });
  await tried.locator('[data-role="recover-form"] [data-role="submit"]').click();
  // The code was good and was redeemed; it is the recovery key that is refused, before anything is uploaded.
  await expect(tried.locator('[data-role="recover-page"] [data-role="error"]')).toContainText(/recovery key does not open this account/i, { timeout: SLOW });
  expect(redeemAnswers, "the code was redeemed").toEqual([200]);
  await expect(tried.locator('[data-role="sheet-page"]')).toHaveCount(0);
  expect(triedCalls.filter((c) => c === "POST /api/vault/recover"), "the old recovery key never gets as far as an upload").toEqual([]);
  await again.close();

  // The new password still signs in (nothing was changed by the refused attempt), on a browser that has never seen the account.
  const check = await newDevice(browser);
  await expect(rowsNamed(check.page, name)).toHaveCount(1, { timeout: 60_000 });
  await check.context.close();

  // The old password signs in nowhere: a browser that has never seen the account is refused with the one plain message.
  const stale = await freshContext(browser);
  const refused = await stale.newPage();
  await refused.goto(`${vaultUrl}/vault/login`);
  await expect(refused.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
  await refused.locator('[data-role="email"]').fill(secrets.email);
  await refused.locator('[data-role="email"]').blur();
  await expect(refused.locator('[data-role="sk-question"]')).toBeVisible();
  await refused.locator('[data-role="password"]').fill(oldPassword);
  await refused.locator('[data-role="sk-yes"]').check();
  await refused.locator('[data-role="sk-code"]').fill(secrets.secretKey);
  await pace();
  await refused.locator('[data-role="credentials"] [data-role="submit"]').click();
  await expect(refused.locator('[data-role="credentials"] ~ [data-role="error"]')).toContainText(/could not be opened/i, { timeout: SLOW });
  await expect(refused.locator('[data-role="list"]')).toHaveCount(0);
  await stale.close();
  await context.close();
  leave("m3-21-a", { done: true });
});

/**
 * Changes the master password on the page for it, in an open vault; resolves when the page says it is done, unless `wait` is false.
 * @param {import("@playwright/test").Page} page @param {string} next @param {boolean} [wait]
 */
async function changePassword(page, next, wait = true) {
  // The page for the change is built again each time (a page that shows "done" is left first).
  await page.evaluate(() => {
    location.hash = "#/items";
  });
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  await page.evaluate(() => {
    location.hash = "#/password";
  });
  await expect(page.locator('[data-role="password-page"]')).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-role="current-password"]').fill(secrets.password);
  await page.locator('[data-role="new-password"]').fill(next);
  await page.locator('[data-role="new-password-again"]').fill(next);
  await pace();
  await page.locator('[data-role="password-form"] [data-role="submit"]').click();
  if (wait) await expect(page.locator('[data-role="password-done"]')).toBeVisible({ timeout: SLOW });
}

test("a_code_redeemed_while_the_password_changes_leaves_one_live_session_at_most", async ({ browser }) => {
  test.setTimeout(1_500_000);
  const stamp = Date.now().toString(36);
  const headers = { "Ferret-Protocol": "1" };
  /** @param {import("@playwright/test").APIRequestContext} api */
  const alive = async (api) => (await api.get(`${vaultUrl}/api/auth/session`, { headers })).status() === 200;

  // ---- The code is redeemed first: every other session of the account is ended at once (the browser's full session), and the
  // recovery session is the only one left. The change that the browser still tries is refused, and nothing is changed.
  const first = await newDevice(browser);
  const codeOne = await hostStep(`code-${secrets.email}`);
  await pace();
  const reset = await request.newContext({ ignoreHTTPSErrors: true });
  const redeemed = await redeemCode(reset, secrets.email, codeOne);
  expect(redeemed.status()).toBe(200);
  expect((await reset.get(`${vaultUrl}/api/vault/recovery`, { headers })).status(), "the recovery session works").toBe(200);
  expect(await alive(first.context.request), "the redeem ended the browser's session").toBe(false);
  const attempted = `Redeem-one-${stamp}-horse-battery-staple`;
  await changePassword(first.page, attempted, false);
  await expect(first.page.locator('[data-role="password-page"] [data-role="error"]')).toBeVisible({ timeout: SLOW });
  await expect(first.page.locator('[data-role="password-done"]')).toBeHidden();
  expect((await reset.get(`${vaultUrl}/api/vault/recovery`, { headers })).status(), "the refused change left the recovery session alone").toBe(200);
  await reset.dispose();
  await first.context.close();
  // The password is the one it was: it signs in on a new browser.
  const second = await newDevice(browser);

  // ---- The change comes first: a code that was made before it is dead after it.
  const codeTwo = await hostStep(`code-${secrets.email}`);
  const passwordTwo = `Redeem-two-${stamp}-horse-battery-staple`;
  addNeedle("password after change then redeem", passwordTwo);
  await changePassword(second.page, passwordTwo);
  secrets.password = passwordTwo;
  remember();
  await pace();
  const late = await request.newContext({ ignoreHTTPSErrors: true });
  const refused = await redeemCode(late, secrets.email, codeTwo);
  expect(refused.status(), "a password change ends the codes that are waiting").toBe(401);
  await late.dispose();
  expect(await alive(second.context.request), "the browser that changed the password keeps its session").toBe(true);

  // ---- Both at once: the redeem is sent while the change is on its way. Whichever is first, no two sessions are left: either the
  // change went through (the code is dead) or the code went through (the browser's session is over and the change is refused).
  const codeThree = await hostStep(`code-${secrets.email}`);
  const passwordThree = `Redeem-three-${stamp}-horse-battery-staple`;
  addNeedle("password after redeem during change", passwordThree);
  const racing = await request.newContext({ ignoreHTTPSErrors: true });
  await changePassword(second.page, passwordThree, false);
  const answer = await redeemCode(racing, secrets.email, codeThree);
  expect([200, 401]).toContain(answer.status());
  // The change has an answer, a done page or an error, and no session is waiting for one.
  await expect(second.page.locator('[data-role="password-done"], [data-role="password-page"] [data-role="error"]').first()).toBeVisible({ timeout: SLOW });
  const changed = await second.page.locator('[data-role="password-done"]').isVisible();
  if (changed) {
    secrets.password = passwordThree;
    remember();
  }
  const resetLive = answer.status() === 200 && (await racing.get(`${vaultUrl}/api/vault/recovery`, { headers })).status() === 200;
  const browserLive = await alive(second.context.request);
  expect(resetLive && browserLive, "the recovery session and the browser's session are never both alive").toBe(false);
  expect(changed ? answer.status() === 401 || !resetLive : browserLive === false, "a change that went through leaves no recovery session; a refused one means the code won").toBe(true);
  await racing.dispose();
  await second.context.close();
  // The account is as the winner left it: the current password signs in on a new browser and the vault is whole.
  const check = await newDevice(browser);
  await expect(check.page.locator('[data-role="list"]')).toBeVisible();
  await check.context.close();
  leave("m3-21-c", { changed });
});

test("the_kit_sign_in_code_link_lands_on_the_recover_page", async ({ browser }) => {
  test.setTimeout(300_000);
  // The earlier scenarios of this file have used the five tries of the hour that the server allows for this address.
  await freshRedeemWindow();
  const context = await freshContext(browser);
  const page = await context.newPage();

  // The kit's page for sign-in codes and its link for a password with a code: both end on the recovery page of the vault.
  for (const path of ["/sign-in-code", "/vault/password?code=1"]) {
    await page.goto(`${adminUrl}${path}`);
    await expect(page.locator('[data-role="recover-page"]')).toBeVisible({ timeout: 20_000 });
    expect(page.url(), `${path} leads to the recovery page of the vault`).toBe(`${vaultUrl}/vault/#/recover`);
  }

  // The kit's form never runs, so it never spends a code: a code sent to it is still good afterwards.
  const code = await hostStep(`code-${secrets.email}`);
  const posted = await context.request.post(`${adminUrl}/sign-in-code`, {
    form: { email: secrets.email, code },
    maxRedirects: 0,
  });
  expect(posted.status()).toBe(303);
  expect(posted.headers().location).toBe(`${vaultUrl}/vault/#/recover`);
  await pace();
  const redeemed = await redeemCode(context.request, secrets.email, code);
  expect(redeemed.status(), "the code that went to the kit's page was not spent").toBe(200);
  expect((await redeemed.json()).scope).toBe("account_reset");
  // The reset session reaches the recovery material and nothing else of the vault.
  expect((await context.request.get(`${vaultUrl}/api/vault/recovery`, { headers: { "Ferret-Protocol": "1" } })).status()).toBe(200);
  expect([401, 403]).toContain((await context.request.get(`${vaultUrl}/api/sync/changes?since=0&limit=1`, { headers: { "Ferret-Protocol": "1" } })).status());
  // A code is good once.
  const twice = await redeemCode(context.request, secrets.email, code);
  expect(twice.status()).toBe(401);
  await context.close();
  leave("m3-21", { done: true });
});
