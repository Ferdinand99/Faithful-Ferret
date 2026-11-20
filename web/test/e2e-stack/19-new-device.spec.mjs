// A new browser signs in with the text of the QR code on page 1 of the sheet. The page reads the text with no request, shows
// the address and whether the account has a secret key, and asks the user to confirm the address before anything is sent. The
// sign-in then pins the server's key from the sheet; a sheet that holds another key is refused before the second message of the
// sign-in goes out, and a sheet for another address is refused before any message goes out.
import { expect, freshContext, leave, noViolations, pace, readStores, requireAccount, secrets, SLOW, test, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  requireAccount();
  if (secrets.qrText === "") throw new Error("no QR text: run 18-sheet.spec.mjs first");
});

/**
 * One value of the setup text.
 * @param {string} text @param {string} key
 */
function param(text, key) {
  const value = new URLSearchParams(text.slice(text.indexOf("?") + 1)).get(key);
  if (value === null) throw new Error(`the setup text has no ${key}`);
  return value;
}

/** The server key in a setup text as hex, whichever way it is written there. @param {string} text */
function keyHex(text) {
  const value = param(text, "o");
  return /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : Buffer.from(value, "base64url").toString("hex");
}

/**
 * Fills the sign-in page with the e-mail, the password and the text of the sheet, and reads the text.
 * @param {import("@playwright/test").Page} page @param {string} qrText
 */
async function fillWithSheet(page, qrText, password = secrets.password) {
  await page.goto(`${vaultUrl}/vault/login`);
  await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
  await page.locator('[data-role="email"]').fill(secrets.email);
  await page.locator('[data-role="email"]').blur();
  // Without a sheet the page says that the first sign-in trusts the server the first time.
  await expect(page.locator('[data-role="tofu-notice"]')).toBeVisible();
  await page.locator('[data-role="password"]').fill(password);
  await page.locator('[data-role="qr-text"]').fill(qrText);
  await page.locator('[data-role="qr-read"]').click();
}

test("a_new_browser_with_the_sheet_text_pins_the_server_key", async ({ browser }) => {
  test.setTimeout(300_000);
  const context = await freshContext(browser);
  const page = await context.newPage();
  /** @type {string[]} */
  const sent = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/")) sent.push(path);
  });

  await fillWithSheet(page, secrets.qrText);
  // The sheet is read, nothing was sent: the page shows the address and the secret key answer, and asks for a confirmation.
  await expect(page.locator('[data-role="qr-shown"]')).toBeVisible({ timeout: 30_000 });
  const host = new URL(vaultUrl).host;
  await expect(page.locator('[data-role="qr-summary"]')).toContainText(host);
  await expect(page.locator('[data-role="qr-summary"]')).toContainText(/secret key/i);
  expect(sent.filter((path) => path.startsWith("/api/auth/opaque")), "nothing of the sign-in was sent while the sheet was only read").toEqual([]);
  // The sheet answers the question about the secret key: the page does not ask it, and asks for the key itself.
  await expect(page.locator('[data-role="sk-question"]')).toBeHidden();
  await expect(page.locator('[data-role="tofu-notice"]')).toBeHidden();
  await expect(page.locator('[data-role="sk-code"]')).toBeVisible();
  await page.locator('[data-role="sk-code"]').fill(secrets.secretKey);

  // Without the confirmation the sign-in is not sent.
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="error"]')).toBeVisible({ timeout: 15_000 });
  expect(sent.filter((path) => path.startsWith("/api/auth/opaque")), "an unconfirmed sheet sends nothing").toEqual([]);

  await page.locator('[data-role="qr-confirm"]').check();
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });

  // The server's key from the sheet is what this browser pinned, along with the account of the sheet.
  const stores = await readStores(page);
  expect(stores.pinned.count).toBe(1);
  const record = stores.pinned.values[0].record;
  expect(record.server_public_key, "the pinned server key is the one on the sheet").toBe(keyHex(secrets.qrText));
  expect(record.sk_bit).toBe(true);
  expect(stores.device_secrets.count, "the secret key is sealed on the device").toBe(1);
  // The text of the sheet is nowhere in what the browser keeps (the key in it is public, the rest is an address and an id), and the
  // page has emptied the field.
  expect(await page.locator('[data-role="qr-text"]').count()).toBe(0);
  await context.close();
});

test("a_sheet_text_with_another_server_key_is_refused_before_sign_in", async ({ browser }) => {
  test.setTimeout(300_000);
  const original = keyHex(secrets.qrText);
  const flipped = (original[0] === "0" ? "1" : "0") + original.slice(1);
  expect(flipped).not.toBe(original);
  const forged = secrets.qrText.replace(/([?&]o=)[^&]+/, (_, lead) => `${lead}${flipped}`);
  expect(forged).not.toBe(secrets.qrText);

  const context = await freshContext(browser);
  const page = await context.newPage();
  /** @type {string[]} */
  const sent = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/auth/")) sent.push(`${request.method()} ${path}`);
  });

  // A sheet that holds another server's key: the page cannot know that before the server has answered, so it asks the server for
  // the first message of the sign-in and refuses on the answer, before the second message (the one that holds the proof) goes.
  await fillWithSheet(page, forged);
  await expect(page.locator('[data-role="qr-shown"]')).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-role="sk-code"]').fill(secrets.secretKey);
  await page.locator('[data-role="qr-confirm"]').check();
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="error"]')).toBeVisible({ timeout: SLOW });
  expect(sent.some((entry) => entry.endsWith("/api/auth/opaque/login/start")), "the first message was the only one of the sign-in").toBe(true);
  expect(sent.filter((entry) => entry.endsWith("/api/auth/opaque/login/finish")), "the second message never went").toEqual([]);
  expect((await page.request.get(`${vaultUrl}/api/auth/session`)).status(), "no session was made").toBe(401);
  const after = await readStores(page);
  expect(after.pinned.count, "nothing was pinned").toBe(0);
  expect(after.device_secrets.count, "no secret key was sealed").toBe(0);
  await expect(page.locator('[data-role="list"]')).toHaveCount(0);

  // A sheet for another address is refused when it is read: nothing at all is sent.
  const elsewhere = secrets.qrText.replace(/([?&]u=)[^&]+/, (_, lead) => `${lead}${encodeURIComponent("https://vault.elsewhere.example")}`);
  expect(elsewhere).not.toBe(secrets.qrText);
  sent.length = 0;
  await page.locator('[data-role="qr-text"]').fill(elsewhere);
  await page.locator('[data-role="qr-read"]').click();
  await expect(page.locator('[data-role="error"]')).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('[data-role="qr-shown"]')).toBeHidden();
  expect(sent, "a sheet for another address sends nothing").toEqual([]);
  await context.close();
  leave("m3-19", { done: true });
});
