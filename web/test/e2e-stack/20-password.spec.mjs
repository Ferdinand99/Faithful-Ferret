// A master password change. The browser that changes it keeps its session and its open vault; every other browser of the account
// is signed out at once (it is told over the live stream, and its session no longer works); the new password opens the vault
// everywhere, on a new browser, after a lock and on the browser that was signed out; the old password opens nothing.
import { addNeedle, createItem, expect, freshContext, leave, newDevice, noViolations, openList, pace, readStores, remember, requireAccount, rowsNamed, secrets, signInHere, SLOW, synced, test, unlockWith, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  requireAccount();
});

test("a_password_change_signs_out_the_other_browser_and_the_new_password_works_everywhere", async ({ browser }) => {
  test.setTimeout(900_000);
  const oldPassword = secrets.password;
  const newPassword = `Changed-${Date.now().toString(36)}-horse-battery-staple`;
  expect(newPassword).not.toBe(oldPassword);
  addNeedle("changed password", newPassword);

  // Two browsers of the account, both signed in, the vault open in both.
  const a = await newDevice(browser);
  const b = await newDevice(browser);
  const name = `Before-change-${Date.now()}`;
  await createItem(a.page, { name, username: "before-the-change", password: `Pw-${Date.now()}-before-change!` });
  await synced(a.page);
  await expect(b.page.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "live", { timeout: 30_000 });
  expect((await b.page.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);

  // ---- Browser A changes the password on the page for it.
  await a.page.evaluate(() => {
    location.hash = "#/password";
  });
  await expect(a.page.locator('[data-role="password-page"]')).toBeVisible({ timeout: 30_000 });
  await expect(a.page.locator('[data-role="old-files-notice"]')).toBeVisible();
  // Nothing is sent for what the page can see is wrong.
  const sent = /** @type {string[]} */ ([]);
  a.page.on("request", (request) => {
    // The sign-in, the password and the keys; not the traffic of the sync, which goes on in the background.
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/auth/") || path.startsWith("/api/vault/")) sent.push(path);
  });
  await a.page.locator('[data-role="current-password"]').fill(oldPassword);
  await a.page.locator('[data-role="new-password"]').fill(newPassword);
  await a.page.locator('[data-role="new-password-again"]').fill(`${newPassword}-typo`);
  await a.page.locator('[data-role="password-form"] [data-role="submit"]').click();
  await expect(a.page.locator('[data-role="password-page"] [data-role="error"]')).toBeVisible();
  expect(sent, "two different new passwords send nothing").toEqual([]);

  await a.page.locator('[data-role="current-password"]').fill(oldPassword);
  await a.page.locator('[data-role="new-password"]').fill(newPassword);
  await a.page.locator('[data-role="new-password-again"]').fill(newPassword);
  await pace();
  await a.page.locator('[data-role="password-form"] [data-role="submit"]').click();
  await expect(a.page.locator('[data-role="password-done"]')).toBeVisible({ timeout: SLOW });
  // The page says what the change does and does not do.
  await expect(a.page.locator('[data-role="done-devices"]')).toBeVisible();
  await expect(a.page.locator('[data-role="done-backup"]')).toContainText(/backup/i);
  await expect(a.page.locator('[data-role="done-old-files"]')).toBeVisible();
  await expect(a.page.locator('[data-role="done-sheet"]')).toBeVisible();
  // The fields are empty again, and the passwords are nowhere on the page.
  expect(await a.page.evaluate(() => document.body.innerHTML + Array.from(document.querySelectorAll("input"), (i) => i.value).join(""))).not.toContain(newPassword);
  secrets.password = newPassword;
  remember();

  // ---- Browser A goes on: its session and its open vault are as they were.
  expect((await a.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the browser that changed the password keeps its session").toBe(200);
  await openList(a.page);
  await expect(rowsNamed(a.page, name)).toHaveCount(1);

  // ---- Browser B is signed out at once: the live stream says so, and its session is dead.
  await expect(b.page.locator('[data-role="live-status"]')).toHaveAttribute("data-state", "unauthorized", { timeout: 30_000 });
  expect((await b.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the other browser's session is over").toBe(401);
  // A write made there is not lost and is not sent: the page says that the user has to sign in again, and the write waits.
  const offline = `Written-after-signout-${Date.now()}`;
  await createItem(b.page, { name: offline, username: "after-the-change" });
  // The server answered the write with 401. Soft checks: the rest of the scenario (the new password everywhere) is still looked at when
  // a browser does not say so.
  await expect.soft(b.page.locator('[data-role="banner"][data-banner="unauthorized"]'), "the page says to sign in again").toBeVisible({ timeout: 20_000 });
  expect.soft((await readStores(b.page)).outbox.count, "the write waits in the browser").toBeGreaterThan(0);

  // ---- The old password opens nothing: a new browser is refused with one plain message.
  const old = await freshContext(browser);
  const refused = await old.newPage();
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
  await expect(refused.locator('[data-role="credentials"] ~ [data-role="error"]')).toBeVisible({ timeout: SLOW });
  await expect(refused.locator('[data-role="list"]')).toHaveCount(0);
  expect((await readStores(refused)).pinned.count, "a refused sign-in pins nothing").toBe(0);
  await old.close();

  // ---- The new password signs in on a new browser, and the item from before the change is there.
  const fresh = await newDevice(browser);
  await expect(rowsNamed(fresh.page, name)).toHaveCount(1, { timeout: 60_000 });

  // ---- It signs in again in the browser that was signed out (it knows the account and keeps the secret key).
  await b.page.goto(`${vaultUrl}/vault/login`);
  await signInHere(b.page);
  await expect(rowsNamed(b.page, name)).toHaveCount(1, { timeout: 60_000 });

  // ---- It opens the vault again after a lock; the old one does not.
  await a.page.locator('[data-role="lock"]').click();
  await expect(a.page.locator('[data-role="unlock-form"]')).toBeVisible({ timeout: 30_000 });
  await unlockWith(a.page, oldPassword);
  await expect(a.page.locator('[data-role="unlock-error"], [data-role="error"]').first()).toBeVisible({ timeout: SLOW });
  await expect(a.page.locator('[data-role="list"]')).toHaveCount(0);
  await a.page.locator('[data-role="password"]').fill("");
  await unlockWith(a.page, newPassword);
  await expect(a.page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
  await expect(rowsNamed(a.page, name)).toHaveCount(1);

  for (const device of [a, b, fresh]) await device.context.close();
  leave("m3-20", { done: true });
});
