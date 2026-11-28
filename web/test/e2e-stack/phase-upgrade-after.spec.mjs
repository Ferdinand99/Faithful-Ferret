// The second half of the upgrade drill (scripts/lanbox-ferret-test.sh upgrade-drill <tag>), on the candidate build that
// replaced the release on the same data (phase-upgrade-before.spec.mjs made the account there and checked the device and the
// passkey method over the swap). In a fresh browser: the first account signs in and finds everything the release held, the
// PIN rule is the one its administrator set, and the first account, the administrator, can invite a second person at once,
// who gets an account and an empty vault of her own.
import { accountRow, joinedPerson, openUsersPage } from "./accounts.mjs";
import {
  adminUrl, API_HEADERS, expect, feedOf, findRows, freshContext, leave, newDevice, noViolations, openItem, openList, secrets, test, totpReference,
  useAccount, vaultUrl,
} from "./support.mjs";

test.skip(process.env.FERRET_E2E_PHASE !== "upgrade-after", "run by scripts/lanbox-ferret-test.sh upgrade-drill");
test.describe.configure({ mode: "serial" });
noViolations();

/**
 * What the first half left about the account.
 * @returns {{ names: { folder: string, totp: string, trashed: string, passkey: string }, totpSecret: string, rule: { allowed: boolean, after_restart: boolean, min_length: number } }}
 */
const upgrade = () => /** @type {any} */ (secrets).upgrade;

test.beforeAll(() => {
  useAccount();
  if (!upgrade()) throw new Error("the state of phase-upgrade-before.spec.mjs has no upgrade part");
});

test("after_the_upgrade_the_first_account_unlocks_with_everything_there", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium");
  test.setTimeout(600_000);
  const { names, totpSecret } = upgrade();
  // A browser that has never seen the account: the e-mail, the master password and the secret key.
  const { context, page } = await newDevice(browser);
  try {
    // The login item, whole, in its folder.
    await openItem(page, secrets.itemTitle);
    const item = page.locator('[data-role="item"]');
    await expect(item).toContainText(secrets.itemUsername);
    await expect(item).toContainText(new URL(secrets.itemUrl).host);
    await expect(page.locator('[data-role="folder-chip"]', { hasText: names.folder })).toBeVisible();
    // The one-time password gives the code of the reference.
    await openItem(page, names.totp);
    const code = page.locator('[data-role="totp-code"]');
    await expect
      .poll(async () => (await code.innerText()).replace(/\s/g, "") === totpReference(totpSecret, Math.floor((await page.evaluate(() => Date.now())) / 1000)), { timeout: 30_000 })
      .toBe(true);
    // The deleted item is not in the list. (The trash is kept by each browser that saw the item before it was deleted, so this
    // new one has none; the browser of the first half shows it there after the swap.)
    await openList(page);
    await expect(await findRows(page, names.trashed)).toHaveCount(0);
    // The server holds what the release held: two live items (the manifest, whose id is all zeros, is not one), the
    // tombstone of the deleted one, and the passkey method beside the password and the recovery key.
    const { changes } = await feedOf(context);
    expect(changes.filter((c) => !c.deleted && c.id !== "0".repeat(32))).toHaveLength(2);
    expect(changes.filter((c) => c.deleted)).toHaveLength(1);
    const methods = await context.request.get(`${vaultUrl}/api/vault/unlock-methods`, { headers: { "Ferret-Protocol": "1" } });
    expect(methods.status()).toBe(200);
    expect(/** @type {any[]} */ ((await methods.json()).methods).filter((m) => m.method_type === 3)).toHaveLength(1);
  } finally {
    await context.close();
  }
});

test("the_pin_rule_is_kept", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium");
  test.setTimeout(600_000);
  const { rule } = upgrade();
  const context = await freshContext(browser);
  try {
    const page = await context.newPage();
    // The administrator's Unlock tab shows the rule, through the hand-over from the vault's sign-in.
    await openUsersPage(page);
    await page.goto(`${adminUrl}/settings/unlock`);
    await expect(page.locator('input[name="min_length"]')).toHaveValue(String(rule.min_length), { timeout: 20_000 });
    await expect(page.locator('input[name="pin_after_restart"]')).not.toBeChecked();
    await expect(page.locator('input[name="pin_allowed"]')).toBeChecked();
    // And every client reads it.
    const policy = await context.request.get(`${vaultUrl}/api/vault/policy`, { headers: API_HEADERS });
    expect(policy.status()).toBe(200);
    expect((await policy.json()).pin).toEqual(rule);
  } finally {
    await context.close();
  }
});

test("the_first_account_can_invite_at_once", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "the drill runs in Chromium");
  test.setTimeout(900_000);
  // An invitation from the Users page, the join, an open vault of her own with nothing of the first account in it.
  const { person, context, page } = await joinedPerson(browser, "upgraded");
  try {
    await expect(page.locator('[data-role="list-empty"]')).toBeVisible({ timeout: 30_000 });
    await expect(await findRows(page, secrets.itemTitle)).toHaveCount(0);
  } finally {
    await context.close();
  }
  // The Users page lists both accounts: the first one as the administrator.
  const admin = await freshContext(browser);
  try {
    const usersPage = await admin.newPage();
    await openUsersPage(usersPage);
    await expect(accountRow(usersPage, secrets.email)).toBeVisible({ timeout: 20_000 });
    await expect(accountRow(usersPage, person.email)).toBeVisible({ timeout: 20_000 });
  } finally {
    await admin.close();
  }
  leave("upgrade-after", { invited: "joined" });
});

