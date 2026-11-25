// A one-time password (TOTP) for a website, in the web vault, with the real server and the real core: it is added through the
// edit form (a bare secret, then an address), shown as a live code that matches an independent RFC 6238 reference, kept when
// the field is left empty, refused with one error when it is not a time-based one, removed after a confirmation, seen on a second
// device, and never in the traffic in the clear. The code is checked at a clock that the test sets (the page's clock is moved with
// Playwright's, and the code follows it).
import { createHmac } from "node:crypto";
import { createItem, expect, findings, leaveMore, newDevice, noViolations, openItem, openList, SLOW, synced, test, unlockWith, secrets, useAccount, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

const SEEN = 30_000;
const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/** @param {string} text Base32 */
function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of text.replace(/[\s=]+/g, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/**
 * The code of RFC 4226 and RFC 6238 (SHA-1), written here from the RFCs, so that what the core makes is compared with something
 * that shares no code with it.
 * @param {string} secret @param {number} seconds @param {number} [digits]
 */
function reference(secret, seconds, digits = 6) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(seconds / 30)));
  const mac = createHmac("sha1", base32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const number = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 10 ** digits).padStart(digits, "0");
}

/** @param {string} code */
const grouped = (code) => (code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : `${code.slice(0, 3)} ${code.slice(3)}`);

/** @type {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} */
let a;
/** @type {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} */
let b;

test.beforeAll(async ({ browser }) => {
  test.setTimeout(400_000);
  useAccount();
  a = await newDevice(browser);
  b = await newDevice(browser);
});

test.afterAll(async () => {
  await a?.context.close();
  await b?.context.close();
});

test("the_reference_is_the_rfc_6238_one", () => {
  // Appendix B of RFC 6238, SHA-1, 8 digits.
  expect(reference(SECRET, 59, 8)).toBe("94287082");
  expect(reference(SECRET, 1111111109, 8)).toBe("07081804");
  expect(reference(SECRET, 1234567890, 8)).toBe("89005924");
  expect(reference(SECRET, 2000000000, 8)).toBe("69279037");
});

/**
 * Waits until the text of a locator is the reference code for the page's own clock.
 * @param {import("@playwright/test").Page} page @param {import("@playwright/test").Locator} where @param {number} digits
 */
async function expectCode(page, where, digits) {
  await expect
    .poll(
      async () => {
        const now = await page.evaluate(() => Date.now());
        return (await where.innerText()) === grouped(reference(SECRET, Math.floor(now / 1000), digits));
      },
      { timeout: SEEN, message: "the code on the page is the one of the reference at the page's clock" },
    )
    .toBe(true);
}

test("a_one_time_password_is_added_shown_changed_kept_refused_and_removed", async () => {
  test.setTimeout(900_000);
  const stamp = Date.now();
  const name = `Totp-${stamp}`;
  const spaced = SECRET.toLowerCase().replace(/(.{4})/g, "$1 ").trim();
  const page = a.page;
  const code = page.locator('[data-role="totp-code"]');
  const card = page.locator('[data-role="item-card"][data-card="totp"]');

  await createItem(page, { name, username: "totp-user" });
  await expect(card).toHaveCount(0);

  // Added with a bare secret (lower case, with spaces): the form shows what the core read and a live code before saving.
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  await expect(page.locator('[data-role="totp"]')).toHaveValue("");
  await page.locator('[data-role="totp"]').fill(spaced);
  await expect(page.locator('[data-role="totp-fact"][data-key="digits"]')).toContainText("6");
  await expect(page.locator('[data-role="totp-fact"][data-key="period"]')).toContainText("30");
  await expect(page.locator('[data-role="totp-fact"][data-key="account"]')).toContainText(name);
  await expectCode(page, page.locator('[data-role="totp-preview-code"]'), 6);
  await expect(page.locator('[data-role="totp-own-host"]')).toHaveCount(0);
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(name, { timeout: SEEN });

  // The item shows the live code, grouped 3 + 3, with the seconds it holds. Only the code is a live region.
  await expect(card).toBeVisible();
  await expectCode(page, code, 6);
  await expect(page.locator('[data-role="totp-left"]')).toHaveText(/^Valid for \d+ s$/);
  await expect(code).toHaveAttribute("aria-live", "polite");
  await expect(page.locator('[data-role="totp-left"]')).not.toHaveAttribute("aria-live", /.*/);
  await synced(page);

  // The secret is not in the page: it stays in the worker. "Show" in the edit form asks for it on the click; hiding it takes it off.
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="totp"]')).toHaveValue("");
  expect(await page.content()).not.toContain(SECRET);
  await page.locator('[data-role="totp-toggle"]').click();
  await expect(page.locator('[data-role="totp"]')).toHaveValue(`otpauth://totp/${encodeURIComponent(name)}?secret=${SECRET}&algorithm=SHA1&digits=6&period=30`);
  await page.locator('[data-role="totp-toggle"]').click();
  await expect(page.locator('[data-role="totp"]')).toHaveValue("");

  // An empty field keeps the stored secret: a change of the user name leaves the code as it was.
  await page.locator('[data-role="username"]').fill("totp-user-2");
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(name, { timeout: SEEN });
  await expect(card).toBeVisible();
  await expectCode(page, code, 6);

  // Not a time-based one-time password: one plain error, nothing saved, the form stays.
  await page.locator('[data-role="edit"]').click();
  for (const text of [`otpauth://hotp/Acme:ada?secret=${SECRET}&counter=1`, `steam://${SECRET}`, "not a secret 1"]) {
    await page.locator('[data-role="totp"]').fill(text);
    await expect(page.locator('[data-role="totp-error"]')).toContainText("not a time-based one-time password");
    await page.locator('[data-role="save"]').click();
    await expect(page.locator('[data-role="error"]')).toContainText("not a time-based one-time password");
    await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  }

  // An address with an issuer and 8 digits replaces it; the form shows what it read.
  const address = `otpauth://totp/Example:ada?secret=${SECRET}&issuer=Example%20Corp&digits=8`;
  await page.locator('[data-role="totp"]').fill(address);
  await expect(page.locator('[data-role="totp-error"]')).toHaveCount(0);
  await expect(page.locator('[data-role="totp-fact"][data-key="issuer"]')).toContainText("Example Corp");
  await expect(page.locator('[data-role="totp-fact"][data-key="digits"]')).toContainText("8");
  await expectCode(page, page.locator('[data-role="totp-preview-code"]'), 8);
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(name, { timeout: SEEN });
  await expectCode(page, code, 8);
  await synced(page);

  // Another device has the item and its code.
  await openItem(b.page, name);
  await expect(b.page.locator('[data-role="item-card"][data-card="totp"]')).toBeVisible({ timeout: SEEN });
  await expectCode(b.page, b.page.locator('[data-role="totp-code"]'), 8);

  // Removing asks first. "No" leaves it; "Yes" takes it out when the item is saved.
  await page.locator('[data-role="edit"]').click();
  await page.locator('[data-role="totp-remove"]').click();
  await expect(page.locator('[data-role="dialog"]')).toBeVisible();
  await page.locator('[data-role="dialog-cancel"]').click();
  await expect(page.locator('[data-role="dialog"]')).toHaveCount(0);
  await page.locator('[data-role="totp-remove"]').click();
  await page.locator('[data-role="dialog-confirm"]').click();
  await expect(page.locator('[data-role="totp-keep"]')).toBeVisible();
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(name, { timeout: SEEN });
  await expect(card).toHaveCount(0);
  await synced(page);
  await expect(b.page.locator('[data-role="item-card"][data-card="totp"]')).toHaveCount(0, { timeout: SEEN });
  // The form of an item that has none shows no remove control and no stored secret.
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="totp-remove-bar"]')).toHaveCount(0);
  await page.locator('[data-role="cancel"]').click();

  // Neither the secret nor the address went over the wire in the clear: not in the browsers' traffic, and (through the list the
  // host script searches) not in the server's data files, its backup sets or its log.
  const traffic = findings.traffic.join("\n");
  expect(traffic.length).toBeGreaterThan(1000);
  expect(traffic).toContain("/api/sync/items/");
  // (The page's own scripts are in the traffic too, and name the address format; so the address is searched for as it was made.)
  const made = `otpauth://totp/${encodeURIComponent(name)}?secret=`;
  for (const [label, value] of [["secret", SECRET], ["spaced secret", spaced], ["address", made], ["typed address", address], ["issuer", "Example%20Corp"]]) {
    expect(traffic.includes(value), `the traffic holds the ${label}`).toBe(false);
  }
  leaveMore([{ name: "totp secret", value: SECRET }, { name: "totp spaced secret", value: spaced }]);
});

test("the_code_follows_a_clock_that_the_test_sets", async ({ browser }) => {
  test.setTimeout(900_000);
  const stamp = Date.now();
  const name = `TotpClock-${stamp}`;
  // A new item with the field filled in at the start: the same path as an edit.
  await a.page.locator('[data-role="nav-items"]').click();
  await expect(a.page.locator('[data-role="list"]')).toBeVisible();
  await a.page.locator('[data-role="new-item"]').click();
  await expect(a.page.locator('[data-role="edit-form"]')).toBeVisible();
  await a.page.locator('[data-role="name"]').fill(name);
  await a.page.locator('[data-role="totp"]').fill(`otpauth://totp/${encodeURIComponent(name)}?secret=${SECRET}&digits=8`);
  await expect(a.page.locator('[data-role="totp-preview-code"]')).not.toHaveText("••• •••", { timeout: SEEN });
  await a.page.locator('[data-role="save"]').click();
  await expect(a.page.locator('[data-role="item"] h1')).toContainText(name, { timeout: SEEN });
  await synced(a.page);

  // The vault is opened again in this browser with the page's clock set to the start of a period a little ahead (a clock that
  // flows from there): the code is the reference code of that second, and after the period it is the next one.
  await a.page.close();
  const start = (Math.floor(Date.now() / 30_000) + 1) * 30_000;
  const late = await a.context.newPage();
  await late.clock.install({ time: new Date(start) });
  await late.goto(`${vaultUrl}/vault/#/items`);
  await expect(late.locator('[data-role="unlock"]')).toBeVisible({ timeout: SEEN });
  await unlockWith(late, secrets.password);
  await expect(late.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
  await openItem(late, name);
  const code = late.locator('[data-role="totp-code"]');
  await expect(code).toHaveText(/^\d{4} \d{4}$/, { timeout: SEEN });
  await expectCode(late, code, 8);
  expect(await late.evaluate(() => Date.now())).toBeGreaterThanOrEqual(start);
  const first = await code.innerText();
  await expect(late.locator('[data-role="totp-left"]')).toHaveText(/^Valid for (\d|[12]\d|30) s$/);

  // The period is over: the page asks for a new code.
  await late.clock.fastForward(31_000);
  await expectCode(late, code, 8);
  expect(await code.innerText()).not.toBe(first);
  await openList(late);
  await late.close();
});
