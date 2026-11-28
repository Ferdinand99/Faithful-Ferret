// The people of the scenarios with several accounts: the administrator of the run makes invitation links and sign-in
// codes on the Users page of the admin origin, and an invited person joins from a link and is kept in a file, so that
// a later test (or a new worker after a failure) knows her.
//
// The actions on the Users page that need a fresh check of the password (an invitation, a sign-in code, enabling an
// account again) run in a Chromium this file launches itself, in every project: Playwright's WebKit stops with an
// internal "Assertion error" on the redirect from the admin origin to the vault's password check
// (`/admin/auth/handoff/begin?purpose=reauth` to `/vault/reauth`), whether the page follows a link or navigates there
// itself. A sign-in through the hand-over (`purpose=login`) and a direct `/vault/reauth` work in WebKit, so the
// protective actions (disable, sign out everywhere), which need no fresh check, run in the project's own browser.
import { chromium } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  adminUrl, confirmSheet, expect, freshContext, outDir, pace, readSheet, secrets, signInHere, SLOW, untilStartAccepted, vaultUrl,
} from "./support.mjs";

export const ACCOUNTS = "/settings/accounts";
const vaultPattern = vaultUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** The link the Users page shows: the vault's setup page with the token in the fragment. */
export const LINK = new RegExp(`^${vaultPattern}/vault/setup#invite=([0-9A-Za-z]{43})$`);

/**
 * A person of this run who is not the administrator.
 * @param {string} name
 * @returns {{ email: string, password: string, secretKey: string, recoveryKey: string }}
 */
export function invitee(name) {
  const tag = randomBytes(5).toString("hex");
  return { email: `${name}-${tag}@e2e.example.test`, password: `Invitee-${tag}-correct-battery`, secretKey: "", recoveryKey: "" };
}

/** Keeps a person of the run in a file of the run, by a name. @param {string} name @param {ReturnType<typeof invitee>} person */
export function keepPerson(name, person) {
  writeFileSync(`${outDir}/person-${name}.json`, JSON.stringify(person));
}

/** A person an earlier test kept, or null. @param {string} name @returns {ReturnType<typeof invitee> | null} */
export function keptPerson(name) {
  const file = `${outDir}/person-${name}.json`;
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
}

/**
 * Opens the Users page as the administrator in `page` (a sign-in through the hand-over when the page asks for it).
 * @param {import("@playwright/test").Page} page
 */
export async function openUsersPage(page) {
  await page.goto(`${adminUrl}${ACCOUNTS}`);
  const atUsers = (/** @type {URL} */ url) => url.origin === adminUrl && url.pathname === ACCOUNTS;
  if (!atUsers(new URL(page.url()))) {
    await signInHere(page, { expectList: false });
    await page.waitForURL(atUsers, { timeout: SLOW });
  }
  await expect(page.locator("main h1")).toBeVisible({ timeout: 20_000 });
}

/**
 * The page's fresh check of the password, when it asks for one: the "Confirm it's you" link leads to the vault origin's
 * password check, and the page comes back.
 * @param {import("@playwright/test").Page} page
 */
export async function confirmItsYou(page) {
  if ((await page.locator('form[action="/settings/accounts/invites"]').count()) > 0) return;
  await page.locator('a[href^="/vault/reauth"]').first().click();
  const credentials = page.locator('[data-role="credentials"]');
  await expect(credentials).toBeVisible({ timeout: 20_000 });
  expect(new URL(page.url()).origin).toBe(vaultUrl);
  await credentials.locator('[data-role="password"]').fill(secrets.password);
  await untilStartAccepted(page.context(), async () => {
    await pace();
    await credentials.locator('[data-role="submit"]').click();
  });
  await page.waitForURL((url) => url.origin === adminUrl && url.pathname === ACCOUNTS, { timeout: SLOW });
  await expect(page.locator('form[action="/settings/accounts/invites"]')).toBeVisible({ timeout: 20_000 });
}

/**
 * Runs `act` on the Users page as the administrator, freshly confirmed, in a Chromium of its own (see the top of this
 * file for why).
 * @template T
 * @param {(page: import("@playwright/test").Page) => Promise<T>} act
 * @returns {Promise<T>}
 */
export async function asConfirmedAdmin(act) {
  const browser = await chromium.launch();
  const context = await freshContext(browser);
  try {
    const page = await context.newPage();
    await openUsersPage(page);
    await confirmItsYou(page);
    return await act(page);
  } finally {
    await context.close();
    await browser.close();
  }
}

/**
 * The administrator makes an invitation and reads the link that the page shows once.
 * @returns {Promise<{ link: string, token: string }>}
 */
export async function makeInvite() {
  return asConfirmedAdmin(async (page) => {
    await page.locator('form[action="/settings/accounts/invites"] button[type="submit"]').click();
    const shown = page.locator("#created-invite");
    await expect(shown).toBeVisible({ timeout: 20_000 });
    const link = ((await shown.textContent()) ?? "").trim();
    const match = LINK.exec(link);
    expect(match, `the link the page shows: ${link}`).not.toBeNull();
    return { link, token: /** @type {RegExpExecArray} */ (match)[1] };
  });
}

/**
 * The row of an account on the Users page.
 * @param {import("@playwright/test").Page} page
 * @param {string} email
 */
export const accountRow = (page, email) => page.locator("li.list-row", { has: page.locator(".list-title", { hasText: email }) });

/**
 * Sends a form of an account's row on the Users page and answers its question (the kit's dialog) with yes.
 * @param {import("@playwright/test").Page} page
 * @param {string} email
 * @param {"sign-in-code" | "disable" | "enable" | "sign-out"} action
 */
export async function rowAction(page, email, action) {
  const row = accountRow(page, email);
  await expect(row).toBeVisible({ timeout: 20_000 });
  // The page answers the form itself (a sign-in code is shown once, in the answer to the POST) or sends the browser
  // back to the list; either way the answer to the POST is what is waited for, not an address.
  const answered = page.waitForResponse(
    (response) => response.request().method() === "POST" && new URL(response.url()).pathname.endsWith(`/${action}`),
    { timeout: 30_000 },
  );
  await row.locator(`form[action$="/${action}"] button[type="submit"]`).click();
  const dialog = page.locator("dialog.sheet-alert[open]");
  if (action === "disable" || action === "sign-out") {
    await expect(dialog).toBeVisible({ timeout: 10_000 });
    await dialog.locator('[data-answer="yes"]').click();
  }
  const answer = await answered;
  expect(answer.status(), `the answer to ${action}`).toBeLessThan(400);
  await page.waitForLoadState("load");
  await expect(page.locator("main h1")).toBeVisible({ timeout: 20_000 });
}

/**
 * The invited person opens the link and makes her account: the join page, the form, the sheet, the keys typed back.
 * Leaves the page on the done screen; the keys are put in `person`.
 * @param {import("@playwright/test").Page} page
 * @param {string} link
 * @param {ReturnType<typeof invitee>} person
 * @param {() => void} [beforeConfirm] runs while the sheet is shown, before the keys are typed back
 */
export async function join(page, link, person, beforeConfirm) {
  await page.goto(link);
  const heading = page.locator('[data-role="join-heading"]');
  await expect(heading).toHaveText(`Join Ferret on ${new URL(vaultUrl).host}`, { timeout: 20_000 });
  await expect(page.locator('[data-role="setup-form"]')).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('[data-role="invited-by"]')).toContainText(secrets.email);
  await expect(page.locator('[data-role="invite-expires"]')).toContainText("works until");
  // The first administrator's field is not here, and the secret key is on.
  await expect(page.locator('[data-role="setup-token"]')).toHaveCount(0);
  await expect(page.locator('[data-role="use-sk"]')).toBeChecked();
  await page.locator('[data-role="email"]').fill(person.email);
  await page.locator('[data-role="password"]').fill(person.password);
  await page.locator('[data-role="password-repeat"]').fill(person.password);
  await page.locator('[data-role="setup-form"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="sheet-page"]')).toBeVisible({ timeout: SLOW });
  const keys = await readSheet(page);
  expect(keys.recoveryKey.length).toBeGreaterThan(10);
  expect(keys.secretKey.length).toBeGreaterThan(10);
  person.recoveryKey = keys.recoveryKey;
  person.secretKey = keys.secretKey;
  beforeConfirm?.();
  await confirmSheet(page, keys);
}

/**
 * A person invited and joined in a browser context of her own, left on her open vault; kept under `name`.
 * @param {import("@playwright/test").Browser} browser
 * @param {string} name
 */
export async function joinedPerson(browser, name) {
  const { link } = await makeInvite();
  const person = invitee(name);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await join(page, link, person);
  keepPerson(name, person);
  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  return { person, context, page };
}

/**
 * What the vault's session says about the browser of `context`: its account id and e-mail (null when there is none).
 * @param {import("@playwright/test").BrowserContext} context
 * @returns {Promise<{ accountId: string, email: string } | null>}
 */
export async function sessionOf(context) {
  const answer = await context.request.get(`${vaultUrl}/api/auth/session`, { headers: { "Ferret-Protocol": "1" } });
  if (answer.status() !== 200) return null;
  const body = await answer.json();
  return { accountId: body.account_id, email: body.email };
}
