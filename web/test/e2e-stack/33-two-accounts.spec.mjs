// Two accounts in one browser profile share nothing. The administrator of the run (A) and a second person (B, who
// joins from an invitation) use the same browser: the list, the sync, the local copy of the rows, the outbox, the
// mark of what "Activity" last showed and the remembered account are each kept per account, and neither ever sees
// an item of the other. When one tab signs in as the other account (the session cookie of the profile changes under
// a tab that is open), the open tab never shows the other account's log as its own and never stores its mark.
// The invited account also adds a passkey and opens the vault with it, as the first account can (Chromium only: the
// virtual authenticator is Chromium's).
//
// The administrator's steps on the Users page run in a Chromium of their own (see accounts.mjs).
import { randomBytes } from "node:crypto";
import { invitee, join, keepPerson, keptPerson, makeInvite, sessionOf } from "./accounts.mjs";
import {
  API_HEADERS, createItem, expect, feedOf, findRows, freshContext, itemIdOf, noViolations, openList, pace, readStores, requireAccount,
  secrets, signInHere, signInOn, signOutOn, SLOW, synced, test, untilStartAccepted, vaultUrl,
} from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

const tag = randomBytes(4).toString("hex");

/** The person of this file. */
function second() {
  const person = keptPerson("second");
  if (person === null) throw new Error("the first test of this file made the second account");
  return person;
}

/**
 * Every row of the local copy, with the account it is kept under and its item id (the key is account, vault, key epoch,
 * item).
 * @param {import("@playwright/test").Page} page
 * @returns {Promise<{ account: string, item: string }[]>}
 */
async function localRows(page) {
  const { rows } = await readStores(page);
  return /** @type {any[]} */ (rows.keys).map((key) => (Array.isArray(key) ? { account: String(key[0]), item: String(key[key.length - 1]) } : { account: "", item: String(key) }));
}

/**
 * The settings of the browser whose key starts with `prefix`, as key and value.
 * @param {import("@playwright/test").Page} page @param {string} prefix
 */
async function settingsLike(page, prefix) {
  const { settings } = await readStores(page);
  /** @type {[string, unknown][]} */
  const out = [];
  settings.keys.forEach((/** @type {unknown} */ key, /** @type {number} */ i) => {
    if (typeof key === "string" && key.startsWith(prefix)) out.push([key, settings.values[i]]);
  });
  return out;
}

/**
 * The bodies of every answer of the vault's API to this context from now on, until `stop` is called.
 * @param {import("@playwright/test").BrowserContext} context
 */
function recordAnswers(context) {
  /** @type {{ url: string, body: string }[]} */
  const answers = [];
  const pending = /** @type {Promise<void>[]} */ ([]);
  const listen = (/** @type {import("@playwright/test").Response} */ response) => {
    const url = response.url();
    if (!url.startsWith(`${vaultUrl}/api/`) || url.includes("/api/sync/events")) return;
    pending.push(response.text().then((body) => {
      answers.push({ url, body });
    }, () => {}));
  };
  context.on("response", listen);
  return {
    async stop() {
      context.off("response", listen);
      await Promise.all(pending);
      return answers;
    },
  };
}

test("join_in_a_browser_that_remembers_another_account", async ({ browser }) => {
  test.setTimeout(900_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();

  // A is signed in here, remembered, with an item of its own.
  await signInOn(page);
  const nameA = `Only-A-${tag}`;
  await createItem(page, { name: nameA, username: `a-${tag}`, password: `pw-a-${tag}` });
  await synced(page);
  await openList(page);
  const itemA = await itemIdOf(page, nameA);
  const a = await sessionOf(context);
  expect(a?.email).toBe(secrets.email);

  // B opens an invitation link in the same tab, and joins.
  const { link } = await makeInvite();
  const person = invitee("second");
  await join(page, link, person);
  keepPerson("second", person);
  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  const b = await sessionOf(context);
  expect(b?.email).toBe(person.email);
  expect(b?.accountId).not.toBe(a?.accountId);

  // B's vault holds nothing of A: not in the list, not in the feed of B's session.
  expect(await (await findRows(page, nameA)).count()).toBe(0);
  expect(await page.locator('[data-role="list"]').innerText()).not.toContain(nameA);
  expect((await feedOf(context)).changes.map((c) => c.id)).not.toContain(itemA);

  // The local copy keeps A's rows under A, and B's under B; the browser now remembers B.
  const rows = await localRows(page);
  expect(rows.filter((r) => r.item === itemA).map((r) => r.account)).toEqual([a?.accountId]);
  expect(rows.some((r) => r.account === b?.accountId)).toBe(true);
  const remembered = await settingsLike(page, "signin.remembered.");
  expect(remembered.map(([, value]) => value)).toEqual([b?.accountId]);

  // B's session ends: the page offers B's e-mail to unlock, not A's.
  expect((await context.request.post(`${vaultUrl}/api/auth/logout`, { headers: API_HEADERS })).status()).toBe(204);
  expect(await sessionOf(context), "B's session is over").toBeNull();
  await page.goto(`${vaultUrl}/vault/login`);
  const unlock = page.locator('[data-role="unlock"][data-mode="remembered"]');
  const signIn = page.locator('[data-role="credentials"]');
  await expect(unlock.or(signIn)).toBeVisible({ timeout: 30_000 });
  const shows = await page.locator("[data-role]").evaluateAll((nodes) => nodes.slice(0, 30).map((n) => `${n.getAttribute("data-role")}${n.getAttribute("data-mode") ? `/${n.getAttribute("data-mode")}` : ""}`).join(" "));
  expect(await unlock.isVisible(), `the page offers the remembered account (it shows: ${shows})`).toBe(true);
  await expect(unlock.locator('[data-role="remembered-email"]')).toHaveValue(person.email);

  // A takes the browser back ("Not you") and finds its item, and nothing of B.
  await unlock.locator('[data-role="not-you"]').click();
  await expect(page.locator('[data-role="credentials"] [data-role="email"]')).toBeVisible({ timeout: 20_000 });
  await signInHere(page);
  await openList(page);
  expect(await (await findRows(page, nameA)).count()).toBe(1);
  expect((await sessionOf(context))?.email).toBe(secrets.email);
  await signOutOn(page);
  await context.close();
});

test("two_accounts_in_one_browser_never_see_each_other", async ({ browser }) => {
  test.setTimeout(1_200_000);
  requireAccount();
  const person = second();
  const context = await freshContext(browser);
  const page = await context.newPage();

  // A signs in, writes an item and signs out.
  await signInOn(page);
  const nameA = `A-again-${tag}`;
  await createItem(page, { name: nameA, notes: `notes-of-a-${tag}` });
  await synced(page);
  await openList(page);
  const itemA = await itemIdOf(page, nameA);
  const a = await sessionOf(context);
  await signOutOn(page);

  // B signs in in the same profile: nothing of A in the list or in anything the server sends B's session.
  const recording = recordAnswers(context);
  await signInHere(page, { account: person });
  await openList(page);
  expect(await (await findRows(page, nameA)).count()).toBe(0);
  const nameB = `Only-B-${tag}`;
  await createItem(page, { name: nameB, notes: `notes-of-b-${tag}` });
  await synced(page);
  await openList(page);
  const itemB = await itemIdOf(page, nameB);
  const b = await sessionOf(context);
  expect(b?.email).toBe(person.email);
  const answers = await recording.stop();
  expect(answers.some((x) => x.url.includes("/api/sync/changes")), "B's sync was recorded").toBe(true);
  for (const { url, body } of answers) {
    expect(body, url).not.toContain(itemA);
    expect(body, url).not.toContain(String(a?.accountId));
    expect(body, url).not.toContain(`notes-of-a-${tag}`);
  }

  // What the browser keeps, per account: A's sign-out wiped A's rows, so the local copy holds B's rows only, under B;
  // nothing waits in the outbox; the sync state and the mark of "Activity" are kept per account.
  const rows = await localRows(page);
  expect(rows.filter((r) => r.item === itemA)).toEqual([]);
  expect(rows.filter((r) => r.item === itemB).map((r) => r.account)).toEqual([b?.accountId]);
  expect(rows.every((r) => r.account === b?.accountId)).toBe(true);
  const stores = await readStores(page);
  expect(stores.outbox.count).toBe(0);
  const syncAccounts = /** @type {any[]} */ (stores.sync_state.keys).map((key) => String(key[1]));
  expect(syncAccounts).toContain(b?.accountId);
  expect(syncAccounts.every((account) => account === a?.accountId || account === b?.accountId)).toBe(true);
  const seen = (await settingsLike(page, "activity.seen.")).map(([key]) => key.split(".").at(-1));
  expect(seen).toContain(b?.accountId);
  expect(seen.every((account) => account === a?.accountId || account === b?.accountId)).toBe(true);

  // ---- In another tab of the profile, B signs out and A signs in, while B's tab is still open: the session of the
  // profile is A's now. B's tab never shows A's log as B's, and never stores a mark for B from A's log.
  const markOf = async (/** @type {string | undefined} */ account) => JSON.stringify((await settingsLike(page, "activity.seen.")).find(([key]) => key.endsWith(`.${account}`))?.[1] ?? null);
  const other = await context.newPage();
  await signOutOn(other);
  await signInHere(other);
  expect((await sessionOf(context))?.email).toBe(secrets.email);
  const markB = await markOf(b?.accountId);
  await page.evaluate(() => {
    location.hash = "#/activity";
  });
  // B's tab either stops at a sign-in or an unlock, or its Activity page says the session is not B's: it never lists
  // A's log (which is empty: "Nothing has been logged") as B's.
  const stopped = page.locator('[data-role="unlock"], [data-role="credentials"], [data-role="activity-error"]:not([hidden])');
  await expect(stopped.first()).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-role="activity-empty"]')).toHaveCount(0);
  await expect(page.locator('[data-role="activity-row"]')).toHaveCount(0);
  expect(await markOf(b?.accountId), "B's mark is B's own").toBe(markB);
  await other.close();

  // ---- B is signed out (the other tab did it); A, whose session the profile holds now, unlocks its own vault again in
  // B's old tab: its item is there, B's is not.
  await page.goto(`${vaultUrl}/vault/login`);
  await expect(page.locator('[data-role="signed-in"]').first()).toContainText(secrets.email, { timeout: 30_000 });
  // The sign-in page of a live session that is locked: the master password only.
  const unlock = page.locator('[data-role="credentials"]');
  await expect(unlock.locator('[data-role="password"]')).toBeVisible({ timeout: 30_000 });
  await expect(unlock.locator('[data-role="email"]')).toHaveCount(0);
  await unlock.locator('[data-role="password"]').fill(secrets.password);
  await untilStartAccepted(context, async () => {
    await pace();
    await unlock.locator('[data-role="submit"]').click();
  });
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
  await openList(page);
  expect(await (await findRows(page, nameA)).count()).toBe(1);
  await openList(page);
  expect(await (await findRows(page, nameB)).count()).toBe(0);
  await context.close();
});

test("an_invited_account_adds_a_passkey_and_opens_the_vault_with_it", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "the virtual authenticator is Chromium's");
  test.setTimeout(900_000);
  const person = second();
  const context = await freshContext(browser);
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
    },
  });
  await signInOn(page, { account: person });

  // The passkey is added on the methods page, with the invited account's master password asked again.
  const name = `Invited-${tag}`;
  await page.evaluate(() => {
    location.hash = "#/unlock-methods";
  });
  await expect(page.locator('[data-role="methods-page"]')).toBeVisible({ timeout: 30_000 });
  await pace();
  await page.locator('[data-role="methods-add"]').click();
  const dialog = page.locator('[data-role="reauth-dialog"]');
  await expect(dialog).toBeVisible({ timeout: 30_000 });
  await dialog.locator('[data-role="reauth-password"]').fill(person.password);
  await pace();
  await dialog.locator('[data-role="reauth-confirm"]').click();
  await expect(dialog).toHaveCount(0, { timeout: SLOW });
  const form = page.locator('[data-role="methods-name-form"]');
  await expect(form).toBeVisible({ timeout: 30_000 });
  await form.locator('[data-role="methods-name-input"]').fill(name);
  await form.locator('[data-role="methods-create"]').click();
  await expect(page.locator('[data-role="methods-confirm"]')).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-role="methods-confirm"]').click();
  await expect(page.locator('[data-role="methods-done"]')).toBeVisible({ timeout: SLOW });
  const methods = await (await context.request.get(`${vaultUrl}/api/vault/unlock-methods`)).json();
  expect(/** @type {any[]} */ (methods.methods).filter((m) => m.method_type === 3)).toHaveLength(1);

  // The vault is closed while the session lives; one click on the passkey opens it, with no password sign-in.
  /** @type {string[]} */
  const requests = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) requests.push(`${request.method()} ${url.pathname}`);
  });
  await page.reload();
  await expect(page.locator('[data-role="unlock"][data-mode="session"]')).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-role="passkey-unlock"]').click();
  await expect(page.locator('[data-role="methods-page"]')).toBeVisible({ timeout: SLOW });
  await expect(page.locator('[data-role="methods-row"] [data-role="methods-row-name"]')).toHaveText(name, { timeout: SLOW });
  expect(requests.filter((r) => r.includes("/opaque/")), "no password sign-in ran").toEqual([]);
  expect((await sessionOf(context))?.email).toBe(person.email);

  // The passkey is removed again, so the account is as it was for the next file.
  await page.locator('[data-role="methods-row"] [data-role="methods-remove"]').click();
  await page.locator('[data-role="dialog-confirm"]').click();
  await expect(page.locator('[data-role="methods-done"]:not([hidden]), [data-role="reauth-dialog"]')).toBeVisible({ timeout: SLOW });
  if (await dialog.isVisible()) {
    await dialog.locator('[data-role="reauth-password"]').fill(person.password);
    await pace();
    await untilStartAccepted(context, () => dialog.locator('[data-role="reauth-confirm"]').click(), false);
  }
  await expect(page.locator('[data-role="methods-done"]')).toContainText("was removed", { timeout: SLOW });
  await context.close();
});
