// A second person joins the server with an invitation link. The administrator
// makes the link on the Users page of the admin origin (with a fresh check of the
// password, as the page asks), and the invited person opens it in a browser of
// her own: the page checks the link before it asks for anything, says who made it
// and when it runs out, and then runs the same setup as the first administrator
// (secret key on, the emergency sheet typed back). A used link says so before a
// password is typed, and the token of the link is in no history entry, no stored
// data and no request address of the browser that opened it.
//
// The invitation runs out by the server's wall clock (the test clock of the stack
// does not move it), so its expiry is covered by the unit tests and the server's
// own tests, not here.
//
// The administrator's browser is Chromium in every project (see accounts.mjs): Playwright's WebKit stops with an
// internal "Assertion error" on the redirect from the admin origin to the vault's password check (`/vault/reauth`),
// and the admin page is not what this file tests. The invited person's browser is the project's own.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { invitee, join, makeInvite } from "./accounts.mjs";
import { adminUrl, bodyText, expect, freshContext, outDir, requireAccount, signInHere, signOutOn, test, vaultUrl } from "./support.mjs";

/** The link the first test used, for the second one (a failed test ends the worker, so it is kept in a file). */
const usedFile = `${outDir}/invite-used.json`;

test("an_invited_person_joins_gets_the_sheet_and_signs_in_again", async ({ browser }) => {
  test.setTimeout(600_000);
  requireAccount();
  const { link, token } = await makeInvite();
  const person = invitee("invitee");

  const context = await freshContext(browser);
  const page = await context.newPage();
  const finishes = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/auth/opaque/register/finish")) finishes.push(r.url());
  });
  // A reload after the page has read the token (and taken it out of the address) does not fall back to the first
  // administrator's form: it says the link is lost, with no field to type into, and asks the server nothing.
  await page.goto(link);
  await expect(page.locator('[data-role="setup-form"]')).toBeVisible({ timeout: 20_000 });
  expect(page.url()).not.toContain(token);
  const asked = [];
  page.on("request", (r) => {
    if (/\/api\/auth\/(invite\/check|opaque\/register\/)/.test(r.url())) asked.push(r.url());
  });
  await page.reload();
  await expect(page.locator('[data-role="invite-lost"]')).toContainText("no longer has the invitation link", { timeout: 20_000 });
  await expect(page.locator('[data-role="setup-page"] input')).toHaveCount(0);
  await expect(page.locator('[data-role="setup-form"]')).toHaveCount(0);
  expect(asked).toEqual([]);
  expect(JSON.stringify(await page.evaluate(() => history.state))).not.toContain(token);

  // Opening the link again works, and the sheet comes before the upload: nothing goes before the keys are typed back.
  await join(page, link, person, () => {
    expect(finishes).toEqual([]);
    expect(page.url()).not.toContain(token);
  });
  expect(finishes.length).toBe(1);
  const after = await bodyText(page);
  expect(after).not.toContain(person.recoveryKey);
  expect(after).not.toContain(person.secretKey);
  // A new account from an invitation is not an administrator: no way to the admin pages.
  await expect(page.locator('[data-role="admin"]')).toHaveCount(0);
  writeFileSync(usedFile, JSON.stringify({ link, token }));

  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  const session = await (await context.request.get(`${vaultUrl}/api/auth/session`)).json();
  expect(session.email).toBe(person.email);
  expect(session.admin).not.toBe(true);

  // She signs out and in again with what she chose; the signed-in panel offers no admin pages.
  await signOutOn(page);
  await signInHere(page, { account: person });
  await page.goto(`${vaultUrl}/vault/login`);
  await expect(page.locator('[data-role="signed-in"]')).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('[data-role="admin"]')).toHaveCount(0);
  await context.close();
});

test("a_used_link_says_so_before_any_password_is_typed", async ({ browser }) => {
  test.setTimeout(120_000);
  requireAccount();
  expect(existsSync(usedFile), "the first test of this file made and used a link").toBe(true);
  const { link, token } = JSON.parse(readFileSync(usedFile, "utf8"));
  // The used link, and a well-formed link the server never made, answer alike.
  const unknown = link.replace(token, token.split("").reverse().join(""));
  for (const address of [link, unknown]) {
    const context = await freshContext(browser);
    const page = await context.newPage();
    const starts = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/auth/opaque/register/")) starts.push(r.url());
    });
    await page.goto(address);
    await expect(page.locator('[data-role="invite-dead"]')).toContainText("no longer works", { timeout: 20_000 });
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
    await expect(page.locator('[data-role="setup-form"]')).toHaveCount(0);
    await expect(page.locator('[data-role="invite-retry"]')).toHaveCount(0);
    expect(starts).toEqual([]);
    expect(page.url()).not.toContain(token);
    await context.close();
  }
});

test("the_invite_never_appears_in_history_storage_or_a_request_url", async ({ browser }) => {
  test.setTimeout(600_000);
  requireAccount();
  const { link, token } = await makeInvite();
  const person = invitee("watched");
  const har = test.info().outputPath("invite.har");
  const context = await freshContext(browser, { recordHar: { path: har, content: "embed" } });
  const page = await context.newPage();
  await join(page, link, person);
  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });

  // The address and the history of the tab.
  const history = await page.evaluate(() => ({
    href: location.href,
    referrer: document.referrer,
    length: history.length,
    state: JSON.stringify(history.state),
    // The Navigation API lists the entries of this tab where the browser has it.
    entries: /** @type {any} */ (window).navigation?.entries?.().map((/** @type {any} */ e) => e.url) ?? null,
  }));
  expect(JSON.stringify(history)).not.toContain(token);
  if (history.entries !== null) expect(history.entries.length).toBeGreaterThan(0);

  // What the browser keeps: every IndexedDB database, the web storage of the page, its caches and its cookies.
  const kept = await page.evaluate(async () => {
    const out = [];
    const text = (/** @type {any} */ v) => {
      if (v instanceof Uint8Array || v instanceof ArrayBuffer) return Array.from(new Uint8Array(v), (n) => String.fromCharCode(n)).join("");
      try {
        return JSON.stringify(v, (_k, x) => (x instanceof Uint8Array ? Array.from(x, (n) => String.fromCharCode(n)).join("") : x));
      } catch {
        return String(v);
      }
    };
    for (const info of await indexedDB.databases()) {
      if (!info.name) continue;
      out.push(`db ${info.name}`);
      const db = await new Promise((resolve, reject) => {
        const open = indexedDB.open(/** @type {string} */ (info.name));
        open.onsuccess = () => resolve(open.result);
        open.onerror = () => reject(open.error);
      });
      const names = Array.from(/** @type {IDBDatabase} */ (db).objectStoreNames);
      for (const name of names) {
        const tx = /** @type {IDBDatabase} */ (db).transaction(name, "readonly");
        const [values, keys] = await Promise.all(
          [tx.objectStore(name).getAll(), tx.objectStore(name).getAllKeys()].map(
            (request) => new Promise((resolve, reject) => {
              request.onsuccess = () => resolve(request.result);
              request.onerror = () => reject(request.error);
            }),
          ),
        );
        out.push(`store ${name}`, text(keys), ...(/** @type {any[]} */ (values)).map(text));
      }
      /** @type {IDBDatabase} */ (db).close();
    }
    for (const storage of [localStorage, sessionStorage]) {
      for (let i = 0; i < storage.length; i += 1) {
        const key = storage.key(i) ?? "";
        out.push(key, storage.getItem(key) ?? "");
      }
    }
    if (typeof caches !== "undefined") {
      for (const name of await caches.keys()) {
        out.push(`cache ${name}`);
        for (const request of await (await caches.open(name)).keys()) out.push(request.url);
      }
    }
    return out;
  });
  expect(kept.length).toBeGreaterThan(0);
  for (const value of kept) expect(value).not.toContain(token);
  for (const cookie of [...(await context.cookies(vaultUrl)), ...(await context.cookies(adminUrl))]) {
    expect(`${cookie.name}=${cookie.value}`).not.toContain(token);
  }

  // Every request of the tab, from the HAR: the token is in no address, no header (Referer among them) and no
  // answer; it is only in the bodies of the two requests that need it.
  await context.close();
  const log = JSON.parse(readFileSync(har, "utf8")).log;
  expect(log.entries.length).toBeGreaterThan(0);
  const carriers = new Set();
  for (const entry of log.entries) {
    const { request, response } = entry;
    // What goes over the wire: the address without its fragment (a browser never sends that part; the recorder may
    // still note it for the navigation to the link itself).
    const wire = request.url.split("#")[0];
    expect(wire, wire).not.toContain(token);
    expect(JSON.stringify(request.headers), `headers of ${request.url}`).not.toContain(token);
    expect(JSON.stringify(request.queryString ?? []), request.url).not.toContain(token);
    expect(JSON.stringify(response), `answer to ${request.url}`).not.toContain(token);
    if ((request.postData?.text ?? "").includes(token)) carriers.add(new URL(request.url).pathname);
  }
  expect([...carriers].sort()).toEqual(["/api/auth/invite/check", "/api/auth/opaque/register/start"]);
});
