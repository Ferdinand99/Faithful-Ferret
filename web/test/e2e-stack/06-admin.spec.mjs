// The hand-over of a session from the vault origin to the admin
// origin. The password is typed on the vault origin and nowhere on the admin
// origin; the admin origin loads no WASM; the two origins do not share cookies;
// and a code that was made for another browser does not change an admin session.
import { adminUrl, expect, freshContext, recordWorkers, requireAccount, signInHere, signInOn, SLOW, test, vaultUrl, workers } from "./support.mjs";

/** @param {import("@playwright/test").BrowserContext} context @param {string} origin */
const cookiesOf = (context, origin) => context.cookies(origin);

test("admin_handoff_gives_the_admin_origin_a_session", async ({ browser }) => {
  test.setTimeout(500_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await recordWorkers(page);
  const adminRequests = [];
  page.on("request", (r) => {
    if (r.url().startsWith(adminUrl)) adminRequests.push(r.url());
  });

  // A page of the admin origin, opened by a browser with no session, leads to the vault's sign-in
  // (with a challenge for the hand-over).
  await page.goto(`${adminUrl}/settings/general`);
  await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
  expect(new URL(page.url()).origin).toBe(vaultUrl);
  expect(page.url()).not.toContain("challenge=");
  // The admin origin set a verifier cookie and nothing that is a session.
  const early = await cookiesOf(context, adminUrl);
  expect(early.map((c) => c.name)).toContain("__Host-ferret_handoff");
  expect(early.map((c) => c.name)).not.toContain("__Host-ferret_sid");
  expect(await context.request.get(`${adminUrl}/api/auth/session`, { maxRedirects: 0 }).then((r) => r.status())).toBe(401);

  // Signing in on the vault origin hands the session over; the admin pages open.
  await signInHere(page, { expectList: false });
  await page.waitForURL((url) => url.origin === adminUrl && !url.pathname.startsWith("/auth/handoff"), { timeout: SLOW });
  expect(page.url()).not.toContain("code=");
  expect(new URL(page.url()).pathname).not.toMatch(/login/);

  // The admin origin takes no master password: the only password field it has is the kit's one for
  // the mail server on the settings page; it loads no WASM and starts no worker.
  expect(new URL(page.url()).pathname).toBe("/settings/general");
  const fields = await page.locator('input[type="password"]').evaluateAll((list) => list.map((i) => i.getAttribute("name") ?? i.id));
  for (const name of fields) expect(name, "a password field on the admin origin").toMatch(/smtp/i);
  expect(adminRequests.filter((u) => /\.wasm(\?|$)/.test(u))).toEqual([]);
  expect(adminRequests.filter((u) => /pkg-web|\/app\//.test(u))).toEqual([]);
  expect(await workers(page)).toEqual([]);

  // The admin session is real and belongs to the admin origin.
  const session = await context.request.get(`${adminUrl}/api/auth/session`);
  expect(session.status()).toBe(200);
  expect((await session.json()).origin).toBe("admin");
  expect((await context.request.get(`${adminUrl}/settings/general`, { maxRedirects: 0 })).status()).toBe(200);

  // The cookies of the two origins are not shared.
  const adminCookies = await cookiesOf(context, adminUrl);
  const vaultCookies = await cookiesOf(context, vaultUrl);
  const sid = (list) => list.find((c) => c.name === "__Host-ferret_sid");
  expect(sid(adminCookies)).toBeTruthy();
  expect(sid(vaultCookies)).toBeTruthy();
  expect(sid(adminCookies).value).not.toBe(sid(vaultCookies).value);
  for (const c of [...adminCookies, ...vaultCookies]) {
    expect(c.name.startsWith("__Host-"), c.name).toBe(true);
    expect(c.secure, c.name).toBe(true);
  }
  expect((await context.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);

  // The button "Go to the admin pages" of the vault lands on a working admin page.
  const vaultPage = await context.newPage();
  await vaultPage.goto(`${vaultUrl}/vault/login`);
  await vaultPage.locator('[data-role="admin"]').click();
  await vaultPage.locator('[data-role="continue-admin"]').click();
  await vaultPage.waitForURL((url) => url.origin === adminUrl && !url.pathname.startsWith("/auth/handoff"), { timeout: SLOW });
  expect(new URL(vaultPage.url()).pathname).toBe("/settings/general");
  expect(await vaultPage.locator("main").count()).toBeGreaterThan(0);
  expect(await vaultPage.locator("text=Not Found").count()).toBe(0);
  await vaultPage.close();

  // A code that another browser's hand-over made does nothing to this admin session. The code is
  // made for the verifier of the stranger's browser; this browser has a verifier of its own.
  const stranger = await freshContext(browser);
  const other = await stranger.newPage();
  await signInOn(other);
  /** A code for the hand-over that the stranger's browser started. */
  const mintForStranger = async () => {
    const begin = await stranger.request.get(`${adminUrl}/auth/handoff/begin?next=/`, { maxRedirects: 0 });
    expect(begin.status()).toBe(302);
    const challenge = new URL(begin.headers().location).searchParams.get("challenge");
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const code = await other.evaluate(async (challenge) => {
      const response = await fetch("/api/auth/handoff", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "Ferret-Protocol": "1" },
        body: JSON.stringify({ purpose: "login", next: "/", challenge }),
      });
      return (await response.json()).code;
    }, challenge);
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);
    return code;
  };
  const code = await mintForStranger();

  // This browser starts a hand-over of its own (so it holds a verifier that does not match), then follows the lure.
  expect((await context.request.get(`${adminUrl}/auth/handoff/begin?next=/`, { maxRedirects: 0 })).status()).toBe(302);
  expect((await cookiesOf(context, adminUrl)).map((c) => c.name)).toContain("__Host-ferret_handoff");
  const before = await cookiesOf(context, adminUrl);
  const link = await context.newPage();
  await link.goto(`${adminUrl}/auth/handoff#code=${code}`);
  await expect(link.locator("#handoff-status")).toContainText("did not work", { timeout: 20_000 });
  const after = await cookiesOf(context, adminUrl);
  expect(sid(after).value).toBe(sid(before).value);
  expect(after.find((c) => c.name === "__Host-ferret_session")?.value).toBe(before.find((c) => c.name === "__Host-ferret_session")?.value);
  const still = await context.request.get(`${adminUrl}/api/auth/session`);
  expect(still.status()).toBe(200);
  expect(await still.json()).toEqual(await session.json());

  // A browser with no verifier at all gets no session from a fresh code either.
  const blank = await freshContext(browser);
  const nothing = await blank.newPage();
  await nothing.goto(`${adminUrl}/auth/handoff#code=${await mintForStranger()}`);
  await expect(nothing.locator("#handoff-status")).toContainText("did not work", { timeout: 20_000 });
  expect((await blank.request.get(`${adminUrl}/api/auth/session`)).status()).toBe(401);

  await blank.close();
  await stranger.close();
  await context.close();
});
