// The server fails closed on a connection that is not https
// (and does not believe a forwarded header from a peer it does not trust), and
// signing out ends the session at the server, not only in the browser.
import { request as playwrightRequest } from "@playwright/test";
import { expect, freshContext, requireAccount, signInOn, signOutOn, test, vaultUrl } from "./support.mjs";

// The app container on the stack's network, reached without the TLS terminator.
const directVault = "http://ferret-e2e-app:3041";
const directAdmin = "http://ferret-e2e-app:3040";

const registerStart = {
  setup_token: "not-the-setup-token",
  email: "transport@e2e.example.test",
  request: "A".repeat(43),
};
const headers = { "ferret-protocol": "1", origin: vaultUrl, "content-type": "application/json" };

test("transport_fails_closed", async () => {
  const direct = await playwrightRequest.newContext();
  try {
    // Plain http straight to the port: refused before anything else, with the same plain answer.
    const plain = await direct.post(`${directVault}/api/auth/opaque/register/start`, { headers, data: registerStart });
    expect(plain.status()).toBe(400);
    expect(await plain.json()).toEqual({ error: "insecure_transport" });

    // A forwarded header from a peer the server does not trust is ignored.
    for (const forged of [
      { "x-forwarded-proto": "https" },
      { "x-forwarded-proto": "https", "x-forwarded-for": "10.9.9.9", forwarded: "proto=https" },
    ]) {
      const response = await direct.post(`${directVault}/api/auth/opaque/register/start`, { headers: { ...headers, ...forged }, data: registerStart });
      expect(response.status(), JSON.stringify(forged)).toBe(400);
      expect(await response.json()).toEqual({ error: "insecure_transport" });
    }

    // The sign-in start is refused the same way.
    const login = await direct.post(`${directVault}/api/auth/opaque/login/start`, {
      headers: { ...headers, "x-forwarded-proto": "https" },
      data: { email: "transport@e2e.example.test", request: "A".repeat(43) },
    });
    expect(login.status()).toBe(400);
    expect(await login.json()).toEqual({ error: "insecure_transport" });

    // Through the TLS terminator, which is trusted, the same request passes the transport check
    // and is refused for what it is (a wrong setup token).
    const secure = await direct.post(`${vaultUrl}/api/auth/opaque/register/start`, { headers, data: registerStart });
    expect(secure.status()).toBe(403);

    // The admin port has no session for a plain request either.
    const admin = await direct.get(`${directAdmin}/api/auth/session`);
    expect(admin.status()).toBe(401);
  } finally {
    await direct.dispose();
  }
});

test("logout_revokes_the_session_server_side", async ({ browser }) => {
  test.setTimeout(300_000);
  requireAccount();
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);

  // A copy of the cookies, as an attacker who had read them would hold them.
  const cookies = await context.cookies(vaultUrl);
  expect(cookies.map((c) => c.name)).toContain("__Host-ferret_sid");
  const header = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
  const copy = await playwrightRequest.newContext({ extraHTTPHeaders: { cookie: header } });
  try {
    expect((await copy.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);
    expect((await copy.get(`${vaultUrl}/api/sync/changes?since=0`)).status()).toBe(200);

    await signOutOn(page);

    // The browser lost its cookies, and the copy is dead at the server.
    expect((await context.cookies(vaultUrl)).find((c) => c.name === "__Host-ferret_sid")).toBeUndefined();
    expect((await copy.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);
    expect((await copy.get(`${vaultUrl}/api/sync/changes?since=0`)).status()).toBe(401);
    expect((await copy.get(`${vaultUrl}/api/vault/unlock-methods`)).status()).toBe(401);
  } finally {
    await copy.dispose();
  }
  await context.close();
});
