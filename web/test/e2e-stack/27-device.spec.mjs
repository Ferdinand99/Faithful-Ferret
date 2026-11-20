// Devices with tokens, against the real server: a device client (the extension's part, run in Node, see
// deviceClient.mjs) signs in as its own device with the account's master password and secret key, syncs, holds the event
// stream, and is ended from the web vault: by the page "Devices", and by a change of the master password. A device token
// reaches neither the admin listener nor the hand-over, and the web vault itself never sends a token header. Nothing here
// uses a shortcut of the server: the device and the browsers use the same routes as a person's would.
import {
  createItem, expect, freshContext, itemIdOf, newDevice, noViolations, openList, pace, readStores, remember, rowsNamed, secrets, signInOn, SLOW, synced, test, useAccount, vaultUrl, adminUrl,
} from "./support.mjs";
import { changes, closeDevice, DEVICE_NAME, holdStream, loadCore, signInDevice, sleep } from "./deviceClient.mjs";
import { createProof } from "../../src/auth/dpop.mjs";

noViolations();

/** The account's credentials, for a device. */
const credentials = () => ({ vaultUrl, email: secrets.email, password: secrets.password, secretKey: secrets.secretKey });

/** Waits for the `hello` frame of a held stream. @param {Awaited<ReturnType<typeof holdStream>>} stream */
const hello = (stream) =>
  expect.poll(() => stream.seen.map((frame) => frame.event), { timeout: 20_000, message: "the stream says hello" }).toContain("hello");

/**
 * The page "Devices" of a signed-in browser, with its rows loaded.
 * @param {import("@playwright/test").Page} page
 */
async function openDevices(page) {
  await page.evaluate(() => {
    window.location.hash = "#/devices";
  });
  await expect(page.locator('[data-role="devices-page"]')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[data-role="devices-list"]')).toBeVisible();
}

/** The rows of the page with a device that has tokens, by name. @param {import("@playwright/test").Page} page */
const deviceRows = (page) => page.locator('[data-role="devices-row"][data-kind="device"]', { hasText: DEVICE_NAME });

// ------------------------------------------------------------------------------------------ revoked from the page

test("a_device_signs_in_syncs_and_is_revoked", async ({ browser }) => {
  test.setTimeout(600_000);
  useAccount();
  const { context, page } = await newDevice(browser);
  /** @type {import("./deviceClient.mjs").Device | null} */
  let device = null;
  try {
    // The vault has an item that the browser wrote; the device sees it in the feed (it holds sealed rows, no vault key).
    const name = `Device-sync-${Date.now()}`;
    await createItem(page, { name, username: "device-sync-user" });
    await synced(page);
    await openList(page);
    await expect(rowsNamed(page, name)).toHaveCount(1, { timeout: 30_000 });
    const itemId = await itemIdOf(page, name);

    await pace();
    device = await signInDevice(credentials());
    expect(device.auth.state).toBe("ok");
    const feed = await changes(device);
    expect(feed.latest_seq, "the device reads the feed").toBeGreaterThan(0);
    expect(feed.changes.map((/** @type {{ id: string }} */ c) => c.id), "the device sees the browser's item").toContain(itemId);
    // The device holds the event stream, and the server greets it.
    const stream = await holdStream(device);
    await hello(stream);
    expect(stream.state.ended).toBe(false);

    // The web vault lists the device by the name the extension gave itself, next to this browser, and revokes it.
    await openDevices(page);
    await expect(deviceRows(page)).toHaveCount(1, { timeout: 30_000 });
    await expect(page.locator('[data-role="devices-row"][data-current="true"]')).toHaveCount(1);
    const row = deviceRows(page).first();
    await expect(row.locator('[data-role="devices-current"]')).toHaveCount(0);
    await row.locator('[data-role="devices-revoke"]').click();
    const revokedAt = Date.now();
    await page.locator('[data-role="dialog-confirm"]').click();

    // The stream closes at once, not at the next heartbeat or the end of its life.
    await expect.poll(() => stream.state.ended, { timeout: 20_000, message: "the revoked device's stream is closed" }).toBe(true);
    expect(stream.state.endedAt - revokedAt, "the stream closed within seconds").toBeLessThan(15_000);
    // The renewal is refused with `device_revoked`, and the device then holds no tokens.
    await expect(device.auth.refresh()).rejects.toMatchObject({ status: 401, code: "device_revoked" });
    expect(device.auth.state).toBe("revoked");
    await expect(changes(device)).rejects.toMatchObject({ status: 401, code: "device_revoked" });
    // The page no longer lists it.
    await expect(deviceRows(page)).toHaveCount(0, { timeout: 30_000 });
  } finally {
    if (device) closeDevice(device);
    await context.close();
  }
});

// -------------------------------------------------------------------- ended by a change of the master password

test("a_password_change_in_the_web_vault_ends_the_device", async ({ browser }) => {
  test.setTimeout(900_000);
  useAccount();
  const original = secrets.password;
  const changed = `${original}-changed`;
  const { context, page } = await newDevice(browser);
  /** @type {import("./deviceClient.mjs").Device | null} */
  let device = null;
  /** Changes the master password in the page. @param {string} from @param {string} to */
  const change = async (from, to) => {
    // A page that shows "changed" is left first: the same route again would show it as it is.
    await page.evaluate(() => {
      window.location.hash = "#/account";
    });
    await expect(page.locator('[data-role="account-page"]')).toBeVisible({ timeout: 30_000 });
    await page.evaluate(() => {
      window.location.hash = "#/password";
    });
    await expect(page.locator('[data-role="password-page"]')).toBeVisible({ timeout: 30_000 });
    await page.locator('[data-role="current-password"]').fill(from);
    await page.locator('[data-role="new-password"]').fill(to);
    await page.locator('[data-role="new-password-again"]').fill(to);
    await page.locator('[data-role="password-form"] [data-role="submit"]').click();
    await expect(page.locator('[data-role="password-done"]')).toBeVisible({ timeout: SLOW });
  };
  try {
    await pace();
    device = await signInDevice(credentials());
    const stream = await holdStream(device);
    await hello(stream);
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);

    await change(original, changed);
    secrets.password = changed;
    remember();
    // The stream is closed, and what the device still holds is refused: the access token (it has not run out) and the
    // refresh token both say `device_revoked`.
    await expect.poll(() => stream.state.ended, { timeout: 30_000, message: "the stream of a device ended by a new password" }).toBe(true);
    await expect(changes(device)).rejects.toMatchObject({ status: 401, code: "device_revoked" });
    await expect(device.auth.refresh()).rejects.toMatchObject({ status: 401, code: "device_revoked" });
    expect(device.auth.state).toBe("revoked");
    // This browser stays signed in, and a new device signs in with the new password only.
    await expect(page.locator('[data-role="password-done"]')).toBeVisible();
    await pace();
    const again = await signInDevice(credentials());
    expect((await changes(again)).latest_seq).toBeGreaterThan(0);
    await again.auth.revoke();
    closeDevice(again);
  } finally {
    // Put the account back as the other scenarios expect it.
    if (secrets.password !== original) {
      await change(changed, original).catch(() => {});
      secrets.password = original;
      remember();
    }
    if (device) closeDevice(device);
    await context.close();
  }
});

// -------------------------------------------------------- a token reaches neither the admin listener nor the hand-over

test("a_device_token_reaches_neither_the_admin_listener_nor_the_handoff", async () => {
  test.setTimeout(300_000);
  useAccount();
  await pace();
  const device = await signInDevice(credentials());
  try {
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);
    // The device's own headers for a request to the vault, and the token and key inside them: the test sends them where
    // the client itself never would (it refuses to send a token to another origin).
    await expect(device.api.get(`${adminUrl}/api/sync/changes`)).rejects.toThrow();
    const { Authorization } = await device.auth.prepare("GET", `${vaultUrl}/api/sync/changes`);
    const token = Authorization.replace(/^DPoP /, "");
    /** @param {string} base @param {string} method @param {string} path @param {unknown} [body] @param {Record<string, string>} [extra] */
    const send = async (base, method, path, body, extra = {}) => {
      const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk }, { method, url: `${base}${path}`, accessToken: token, clock: device.clock });
      const response = await device.fetchImpl(`${base}${path}`, {
        method,
        headers: { Authorization: `DPoP ${token}`, DPoP: proof, "Ferret-Protocol": "1", ...extra, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit",
        redirect: "manual",
      });
      const text = await response.text();
      return { status: response.status, text, cookie: response.headers.get("set-cookie") };
    };
    // The admin listener takes no token header at all: a refusal of the request, before any route.
    for (const [method, path] of /** @type {[string, string][]} */ ([
      ["GET", "/"],
      ["GET", "/api/sync/changes"],
      ["GET", "/api/auth/devices"],
      ["POST", "/api/auth/handoff/redeem"],
      ["GET", "/auth/handoff"],
    ])) {
      const answer = await send(adminUrl, method, path, method === "POST" ? { code: "x".repeat(43) } : undefined);
      expect(answer.status, `admin ${method} ${path}`).toBe(400);
      expect(answer.cookie, `admin ${method} ${path} sets no cookie`).toBeNull();
    }
    // The hand-over is a session's: a token mints no code, and starts no session.
    const handoff = { purpose: "login", next: "/", challenge: "A".repeat(43) };
    for (const extra of [{}, { Origin: vaultUrl }]) {
      const minted = await send(vaultUrl, "POST", "/api/auth/handoff", handoff, extra);
      expect(minted.status, `a token mints no hand-over code (${Object.keys(extra).join() || "no Origin"})`).toBe(Object.keys(extra).length === 0 ? 403 : 401);
      expect(minted.text).not.toMatch(/"code"/);
      expect(minted.cookie).toBeNull();
    }
    // The routes a token does not take are closed to it, the sensitive ones included.
    for (const [method, path] of /** @type {[string, string][]} */ ([
      ["GET", "/api/auth/devices"],
      ["POST", "/api/auth/devices/revoke-all"],
      ["GET", "/api/auth/session"],
    ])) {
      const answer = await send(vaultUrl, method, path);
      expect(answer.status, `vault ${method} ${path}`).toBe(401);
      expect(JSON.parse(answer.text).error, `vault ${method} ${path}`).toBe("unauthorized");
      expect(answer.cookie, `vault ${method} ${path} sets no cookie`).toBeNull();
    }
    // Nothing of that ended the device: it still syncs.
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);
  } finally {
    await device.auth.revoke().catch(() => {});
    closeDevice(device);
  }
});

// -------------------------------------------------------------------------- the web vault sends no token header

test("the_web_vault_sends_no_token_headers", async ({ browser }) => {
  test.setTimeout(600_000);
  useAccount();
  const context = await freshContext(browser);
  /** @type {Promise<{ url: string, method: string, headers: Record<string, string> }>[]} */
  const sent = [];
  context.on("request", (request) => {
    if (!request.url().startsWith(vaultUrl) && !request.url().startsWith(adminUrl)) return;
    sent.push(request.allHeaders().catch(() => ({})).then((headers) => ({ url: request.url(), method: request.method(), headers })));
  });
  try {
    const page = await context.newPage();
    await signInOn(page);
    const name = `No-token-${Date.now()}`;
    await createItem(page, { name, username: "no-token-user" });
    await synced(page);
    await openDevices(page);
    await page.evaluate(() => {
      window.location.hash = "#/account";
    });
    await expect(page.locator('[data-role="account-page"]')).toBeVisible({ timeout: 30_000 });
    await page.locator('[data-role="nav-items"]').click();
    await synced(page);
    const requests = await Promise.all(sent);
    const api = requests.filter((r) => new URL(r.url).pathname.startsWith("/api/"));
    expect(api.length, "the page made API requests").toBeGreaterThan(8);
    expect(api.some((r) => r.headers.cookie !== undefined), "the page's requests carry its session cookie").toBe(true);
    for (const request of requests) {
      const names = Object.keys(request.headers).map((n) => n.toLowerCase());
      expect(names, `${request.method} ${request.url}`).not.toContain("authorization");
      expect(names, `${request.method} ${request.url}`).not.toContain("dpop");
    }
    // The browser holds no device key and no tokens: its record store for them is empty.
    const stores = /** @type {any} */ (await readStores(page));
    expect(stores.device_keys?.count ?? 0, "no device key in the web vault's store").toBe(0);
    // And no token or key in the page's storage.
    const storage = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
    expect(storage).not.toMatch(/dpop|access_token|refresh_token/i);
  } finally {
    await context.close();
  }
});

// ----------------------------------------------------------- a stream with the fetch metadata of an extension

test("a_device_stream_with_extension_fetch_metadata_is_accepted", async ({ browser }) => {
  test.setTimeout(600_000);
  useAccount();
  const devices = [];
  try {
    // Chromium sends `none` from an extension's own pages, Firefox another value for a request across origins; the stream
    // of a device is the same either way (it has no ambient credential for a page to ride on).
    for (const [site, origin] of /** @type {[string, string | null][]} */ ([
      ["none", null],
      ["cross-site", "moz-extension://5f0e3a1c-0b5d-4e0d-9f45-2c9a8d7e6b10"],
    ])) {
      await pace();
      const device = await signInDevice({ ...credentials(), site, origin });
      devices.push(device);
      expect((await changes(device)).latest_seq, `the feed with ${site}`).toBeGreaterThan(0);
      const stream = await holdStream(device);
      await hello(stream);
      expect(stream.state.ended, `the stream with ${site} stays open`).toBe(false);
      await sleep(1_000);
      expect(stream.state.ended).toBe(false);
      stream.close();
      await stream.done;
    }

    // The same request with a session cookie is not accepted across sites: the check is kept for a page's stream.
    const { context, page } = await newDevice(browser);
    try {
      await synced(page);
      for (const site of ["cross-site", "same-site", "none"]) {
        const response = await context.request.get(`${vaultUrl}/api/sync/events`, { headers: { "Ferret-Protocol": "1", "Sec-Fetch-Site": site }, timeout: 20_000 });
        expect(response.status(), `a stream with a cookie and Sec-Fetch-Site ${site}`).toBe(403);
      }
    } finally {
      await context.close();
    }
  } finally {
    for (const device of devices) {
      await device.auth.revoke().catch(() => {});
      closeDevice(device);
    }
  }
});

// ------------------------------------------------- contexts of one browser renew at once without reusing a token

test("contexts_of_one_browser_renew_at_once_and_never_reuse_a_token", async ({ browser }) => {
  test.setTimeout(900_000);
  useAccount();
  const core = await loadCore();
  const context = await freshContext(browser);
  const first = await context.newPage();
  await first.goto(`${vaultUrl}/vault/login`);
  // The OPAQUE messages are made here, from the account's password (the page holds the key, the tokens and the proofs, and
  // sends the requests); the master password never goes into the page.
  const job = new core.UnlockJob();
  await first.exposeFunction("opaqueStart", (/** @type {string} */ password, /** @type {string} */ secretKey) => {
    const ke1 = job.login_start(new TextEncoder().encode(password), secretKey === "" ? undefined : secretKey);
    return Buffer.from(ke1).toString("base64url");
  });
  await first.exposeFunction("opaqueFinish", (/** @type {string} */ ke2, /** @type {number} */ profile, /** @type {boolean} */ skBit) => {
    const finished = job.login_finish(Buffer.from(ke2, "base64url"), profile, { kind: "first_use", sk_bit: skBit });
    return Buffer.from(finished.ke3).toString("base64url");
  });
  try {
    await pace();
    // The device signs in from the first page: its key and its refresh token go into this browser's IndexedDB.
    const signedIn = await first.evaluate(
      async ({ email, password, secretKey, name }) => {
        const { openStore } = await import("/app/store/idb.mjs");
        const { generateDeviceKey } = await import("/app/auth/deviceKey.mjs");
        const { createClock, createProof } = await import("/app/auth/dpop.mjs");
        const { createTokenAuth } = await import("/app/auth/tokens.mjs");
        const { createApi } = await import("/app/api.mjs");
        const { b64u } = await import("/app/b64.mjs");
        const origin = window.location.origin;
        const store = await openStore();
        const key = await generateDeviceKey(origin);
        const clock = createClock();
        const auth = createTokenAuth({ serverUrl: origin, store, key, clock });
        const open = createApi({ base: origin });
        const ke1 = await /** @type {any} */ (window).opaqueStart(password, secretKey);
        const start = await open.post("/api/auth/opaque/login/start", { email, ke1, purpose: "login" }, { shape: "login_start_res" });
        const ke3 = await /** @type {any} */ (window).opaqueFinish(start.ke2, start.ksf_profile, secretKey !== "");
        const url = `${origin}/api/auth/opaque/login/finish`;
        let answer = null;
        for (let attempt = 0; attempt < 2 && answer === null; attempt += 1) {
          const proof = await createProof(key, { method: "POST", url, clock });
          const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Ferret-Protocol": "1", DPoP: proof },
            body: JSON.stringify({ login_id: start.login_id, ke3, client: "device", device_name: name, platform: "windows" }),
            credentials: "omit",
            redirect: "error",
          });
          const body = await response.json();
          if (response.status === 200) answer = body;
          else if (response.status === 401 && body.error === "dpop_invalid" && attempt === 0) clock.resync(response.headers.get("date"));
          else throw new Error(`the sign-in answered ${response.status} ${body.error}`);
        }
        await auth.accept(answer);
        void b64u;
        return { deviceId: answer.device_id, state: auth.state };
      },
      { email: secrets.email, password: secrets.password, secretKey: secrets.secretKey, name: `${DEVICE_NAME} (browser)` },
    );
    expect(signedIn.state).toBe("ok");

    // Six pages of the one browser, each as a new background page that holds no access token: each one's first request
    // renews, all at the same moment, over and over. Each round must leave every page with a working request, and the
    // device alive: a renewal that sent a used token would revoke it.
    const pages = [first];
    for (let i = 0; i < 5; i += 1) {
      const page = await context.newPage();
      await page.goto(`${vaultUrl}/vault/login`);
      pages.push(page);
    }
    /** A new token auth in a page, whose first request renews. @param {import("@playwright/test").Page} page */
    const renewOn = (page) =>
          page.evaluate(async () => {
            // A little jitter, so the pages meet the lock and the record at different points of their renewal.
            await new Promise((resolve) => setTimeout(resolve, Math.random() * 200));
            const { openStore } = await import("/app/store/idb.mjs");
            const { loadDeviceKey } = await import("/app/auth/deviceKey.mjs");
            const { createClock } = await import("/app/auth/dpop.mjs");
            const { createTokenAuth } = await import("/app/auth/tokens.mjs");
            const { createApi } = await import("/app/api.mjs");
            const origin = window.location.origin;
            const store = await openStore();
            try {
              const key = await loadDeviceKey(store, origin);
              if (key === null) return { ok: false, error: "no device key" };
              const auth = createTokenAuth({ serverUrl: origin, store, key, clock: createClock() });
              const api = createApi({ base: origin, auth });
              // The first request has no access token: it renews, in step with the other pages.
              const feed = await api.get("/api/sync/changes?since=0&limit=1");
              return { ok: true, latest: feed.latest_seq, state: auth.state };
            } catch (error) {
              return { ok: false, error: `${/** @type {any} */ (error)?.status ?? ""} ${/** @type {any} */ (error)?.code ?? String(error)}` };
            } finally {
              store.close();
            }
          });
    const round = () => Promise.all(pages.map(renewOn));
    for (let n = 1; n <= 20; n += 1) {
      const results = await round();
      expect(results, `round ${n}: every page renewed and synced`).toEqual(results.map(() => expect.objectContaining({ ok: true, state: "ok" })));
    }

    // A page whose renewal is slow on the network (the request is held for two and a half seconds) while the others renew twice
    // over: its record was read before two rotations. It must not send a token that two others have used since, which would
    // revoke the device; the lock makes the others wait for it.
    const slow = pages[1];
    const others = pages.filter((page) => page !== slow);
    await slow.route("**/api/auth/token/refresh", async (route) => {
      await sleep(2_500);
      await route.continue();
    });
    const held = renewOn(slow);
    await sleep(700);
    for (let n = 1; n <= 2; n += 1) {
      const results = await Promise.all(others.map(renewOn));
      expect(results, `while one page is slow, round ${n}`).toEqual(results.map(() => expect.objectContaining({ ok: true, state: "ok" })));
    }
    expect(await held, "the slow page").toEqual(expect.objectContaining({ ok: true, state: "ok" }));
    await slow.unroute("**/api/auth/token/refresh");
    const after = await round();
    expect(after, "every page renews after it").toEqual(after.map(() => expect.objectContaining({ ok: true, state: "ok" })));

    // The device is still its own: the last renewal worked, and signing it out is accepted.
    const out = await first.evaluate(async () => {
      const { openStore } = await import("/app/store/idb.mjs");
      const { loadDeviceKey } = await import("/app/auth/deviceKey.mjs");
      const { createClock } = await import("/app/auth/dpop.mjs");
      const { createTokenAuth } = await import("/app/auth/tokens.mjs");
      const store = await openStore();
      const key = await loadDeviceKey(store, window.location.origin);
      const auth = createTokenAuth({ serverUrl: window.location.origin, store, key, clock: createClock() });
      await auth.refresh();
      await auth.revoke();
      store.close();
      return auth.state;
    });
    expect(out).toBe("signed_out");
  } finally {
    job.free?.();
    await context.close();
  }
});

// ------------------------------------------------------------ the clock follows a refusal of a proof, and only that

test("a_device_takes_the_servers_time_from_a_refused_proof_once_and_from_nothing_else", async ({ browser }) => {
  test.setTimeout(600_000);
  useAccount();
  const { context, page } = await newDevice(browser);
  await pace();
  // The device signs in with a right clock: no proof is refused so far.
  const device = await signInDevice(credentials());
  try {
    const refused = () => device.answers.filter((answer) => answer.code === "dpop_invalid").length;
    expect(refused(), "no refused proof with a right clock").toBe(0);
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);

    // Its clock then runs ten minutes ahead. The next request's proof is outside the server's window: the answer is
    // `dpop_invalid`, the client takes the server's time from that answer and sends the request once more, and it works.
    device.skew.ms = 10 * 60_000;
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);
    expect(refused(), "one refused proof, then the retry with the server's time").toBe(1);
    // Everything after it carries the server's time: no more refusals, for requests and for the renewal.
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);
    await device.auth.refresh();
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);
    expect(refused(), "no further refused proof").toBe(1);

    // A clock that no answer can set right (each reading is ten minutes later than the last): the request is refused,
    // the time is taken once, the retry is refused too, and that is the end of it (no loop).
    device.skew.runaway = 10 * 60_000;
    await expect(changes(device)).rejects.toMatchObject({ status: 401, code: "dpop_invalid" });
    expect(refused(), "exactly two refused proofs for one request").toBe(3);
    // The clock is put right again by the same rule on the next request.
    device.skew.runaway = 0;
    device.skew.ms = 0;
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);

    // Only a refused proof sets the clock: another refusal of the server (a revoked device) does not. The device's clock
    // is 30 seconds ahead (inside the window, so every proof is accepted), the device is revoked from the page, and the
    // refusal `device_revoked` carries the server's `Date` all the same: the clock stays 30 seconds ahead.
    device.skew.ms = 30_000;
    expect((await changes(device)).latest_seq).toBeGreaterThan(0);
    const before = refused();
    await openDevices(page);
    const row = deviceRows(page).first();
    await expect(deviceRows(page)).toHaveCount(1, { timeout: 30_000 });
    await row.locator('[data-role="devices-revoke"]').click();
    await page.locator('[data-role="dialog-confirm"]').click();
    await expect(deviceRows(page)).toHaveCount(0, { timeout: 30_000 });
    await expect(changes(device)).rejects.toMatchObject({ status: 401, code: "device_revoked" });
    const ahead = device.clock.nowSeconds() - Math.floor(Date.now() / 1000);
    expect(ahead, "the clock was not set by a refusal that is not dpop_invalid").toBeGreaterThanOrEqual(28);
    expect(refused(), "and no proof was refused on the way").toBe(before);
  } finally {
    closeDevice(device);
    await context.close();
  }
});
