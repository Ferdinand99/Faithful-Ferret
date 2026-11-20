// A backup of the server, the data wiped, the backup put back by the server's own command, with the browsers of the account open the
// whole time. Everything that was in the backup is back and the browsers say that the server was restored; a session and a one-time
// code from before the restore are dead after it; an import window that was open during a restore writes nothing, and a new one
// opens on the restored server. The host script (scripts/lanbox-ferret-e2e-gate.sh m3) makes the backup and puts it back.
import { request } from "@playwright/test";
import { API_HEADERS, bulkJson, createItem, expect, feedOf, hostStep, leave, listNames, memory, newDevice, noViolations, openImport, chooseImportFile, openList, remember, requireAccount, rowsNamed, runChosenImport, secrets, signInHere, startHeldImport, synced, syncBanner, test, vaultUrl } from "./support.mjs";
import { fileURLToPath } from "node:url";

test.describe.configure({ mode: "serial" });
noViolations();

test.beforeAll(() => {
  requireAccount();
});

const WARNED = 150_000;

/** What the first test leaves for the ones after it. */
const shared = { set: "", sessionCookie: "", oldCode: "" };

/**
 * A call to the vault's API with the cookies of a session that was made before the restore (no browser).
 * @param {string} path @param {{ cookie?: string, method?: "GET" | "POST", data?: unknown }} [options]
 */
async function raw(path, { cookie, method = "GET", data } = {}) {
  const api = await request.newContext({ ignoreHTTPSErrors: true });
  try {
    const headers = { ...API_HEADERS, ...(cookie ? { Cookie: cookie } : {}) };
    const response = method === "GET" ? await api.get(`${vaultUrl}${path}`, { headers }) : await api.post(`${vaultUrl}${path}`, { headers, data });
    return { status: response.status(), text: await response.text() };
  } finally {
    await api.dispose();
  }
}

/**
 * Opens the page that the restored-server banner leads to.
 * @param {import("@playwright/test").Page} page
 */
async function openRestoredPage(page) {
  await syncBanner(page, "server_restored").locator('[data-action="see_what_happened"]').click();
  await expect(page.locator('[data-role="restored"]')).toBeVisible();
  await expect(page.locator('[data-role="restored-preview"]')).toBeVisible({ timeout: 60_000 });
}

/**
 * Accepts the older state on the page that shows it.
 * @param {import("@playwright/test").Page} page
 */
async function accept(page) {
  await page.locator('[data-role="restored-word"]').fill("accept");
  await page.locator('[data-role="restored-accept"]').click();
  await expect(page.locator('[data-role="restored-done"]')).toBeVisible({ timeout: 120_000 });
}

test("backup_wipe_restore_and_every_item_is_back", async ({ browser }) => {
  test.setTimeout(2_400_000);
  const tag = Date.now().toString(36);
  const a = await newDevice(browser);
  const b = await newDevice(browser);
  const c = await newDevice(browser);
  const kept = [`Backup-one-${tag}`, `Backup-two-${tag}`, `Backup-three-${tag}`];
  for (const name of kept) await createItem(a.page, { name, username: "in-the-backup", password: `Pw-${tag}-${name}!` });
  await synced(a.page);
  await openList(b.page);
  for (const name of kept) await expect(rowsNamed(b.page, name)).toHaveCount(1, { timeout: 60_000 });
  await synced(b.page);

  // What the second test looks at afterwards: a session cookie that works now, and a one-time code that is pending now.
  shared.sessionCookie = (await c.context.cookies(vaultUrl)).map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
  expect((await raw("/api/auth/session", { cookie: shared.sessionCookie })).status, "the session works before the restore").toBe(200);
  shared.oldCode = await hostStep(`code-${secrets.email}`);
  expect(shared.oldCode).toMatch(/\S{6,}/);

  const epochBefore = (await feedOf(a.context)).restore_epoch;
  // The backup: the host stops the app, makes a set with the server's own command and starts the app again.
  shared.set = await hostStep("backup");
  expect(shared.set, "the host says which set it made").toMatch(/^[A-Za-z0-9._-]+$/);

  // After the backup: an item that the backup does not hold.
  const lost = `After-backup-${tag}`;
  await createItem(a.page, { name: lost, username: "after-the-backup" });
  await synced(a.page, 90_000);

  // The data is wiped and the set is put back (the host stops the app, empties the data, restores, starts the app).
  await hostStep(`restore-backup-${shared.set}`);

  // Every session of the account is over, in all three browsers.
  for (const device of [a, b, c]) expect((await device.page.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);

  // Both browsers have to sign in again (they know the account and keep its secret key): the password is enough.
  for (const device of [a, b]) {
    await device.page.goto(`${vaultUrl}/vault/login`);
    await signInHere(device.page);
  }
  // The server says it was restored (its restore number is higher), and the browsers say so.
  const restored = await feedOf(a.context);
  expect(restored.restore_epoch, "the restore number went up").toBeGreaterThan(epochBefore);
  await expect(syncBanner(a.page, "server_restored")).toBeVisible({ timeout: WARNED });
  await expect(syncBanner(b.page, "server_restored")).toBeVisible({ timeout: WARNED });
  await expect(syncBanner(a.page, "server_restored")).toContainText(/restored/i);

  // Everything that was in the backup is there, in both browsers (and the server holds it: a new browser sees it too).
  await openList(a.page);
  await openList(b.page);
  for (const name of kept) {
    await expect(rowsNamed(a.page, name)).toHaveCount(1);
    await expect(rowsNamed(b.page, name)).toHaveCount(1);
  }
  const server = await newDevice(browser);
  for (const name of kept) await expect(rowsNamed(server.page, name), "the restored server holds the item").toHaveCount(1, { timeout: 90_000 });
  await expect(rowsNamed(server.page, lost), "what came after the backup is not on the restored server").toHaveCount(0);
  const names = await listNames(server.page);
  expect(names.filter((n) => kept.includes(n)).length).toBe(kept.length);

  // The first browser says what it knows that the server lost, and puts it back; a new browser then sees that too.
  await openRestoredPage(a.page);
  await expect(a.page.locator('[data-role="preview-reupload"]')).toHaveText("Your newer changes that will be sent to the server: 1");
  await accept(a.page);
  await synced(a.page, 90_000);
  await server.page.reload();
  await expect(server.page.locator('[data-role="unlock"]')).toBeVisible({ timeout: 30_000 });
  await server.context.close();
  const again = await newDevice(browser);
  await expect(rowsNamed(again.page, lost), "the browser put the item back").toHaveCount(1, { timeout: 90_000 });
  expect(await listNames(again.page)).toContain(lost);
  for (const device of [a, b, c, again]) await device.context.close();
  remember();
  leave("m3-25-a", { set: shared.set });
});

test("a_session_and_a_code_from_before_the_restore_are_dead_after_it", async () => {
  test.setTimeout(300_000);
  expect(shared.sessionCookie, "the first test of this file ran").not.toBe("");
  // The session cookie that worked before the restore does not work now, and the code that was pending is not good.
  expect((await raw("/api/auth/session", { cookie: shared.sessionCookie })).status).toBe(401);
  expect([401, 403]).toContain((await raw("/api/sync/changes?since=0&limit=1", { cookie: shared.sessionCookie })).status);
  const redeemed = await raw("/api/auth/redeem", { method: "POST", data: { email: secrets.email, code: shared.oldCode } });
  expect(redeemed.status, "a code from before the restore is refused").toBe(401);
  // The same refusal as for a code that never existed: nothing tells the two apart.
  const never = await raw("/api/auth/redeem", { method: "POST", data: { email: secrets.email, code: "never-was-a-code" } });
  expect(never.status).toBe(401);
  expect(never.text).toBe(redeemed.text);
  leave("m3-25-b", { done: true });
});

test("a_restore_while_an_import_window_is_open_writes_nothing_from_the_old_window", async ({ browser }) => {
  test.setTimeout(2_400_000);
  expect(shared.set, "the first test of this file ran").not.toBe("");
  const tag = Date.now().toString(36);
  const importing = await newDevice(browser);
  await synced(importing.page);
  const witness = await newDevice(browser);
  await synced(witness.page);
  const held = await startHeldImport(importing.page, bulkJson(`restore-${tag}`, 200));

  // The server is restored while the batches wait: the windows are in memory and go with the restart.
  await hostStep(`restore-backup-${shared.set}`);
  expect((await importing.page.request.get(`${vaultUrl}/api/auth/session`)).status(), "the session of the import is over").toBe(401);
  expect((await witness.page.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(401);

  // The batches go out now; the server refuses them. A fresh browser (the only way in is to sign in) sees none of the import.
  held.release();
  await importing.page.waitForTimeout(10_000);
  const fresh = await newDevice(browser);
  await synced(fresh.page, 90_000);
  const feed = await feedOf(fresh.context);
  const seqAfterRestore = feed.latest_seq;
  await fresh.page.waitForTimeout(5_000);
  expect((await feedOf(fresh.context)).latest_seq, "the old window wrote nothing on the restored server").toBe(seqAfterRestore);
  expect((await listNames(fresh.page)).filter((n) => n.startsWith(`Bulk-restore-${tag}`)), "no item of the dead import is there").toEqual([]);

  // A new window opens on the restored server (the page asks for the password again) and an import goes through.
  const before = (await memory(fresh.page)).items;
  await openImport(fresh.page);
  await chooseImportFile(fresh.page, fileURLToPath(new URL("../fixtures/import/bitwarden/small.json", import.meta.url)));
  await runChosenImport(fresh.page, 2);
  await synced(fresh.page, 90_000);
  expect((await memory(fresh.page)).items).toBe(before + 2);
  for (const device of [importing, witness, fresh]) await device.context.close();
  leave("m3-25", { done: true });
});
