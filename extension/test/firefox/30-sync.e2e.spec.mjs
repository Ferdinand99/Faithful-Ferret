// The sync of the extension against the end-to-end stack (run by
// the e2e mode of the Firefox runner): a real server, the real core, the shared sync
// engine in the extension's background, and a real Firefox in which the web
// vault and the extension run side by side.
//
// - An item made in the web vault reaches the extension within two seconds of
//   the server having it: the server's event stream (opened with the device's
//   token and a proof) tells the extension, which reads the feed and stores the
//   row.
// - The malicious server of the stack replays an old version of an item
//   (`replay_old`): the extension shows the warning the web vault shows for it,
//   with the same text, and keeps the version it has.
//
// The account is the one the sign-in specs made (or the first test here makes
// it). The stack must have been started by `e2e-up`.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, extensionSignIn, helpers, start, webVaultAccount } from "./e2e.mjs";
import { channels, openBridge, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/** How long after the server has an item the extension must have it. */
const WITHIN_MS = 2_000;
/** How long a warning may take: the edit, the hint, a read of the feed and the popup's next look. */
const WARNED = 60_000;

const here = dirname(fileURLToPath(import.meta.url));

/** The web vault's own text of a sync warning (its English catalog, from the tree the stack was built from). @param {string} code */
function webVaultWarning(code) {
  const catalog = JSON.parse(readFileSync(join(here, "..", "..", "..", "web", "src", "locales", "en", "sync.json"), "utf8"));
  const text = catalog[`sync.warning.${code}`];
  assert.equal(typeof text, "string", `the web vault has a text for ${code}`);
  return text;
}

/**
 * Switches the malicious server of the stack to a mode (web/test/e2e-stack/evil/modes.mjs).
 * @param {string} mode @param {Record<string, unknown>} [params]
 */
async function evil(mode, params = {}) {
  const base = process.env.FERRET_E2E_EVIL_URL ?? "";
  assert.ok(base, "FERRET_E2E_EVIL_URL is not set (run the specs in the e2e mode of the Firefox runner)");
  const response = await fetch(`${base}/mode`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...params, mode }) });
  assert.equal(response.ok, true, `the malicious server answered ${response.status} for ${mode}: ${await response.text()}`);
}

/**
 * The rows the extension has stored (ciphertext; the ids and revisions are all that is read), from the test bridge,
 * a page of the extension's origin that the current tab shows.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<Array<{ itemId: string, rev: number }>>}
 */
function extensionRows(session) {
  return session.content(() => new Promise((resolve, reject) => {
    const open = indexedDB.open("ferret");
    // Never make the database here: the background makes it with its own version and stores.
    open.onupgradeneeded = () => open.transaction?.abort();
    open.onerror = () => (open.error?.name === "AbortError" ? resolve([]) : reject(open.error));
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("rows")) {
        db.close();
        resolve([]);
        return;
      }
      const all = db.transaction(["rows"], "readonly").objectStore("rows").getAll();
      all.onerror = () => reject(all.error);
      all.onsuccess = () => {
        resolve(all.result.map((row) => ({ itemId: row.itemId, rev: row.rev })));
        db.close();
      };
    };
  }));
}

/**
 * Whether the server's feed has the item at `rev` or above, read in the web vault's tab with its session.
 * @param {import("./driver.mjs").Session} session @param {string} id @param {number} rev
 */
function serverHas(session, id, rev) {
  return session.content(async (/** @type {string} */ wanted, /** @type {number} */ atLeast) => {
    let since = 0;
    for (let page = 0; page < 50; page += 1) {
      const response = await fetch(`/api/sync/changes?since=${since}&limit=500`, { headers: { "Ferret-Protocol": "1" }, cache: "no-store" });
      if (!response.ok) return false;
      const feed = await response.json();
      if (feed.changes.some((/** @type {any} */ c) => c.id === wanted && c.rev >= atLeast)) return true;
      if (!feed.has_more || feed.changes.length === 0) return false;
      since = feed.changes[feed.changes.length - 1].seq;
    }
    return false;
  }, id, rev);
}

/**
 * The web vault (its tab) and the extension (another tab, signed in at the same account), with the extension's
 * sync running and its event stream open.
 * @param {string} channel
 */
async function sideBySide(channel) {
  const session = await start(channel);
  const account = await webVaultAccount(session, channel);
  const vaultTab = await session.windowHandle();
  const extensionTab = await session.newTab();
  await session.switchTo(extensionTab);
  const signedIn = await extensionSignIn(session, account);
  assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
  const page = helpers(session);
  // The popup (in the tab) shows the sync once it has read the feed, and whether the stream is open.
  await session.navigate(POPUP_URL);
  await page.ready();
  await page.waitVisible('[data-role="sync"][data-state="idle"][data-live="live"]', SLOW);
  await openBridge(session);
  return { session, page, vaultTab, extensionTab };
}

/**
 * Makes an item in the web vault (its tab must be shown) and returns its id.
 * @param {ReturnType<typeof helpers>} page @param {import("./driver.mjs").Session} session @param {string} name
 */
async function webVaultCreate(page, session, name) {
  await page.click('[data-role="nav-new"]');
  await page.waitVisible('[data-role="edit-form"]');
  await page.type('[data-role="name"]', name);
  await page.type('[data-role="username"]', "sync-user");
  await page.click('[data-role="save"]');
  await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the saved item");
  const id = /#\/items\/([0-9a-f]{32})/.exec(await session.currentUrl())?.[1];
  assert.ok(id, "the item page names the item");
  return id;
}

/**
 * Renames the item that the web vault shows.
 * @param {ReturnType<typeof helpers>} page @param {import("./driver.mjs").Session} session @param {string} name
 */
async function webVaultRename(page, session, name) {
  await page.click('[data-role="edit"]');
  await page.waitVisible('[data-role="edit-form"]');
  await page.paste('[data-role="name"]', name);
  await page.click('[data-role="save"]');
  await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the renamed item");
}

test("an_item_created_in_the_web_vault_shows_in_the_extension_within_two_seconds", async () => {
  for (const channel of channels()) {
    const { session, page, vaultTab, extensionTab } = await sideBySide(channel);
    try {
      await session.switchTo(vaultTab);
      const id = await webVaultCreate(page, session, `Ext-sync-${randomBytes(4).toString("hex")}`);
      // From the moment the server has it (the web vault's own feed shows it).
      await session.waitFor(() => serverHas(session, id, 1), 30_000, "the server has the item");
      const serverAt = Date.now();
      await session.switchTo(extensionTab);
      await session.waitFor(async () => (await extensionRows(session)).some((row) => row.itemId === id), 10_000, "the extension has the item");
      const took = Date.now() - serverAt;
      assert.ok(took <= WITHIN_MS, `${channel}: the extension had the item ${took} ms after the server (at most ${WITHIN_MS})`);
    } finally {
      await session.quit();
    }
  }
});

test("an_evil_server_mode_gives_the_same_warning_as_in_the_web_vault", async () => {
  for (const channel of channels()) {
    const { session, page, vaultTab, extensionTab } = await sideBySide(channel);
    try {
      await session.switchTo(vaultTab);
      const name = `Ext-replay-${randomBytes(4).toString("hex")}`;
      const id = await webVaultCreate(page, session, name);
      await webVaultRename(page, session, `${name}-2`);
      await session.waitFor(() => serverHas(session, id, 2), 30_000, "the server has the second version");
      await session.switchTo(extensionTab);
      await session.waitFor(async () => (await extensionRows(session)).some((row) => row.itemId === id && row.rev === 2), 30_000, "the extension has the second version");

      // The server now sends the first version it held of the item whenever the item changes.
      await evil("replay_old", { id });
      try {
        await session.switchTo(vaultTab);
        await webVaultRename(page, session, `${name}-3`);
        await session.switchTo(extensionTab);
        await session.navigate(POPUP_URL);
        await page.ready();
        const warning = '[data-role="sync-warning"][data-code="rev_lower_than_local"]';
        await page.waitVisible(warning, WARNED);
        assert.equal(await page.text(warning), webVaultWarning("rev_lower_than_local"), `${channel}: the web vault's own words`);
        // The warning stops nothing, and the extension keeps the version it had.
        assert.equal(await page.visible('[data-role="sync-stop"]'), false, channel);
        await openBridge(session);
        const kept = (await extensionRows(session)).find((row) => row.itemId === id);
        assert.ok(kept && kept.rev >= 2, `${channel}: the extension kept a version it had (${JSON.stringify(kept)})`);
      } finally {
        await evil("honest");
      }
    } finally {
      await session.quit();
    }
  }
});
