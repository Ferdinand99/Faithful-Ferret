// The write side of the extension's sync against the end-to-end stack (run by
// the e2e mode of the Firefox runner): a real server, the real core, the shared
// sync engine in the extension's background, and the web vault in another tab
// of the same Firefox. The changes are made with the test build's probes
// (`item_probe`, `item_rename_probe`), which write through the sync engine as a
// change saved on this device does.
//
// - A change that waits survives a lock and a restart of the browser and goes
//   out after the next unlock. It waits because the extension's sync stopped:
//   the malicious server of the stack reports a lower position than the device
//   has seen (`seq_lie`), which stops the sync, and nothing is sent while it is
//   stopped.
// - A change made here to an item the web vault changed meanwhile becomes a
//   conflict: the popup shows both versions, nothing is lost until the user
//   chooses, and "Keep mine" (two clicks) writes this device's version on top.
//
// The account is the one the sign-in specs made (or the first test here makes
// it). The stack must have been started by `e2e-up`.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, extensionSignIn, helpers, pace, start, webVaultAccount } from "./e2e.mjs";
import { TEST_ADDON_ID, channels, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

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
 * The rows the extension has stored from the server (ids and revisions only), read in an extension page.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<Array<{ itemId: string, rev: number }>>}
 */
function extensionRows(session) {
  return session.content(() => new Promise((resolve, reject) => {
    const open = indexedDB.open("ferret");
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
 * A core operation of the test build, asked from the extension page the current tab shows.
 * @param {import("./driver.mjs").Session} session @param {string} op @param {Record<string, unknown>} args
 */
async function core(session, op, args) {
  const reply = JSON.parse(await session.content((/** @type {string} */ text) => new Promise((resolve, reject) => {
    const port = browser.runtime.connect({ name: "ferret-test-core" });
    const timer = setTimeout(() => reject(new Error("the core port did not answer")), 120_000);
    port.onMessage.addListener((answer) => {
      clearTimeout(timer);
      port.disconnect();
      resolve(typeof answer === "string" ? answer : JSON.stringify(answer));
    });
    port.onDisconnect.addListener(() => reject(new Error("the core port hung up")));
    port.postMessage(JSON.parse(text));
  }), JSON.stringify({ id: "1", op, args })));
  assert.equal(reply.ok, true, `${op}: ${reply.code}`);
  return reply.value;
}

/** The web vault's steps (its tab must be shown). */
const vault = {
  /** @param {ReturnType<typeof helpers>} page @param {import("./driver.mjs").Session} session @param {string} name */
  async create(page, session, name) {
    await page.click('[data-role="nav-items"]');
    await page.waitVisible('[data-role="new-item"]');
    await page.click('[data-role="new-item"]');
    await page.waitVisible('[data-role="edit-form"]');
    await page.type('[data-role="name"]', name);
    await page.type('[data-role="username"]', "write-user");
    await page.click('[data-role="save"]');
    await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the saved item");
    const id = /#\/items\/([0-9a-f]{32})/.exec(await session.currentUrl())?.[1];
    assert.ok(id, "the item page names the item");
    return id;
  },
  /** Renames the item the web vault shows. @param {ReturnType<typeof helpers>} page @param {import("./driver.mjs").Session} session @param {string} name */
  async rename(page, session, name) {
    await page.click('[data-role="edit"]');
    await page.waitVisible('[data-role="edit-form"]');
    await page.paste('[data-role="name"]', name);
    await page.click('[data-role="save"]');
    await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the renamed item");
  },
};

/** The popup, in a tab, as it builds itself. @param {import("./driver.mjs").Session} session @param {ReturnType<typeof helpers>} page */
async function popup(session, page) {
  await session.navigate(POPUP_URL);
  await page.ready();
}

/** Locks the extension with the popup's button. @param {import("./driver.mjs").Session} session @param {ReturnType<typeof helpers>} page */
async function lockExtension(session, page) {
  await popup(session, page);
  await page.waitVisible('[data-role="unlocked-view"]', SLOW);
  await page.click('[data-role="lock"]');
  await page.waitVisible('[data-role="locked-view"]');
}

/**
 * Unlocks the extension in the popup with the master password.
 * @param {import("./driver.mjs").Session} session @param {ReturnType<typeof helpers>} page @param {string} password
 */
async function unlockExtension(session, page, password) {
  await popup(session, page);
  await page.waitVisible('[data-role="locked-view"]', SLOW);
  await page.type('[data-role="password"]', password);
  await pace();
  await page.click('[data-role="unlock"]');
  await page.waitVisible('[data-role="unlocked-view"]', SLOW);
}

/**
 * The web vault (its tab) and the extension (another tab, signed in at the same account), with the extension's sync
 * up to date.
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
  await popup(session, page);
  await page.waitVisible('[data-role="sync"][data-state="idle"]', SLOW);
  return { session, page, account, vaultTab, extensionTab };
}

/**
 * Stops the extension's sync: the malicious server reports a position below the one the device has seen, and the
 * extension reads the feed again on its next unlock. Nothing is sent while the sync is stopped.
 * @param {import("./driver.mjs").Session} session @param {ReturnType<typeof helpers>} page @param {string} password
 */
async function stopExtensionSync(session, page, password) {
  await lockExtension(session, page);
  await evil("seq_lie", { latest_seq: 1 });
  await unlockExtension(session, page, password);
  await page.waitVisible('[data-role="sync-stop"][data-code="rollback_suspected"]', SLOW);
}

test("pending_writes_survive_a_lock_and_a_restart_and_go_out_after_unlock", async () => {
  for (const channel of channels()) {
    const { session, page, account } = await sideBySide(channel);
    try {
      let id = "";
      const name = `Ext-pending-${randomBytes(4).toString("hex")}`;
      try {
        await stopExtensionSync(session, page, account.password);
        // A change saved on this device while the sync is stopped: it waits, and the popup says so.
        id = (await core(session, "item_probe", { name, url: "https://pending.example.net/login", matching: "host", username: "pending-user" })).id;
        assert.match(id, /^[0-9a-f]{32}$/);
        await popup(session, page);
        await page.waitVisible('[data-role="sync-pending"]', SLOW);
        assert.match(await page.text('[data-role="sync-pending"]'), /: 1$/, `${channel}: one change waits`);
        assert.equal((await extensionRows(session)).some((row) => row.itemId === id), false, `${channel}: the server has not taken it`);

        // Lock, and end the browser: the change stays on this device.
        await lockExtension(session, page);
      } finally {
        await evil("honest");
      }
      await session.restart();
      await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active, 30_000, `${channel}: the add-on after the restart`);
      // A new start is locked, and nothing goes out before the unlock.
      await popup(session, page);
      await page.waitVisible('[data-role="locked-view"]', SLOW);
      assert.equal((await extensionRows(session)).some((row) => row.itemId === id), false, `${channel}: nothing went out while locked`);

      // After the unlock the change goes out, and the server has it.
      await unlockExtension(session, page, account.password);
      await session.waitFor(async () => (await extensionRows(session)).some((row) => row.itemId === id), SLOW, `${channel}: the server took the change`);
      await popup(session, page);
      await page.waitVisible('[data-role="sync"][data-state="idle"]', SLOW);
      assert.equal(await page.visible('[data-role="sync-pending"]'), false, `${channel}: nothing waits any more`);
      // The web vault (signed in again after the restart) reads it from the server.
      const vaultTab = await session.newTab();
      await session.switchTo(vaultTab);
      await webVaultAccount(session, channel);
      await session.waitFor(() => serverHas(session, id, 1), SLOW, `${channel}: the server's feed has the item`);
    } finally {
      await session.quit();
    }
  }
});

test("a_conflict_with_a_web_vault_edit_is_shown_and_nothing_is_lost", async () => {
  for (const channel of channels()) {
    const { session, page, account, vaultTab, extensionTab } = await sideBySide(channel);
    try {
      const tag = randomBytes(4).toString("hex");
      const first = `Ext-conflict-${tag}`;
      const theirs = `${first}-web`;
      const mine = `${first}-here`;

      // The item, in both.
      await session.switchTo(vaultTab);
      const id = await vault.create(page, session, first);
      await session.waitFor(() => serverHas(session, id, 1), 30_000, "the server has the item");
      await session.switchTo(extensionTab);
      await popup(session, page);
      await session.waitFor(async () => (await extensionRows(session)).some((row) => row.itemId === id && row.rev === 1), SLOW, "the extension has the item");

      // The web vault changes it while the extension cannot see the change, and the extension changes it too.
      await lockExtension(session, page);
      await session.switchTo(vaultTab);
      await vault.rename(page, session, theirs);
      await session.waitFor(() => serverHas(session, id, 2), 30_000, "the server has the web vault's change");
      await session.switchTo(extensionTab);
      try {
        await stopExtensionSync(session, page, account.password);
        await core(session, "item_rename_probe", { id, name: mine, rev: 1 });
      } finally {
        await evil("honest");
      }

      // The sync goes on: the change was made over an older version, so it becomes a conflict, and the popup shows it.
      await popup(session, page);
      await page.click('[data-role="sync-action"][data-action="try_again"]');
      await page.waitVisible('[data-role="sync-review"]', SLOW);
      await page.click('[data-role="sync-review"]');
      await page.waitVisible('[data-role="sync-item"][data-state="conflict"]', SLOW);
      await page.click('[data-role="sync-item"][data-state="conflict"] [data-role="sync-item-resolve"]');
      await page.waitVisible('[data-role="conflict-card"] [data-role="keep-mine"]', SLOW);
      const names = await session.content(() => [...document.querySelectorAll('[data-role="conflict-name"]')].map((n) => n.textContent));
      assert.deepEqual(names, [mine, theirs], `${channel}: both versions are shown`);

      // Nothing is lost while the user decides: the server keeps the web vault's version, this device keeps its own.
      await session.switchTo(vaultTab);
      assert.equal(await serverHas(session, id, 3), false, `${channel}: nothing was written over the web vault's change`);
      await session.switchTo(extensionTab);

      // "Keep mine" takes two clicks; then this device's version is written on top of the web vault's.
      await page.click('[data-role="keep-mine"]');
      assert.equal(await page.visible('[data-role="conflict-card"] [data-role="keep-mine"][data-armed="1"]'), true, `${channel}: the first click only asks`);
      await new Promise((resolve) => setTimeout(resolve, 600));
      await page.click('[data-role="keep-mine"]');
      await page.waitVisible('[data-role="sync"]', SLOW);
      await session.switchTo(vaultTab);
      await session.waitFor(() => serverHas(session, id, 3), SLOW, `${channel}: the server has the version kept`);
      // The web vault shows it (a fresh read of its own: the page is loaded again on the item).
      assert.match(await session.currentUrl(), new RegExp(`#/items/${id}$`));
      await session.content(() => location.reload());
      await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(mine), SLOW, `${channel}: the web vault shows the version kept`);
    } finally {
      await session.quit();
    }
  }
});
