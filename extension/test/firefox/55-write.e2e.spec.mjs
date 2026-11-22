// The write path of the extension against the end-to-end stack (run by the e2e
// mode of the Firefox runner): a real server, the real core, the shared sync
// engine in the extension's background, and the web vault beside it in the
// same Firefox.
//
// - A login saved from an offer in the extension reaches the web vault within
//   two seconds of the server having it, with the web vault's fields, the
//   page's origin as its address and the folder chosen.
// - An update from an offer changes the password of an item made in the web
//   vault and nothing else the web vault shows: its folders, its address and
//   its user name stay, and the new password is the one shown.
// - Classifying a capture over 1000 items (the reuse check included) takes at
//   most 500 ms in Firefox, and closes every handle it opened.
//
// The offers are the test build's own (the core op `offer_plant`): a capture
// the test makes up, as the background would hold one. The writes go through
// the same core ops (`offer_classify`, `offer_save`, `offer_update`) that the
// popup's offer will use.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, extensionSignIn, helpers, start, webVaultAccount } from "./e2e.mjs";
import { channels, openBridge, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/** How long after the server has an item the web vault must show it. */
const WITHIN_MS = 2_000;
/** The page the captures come from (a test site's address; the test never loads it). */
const PAGE_URL = "https://login.example.net/signin";
const ORIGIN = "https://login.example.net";

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
 * The web vault (its tab) and the extension (another tab, signed in at the same account, showing the test bridge),
 * with a caller of the test build's core ops.
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
  await session.navigate(POPUP_URL);
  await page.ready();
  await page.waitVisible('[data-role="sync"][data-state="idle"][data-live="live"]', SLOW);
  await openBridge(session);
  /**
   * A core op of the test build, from the bridge page (the extension's tab must be the current one).
   * @param {string} op @param {Record<string, unknown>} [args]
   */
  const core = async (op, args = {}) => {
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
    assert.equal(reply.ok, true, `${channel}: ${op}: ${reply.code}`);
    return reply.value;
  };
  return { session, page, vaultTab, extensionTab, core };
}

/** A popup session of the test's own (an offer is good only in the session it was given to). */
const uiSession = () => randomBytes(16).toString("hex");

/**
 * The text of the web vault's current page under `css` (its tab must be shown).
 * @param {import("./driver.mjs").Session} session @param {string} css
 */
const allText = (session, css) => session.content((/** @type {string} */ selector) => [...document.querySelectorAll(selector)].map((n) => (n.textContent ?? "").trim()), css);

test("an_item_saved_in_the_extension_shows_in_the_web_vault_within_two_seconds", async () => {
  for (const channel of channels()) {
    const { session, page, vaultTab, extensionTab, core } = await sideBySide(channel);
    try {
      const name = `Ext-save-${randomBytes(4).toString("hex")}`;
      const folder = `E2E ${randomBytes(3).toString("hex")}`;
      const password = `Pw-${randomBytes(8).toString("hex")}`;
      const session_ = uiSession();
      const { offer_id: offerId } = await core("offer_plant", { session: session_, frame_url: PAGE_URL, kind: "signup", username: "e2e-saver", password });
      const classified = await core("offer_classify", { session: session_, offer_id: offerId });
      assert.equal(classified.action, "save", `${channel}: ${JSON.stringify(classified)}`);
      const saved = await core("offer_save", { session: session_, offer_id: offerId, name, username: "e2e-saver", folder });
      assert.equal(saved.ok, true, `${channel}: ${JSON.stringify(saved)}`);
      // Used once.
      assert.deepEqual(await core("offer_save", { session: session_, offer_id: offerId, name, username: "e2e-saver", folder }), { ok: false, reason: "not_offered" });

      await session.switchTo(vaultTab);
      await session.navigate(`${await session.currentUrl().then((u) => u.split("#")[0])}#/items`);
      await page.waitVisible('[data-role="list"]', SLOW);
      // From the moment the server has it, the web vault's list shows it within the limit.
      await session.waitFor(() => serverHas(session, saved.id, 1), 30_000, "the server has the item");
      const serverAt = Date.now();
      await session.waitFor(async () => (await page.text('[data-role="list"]')).includes(name), 10_000, "the web vault lists the item");
      const took = Date.now() - serverAt;
      assert.ok(took <= WITHIN_MS, `${channel}: the web vault showed the item ${took} ms after the server had it (at most ${WITHIN_MS})`);

      // The item as the web vault shows it: the web vault's fields, the origin, the folder.
      await session.navigate(`${(await session.currentUrl()).split("#")[0]}#/items/${saved.id}`);
      await page.waitVisible('[data-role="item"] h1', SLOW);
      assert.ok((await page.text('[data-role="item"] h1')).includes(name), channel);
      assert.deepEqual(await allText(session, '[data-role="url"]'), [ORIGIN], channel);
      assert.deepEqual(await allText(session, '[data-role="folder-chip"]'), [folder], channel);
      const labels = await allText(session, '[data-role="field"] .label');
      assert.ok(labels.some((l) => l.includes("User name")) && labels.some((l) => l.includes("Password")), `${channel}: ${JSON.stringify(labels)}`);
      assert.ok((await allText(session, '[data-role="value"]')).includes("e2e-saver"), channel);
      await session.switchTo(extensionTab);
    } finally {
      await session.quit();
    }
  }
});

test("an_update_from_the_extension_keeps_the_folders_seen_in_the_web_vault", async () => {
  for (const channel of channels()) {
    const { session, page, vaultTab, extensionTab, core } = await sideBySide(channel);
    try {
      // An item made in the web vault: a user name, a password, the page's address and two folders.
      await session.switchTo(vaultTab);
      const name = `Ext-update-${randomBytes(4).toString("hex")}`;
      const username = `e2e-${randomBytes(3).toString("hex")}`;
      const folders = [`Keep A ${randomBytes(2).toString("hex")}`, `Keep B ${randomBytes(2).toString("hex")}`];
      const oldPassword = `Old-${randomBytes(8).toString("hex")}`;
      const newPassword = `New-${randomBytes(8).toString("hex")}`;
      await page.click('[data-role="nav-items"]');
      await page.waitVisible('[data-role="new-item"]');
      await page.click('[data-role="new-item"]');
      await page.waitVisible('[data-role="edit-form"]');
      await page.type('[data-role="name"]', name);
      await page.type('[data-role="username"]', username);
      await page.type('[data-role="password"]', oldPassword);
      await page.type('[data-role="url"]', `${ORIGIN}/`);
      for (const folder of folders) {
        await page.type('[data-role="folder-input"]', folder);
        await page.click('[data-role="folder-add"]');
      }
      await page.click('[data-role="save"]');
      await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(name), 30_000, "the saved item");
      const id = /#\/items\/([0-9a-f]{32})/.exec(await session.currentUrl())?.[1];
      assert.ok(id, "the item page names the item");
      const shownBefore = {
        folders: await allText(session, '[data-role="folder-chip"]'),
        urls: await allText(session, '[data-role="url"]'),
      };
      assert.deepEqual([...shownBefore.folders].sort(), [...folders].sort(), channel);
      await session.waitFor(() => serverHas(session, id, 1), 30_000, "the server has the item");

      // The extension has it, and an offer for the page with the same user name and a new password updates it.
      await session.switchTo(extensionTab);
      const session_ = uiSession();
      const { offer_id: offerId } = await core("offer_plant", { session: session_, frame_url: PAGE_URL, kind: "login", username, password: newPassword });
      const classified = await session.waitFor(async () => {
        const c = await core("offer_classify", { session: session_, offer_id: offerId });
        return c.targets?.some((/** @type {any} */ t) => t.id === id) ? c : null;
      }, 30_000, "the extension has the item");
      assert.equal(classified.action, "update", `${channel}: ${JSON.stringify(classified)}`);
      const target = classified.targets.find((/** @type {any} */ t) => t.id === id);
      const updated = await core("offer_update", { session: session_, offer_id: offerId, id, rev: target.rev });
      assert.equal(updated.ok, true, `${channel}: ${JSON.stringify(updated)}`);

      // The web vault shows the new revision: the same folders, address and user name, the new password.
      await session.switchTo(vaultTab);
      await session.waitFor(() => serverHas(session, id, target.rev + 1), 30_000, "the server has the update");
      // The item page again, until it shows the new revision; the password field (the second field) is shown on a click.
      await session.waitFor(async () => {
        await session.navigate(`${(await session.currentUrl()).split("#")[0]}#/items`);
        await page.waitVisible('[data-role="list"]', SLOW);
        await session.navigate(`${(await session.currentUrl()).split("#")[0]}#/items/${id}`);
        await page.waitVisible('[data-role="reveal"][data-key="f1"]', SLOW);
        const hidden = await page.text('[data-role="value"][data-key="f1"]');
        await page.click('[data-role="reveal"][data-key="f1"]');
        const shown = await session.waitFor(async () => {
          const text = await page.text('[data-role="value"][data-key="f1"]');
          return text !== hidden ? text : null;
        }, 10_000, "the shown password");
        return shown === newPassword;
      }, 60_000, "the new password in the web vault");
      assert.deepEqual([...(await allText(session, '[data-role="folder-chip"]'))].sort(), [...shownBefore.folders].sort(), `${channel}: the folders stay`);
      assert.deepEqual(await allText(session, '[data-role="url"]'), shownBefore.urls, `${channel}: the address stays`);
      assert.ok((await allText(session, '[data-role="value"]')).includes(username), `${channel}: the user name stays`);
      await session.switchTo(extensionTab);
    } finally {
      await session.quit();
    }
  }
});

test("reuse_check_of_1000_items_stays_within_500_ms", async () => {
  for (const channel of channels()) {
    const { session, core } = await sideBySide(channel);
    try {
      const bench = await core("offer_bench", { session: uiSession(), n: 1000, frame_url: PAGE_URL, kind: "login", username: "bench", password: `Pw-${randomBytes(8).toString("hex")}`, other: "https://shop.example.org/" });
      assert.equal(bench.items, 1000);
      assert.equal(bench.opened, 1000, channel);
      assert.equal(bench.closed, 1000, `${channel}: every handle is closed`);
      assert.equal(bench.still_open, 0, channel);
      assert.equal(bench.action, "save", channel);
      assert.equal(bench.reused, 3, `${channel}: half of them hold the password; three are named`);
      assert.ok(bench.ms <= 500, `${channel}: classifying over 1000 items took ${bench.ms} ms (at most 500)`);
      console.log(`# ${channel}: classifying over 1000 items took ${Math.round(bench.ms)} ms`);
    } finally {
      await session.quit();
    }
  }
});
