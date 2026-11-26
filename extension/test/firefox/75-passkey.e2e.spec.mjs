// A passkey of Ferret from end to end (U4-13; run by `scripts/lanbox-ext.sh e2e --passkey-rp` with the fixture container up): the
// signed-in extension against the end-to-end stack, the web vault of the same account in the same browser, and the fixture
// container's relying party (webauthn-rs, the strict one) on rp-a.test.
//
// full_u4_flow_end_to_end, in each channel:
//   1. the extension makes a passkey: the page's create, "Save in Ferret" in Ferret's window (with the item's name), and the relying
//      party verifies the registration; then a sign-in with it;
//   2. the web vault shows it: the item has the passkey card with the site, the user name and the date, never a key; the list marks
//      the item;
//   3. the item is renamed in the web vault: the extension gets the change, and signs in with the passkey again;
//   4. the item is deleted in the web vault and restored from the trash (the note names the site): the extension gets both, and
//      signs in again;
//   5. "Remove passkey" in the web vault: the item stays, and the extension's window no longer offers the passkey for the site.
//
// no_sentinel_key_leaves_the_core, in each channel: a passkey with a sentinel private key (a test key of the relying party,
// extension/test/fixtures/passkey-sentinel.json) goes into the vault through the core's import (the test build's
// `item_import_probe`), then the page signs in with it through Ferret's window. None of the key's forms is then in a file of the
// profile, in the browser's console, in a runtime message, in a request the browser sent, or in what the page saw (passkeyLeak.mjs);
// the run also greps the stack's logs for it.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { SLOW, helpers, pace } from "./e2e.mjs";
import { TEST_ADDON_ID, channels, stopFixtures } from "./harness.mjs";
import { CHOOSER_PAGE, launchMatrixBrowser, pressInChooser, turnOnFerret } from "./passkeyMatrix.mjs";
import { coreOp } from "./passkeyDrive.mjs";
import { registerTestKey } from "./passkeyFerret.mjs";
import { CONSOLE_PREFS, consoleFindings, messageFindings, networkFindings, sentinel, watchMessages, watchNetwork } from "./passkeyLeak.mjs";
import { ask, scanFolder } from "./unlock.mjs";

after(() => stopFixtures());

const RP = "https://rp-a.test";
const RP_ID = "rp-a.test";

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * One ceremony on the fixture page from a real click, with Ferret's window answered as a person would (the master password when it
 * asks to verify). Returns what the page reported and what was pressed.
 * @param {import("./driver.mjs").Session} session @param {string} pageTab
 * @param {{ sid: string, steps: string[], name: string | null, user?: string, password: string, press?: boolean }} o
 */
async function ceremony(session, pageTab, { sid, steps, name, user = "anna", password, press = true }) {
  const run = `e2e-${Math.random().toString(16).slice(2, 10)}`;
  const spec = { run, sid, lib: "rs", client: "manual", steps, user: { name: user, displayName: "Anna" }, create: { userVerification: "preferred", residentKey: "required", attestation: "none" }, get: { userVerification: "preferred", allow: "all" } };
  await session.switchTo(pageTab);
  await session.navigate(`${RP}/ceremony.html?spec=${Buffer.from(JSON.stringify(spec), "utf8").toString("base64url")}`);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the ceremony page");
  const baseline = new Set(await session.windowHandles());
  const [go] = await session.findAll("#go");
  assert.ok(go, "the page's button");
  await session.click(go);
  /** @type {Set<string>} */
  const pressed = new Set();
  /** @type {Array<{ kind: string, role: string }>} */
  const presses = [];
  if (!press) return { result: null, presses, baseline };
  const result = await session.waitFor(async () => {
    presses.push(...(await pressInChooser(session, baseline, pressed, pageTab, { name, password })));
    await session.switchTo(pageTab);
    const state = await session.content(() => document.getElementById("result")?.dataset.state ?? "");
    return state === "ok" || state === "failed" ? session.content(() => /** @type {any} */ (window).__result) : null;
  }, 120_000, "the ceremony's end");
  await session.waitFor(async () => (await session.windowHandles()).every((h) => baseline.has(h)), 20_000, "Ferret's window closed");
  return { result, presses, baseline };
}

/** Asks the extension to sync until the item named `name` is there (`present`), returning it. @param {import("./driver.mjs").Session} session @param {string} extTab @param {string} name @param {boolean} present @param {number} [minRev] */
async function syncUntil(session, extTab, name, present, minRev = 0) {
  await session.switchTo(extTab);
  return session.waitFor(async () => {
    await ask(session, "sync_retry", {}).catch(() => null);
    const found = await coreOp(session, "item_find_probe", { name });
    if (found?.ok !== true) return null;
    const item = found.value?.item ?? null;
    if (present) return item !== null && item.rev >= minRev ? item : null;
    return item === null ? { gone: true } : null;
  }, 60_000, `the extension's sync: ${name} ${present ? "there" : "gone"}`);
}

/** The web vault's tab at an item (the vault is signed in and open in it). @param {import("./driver.mjs").Session} session @param {string} vaultTab @param {string} id */
async function openItem(session, vaultTab, id) {
  const page = helpers(session);
  await session.switchTo(vaultTab);
  const base = (await session.currentUrl()).split("#")[0];
  await session.navigate(`${base}#/items`);
  await page.waitVisible('[data-role="list"]', SLOW);
  await session.waitFor(() => session.content((/** @type {string} */ wanted) => document.querySelector(`[data-role="list"] a[href="#/items/${wanted}"]`) !== null, id), 60_000, "the item in the web vault's list");
  await session.navigate(`${base}#/items/${id}`);
  await page.waitVisible('[data-role="item"]', SLOW);
  return page;
}

test("full_u4_flow_end_to_end", async () => {
  assert.ok(process.env.FERRET_PASSKEY_CA_PEM, "FERRET_PASSKEY_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e --passkey-rp)");
  for (const channel of channels()) {
    const session = await launchMatrixBrowser({ channel });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const vaultTab = await session.windowHandle();
      // The web vault is signed in in this tab, and the extension in a tab of its own.
      const { tab: extTab, account } = await turnOnFerret(session, channel);
      const pageTab = await session.newTab();
      const name = `U4-test e2e ${channel} ${Math.random().toString(16).slice(2, 8)}`;
      const sid = `e2e-${Math.random().toString(16).slice(2, 12)}`;

      // 1. The extension makes a passkey, and signs in with it.
      let made = await ceremony(session, pageTab, { sid, steps: ["create", "get"], name, password: account.password });
      assert.equal(made.result.ok, true, `${channel}: create and sign-in: ${JSON.stringify(made.result.steps?.map((/** @type {any} */ s) => ({ step: s.step, error: s.error })))}`);
      assert.deepEqual(made.presses.map((p) => p.role), ["passkey-create-new", "passkey-candidate"], `${channel}: made and used in Ferret's window`);
      const item = await syncUntil(session, extTab, name, true);
      assert.match(item.id, /^[0-9a-f]{32}$/);

      console.error(`full_u4_flow_end_to_end ${channel}: 1 made and used`);
      // 2. The web vault shows the passkey: the site, the user name and the date, never a key; the list marks the item.
      let page = await openItem(session, vaultTab, item.id);
      const card = await session.waitFor(() => session.content(() => {
        const node = document.querySelector('[data-card="passkey"]');
        if (!node) return null;
        const value = (/** @type {string} */ key) => node.querySelector(`[data-role="passkey-value"][data-key="${key}"]`)?.textContent?.trim() ?? null;
        return { site: value("site"), user: value("user"), created: value("created"), text: node.textContent ?? "" };
      }), 30_000, "the passkey card");
      assert.equal(card.site, RP_ID, `${channel}: the site`);
      assert.equal(card.user, "anna", `${channel}: the user name`);
      assert.ok(card.created && /\d/.test(card.created), `${channel}: the date (${card.created})`);
      assert.doesNotMatch(card.text, /priv|BEGIN|-----/i, `${channel}: no key in the card`);

      console.error(`full_u4_flow_end_to_end ${channel}: 2 the web vault shows it`);
      // 3. Renamed in the web vault: the extension gets it, and the passkey still signs.
      const renamed = `${name} renamed`;
      await page.click('[data-role="edit"]');
      await page.waitVisible('[data-role="edit-form"]');
      await page.paste('[data-role="name"]', renamed);
      await page.click('[data-role="save"]');
      await session.waitFor(async () => (await page.text('[data-role="item"] h1')).includes(renamed), 30_000, "the renamed item");
      await syncUntil(session, extTab, renamed, true, item.rev + 1);
      made = await ceremony(session, pageTab, { sid, steps: ["get"], name: renamed, password: account.password });
      assert.equal(made.result.ok, true, `${channel}: the sign-in after the rename: ${JSON.stringify(made.result.steps?.map((/** @type {any} */ s) => s.error))}`);

      console.error(`full_u4_flow_end_to_end ${channel}: 3 signs after the rename`);
      // 4. Deleted in the web vault and restored from the trash: the extension gets both, and the passkey signs again.
      page = await openItem(session, vaultTab, item.id);
      await page.click('[data-role="delete"]');
      await page.waitVisible('[data-role="dialog"]');
      assert.match(await page.text('[data-role="dialog"]'), new RegExp(RP_ID.replace(/\./g, "\\.")), `${channel}: the delete dialog names the site`);
      await page.click('[data-role="dialog-confirm"]');
      await syncUntil(session, extTab, renamed, false);
      await session.switchTo(vaultTab);
      const base = (await session.currentUrl()).split("#")[0];
      await session.navigate(`${base}#/trash`);
      await page.waitVisible('[data-role="trash"]', SLOW);
      const row = `[data-role="trash-item"][data-id="${item.id}"]`;
      await page.waitVisible(row, 60_000);
      assert.match(await page.text(`${row} [data-role="trash-passkey"]`), new RegExp(RP_ID.replace(/\./g, "\\.")), `${channel}: the trash note names the site`);
      await page.click(`${row} [data-role="restore"]`);
      await syncUntil(session, extTab, renamed, true);
      made = await ceremony(session, pageTab, { sid, steps: ["get"], name: renamed, password: account.password });
      assert.equal(made.result.ok, true, `${channel}: the sign-in after the restore: ${JSON.stringify(made.result.steps?.map((/** @type {any} */ s) => s.error))}`);

      console.error(`full_u4_flow_end_to_end ${channel}: 4 signs after delete and restore`);
      // 5. "Remove passkey" in the web vault: the item stays, and the extension's window offers no passkey for the site.
      const before = await syncUntil(session, extTab, renamed, true);
      page = await openItem(session, vaultTab, item.id);
      await page.click('[data-role="remove-passkey"]');
      await page.waitVisible('[data-role="dialog"]');
      await page.click('[data-role="dialog-confirm"]');
      await session.waitFor(async () => (await session.findAll('[data-card="passkey"]')).length === 0, 30_000, "the passkey card gone");
      await syncUntil(session, extTab, renamed, true, before.rev + 1);
      const asked = await ceremony(session, pageTab, { sid, steps: ["get"], name: renamed, password: account.password, press: false });
      const handle = await session.waitFor(async () => {
        for (const h of await session.windowHandles()) {
          if (asked.baseline.has(h)) continue;
          await session.switchTo(h);
          if ((await session.currentUrl()).startsWith(CHOOSER_PAGE)) return h;
        }
        return null;
      }, 30_000, "Ferret's window");
      await session.switchTo(handle);
      const shown = await session.waitFor(() => session.content(() => {
        const root = document.querySelector('[data-role="passkey-chooser"]');
        if (document.body?.dataset.ready !== "1" || root?.getAttribute("data-state") !== "ready") return null;
        return { candidates: document.querySelectorAll('[data-role="passkey-candidate"]').length, none: document.querySelector('[data-role="passkey-none"]') !== null };
      }), 30_000, "the window's choices");
      assert.deepEqual(shown, { candidates: 0, none: true }, `${channel}: no passkey is offered after "Remove passkey"`);
      await sleep(900);
      const [cancel] = await session.findAll('[data-role="passkey-cancel"]');
      if (cancel) await session.click(cancel);
      console.error(`full_u4_flow_end_to_end ${channel}: 5 no passkey offered after "Remove passkey"`);
    } finally {
      await session.quit();
    }
  }
}, { timeout: 12 * SLOW });

test("no_sentinel_key_leaves_the_core", async () => {
  assert.ok(process.env.FERRET_PASSKEY_CA_PEM, "FERRET_PASSKEY_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e --passkey-rp)");
  const key = sentinel();
  for (const channel of channels()) {
    const session = await launchMatrixBrowser({ channel, prefs: CONSOLE_PREFS });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const { tab: extTab, account } = await turnOnFerret(session, channel);
      const pageTab = await session.newTab();
      // The sentinel key, registered at the relying party by the page.
      await session.switchTo(pageTab);
      await session.navigate(`${RP}/ceremony.html`);
      await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the relying party's page");
      const reg = /** @type {any} */ (await registerTestKey(session, "rs", RP_ID, `sentinel-${channel}`, key.pkcs8));
      assert.equal(reg.ok, true, `${channel}: the registration of the sentinel key: ${JSON.stringify(reg)}`);
      assert.equal(reg.key_pkcs8, key.pkcs8, `${channel}: the page registered the sentinel itself`);
      await session.navigate("about:blank");
      // Into the vault through the core's import (the one place the test hands the key over).
      await session.switchTo(extTab);
      const planted = await coreOp(session, "item_import_probe", { name: `Sentinel ${channel}`, rp_id: RP_ID, user_name: `sentinel-${channel}`, cred_id: reg.cred_id, user_handle: reg.user_handle, key_pkcs8: reg.key_pkcs8 });
      assert.equal(planted?.ok, true, `${channel}: item_import_probe: ${JSON.stringify(planted)}`);
      // From here on every message, request and console line is watched.
      await watchMessages(session, key.needles);
      await watchNetwork(session, key.needles, key.bytes);
      // The page signs in with it through Ferret's window (a sync first, so the background has the item).
      await ask(session, "sync_retry", {}).catch(() => null);
      const signed = await ceremony(session, pageTab, { sid: reg.sid, steps: ["get"], name: null, user: `sentinel-${channel}`, password: account.password });
      assert.equal(signed.result.ok, true, `${channel}: the sign-in with the sentinel key: ${JSON.stringify(signed.result.steps?.map((/** @type {any} */ s) => s.error))}`);
      assert.equal(signed.presses.some((p) => p.role === "passkey-candidate"), true, `${channel}: signed by Ferret`);
      // A sync and a lock, so whatever the background might write is written.
      await session.switchTo(extTab);
      await ask(session, "sync_retry", {}).catch(() => null);
      await pace();
      const messages = await messageFindings(session);
      const network = await networkFindings(session);
      // A control line in the console of the page (a script of its own): the scan must find it, or it proves nothing.
      await session.switchTo(pageTab);
      await session.content(() => {
        const script = document.createElement("script");
        script.textContent = 'console.log("ferret-leak-control")';
        document.head.append(script);
      });
      await sleep(1000);
      await session.switchTo(extTab);
      const consoleSeen = await consoleFindings(session, key.needles);
      await ask(session, "lock", {});
      await sleep(2000);
      // What the page saw: its reports at the relying party.
      await session.switchTo(pageTab);
      const pageSaw = JSON.stringify(signed.result);
      const files = scanFolder(session.profileDir, key.bytes);
      assert.ok(messages.messages > 0, `${channel}: the message watch saw no message at all`);
      assert.ok(network.requests > 0 && network.bodies > 0, `${channel}: the network watch saw no request body (${JSON.stringify(network)})`);
      assert.ok(consoleSeen.control, `${channel}: the console scan did not find its own control line (${consoleSeen.messages} messages)`);
      assert.deepEqual(messages.hits, [], `${channel}: a runtime message holds the sentinel key`);
      assert.deepEqual(network.hits, [], `${channel}: a request holds the sentinel key`);
      assert.deepEqual(consoleSeen.hits, [], `${channel}: the console holds the sentinel key`);
      assert.equal(key.needles.some((n) => pageSaw.includes(n)), false, `${channel}: the page saw the sentinel key`);
      assert.deepEqual(files, [], `${channel}: a file of the profile holds the sentinel key`);
      // Controls: the scans find the needles where they are.
      assert.equal(key.needles.some((n) => JSON.stringify(reg).includes(n)), true, "the control: the registration's own answer holds the key");
    } finally {
      await session.quit();
    }
  }
}, { timeout: 6 * SLOW });

