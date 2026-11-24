// The offer in the real popup, end to end on the end-to-end stack: the extension is signed in to a real server with its vault
// open, "Offer to save passwords" is on (the settings tab's real click asks for access to https pages), and a form of the
// corpus is submitted in a tab with real key events.
//
// - sign_up_on_the_fixture_save_in_the_popup_and_see_it_in_the_web_vault: the sign-up fixture is submitted; the popup about
//   that tab shows "Save in Ferret?" with the host and no password; the name is changed with real keys, "Save" is clicked, and
//   the web vault lists the new item.
// - change_password_on_the_fixture_update_and_see_the_old_one_under_previous_passwords: the change fixture is submitted with
//   the password of an entry of the vault as the current one; the popup shows "Update the password?" with that entry; "Update" is
//   clicked, and the item in the web vault has the old password under "Previous passwords".
// - the_popup_bottom_bar_shows_vault_generator_and_settings_and_settings_opens_in_the_popup: Settings shows the settings view
//   in the popup itself (marked in the bar) and opens no tab.
// - offer_to_save_is_turned_on_and_off_from_the_settings_part_of_the_popup: the switch in the popup's settings view asks for
//   access to https pages in its click and turns the setting on, and off again (the test profile answers the request without
//   a prompt; a person's Firefox shows one and closes the popup, which captureSettings.mjs answers).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { ENTRIES, captureCase, casesOf, offersPeek } from "./matrix.mjs";
import { world } from "./adversary.mjs";
import { EXTENSION_ORIGIN, channels, stopFixtures } from "./harness.mjs";
import { POPUP_URL, SLOW } from "./e2e.mjs";

after(() => stopFixtures());

const sleep = (/** @type {number} */ ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A world with the vault kept open and "Offer to save passwords" on.
 * @param {string} channel
 */
async function ready(channel) {
  const w = await world(channel, { grant: [], entries: ENTRIES });
  await w.ui.open();
  try {
    await w.ui.body("settings", { lock_seconds: 86_400 });
  } finally {
    await w.ui.close();
  }
  await w.session.navigate(`${EXTENSION_ORIGIN}/pages/settings.html`);
  await w.session.waitFor(() => w.session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
  const [toggle] = await w.session.findAll('[data-role="capture-switch"]');
  assert.ok(toggle, `${channel}: the settings page has the switch`);
  await w.session.click(toggle);
  await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "true"), 15_000, "capture on");
  await w.session.switchTo(w.pageTab);
  return w;
}

/** The id of the newest tab (the page of the case). @param {Awaited<ReturnType<typeof world>>} w */
async function newestTab(w) {
  const tabs = await w.fromBridge(() => w.bridge.invoke("tabs.query", {}));
  return tabs.reduce((/** @type {{ id: number }} */ a, /** @type {{ id: number }} */ b) => (b.id > a.id ? b : a)).id;
}

/**
 * The real popup about a tab, in a window of its own, with the offer card shown and the guard's 400 ms passed.
 * @param {Awaited<ReturnType<typeof world>>} w @param {number} tabId @param {string} kind the card's `data-kind`
 */
async function popupWithCard(w, tabId, kind) {
  const handle = await w.session.newWindow();
  await w.session.switchTo(handle);
  await w.session.navigate(`${POPUP_URL}?tab=${tabId}`);
  await w.page.ready();
  try {
    await w.page.waitVisible('[data-role="offer-card"]', 30_000);
  } catch (error) {
    const body = await w.session.content(() => (document.body.textContent ?? "").replace(/\s+/g, " ").slice(0, 600));
    const listed = await offersPeek(w, tabId);
    throw new Error(`no offer card in the popup about tab ${tabId}: ${String(error)}; the popup shows: ${body}; the store holds ${JSON.stringify(listed.offers.map((o) => [o.type, o.origin]))}`);
  }
  await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="offer-card"] [data-role="offer-actions"], [data-role="offer-gone"]') !== null), SLOW, "the card");
  const shown = await w.session.content(() => document.querySelector('[data-role="offer-card"]')?.getAttribute("data-kind") ?? "");
  assert.equal(shown, kind, `the card is a ${kind} card: ${await w.session.content(() => (document.querySelector('[data-role="offer-card"]')?.textContent ?? "").slice(0, 300))}`);
  // A click is ignored for the first 400 ms after the card appears.
  await sleep(700);
  return handle;
}

test("sign_up_on_the_fixture_save_in_the_popup_and_see_it_in_the_web_vault", async () => {
  const [base] = casesOf("corpus", "signup-confirm-fr");
  assert.equal(base?.id, "signup-confirm-fr");
  for (const channel of channels()) {
    const w = await ready(channel);
    try {
      // A user name and a password of this run: the account is shared by the channels, and a login the vault holds already
      // would be no offer.
      const unique = randomBytes(3).toString("hex");
      const c = structuredClone(base);
      const user = `anna-${unique}@example.net`;
      const password = `Zq7!su-${unique}-Vm4$`;
      c.steps = c.steps.map((/** @type {any} */ s) => (s.type === "#email" ? { ...s, text: user } : s.type === "#pw" || s.type === "#pw2" ? { ...s, text: password } : s));
      c.expect.capture.username = user;
      const result = await captureCase(w, c);
      assert.equal(result.error, undefined, `${channel}: ${result.error}`);
      assert.equal(result.observed?.offers.length, 1, `${channel}: one offer (${JSON.stringify(result.observed?.offers)})`);
      assert.equal(result.observed?.vault_changed, false, `${channel}: nothing was written before the click`);
      const tabId = await newestTab(w);

      const handle = await popupWithCard(w, tabId, "save");
      assert.equal(await w.page.text('[data-role="offer-title"]'), "Save in Ferret?", channel);
      assert.equal(await w.page.text('[data-role="offer-host"]'), "forms.example.net", channel);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="offer-password"]')?.value), "", `${channel}: the password is hidden`);
      assert.equal((await w.session.content(() => document.body.textContent ?? "")).includes(password), false, `${channel}: no password in the popup`);
      // The focus did not start on a button that writes.
      const focused = await w.session.content(() => document.activeElement?.getAttribute("data-role") ?? document.activeElement?.tagName ?? "");
      assert.ok(!["offer-save", "offer-update", "offer-not-now", "offer-never"].includes(focused), `${channel}: the focus is on ${focused}`);
      assert.equal(await w.page.text('[data-role="tab-generator"]'), "Generator", `${channel}: the bar has the generator in the test build`);

      // The name: the host, changed with real keys.
      const name = `Offer-save-${unique}`;
      const [nameField] = await w.session.findAll('[data-role="offer-name"]');
      await w.session.content(() => {
        const input = /** @type {HTMLInputElement} */ (document.querySelector('[data-role="offer-name"]'));
        input.value = "";
        input.focus();
      });
      await w.session.type(nameField, name);
      await w.page.click('[data-role="offer-save"]');
      await w.page.waitVisible('[data-role="offer-result"]', SLOW);
      assert.ok(["Saved.", "Saved. Waiting for sync."].includes(await w.page.text('[data-role="offer-result"]')), channel);
      // Used once: the offers of the tab are gone.
      await w.session.switchTo(w.pageTab);
      assert.deepEqual((await offersPeek(w, tabId)).offers, [], `${channel}: the offer is used up`);

      // The web vault lists the new item, with the page's origin as its address.
      await w.session.switchTo(w.vaultTab);
      await w.session.navigate(`${(await w.session.currentUrl()).split("#")[0]}#/items`);
      await w.page.waitVisible('[data-role="list"]', SLOW);
      await w.session.waitFor(async () => (await w.page.text('[data-role="list"]')).includes(name), 60_000, "the web vault lists the saved item");
      await w.session.switchTo(handle).catch(() => {});
    } finally {
      await w.quit();
    }
  }
});

test("change_password_on_the_fixture_update_and_see_the_old_one_under_previous_passwords", async () => {
  const [base] = casesOf("corpus", "change-two-fr");
  assert.equal(base?.id, "change-two-fr");
  for (const channel of channels()) {
    const w = await ready(channel);
    try {
      const unique = randomBytes(3).toString("hex");
      const c = structuredClone(base);
      const next = `Zq7!chg-${unique}-Vm4$`;
      c.steps = c.steps.map((/** @type {any} */ s) => (s.type === "#new" ? { ...s, text: next } : s));
      const result = await captureCase(w, c);
      assert.equal(result.error, undefined, `${channel}: ${result.error}`);
      assert.equal(result.observed?.offers.length, 1, `${channel}: one offer (${JSON.stringify(result.observed?.offers)})`);
      assert.equal(result.observed?.offers[0].type, "update", channel);
      assert.equal(result.observed?.vault_changed, false, `${channel}: nothing was written before the click`);
      const tabId = await newestTab(w);
      const entryName = w.named.forms;
      const oldPassword = w.passwords.forms;

      const handle = await popupWithCard(w, tabId, "update");
      assert.equal(await w.page.text('[data-role="offer-title"]'), "Update the password?", channel);
      assert.equal(await w.page.text('[data-role="offer-target-name"]'), entryName, `${channel}: the card names the item`);
      assert.equal((await w.session.content(() => document.body.textContent ?? "")).includes(next), false, `${channel}: no password in the popup`);
      await w.page.click('[data-role="offer-update"]');
      await w.page.waitVisible('[data-role="offer-result"]', SLOW);
      assert.ok(["Updated.", "Updated. Waiting for sync."].includes(await w.page.text('[data-role="offer-result"]')), channel);

      // The web vault: the item shows the old password under "Previous passwords", once the update has reached it.
      await w.session.switchTo(w.vaultTab);
      const base_ = (await w.session.currentUrl()).split("#")[0];
      await w.session.navigate(`${base_}#/items`);
      await w.page.waitVisible('[data-role="list"]', SLOW);
      const href = await w.session.waitFor(
        () => w.session.content((/** @type {string} */ wanted) => [...document.querySelectorAll('[data-role="list"] a[href^="#/items/"]')].find((a) => (a.textContent ?? "").includes(wanted))?.getAttribute("href") ?? null, entryName),
        60_000,
        "the item in the list",
      );
      await w.session.waitFor(async () => {
        await w.session.navigate(`${base_}#/items`);
        await w.page.waitVisible('[data-role="list"]', SLOW);
        await w.session.navigate(`${base_}${href}`);
        await w.page.waitVisible('[data-role="item"] h1', SLOW);
        return w.page.visible('[data-card="history"]');
      }, 90_000, "the previous passwords card");
      const [reveal] = await w.session.findAll('[data-card="history"] [data-role="reveal"]');
      assert.ok(reveal, `${channel}: the earlier password can be shown`);
      await w.session.click(reveal);
      const shown = await w.session.waitFor(async () => {
        const text = await w.session.content(() => document.querySelector('[data-card="history"] [data-role="value"]')?.textContent?.trim() ?? "");
        return text !== "" && !/^[•*]+$/.test(text) ? text : null;
      }, 20_000, "the shown earlier password");
      assert.equal(shown, oldPassword, `${channel}: the old password is the one under Previous passwords`);
      await w.session.switchTo(handle).catch(() => {});
    } finally {
      await w.quit();
    }
  }
});

test("the_popup_bottom_bar_shows_vault_generator_and_settings_and_settings_opens_in_the_popup", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { grant: [], entries: ENTRIES });
    try {
      const tabId = await newestTab(w);
      const handle = await w.session.newWindow();
      await w.session.switchTo(handle);
      await w.session.navigate(`${POPUP_URL}?tab=${tabId}`);
      await w.page.ready();
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      const roles = await w.session.content(() => [...document.querySelectorAll('[data-role="tabs"] button')].map((b) => b.getAttribute("data-role")));
      assert.deepEqual(roles, ["tab-vault", "tab-generator", "tab-health", "tab-settings"], channel);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="tab-health"]')?.getAttribute("aria-disabled")), "true", `${channel}: Health is not available yet`);
      assert.equal(await w.page.text('[data-role="tab-soon"]'), "Coming soon", channel);
      await w.page.click('[data-role="tab-health"]');
      assert.equal(await w.session.content(() => document.querySelector('[data-role="tab-vault"]')?.getAttribute("aria-current")), "page", `${channel}: a click on Health changes nothing`);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="tab-vault"]')?.getAttribute("aria-current")), "page", `${channel}: the vault is marked`);
      await w.page.click('[data-role="tab-generator"]');
      assert.equal(await w.session.content(() => document.querySelector('[data-role="tab-generator"]')?.getAttribute("aria-current")), "page", channel);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="tab-vault"]')?.hasAttribute("aria-current")), false, channel);
      const before = (await w.session.windowHandles()).length;
      await w.page.click('[data-role="tab-settings"]');
      // Settings is a part of the popup: the view is shown in it, the bar marks it, and no tab or window opens.
      await w.page.waitVisible('[data-role="settings-view"]', SLOW);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="tab-settings"]')?.getAttribute("aria-current")), "page", `${channel}: the settings item is marked`);
      assert.equal(await w.session.content(() => document.querySelector('[data-role="tab-generator"]')?.hasAttribute("aria-current")), false, channel);
      await w.session.waitFor(() => w.session.content(() => document.querySelector('[data-role="lock-after"]')?.value !== ""), 20_000, "the lock choice");
      await sleep(1_000);
      assert.equal((await w.session.windowHandles()).length, before, `${channel}: Settings opens no tab or window`);
      assert.equal(await w.session.content(() => location.pathname), "/pages/popup.html", channel);
    } finally {
      await w.quit();
    }
  }
});

test("offer_to_save_is_turned_on_and_off_from_the_settings_part_of_the_popup", async () => {
  for (const channel of channels()) {
    const w = await world(channel, { grant: [], entries: ENTRIES });
    try {
      const tabId = await newestTab(w);
      const handle = await w.session.newWindow();
      await w.session.switchTo(handle);
      await w.session.navigate(`${POPUP_URL}?tab=${tabId}`);
      await w.page.ready();
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      await w.page.click('[data-role="tab-settings"]');
      await w.page.waitVisible('[data-role="capture-switch"]', SLOW);
      const on = () => w.session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked"));
      const https = () => w.session.content(() => browser.permissions.contains({ origins: ["https://*/*"] }));
      await w.session.waitFor(async () => (await on()) === "false", 20_000, "the switch is read");
      assert.equal(await https(), false, `${channel}: no access to https pages before`);
      const before = (await w.session.windowHandles()).length;
      // A real click: the access is asked for in the click (the test profile gives it without a prompt), then the setting goes on.
      await w.page.click('[data-role="capture-switch"]');
      await w.session.waitFor(async () => (await on()) === "true", 20_000, "the switch on");
      assert.equal(await https(), true, `${channel}: the access to https pages is given`);
      assert.match(await w.page.text('[data-role="capture-state"]'), /^On\./, channel);
      // The same state is on the settings page of the add-on (one setting, two places), and it is kept when the popup is built again.
      await w.session.navigate(`${POPUP_URL}?tab=${tabId}`);
      await w.page.ready();
      await w.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      await w.page.click('[data-role="tab-settings"]');
      await w.session.waitFor(async () => (await on()) === "true", 20_000, "the switch on after a new popup");
      // Off again: the setting goes, and so does the access.
      await w.page.click('[data-role="capture-switch"]');
      await w.session.waitFor(async () => (await on()) === "false", 20_000, "the switch off");
      await w.session.waitFor(async () => (await https()) === false, 20_000, "the access taken back");
      assert.equal((await w.session.windowHandles()).length, before, `${channel}: no tab or window was opened`);
      // The lock choice is saved from the popup too.
      await w.session.content(() => {
        const node = /** @type {HTMLSelectElement} */ (document.querySelector('[data-role="lock-after"]'));
        node.value = "3600";
        node.dispatchEvent(new Event("change", { bubbles: true }));
      });
      await w.session.waitFor(async () => (await w.page.text('[data-role="saved"]')) === "Saved.", 20_000, "the lock choice saved");
    } finally {
      await w.quit();
    }
  }
});
