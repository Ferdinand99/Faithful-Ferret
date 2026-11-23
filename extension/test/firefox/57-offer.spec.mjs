// The offer in Ferret's own UI in real Firefox, on the form fixtures (test/fixtures/forms), with the vault locked:
//
// - the_badge_shows_on_the_offer_tab_and_the_popup_shows_no_offer_before_the_vault_is_open: with "Offer to save passwords"
//   on, a sign-up form that is submitted gives an offer while the vault is locked (a capture is taken then). The toolbar
//   button shows "1" on that tab and on no other, and the popup about that tab shows no offer while the vault is not open (it is not even
//   signed in here: the sign-in and unlock views come first).
// - the_settings_page_has_the_switch_for_the_popup_that_opens_by_itself: the switch is there, on by default, and turning it
//   off is kept.
//
// What the cards do with an unlocked vault is the end-to-end spec's (57-offer.e2e.spec.mjs).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { casesOf, caseUrl, leave, runSteps } from "./matrix.mjs";
import { EXTENSION_ORIGIN, channels, fixtures, launch, openBridge, stopFixtures, TEST_ADDON_ID } from "./harness.mjs";

after(() => stopFixtures());

const SETTINGS_URL = `${EXTENSION_ORIGIN}/pages/settings.html`;
const POPUP_URL = `${EXTENSION_ORIGIN}/pages/popup.html`;
const CASE = "signup-confirm-fr";

/** One Firefox with the bridge in one tab and the page in another. @param {string} channel */
async function open(channel) {
  const server = await fixtures();
  const session = await launch({ channel });
  await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
  const bridgeTab = await session.windowHandle();
  const bridge = await openBridge(session);
  const pageTab = await session.newTab();
  await session.switchTo(pageTab);
  /** Runs `body` in the bridge tab and goes back to the page tab. @template T @param {() => Promise<T>} body */
  const fromBridge = async (body) => {
    await session.switchTo(bridgeTab);
    try {
      return await body();
    } finally {
      await session.switchTo(pageTab);
    }
  };
  return { session, server, bridge, bridgeTab, fromBridge, pageTab };
}

/** Turns "Offer to save passwords" on in the settings tab with a real click. @param {import("./driver.mjs").Session} session */
async function turnOn(session) {
  await session.navigate(SETTINGS_URL);
  await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
  const [toggle] = await session.findAll('[data-role="capture-switch"]');
  assert.ok(toggle, "the settings page has the switch");
  await session.click(toggle);
  await session.waitFor(() => session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "true"), 15_000, "the switch on");
}

test("the_badge_shows_on_the_offer_tab_and_the_popup_shows_no_offer_before_the_vault_is_open", async () => {
  const [c] = casesOf("corpus", CASE);
  assert.equal(c?.id, CASE);
  for (const channel of channels()) {
    const { session, server, bridge, fromBridge, pageTab } = await open(channel);
    try {
      await turnOn(session);
      const url = caseUrl(c, server);
      await session.navigate(url);
      await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, url);
      /** @type {Record<string, string>} */
      const typed = {};
      await runSteps(session, c.steps, { passwords: {}, typed });
      await leave(session);
      const tabs = await fromBridge(() => bridge.invoke("tabs.query", {}));
      const tab = tabs.reduce((/** @type {{ id: number }} */ a, /** @type {{ id: number }} */ b) => (b.id > a.id ? b : a));
      // A sign-up is offered three seconds after the last input: the button then shows how many offers wait on this tab.
      const text = await session.waitFor(async () => {
        const shown = await fromBridge(() => bridge.invoke("action.getBadgeText", { tab_id: tab.id }));
        return shown === "1" ? shown : null;
      }, 30_000, "the badge");
      assert.equal(text, "1", `${channel}: the offer's tab shows the number`);
      const other = tabs.find((/** @type {{ id: number }} */ t) => t.id !== tab.id);
      if (other) assert.ok(["", null].includes(await fromBridge(() => bridge.invoke("action.getBadgeText", { tab_id: other.id }))), `${channel}: no other tab shows one`);

      // The popup about that tab: the vault is not open (this browser is not signed in), so it shows a sign-in or unlock view and no offer.
      const popupTab = await session.newTab();
      await session.switchTo(popupTab);
      await session.navigate(`${POPUP_URL}?tab=${tab.id}`);
      await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 20_000, "the popup");
      assert.equal(await session.content(() => document.querySelector('[data-role="unlocked-view"]') === null), true, `${channel}: the vault is not open`);
      assert.equal(await session.content(() => document.querySelector('[data-role="offer-card"]') === null), true, `${channel}: no offer is shown before the unlock`);
      await session.closeTab();
      await session.switchTo(pageTab);
    } finally {
      await session.quit();
    }
  }
});

test("the_settings_page_has_the_switch_for_the_popup_that_opens_by_itself", async () => {
  for (const channel of channels()) {
    const { session } = await open(channel);
    try {
      await session.navigate(SETTINGS_URL);
      await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
      const state = () => session.content(() => document.querySelector('[data-role="auto-open-switch"]')?.getAttribute("aria-checked"));
      assert.equal(await state(), "true", `${channel}: on by default`);
      const [toggle] = await session.findAll('[data-role="auto-open-switch"]');
      await session.click(toggle);
      await session.waitFor(async () => (await state()) === "false", 15_000, "the switch off");
      await session.navigate(SETTINGS_URL);
      await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page again");
      assert.equal(await state(), "false", `${channel}: the choice is kept`);
    } finally {
      await session.quit();
    }
  }
});
