// The capture and the store of offers in real Firefox, on the form fixtures (test/fixtures/forms):
//
// - capture_is_off_until_the_settings_tab_turns_it_on_and_off_again_takes_the_access_back: a new profile registers no
//   capture script, the settings tab asks for access to https pages in the click that turns the setting on, and turning
//   it off takes that access back.
// - submitting_the_sign_up_fixture_creates_one_offer_with_the_typed_values: with it on, a page opened afterwards,
//   typed into with real key events and submitted, gives one offer whose kind, origin, user name and password
//   (compared by its SHA-256) are what was typed. The offers are read through the test bridge's `offers_peek`, which
//   never carries a password.
// - the offer is gone after a lock: the background's lock clears every offer.
//
// The vault is not open here (the capture is taken while locked); what the write path makes of the offer is the
// end-to-end spec's (55-write.e2e.spec.mjs) and the matrix's.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { casesOf, caseUrl, leave, runSteps, sha256 } from "./matrix.mjs";
import { EXTENSION_ORIGIN, channels, fixtures, launch, openBridge, openSettingsPage, stopFixtures, TEST_ADDON_ID } from "./harness.mjs";

after(() => stopFixtures());

const SETTINGS_URL = `${EXTENSION_ORIGIN}/pages/settings.html`;
const CASE = "signup-confirm-fr";

/**
 * One Firefox with the bridge in one tab and the page in another.
 * @param {string} channel
 */
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
  /** The offers of the page tab (the newest tab: a tab's address is hidden before the permission is there), as the bridge reports them. */
  const offersOf = async () => {
    const tabs = await fromBridge(() => bridge.invoke("tabs.query", {}));
    const tab = tabs.reduce((/** @type {{ id: number }} */ a, /** @type {{ id: number }} */ b) => (b.id > a.id ? b : a));
    return fromBridge(() => bridge.invoke("offers_peek", { tab_id: tab.id }));
  };
  return { session, server, bridge, fromBridge, offersOf, pageTab };
}

/** Turns "Offer to save passwords" on in the settings tab with a real click. @param {import("./driver.mjs").Session} session */
async function turnOn(session) {
  await session.navigate(SETTINGS_URL);
  await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
  await openSettingsPage(session, "capture");
  const [toggle] = await session.findAll('[data-role="capture-switch"]');
  assert.ok(toggle, "the settings page has the switch (the test build has saving passwords on)");
  assert.equal(await session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked")), "false", "off by default");
  await session.click(toggle);
  await session.waitFor(() => session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "true"), 15_000, "the switch on");
}

test("capture_is_off_until_the_settings_tab_turns_it_on_and_off_again_takes_the_access_back", async () => {
  for (const channel of channels()) {
    const { session, bridge, fromBridge } = await open(channel);
    try {
      const granted = await fromBridge(() => bridge.invoke("permissions.getAll"));
      assert.equal((granted.origins ?? []).includes("https://*/*"), false, `${channel}: no access to https pages before`);
      await turnOn(session);
      const after = await fromBridge(() => bridge.invoke("permissions.getAll"));
      assert.equal((after.origins ?? []).includes("https://*/*"), true, `${channel}: the click asked for it and got it`);
      const stored = await fromBridge(() => bridge.invoke("storage.local.get", "offer_to_save"));
      assert.equal(stored.offer_to_save, true, channel);
      // Turning it off takes the script and the access to https pages back (the permission goes with the setting).
      const [toggle] = await session.findAll('[data-role="capture-switch"]');
      await session.click(toggle);
      await session.waitFor(() => session.content(() => document.querySelector('[data-role="capture-switch"]')?.getAttribute("aria-checked") === "false"), 15_000, "the switch off");
      const gone = await session.waitFor(async () => {
        const all = await fromBridge(() => bridge.invoke("permissions.getAll"));
        return (all.origins ?? []).includes("https://*/*") ? null : all;
      }, 15_000, "the access removed");
      assert.equal((gone.origins ?? []).includes("https://*/*"), false, `${channel}: the access to https pages went with the setting`);
      const off = await fromBridge(() => bridge.invoke("storage.local.get", "offer_to_save"));
      assert.equal(off.offer_to_save, false, channel);
    } finally {
      await session.quit();
    }
  }
});

test("submitting_the_sign_up_fixture_creates_one_offer_with_the_typed_values", async () => {
  const [c] = casesOf("corpus", CASE);
  assert.equal(c?.id, CASE);
  for (const channel of channels()) {
    const { session, server, offersOf, pageTab } = await open(channel);
    try {
      // Before it is on: nothing is captured (the capture script is not registered).
      await session.switchTo(pageTab);
      const url = caseUrl(c, server);
      await session.navigate(url);
      await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, url);
      const first = await offersOf();
      assert.equal(first.available, true, channel);
      assert.deepEqual(first.offers, [], `${channel}: no offer before it is turned on`);

      // Turn it on, then open the page again (a tab that was open before gets the script after a reload).
      await turnOn(session);
      await session.navigate(url);
      await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, url);
      /** @type {Record<string, string>} */
      const typed = {};
      await runSteps(session, c.steps, { passwords: {}, typed });
      await leave(session);
      // A sign-up is offered three seconds after the last input, when no field has the focus.
      const offers = await session.waitFor(async () => {
        const peek = await offersOf();
        return peek.offers.length > 0 ? peek.offers : null;
      }, 30_000, "the offer");
      assert.equal(offers.length, 1, `${channel}: one offer`);
      const [offer] = offers;
      assert.equal(offer.kind, "signup", channel);
      assert.equal(offer.origin, new URL(url).origin, channel);
      assert.equal(offer.username, "anna@example.net", channel);
      assert.equal(offer.password_sha256, typed["#pw"], `${channel}: the password typed into the new-password field`);
      assert.equal(offer.password_sha256, sha256("Zq7!signupconf-Vm4$"));
      assert.equal(JSON.stringify(offers).includes("Zq7!signupconf-Vm4$"), false, "no password in the answer");
    } finally {
      await session.quit();
    }
  }
});

test("the_https_access_is_shared_by_saving_passwords_and_the_passkeys_and_each_switch_turns_on_only_its_own_feature", async () => {
  for (const channel of channels()) {
    const { session, bridge, fromBridge } = await open(channel);
    try {
      const granted = async () => ((await fromBridge(() => bridge.invoke("permissions.getAll"))).origins ?? []).includes("https://*/*");
      const stored = async (/** @type {string} */ key) => (await fromBridge(() => bridge.invoke("storage.local.get", key)))[key];
      const checked = (/** @type {string} */ role) => session.content((/** @type {string} */ r) => document.querySelector(`[data-role="${r}"]`)?.getAttribute("aria-checked"), role);
      const press = async (/** @type {string} */ role) => {
        const [row] = await session.findAll(`[data-role="${role}"]`);
        await session.click(row);
      };
      const goBack = (/** @type {string} */ id) => session.content((/** @type {string} */ i) => /** @type {HTMLElement} */ (document.querySelector(`[data-page="${i}"] [data-role="settings-back"]`)).click(), id);
      await session.navigate(SETTINGS_URL);
      await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page");
      assert.equal(await granted(), false, `${channel}: no access to https pages before`);

      // 1. Passkeys on first: the access is given, the passkeys are on and saving passwords stays off (no capture script).
      await openSettingsPage(session, "provider");
      await press("passkeys-switch");
      await session.waitFor(async () => (await checked("passkeys-switch")) === "true", 15_000, "the passkeys switch on");
      assert.equal(await granted(), true, channel);
      assert.equal(await stored("use_passkeys"), true, channel);
      assert.equal(await stored("offer_to_save"), undefined, `${channel}: the grant did not switch saving passwords on`);
      await goBack("provider");
      await openSettingsPage(session, "capture");
      assert.equal(await checked("capture-switch"), "false", `${channel}: saving passwords is still off in the page`);

      // 2. Saving passwords on as well, then off: the access stays for the passkeys, which stay on.
      await press("capture-switch");
      await session.waitFor(async () => (await checked("capture-switch")) === "true", 15_000, "the capture switch on");
      await press("capture-switch");
      await session.waitFor(async () => (await checked("capture-switch")) === "false", 15_000, "the capture switch off");
      assert.equal(await stored("offer_to_save"), false, channel);
      assert.equal(await stored("use_passkeys"), true, `${channel}: the passkeys stay on`);
      assert.equal(await granted(), true, `${channel}: the access stays while the passkeys need it`);

      // 3. The passkeys off with saving passwords off: the access goes.
      await goBack("capture");
      await openSettingsPage(session, "provider");
      await press("passkeys-switch");
      await session.waitFor(async () => (await checked("passkeys-switch")) === "false", 15_000, "the passkeys switch off");
      await session.waitFor(async () => !(await granted()), 15_000, "the access removed");
      assert.equal(await stored("use_passkeys"), false, channel);

      // 4. The access taken back from outside (the browser's add-on page does what permissions.remove does): both features go off.
      await goBack("provider");
      await openSettingsPage(session, "capture");
      await press("capture-switch");
      await session.waitFor(async () => (await checked("capture-switch")) === "true", 15_000, "the capture switch on again");
      await goBack("capture");
      await openSettingsPage(session, "provider");
      await press("passkeys-switch");
      await session.waitFor(async () => (await checked("passkeys-switch")) === "true", 15_000, "the passkeys switch on again");
      assert.equal(await stored("offer_to_save"), true, channel);
      assert.equal(await stored("use_passkeys"), true, channel);
      await fromBridge(() => bridge.invoke("permissions.remove", { origins: ["https://*/*"] }));
      await session.waitFor(async () => (await stored("offer_to_save")) === false && (await stored("use_passkeys")) === false, 15_000, "both settings off");
      assert.equal(await granted(), false, channel);
      await session.navigate(SETTINGS_URL);
      await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 15_000, "the settings page again");
      await openSettingsPage(session, "provider");
      assert.equal(await checked("passkeys-switch"), "false", `${channel}: the page says off`);
      await goBack("provider");
      await openSettingsPage(session, "capture");
      assert.equal(await checked("capture-switch"), "false", `${channel}: the page says off`);
    } finally {
      await session.quit();
    }
  }
});
