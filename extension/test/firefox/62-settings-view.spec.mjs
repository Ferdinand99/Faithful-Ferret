// The settings view in real Firefox (no server needed): the main screen of grouped rows, a sub-page opened from a row and left by
// its back button with the focus returning to the row, and a switch that is told apart in colour, place of the knob and words and
// that the keyboard operates. What the unit tests cannot see: the CSS (a hidden page is not drawn, nothing overflows, the on and
// off switch look different) and a real Space and Enter on a focused row.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { shotPath } from "./adversary.mjs";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, channels, launch, openSettingsPage, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/** The keys of the WebDriver protocol: real key presses on the focused element. */
const SPACE = String.fromCharCode(0xe00d);
const ENTER = String.fromCharCode(0xe007);
const SETTINGS_URL = `${EXTENSION_ORIGIN}/pages/settings.html`;

/** What the page shows of one switch row: the state, the words, and how the track and the knob are drawn. @param {import("./driver.mjs").Session} session @param {string} role */
const look = (session, role) =>
  session.content(async (/** @type {string} */ r) => {
    const row = /** @type {HTMLElement} */ (document.querySelector(`[data-role="${r}"]`));
    // The switch animates its track and knob: read the colours and the place only when the transitions are done.
    await Promise.all(row.getAnimations({ subtree: true }).map((a) => a.finished.catch(() => {})));
    const track = /** @type {HTMLElement} */ (row.querySelector(".ff-switch-track"));
    const knob = /** @type {HTMLElement} */ (row.querySelector(".ff-switch-knob"));
    return {
      checked: row.getAttribute("aria-checked"),
      words: row.querySelector(".ff-switch-text")?.textContent ?? "",
      trackColor: getComputedStyle(track).backgroundColor,
      knobShift: knob.getBoundingClientRect().left - track.getBoundingClientRect().left,
      knobColor: getComputedStyle(knob).backgroundColor,
    };
  }, role);

test("the_settings_view_shows_groups_opens_a_page_and_its_switches_tell_on_from_off", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      await session.navigate(SETTINGS_URL);
      await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 20_000, "the settings page");
      // The main screen: the rows in their groups, and no page.
      const main = await session.content(() => ({
        rows: [...document.querySelectorAll('[data-role="settings-main"] .ff-nav-row')].map((b) => b.getAttribute("data-role")),
        groups: [...document.querySelectorAll(".ff-sgroup-title")].map((h) => h.textContent),
        pagesShown: [...document.querySelectorAll('[data-role="settings-page"]')].filter((p) => p.getClientRects().length > 0).length,
        overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      }));
      assert.deepEqual(main.rows, ["settings-row-capture", "settings-row-never", "settings-row-pin", "settings-row-passkeys", "settings-row-provider", "settings-row-provider-never", "settings-row-lock", "settings-row-credits"], channel);
      assert.deepEqual(main.groups, ["Filling and saving", "Unlocking", "Passkeys on websites", "Security", "About"], channel);
      assert.equal(main.pagesShown, 0, `${channel}: a page that is hidden is not drawn`);
      assert.equal(main.overflow, false, `${channel}: nothing pushes the page wider`);

      // A row opens its page; the main screen is gone and the heading has the focus.
      await openSettingsPage(session, "capture");
      assert.equal(await session.content(() => document.querySelector('[data-role="settings-main"]')?.getClientRects().length), 0, channel);
      assert.equal(await session.content(() => document.activeElement?.getAttribute("data-role")), "settings-page-title", `${channel}: the focus is on the heading`);

      // A switch: the same row says On or Off in words, with another colour and another place of the knob.
      const before = await look(session, "auto-open-switch");
      assert.equal(before.checked, "true", `${channel}: on by default`);
      assert.equal(before.words, "On", channel);
      // The keyboard: the row is a button, so Space turns it and Enter turns it back.
      const [row] = await session.findAll('[data-role="auto-open-switch"]');
      await session.type(row, SPACE);
      await session.waitFor(async () => (await look(session, "auto-open-switch")).checked === "false", 15_000, "Space turned the switch off");
      const off = await look(session, "auto-open-switch");
      assert.equal(off.words, "Off", channel);
      assert.notEqual(off.trackColor, before.trackColor, `${channel}: the track is another colour`);
      assert.notEqual(off.knobColor, before.knobColor, `${channel}: the knob is another colour`);
      assert.ok(Math.abs(off.knobShift - before.knobShift) > 8, `${channel}: the knob has moved (${before.knobShift} to ${off.knobShift})`);
      await session.type(row, ENTER);
      await session.waitFor(async () => (await look(session, "auto-open-switch")).checked === "true", 15_000, "Enter turned the switch on");

      // "More about this" is closed, and opens with its whole text.
      assert.equal(await session.content(() => document.querySelector('[data-page="capture"] [data-role="more"]')?.hasAttribute("open")), false, channel);
      const moreHeight = () => session.content(() => /** @type {HTMLElement} */ (document.querySelector('[data-page="capture"] [data-role="more"]')).getBoundingClientRect().height);
      const closedHeight = await moreHeight();
      await session.content(() => /** @type {HTMLElement} */ (document.querySelector('[data-page="capture"] [data-role="more"] summary')).click());
      assert.equal(await session.content(() => document.querySelector('[data-page="capture"] [data-role="more"]')?.hasAttribute("open")), true, channel);
      assert.ok((await moreHeight()) > closedHeight + 40, `${channel}: the long text takes room only when opened`);
      assert.equal(await session.content(() => document.querySelector('[data-role="capture-why"]')?.checkVisibility()), true, `${channel}: and is visible then`);

      // Back: the main screen again, with the focus on the row that opened the page.
      await session.content(() => /** @type {HTMLElement} */ (document.querySelector('[data-page="capture"] [data-role="settings-back"]')).click());
      await session.waitFor(() => session.content(() => (document.querySelector('[data-role="settings-main"]')?.getClientRects().length ?? 0) > 0), 10_000, "the main screen");
      assert.equal(await session.content(() => document.activeElement?.getAttribute("data-role")), "settings-row-capture", `${channel}: the focus is back on the row`);

      // The passkeys page: the switch and the recent-unlock choice, as switches that tell on from off, and the never list behind its own row.
      await openSettingsPage(session, "provider");
      const provider = await session.content(() => ({
        switches: [...document.querySelectorAll('[data-page="provider"] [role="switch"]')].map((b) => [b.getAttribute("data-role"), b.getAttribute("aria-checked")]),
        title: document.querySelector('[data-page="provider"] [data-role="settings-page-title"]')?.textContent,
        feature: document.querySelector('[data-page="provider"]')?.getAttribute("data-feature"),
      }));
      assert.deepEqual(provider.switches, [["passkeys-switch", "false"], ["passkeys-recent-switch", "true"]], channel);
      assert.equal(provider.title, "Passkeys in Ferret", channel);
      assert.equal(provider.feature, "passkeys", channel);
      assert.equal(await session.content(() => document.querySelector('[data-role="passkeys-recent-switch"]')?.getClientRects().length), 0, `${channel}: the recent-unlock row is not drawn while the passkeys are off`);
      await session.screenshot(shotPath(channel, "ext-settings-passkeys"));
      await session.content(() => /** @type {HTMLElement} */ (document.querySelector('[data-page="provider"] [data-role="settings-back"]')).click());
      await openSettingsPage(session, "provider-never");
      await session.screenshot(shotPath(channel, "ext-settings-passkeys-never"));
      assert.equal(await session.content(() => document.querySelector('[data-role="passkeys-never-empty"]')?.getClientRects().length > 0), true, `${channel}: an empty list says so`);
      await session.content(() => /** @type {HTMLElement} */ (document.querySelector('[data-page="provider-never"] [data-role="settings-back"]')).click());

      // The lock is a compact row with the select on the right, and the row of the main screen says the choice.
      await openSettingsPage(session, "lock");
      const lock = await session.content(() => {
        const select = /** @type {HTMLSelectElement} */ (document.querySelector('[data-role="lock-after"]'));
        const card = /** @type {HTMLElement} */ (document.querySelector('[data-role="lock-card"]'));
        return { selectLeft: select.getBoundingClientRect().left, cardMid: card.getBoundingClientRect().left + card.getBoundingClientRect().width / 2, value: select.selectedOptions[0]?.textContent };
      });
      assert.ok(lock.selectLeft > lock.cardMid - 60, `${channel}: the select sits on the right of its card`);
      assert.equal(lock.value, "15 minutes", channel);
    } finally {
      await session.quit();
    }
  }
});
