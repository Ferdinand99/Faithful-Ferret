// The lock in real Firefox: a restart of the browser and an end of the background
// page both leave the vault locked with no deadline, and the settings page opens
// in a tab and keeps "Lock after" over a restart. These need no server: the
// test build can open the vault without a password (the lifetime measurement's
// `idle` scenario does), which starts the vault worker and the deadline as a
// real unlock does. That the popup then asks for the password is a test against
// the end-to-end stack (60-lock.e2e.spec.mjs).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, channels, launch, openBridge, stopFixtures } from "./harness.mjs";
import { openMeasurePage, portCommand, startScenario } from "./measure.mjs";

after(() => stopFixtures());

const MANIFESTS = /** @type {const} */ (["mv3", "mv2"]);
const SETTINGS_URL = `${EXTENSION_ORIGIN}/pages/settings.html`;

/** @typedef {import("./driver.mjs").Session} Session */

/**
 * Opens the vault the way the test build can and returns what the background says: the host's state and the deadline.
 * @param {Session} session
 */
async function openVault(session) {
  await session.waitFor(async () => (await session.backgroundState(TEST_ADDON_ID)) === "running", 30_000, "a running background");
  const tab = await session.newTab();
  await session.switchTo(tab);
  await startScenario(session, "idle");
  return readState(session);
}

/** @param {Session} session @returns {Promise<{ core: string, lockAt: number | null }>} */
async function readState(session) {
  const state = await portCommand(session, { cmd: "state" });
  return { core: state.core, lockAt: typeof state.lockAt === "number" ? state.lockAt : null };
}

/** The selected setting and the saved note of the settings page, once it has built itself. @param {Session} session */
async function readSettingsPage(session) {
  await session.waitFor(() => session.content(() => document.body?.dataset.ready === "1"), 20_000, "the settings page");
  const json = await session.content(() => {
    const select = /** @type {HTMLSelectElement | null} */ (document.querySelector("[data-role=lock-after]"));
    const saved = document.querySelector("[data-role=saved]");
    const error = document.querySelector("[data-role=error]");
    const choices = [];
    for (const option of document.querySelectorAll("[data-role=lock-after] option")) choices.push(option.getAttribute("value"));
    return JSON.stringify({
      value: select ? select.value : null,
      choices,
      saved: saved ? (saved.textContent || "").trim() : "",
      error: error && !error.hidden ? error.textContent || "" : "",
    });
  });
  return JSON.parse(json);
}

test("restart_of_the_browser_starts_locked", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      const where = `${channel} ${manifest}`;
      const session = await launch({ channel, manifest });
      try {
        const before = await openVault(session);
        assert.equal(before.core, "unlocked", `${where}: the vault is open`);
        assert.equal(typeof before.lockAt, "number", `${where}: and has its deadline`);

        // The browser ends and starts again on the same profile (the add-on is installed for good, not temporarily).
        await session.restart();
        await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active, 30_000, `${where}: the add-on after the restart`);
        await openMeasurePage(session);
        const afterwards = await readState(session);
        assert.equal(afterwards.core, "locked", `${where}: a new start is locked`);
        assert.equal(afterwards.lockAt, null, `${where}: with no deadline left from before`);
      } finally {
        await session.quit();
      }
    }
  }
});

test("killed_background_comes_back_locked_and_asks_for_the_password", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      const where = `${channel} ${manifest}`;
      const session = await launch({ channel, manifest });
      try {
        const before = await openVault(session);
        assert.equal(before.core, "unlocked", `${where}: the vault is open`);
        // The browser ends the background the way the Terminate button of about:debugging does.
        const state = await session.terminateBackground(TEST_ADDON_ID);
        assert.notEqual(state, "running", `${where}: the background was ended (${state})`);
        // The next message wakes it: no vault, no deadline, and a call that needs the vault is refused (the popup then shows the
        // unlock view, which asks for the master password only; the end-to-end stack shows that).
        const afterwards = await readState(session);
        assert.equal(afterwards.core, "locked", `${where}: it comes back locked`);
        assert.equal(afterwards.lockAt, null, `${where}: no deadline`);
        const reply = await session.content(
          () =>
            new Promise((resolve) => {
              const port = browser.runtime.connect({ name: "ferret-ui" });
              port.onMessage.addListener((raw) => {
                port.disconnect();
                resolve(JSON.parse(raw));
              });
              port.postMessage(JSON.stringify({ v: 1, id: "k1", type: "sync_retry", body: {} }));
            }),
        );
        assert.deepEqual([reply.type, reply.body], ["refused", { reason: "vault_locked" }], `${where}: a call after the kill never reaches a worker`);
      } finally {
        await session.quit();
      }
    }
  }
});

test("settings_open_in_a_tab", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      const where = `${channel} ${manifest}`;
      const session = await launch({ channel, manifest });
      try {
        await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
        const first = await session.windowHandle();
        await openBridge(session);
        // What the add-on manager's "Preferences" button does.
        await session.execute(async () => {
          await browser.runtime.openOptionsPage();
        });
        const tab = await session.waitFor(async () => (await session.windowHandles()).find((h) => h !== first), 20_000, `${where}: a tab for the settings`);
        await session.switchTo(tab);
        // A new tab is about:blank for a moment.
        await session.waitFor(async () => (await session.currentUrl()) === SETTINGS_URL, 20_000, `${where}: the settings open in a tab of their own`);

        // The default, and exactly the ten choices.
        const page = await readSettingsPage(session);
        assert.equal(page.value, "900", `${where}: 15 minutes by default`);
        assert.deepEqual(page.choices, ["15", "30", "60", "300", "900", "1800", "3600", "14400", "28800", "86400"], where);

        // A choice saves, and the page asks the background again when it is opened anew.
        await session.content(() => {
          const select = /** @type {HTMLSelectElement} */ (document.querySelector('[data-role="lock-after"]'));
          select.value = "30";
          select.dispatchEvent(new Event("change", { bubbles: true }));
        });
        await session.waitFor(async () => (await readSettingsPage(session)).saved !== "", 20_000, `${where}: saved`);
        await session.navigate(SETTINGS_URL);
        assert.equal((await readSettingsPage(session)).value, "30", `${where}: kept`);

        // It is kept over a restart of the browser too, and the vault of the new start is locked.
        await session.restart();
        await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active, 30_000, `${where}: the add-on after the restart`);
        await session.navigate(SETTINGS_URL);
        const afterwards = await readSettingsPage(session);
        assert.equal(afterwards.value, "30", `${where}: still 30 seconds after the restart`);
        assert.equal(afterwards.error, "", where);
      } finally {
        await session.quit();
      }
    }
  }
});
