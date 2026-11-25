// The "Unlock" part of the settings page in real Firefox, against the end-to-end stack (run by `scripts/lanbox-ext.sh e2e`): the real
// page (pages/settings.html with its CSS), the real background over the UI port, the real server and the real core with its
// Argon2id. What these specs check that the unit tests cannot: the section lays out and takes the focus in a real page; a PIN set
// from it lands where the choice says (the database of the extension, or the session storage) and nowhere else; a wrong master
// password and two PINs that differ are said and cost nothing; a turn-off removes the PIN and asks for no password; and across
// a restart of the browser the PIN kept on disk is still there while the PIN kept in memory is gone.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { SETTINGS_URL, SLOW, extensionSignIn, helpers, pace, start, webVaultAccount } from "./e2e.mjs";
import { channels, openSettingsPage, stopFixtures } from "./harness.mjs";
import { afterStart, ask, pinPlaces } from "./unlock.mjs";

after(() => stopFixtures());

/** @typedef {import("./driver.mjs").Session} Session */

/** Opens the settings page and waits until it has built itself. @param {Session} session */
async function openSettings(session) {
  await session.navigate(SETTINGS_URL);
  await helpers(session).ready();
  await openSettingsPage(session, "pin");
  await helpers(session).waitVisible("[data-role=unlock-section]");
  // The section shows what the background says once the policy has answered.
  await session.waitFor(() => session.content(() => (document.querySelector("[data-role=unlock-pin-status]")?.textContent ?? "") !== ""), 20_000, "the status of the PIN");
}

/** Reads what the page shows of the section. @param {Session} session */
const look = (session) =>
  session.content(() => {
    const text = (/** @type {string} */ role) => document.querySelector(`[data-role=${role}]`)?.textContent ?? null;
    const dialog = /** @type {HTMLElement | null} */ (document.querySelector("[data-role=pin-dialog]"));
    return {
      section: document.querySelector("[data-role=unlock-section]") !== null,
      status: text("unlock-pin-status"),
      buttons: [...document.querySelectorAll("[data-role=unlock-pin-actions] button")].map((b) => b.getAttribute("data-role")),
      dialogShown: dialog !== null && dialog.offsetParent !== null,
      focus: document.activeElement?.getAttribute("data-role") ?? null,
      problem: (() => {
        const box = /** @type {HTMLElement | null} */ (document.querySelector("[data-role=pin-error]"));
        return box && box.offsetParent !== null ? box.textContent : null;
      })(),
      fields: ["pin-password", "pin-secret", "pin-pin", "pin-again"].map((role) => /** @type {HTMLInputElement} */ (document.querySelector(`[data-role=${role}]`))?.value ?? null),
      ack: /** @type {HTMLInputElement | null} */ (document.querySelector("[data-role=pin-ack]"))?.checked ?? null,
      restart: /** @type {HTMLInputElement | null} */ (document.querySelector("[data-role=pin-restart]"))?.checked ?? null,
    };
  });

/** Presses a control of the page, like a click. @param {Session} session @param {string} role */
const press = async (session, role) => {
  await session.content((/** @type {string} */ r) => /** @type {HTMLElement} */ (document.querySelector(`[data-role=${r}]`)).click(), role);
  await new Promise((resolve) => setTimeout(resolve, 400));
};

/**
 * Types into the dialog and submits it, and waits until the page has answered (the answer needs the core's Argon2id).
 * @param {Session} session
 * @param {{ password: string, pin: string, again?: string, memory?: boolean, acknowledge?: boolean }} o
 */
async function submitDialog(session, { password, pin, again = pin, memory = false, acknowledge = true }) {
  await session.content(
    (/** @type {any} */ o) => {
      const set = (/** @type {string} */ role, /** @type {string} */ value) => {
        const input = /** @type {HTMLInputElement} */ (document.querySelector(`[data-role=${role}]`));
        input.value = value;
        input.dispatchEvent(new Event("input", { bubbles: true }));
      };
      set("pin-password", o.password);
      set("pin-pin", o.pin);
      set("pin-again", o.again);
      const restart = /** @type {HTMLInputElement} */ (document.querySelector("[data-role=pin-restart]"));
      if (restart.checked !== o.memory && !restart.disabled) restart.click();
      const ack = /** @type {HTMLInputElement} */ (document.querySelector("[data-role=pin-ack]"));
      if (ack.checked !== o.acknowledge && !o.memory) ack.click();
      /** @type {HTMLFormElement} */ (document.querySelector("[data-role=pin-dialog]")).requestSubmit();
    },
    { password, pin, again, memory, acknowledge },
  );
  await new Promise((resolve) => setTimeout(resolve, 600));
  // The submit button is busy while the background works (the Argon2id of the master password and of the PIN take seconds).
  await session.waitFor(() => session.content(() => document.querySelector("[data-role=pin-submit]")?.getAttribute("aria-busy") !== "true"), SLOW, "the answer to the dialog");
  await new Promise((resolve) => setTimeout(resolve, 300));
}

test("set_change_and_turn_off_a_pin_from_settings", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await openSettings(session);
      let seen = await look(session);
      assert.equal(seen.section, true, `${channel}: the section is in the view`);
      assert.equal(seen.status, "No PIN is set.", channel);
      assert.deepEqual(seen.buttons, ["unlock-pin-on"], channel);
      assert.equal(seen.dialogShown, false, channel);

      // Open the dialog: it shows, the title has the focus, the restart choice is off, the box is not ticked.
      await press(session, "unlock-pin-on");
      seen = await look(session);
      assert.equal(seen.dialogShown, true, `${channel}: the dialog is shown`);
      assert.equal(seen.focus, "pin-title", `${channel}: the focus is on the title`);
      assert.equal(seen.restart, false, `${channel}: the restart choice is off`);
      assert.equal(seen.ack, false, `${channel}: the acknowledgement is not ticked`);

      // A wrong master password: refused, said, the fields empty, nothing stored.
      await pace();
      await submitDialog(session, { password: "not the master password", pin: "246810" });
      seen = await look(session);
      assert.match(seen.problem ?? "", /master password/i, `${channel}: the refusal is said (${seen.problem})`);
      assert.deepEqual(seen.fields, ["", "", "", ""], `${channel}: the fields are empty after the answer`);
      assert.equal(seen.ack, false, `${channel}: and the box is unticked`);
      assert.deepEqual(await pinPlaces(session), { disk: false, sessionKeys: [], localKeys: [] }, `${channel}: nothing was stored`);

      // The two PINs differ: said on the page, and no PIN is stored (that nothing is sent to the background is shown by the unit test of the dialog).
      await submitDialog(session, { password: account.password, pin: "246810", again: "246811" });
      seen = await look(session);
      assert.match(seen.problem ?? "", /not the same/, `${channel}: the mismatch is said`);
      assert.equal((await pinPlaces(session)).disk, false, channel);

      // Without the acknowledgement a PIN is not kept on disk.
      await submitDialog(session, { password: account.password, pin: "246810", acknowledge: false });
      seen = await look(session);
      assert.match(seen.problem ?? "", /Tick .I understand./, `${channel}: the acknowledgement is asked for`);
      assert.equal((await pinPlaces(session)).disk, false, `${channel}: nothing was stored without it`);

      // With it: the PIN is on disk (the default), and the section says so.
      await pace();
      await submitDialog(session, { password: account.password, pin: "246810" });
      seen = await look(session);
      assert.equal(seen.dialogShown, false, `${channel}: the dialog is closed (${seen.problem})`);
      assert.match(seen.status ?? "", /PIN is on\./, channel);
      assert.deepEqual(seen.buttons, ["unlock-pin-change", "unlock-pin-off"], channel);
      assert.equal(seen.focus, "unlock-pin-change", `${channel}: the focus is on a button that is there`);
      assert.deepEqual(await pinPlaces(session), { disk: true, sessionKeys: [], localKeys: [] }, `${channel}: on disk, and nowhere else`);
      assert.deepEqual(await ask(session, "unlock_policy", {}).then((r) => [r.pin_state.set, r.pin_state.location]), [true, "disk"], channel);

      // Change it, this time in memory only: the record moves to the session storage.
      await press(session, "unlock-pin-change");
      seen = await look(session);
      assert.equal(seen.dialogShown, true, channel);
      assert.equal(seen.restart, false, `${channel}: the choice is off again for a change`);
      await pace();
      await submitDialog(session, { password: account.password, pin: "135790", memory: true });
      seen = await look(session);
      assert.match(seen.status ?? "", /PIN changed\./, `${channel}: ${seen.status} ${seen.problem}`);
      let places = await pinPlaces(session);
      assert.equal(places.disk, false, `${channel}: the disk record is gone`);
      assert.equal(places.sessionKeys.length, 1, `${channel}: the record is in the session storage`);
      assert.deepEqual(places.localKeys, [], channel);
      assert.deepEqual((await look(session)).fields, ["", "", "", ""], `${channel}: no field holds anything`);

      // Turn it off: no password asked, the record is gone.
      await press(session, "unlock-pin-off");
      await session.waitFor(async () => (await look(session)).status === "PIN turned off.", 20_000, "the turn-off");
      seen = await look(session);
      assert.deepEqual(seen.buttons, ["unlock-pin-on"], channel);
      places = await pinPlaces(session);
      assert.deepEqual([places.disk, places.sessionKeys], [false, []], channel);

      // Escape closes the dialog and empties it.
      await press(session, "unlock-pin-on");
      await session.content(() => {
        /** @type {HTMLInputElement} */ (document.querySelector("[data-role=pin-pin]")).value = "typed";
        document.querySelector("[data-role=pin-dialog]")?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
      });
      seen = await look(session);
      assert.equal(seen.dialogShown, false, `${channel}: Escape closes the dialog`);
      assert.deepEqual(seen.fields, ["", "", "", ""], `${channel}: and empties it`);
      assert.equal(seen.focus, "unlock-pin-on", channel);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 6 });

test("the_default_pin_survives_a_browser_restart_and_the_memory_choice_does_not", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await openSettings(session);

      // The default is disk: the PIN works after a restart, and the section says so after one.
      await press(session, "unlock-pin-on");
      await pace();
      await submitDialog(session, { password: account.password, pin: "disk-pin-1" });
      assert.match((await look(session)).status ?? "", /PIN is on\./, channel);
      await session.restart();
      await afterStart(session);
      assert.deepEqual(await ask(session, "unlock_policy", {}).then((r) => [r.pin_state.set, r.pin_state.location]), [true, "disk"], `${channel}: the PIN on disk is still there`);
      await openSettings(session);
      const seen = await look(session);
      assert.match(seen.status ?? "", /works after a restart/, `${channel}: the view reads the PIN that survived`);
      assert.deepEqual(seen.buttons, ["unlock-pin-change", "unlock-pin-off"], channel);

      // The choice of memory: gone after a restart. (The vault is locked after the restart: the master password opens it first.)
      await pace();
      const opened = await ask(session, "unlock", { mp: account.password });
      assert.equal(opened.ok, true, `${channel}: ${JSON.stringify(opened)}`);
      await openSettings(session);
      await press(session, "unlock-pin-change");
      await pace();
      await submitDialog(session, { password: account.password, pin: "memory-pin-2", memory: true });
      assert.deepEqual(await ask(session, "unlock_policy", {}).then((r) => [r.pin_state.set, r.pin_state.location]), [true, "session"], `${channel}: the choice is memory`);
      await session.restart();
      await afterStart(session);
      assert.deepEqual(await ask(session, "unlock_policy", {}).then((r) => r.pin_state.set), false, `${channel}: the PIN in memory is gone`);
      assert.deepEqual(await pinPlaces(session), { disk: false, sessionKeys: [], localKeys: [] }, channel);
      await openSettings(session);
      assert.equal((await look(session)).status, "No PIN is set.", channel);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 6 });
