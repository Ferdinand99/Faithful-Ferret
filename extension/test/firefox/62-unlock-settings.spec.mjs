// The "Unlock" part of the settings view in real Firefox: the real view (pages/settingsView.mjs with its CSS), the real
// PIN store over the real IndexedDB and `storage.session` of the extension's origin, and a stand-in for the background
// between them. The stand-in answers the three requests of the part (`unlock_policy`, `pin_set`, `pin_off`) with what the
// store says, checks the master password against a fixed test value, and stores a blob of random bytes in place of a wrap
// (the core's wrap is not under test here). What these specs check that the unit tests cannot: the section lays out and
// takes the focus in a real page, a PIN set from it lands where the choice says (the database of the extension, or the
// session storage), a turn-off removes it, and across a restart of the browser the PIN kept on disk is still there while the
// PIN kept in memory is gone.
//
// Run by the Firefox runner with the test build (see 01-corehost.spec.mjs). The page is the test bridge, because a page of the
// extension may import the store there; the build's own pages may not reach the background.
import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import { BRIDGE_URL, TEST_ADDON_ID, channels, launch, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const MASTER = "the master password of this test";
const DISK_ACCOUNT = "a1".repeat(16);
const MEMORY_ACCOUNT = "b2".repeat(16);

/** @typedef {import("./driver.mjs").Session} Session */

/**
 * Builds the settings view of one account on the bridge page, over the real store.
 * @param {Session} session
 * @param {string} account
 */
async function mount(session, account) {
  await session.navigate(BRIDGE_URL);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the bridge page");
  await session.content(
    async (/** @type {string} */ id, /** @type {string} */ master) => {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = "/assets/app.css";
      document.head.append(link);
      document.body.className = "ff-page ff-signin";
      const [{ createSettingsView }, { createSettingsFlow }, { loadTexts }, { mount: put }, unlockStore] = await Promise.all([
        import("/pages/settingsView.mjs"),
        import("/pages/settingsFlow.mjs"),
        import("/pages/page.mjs"),
        import("/shared/dom.mjs"),
        import("/background/unlockStore.gen.mjs"),
      ]);
      const server = "https://vault.example.com";
      const local = unlockStore.createLocalUnlock({ idb: indexedDB, session: browser.storage.session });
      await local.cachePolicy(server, { pin: { allowed: true, after_restart: true, min_length: 6 }, prf: { enabled: true } });
      /** What the page asked, without a secret: the type and the keys of the body. */
      const asked = [];
      /** @type {(type: string, body: any) => Promise<any>} */
      const request = async (type, body) => {
        asked.push([type, Object.keys(body)]);
        if (type === "state") return { state: "unlocked", server };
        if (type === "unlock_policy") {
          const status = await local.status(server, id);
          const rule = await local.cachedPolicy(server);
          return {
            pin: {
              allowed: rule.pin.allowed,
              after_restart: rule.pin.after_restart,
              min_length: rule.pin.min_length,
              set: status.set,
              location: status.location,
              failures_left: status.failuresLeft,
              wait_ms: status.waitMs,
              offline_ok: status.offlineOk,
              last_contact_at: Date.now(),
            },
            prf: { enabled: true, count: 1 },
          };
        }
        if (type === "pin_set") {
          if (body.password !== master) return { ok: false, reason: "wrong_credentials" };
          const bytes = (/** @type {number} */ n) => crypto.getRandomValues(new Uint8Array(n));
          await local.save(
            server,
            id,
            { methodId: bytes(16), wrap: bytes(104), deviceSalt: bytes(16), pinProfile: 1, vkEpoch: 1, rule: { minLength: 6 } },
            { location: body.location, acknowledged: body.acknowledged },
          );
          return { ok: true };
        }
        if (type === "pin_off") {
          await local.wipe(server, id, "pin_off");
          return { ok: true };
        }
        throw new Error(`not_available ${type}`);
      };
      const texts = await loadTexts();
      const flow = createSettingsFlow(request, { openTab: async () => {} });
      const view = createSettingsView({ texts, flow });
      const root = document.getElementById("root");
      put(root, ...view.nodes);
      await view.ready;
      /** @type {any} */ (window).unlockHarness = { asked, local, server, id };
    },
    account,
    MASTER,
  );
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
 * Types into the dialog and submits it.
 * @param {Session} session
 * @param {{ password?: string, pin: string, again?: string, memory?: boolean, acknowledge?: boolean }} o
 */
async function submitDialog(session, { password = MASTER, pin, again = pin, memory = false, acknowledge = true }) {
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
}

/** What the real store holds for the account of the page. @param {Session} session */
const stored = (session) =>
  session.content(async () => {
    const { local, server, id } = /** @type {any} */ (window).unlockHarness;
    const status = await local.status(server, id);
    const sessionKeys = Object.keys(await browser.storage.session.get(null)).filter((key) => key.startsWith("ferretPin"));
    const localKeys = Object.keys(await browser.storage.local.get(null)).filter((key) => /pin/i.test(key));
    return { set: status.set, location: status.location, failuresLeft: status.failuresLeft, sessionKeys, localKeys };
  });

/** The store's answer for another account, read after a restart (no view needed). @param {Session} session @param {string} account */
const storedFor = (session, account) =>
  session.content(
    async (/** @type {string} */ id) => {
      const unlockStore = await import("/background/unlockStore.gen.mjs");
      const local = unlockStore.createLocalUnlock({ idb: indexedDB, session: browser.storage.session });
      const status = await local.status("https://vault.example.com", id);
      return { set: status.set, location: status.location };
    },
    account,
  );

describe("unlock settings in real Firefox", () => {
  test("set_change_and_turn_off_a_pin_from_settings", async () => {
    for (const channel of channels()) {
      {
        const where = channel;
        const session = await launch({ channel });
        try {
          await session.waitFor(async () => (await session.backgroundState(TEST_ADDON_ID)) === "running", 30_000, `${where}: a running background`);
          await mount(session, DISK_ACCOUNT);
          let seen = await look(session);
          assert.equal(seen.section, true, `${where}: the section is in the view`);
          assert.equal(seen.status, "No PIN is set.", where);
          assert.deepEqual(seen.buttons, ["unlock-pin-on"], where);
          assert.equal(seen.dialogShown, false, where);

          // Open the dialog: it shows, the title has the focus, the restart choice is off, the box is not ticked.
          await press(session, "unlock-pin-on");
          seen = await look(session);
          assert.equal(seen.dialogShown, true, `${where}: the dialog is shown`);
          assert.equal(seen.focus, "pin-title", `${where}: the focus is on the title`);
          assert.equal(seen.restart, false, `${where}: the restart choice is off`);
          assert.equal(seen.ack, false, `${where}: the acknowledgement is not ticked`);

          // A wrong master password: refused, said, the fields empty, the store untouched.
          await submitDialog(session, { password: "not it", pin: "246810" });
          seen = await look(session);
          assert.match(seen.problem ?? "", /master password .* not right/, `${where}: the refusal is said`);
          assert.deepEqual(seen.fields, ["", "", "", ""], `${where}: the fields are empty after the answer`);
          assert.equal(seen.ack, false, `${where}: and the box is unticked`);
          assert.equal((await stored(session)).set, false, `${where}: nothing was stored`);

          // The two PINs differ: said on the page, nothing is asked of the background.
          const sets = () => session.content(() => /** @type {any} */ (window).unlockHarness.asked.filter(([type]) => type === "pin_set").length);
          const askedBefore = await sets();
          await submitDialog(session, { pin: "246810", again: "246811" });
          seen = await look(session);
          assert.match(seen.problem ?? "", /not the same/, `${where}: the mismatch is said`);
          assert.equal(await sets(), askedBefore, `${where}: nothing was sent`);

          // Without the acknowledgement a PIN is not kept on disk.
          await submitDialog(session, { pin: "246810", acknowledge: false });
          seen = await look(session);
          assert.match(seen.problem ?? "", /Tick .I understand./, `${where}: the acknowledgement is asked for`);
          assert.equal((await stored(session)).set, false, `${where}: nothing was stored without it`);

          // With it: the PIN is on disk (the default), and the section says so.
          await submitDialog(session, { pin: "246810" });
          seen = await look(session);
          assert.equal(seen.dialogShown, false, `${where}: the dialog is closed`);
          assert.match(seen.status ?? "", /PIN is on\./, where);
          assert.deepEqual(seen.buttons, ["unlock-pin-change", "unlock-pin-off"], where);
          assert.equal(seen.focus, "unlock-pin-change", `${where}: the focus is on a button that is there`);
          let kept = await stored(session);
          assert.deepEqual({ set: kept.set, location: kept.location }, { set: true, location: "disk" }, where);
          assert.deepEqual(kept.sessionKeys, [], `${where}: nothing in the session storage`);
          assert.deepEqual(kept.localKeys, [], `${where}: nothing in the local storage`);

          // Change it, this time in memory only: the record moves to the session storage.
          await press(session, "unlock-pin-change");
          seen = await look(session);
          assert.equal(seen.dialogShown, true, where);
          assert.equal(seen.restart, false, `${where}: the choice is off again for a change`);
          await submitDialog(session, { pin: "135790", memory: true });
          seen = await look(session);
          assert.match(seen.status ?? "", /PIN changed\./, where);
          kept = await stored(session);
          assert.deepEqual({ set: kept.set, location: kept.location }, { set: true, location: "session" }, where);
          assert.equal(kept.sessionKeys.length, 1, `${where}: the record is in the session storage`);

          // The secrets went nowhere but the one request: the stand-in saw the keys of the body, and no field holds anything.
          const asked = await session.content(() => /** @type {any} */ (window).unlockHarness.asked);
          assert.ok(asked.some(([type, keys]) => type === "pin_set" && keys.includes("pin") && keys.includes("password")), where);
          assert.deepEqual((await look(session)).fields, ["", "", "", ""], where);

          // Turn it off: no password asked, the record is gone.
          await press(session, "unlock-pin-off");
          seen = await look(session);
          assert.equal(seen.status, "PIN turned off.", where);
          assert.deepEqual(seen.buttons, ["unlock-pin-on"], where);
          kept = await stored(session);
          assert.deepEqual({ set: kept.set, sessionKeys: kept.sessionKeys }, { set: false, sessionKeys: [] }, where);
          const offAsk = await session.content(() => /** @type {any} */ (window).unlockHarness.asked.filter(([type]) => type === "pin_off"));
          assert.deepEqual(offAsk, [["pin_off", []]], `${where}: the turn-off carries nothing`);

          // Escape closes the dialog and empties it.
          await press(session, "unlock-pin-on");
          await session.content(() => {
            /** @type {HTMLInputElement} */ (document.querySelector("[data-role=pin-pin]")).value = "typed";
            document.querySelector("[data-role=pin-dialog]")?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
          });
          seen = await look(session);
          assert.equal(seen.dialogShown, false, `${where}: Escape closes the dialog`);
          assert.deepEqual(seen.fields, ["", "", "", ""], `${where}: and empties it`);
          assert.equal(seen.focus, "unlock-pin-on", where);
        } finally {
          await session.quit();
        }
      }
    }
  });

  test("the_default_pin_survives_a_browser_restart_and_the_memory_choice_does_not", async () => {
    for (const channel of channels()) {
      {
        const where = channel;
        const session = await launch({ channel });
        try {
          await session.waitFor(async () => (await session.backgroundState(TEST_ADDON_ID)) === "running", 30_000, `${where}: a running background`);
          // One account keeps its PIN as the dialog offers it (on disk), the other chooses the master password after a restart.
          await mount(session, DISK_ACCOUNT);
          await press(session, "unlock-pin-on");
          await submitDialog(session, { pin: "disk-pin-1" });
          assert.deepEqual(await storedFor(session, DISK_ACCOUNT), { set: true, location: "disk" }, `${where}: the default is disk`);
          await mount(session, MEMORY_ACCOUNT);
          await press(session, "unlock-pin-on");
          await submitDialog(session, { pin: "memory-pin-2", memory: true });
          assert.deepEqual(await storedFor(session, MEMORY_ACCOUNT), { set: true, location: "session" }, `${where}: the choice is memory`);

          // The browser ends and starts again on the same profile.
          await session.restart();
          await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active, 30_000, `${where}: the add-on after the restart`);
          await session.navigate(BRIDGE_URL);
          await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, `${where}: the bridge page after the restart`);
          assert.deepEqual(await storedFor(session, DISK_ACCOUNT), { set: true, location: "disk" }, `${where}: the PIN on disk is still there`);
          assert.deepEqual(await storedFor(session, MEMORY_ACCOUNT), { set: false, location: null }, `${where}: the PIN in memory is gone`);

          // The section of the account that kept its PIN says so after the restart.
          await mount(session, DISK_ACCOUNT);
          const seen = await look(session);
          assert.match(seen.status ?? "", /works after a restart/, `${where}: the view reads the PIN that survived`);
          assert.deepEqual(seen.buttons, ["unlock-pin-change", "unlock-pin-off"], where);
        } finally {
          await session.quit();
        }
      }
    }
  });
});
