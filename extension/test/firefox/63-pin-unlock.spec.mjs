// The PIN on the popup's locked view in real Firefox (Release and ESR): the real part (pages/pinUnlockView.mjs with the popup's
// flow and CSS), the real PIN store over the real IndexedDB and `storage.session` of the extension's origin, and a stand-in for
// the background between them. The stand-in answers `unlock_policy`, `pin_unlock` and `state` with what the store says; it
// checks the PIN against a hash kept next to random bytes in place of a wrap (the core's unlock is not under test here), so the
// counter, the waits and the wipe are the store's own. What these specs check that the unit tests cannot: the part lays out and
// takes the focus in a real page, a wrong PIN raises the counter in the browser's own storage and the field is empty after it,
// the wait is shown and held in real time, a right PIN opens the vault and resets the counter, a PIN kept on disk is offered again
// after the vault was locked and after the browser restarted while a PIN kept in memory is not, and five wrong tries leave no PIN.
//
// These are stand-in tests: the page talks to a function in the page, not to the real background over the UI port, so the
// protocol, the router and the real handlers are not under test. Once the background handlers exist, the same assertions must
// run on pages/popup.html over the real port, and this stand-in goes.
//
// Run by the Firefox runner with the test build (see 01-corehost.spec.mjs). The page is the test bridge, because a page of the
// extension may import the store there; the build's own pages may not reach the background.
import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import { BRIDGE_URL, TEST_ADDON_ID, channels, launch, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const PIN = "pin-unlock-246810";
const DISK_ACCOUNT = "c3".repeat(16);
const MEMORY_ACCOUNT = "d4".repeat(16);
const WIPE_ACCOUNT = "e5".repeat(16);
const SERVER = "https://vault.example.com";

/** @typedef {import("./driver.mjs").Session} Session */

/**
 * Builds the locked popup's PIN part of one account on the bridge page, over the real store. The PIN is saved first when
 * `save` says where (`disk` or `session`); a page that finds no PIN shows nothing, as the popup does.
 * @param {Session} session
 * @param {{ account: string, save?: "disk" | "session" | null, pin?: string }} o
 */
async function mount(session, { account, save = null, pin = PIN }) {
  await session.navigate(BRIDGE_URL);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the bridge page");
  await session.content(
    async (/** @type {string} */ id, /** @type {string} */ where, /** @type {string} */ right, /** @type {string} */ server) => {
      if (!document.querySelector("link[data-pin-css]")) {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = "/assets/app.css";
        link.setAttribute("data-pin-css", "1");
        document.head.append(link);
      }
      document.body.className = "ff-page ff-popup";
      const [{ createPinUnlockPart }, { createPopupFlow }, { loadTexts }, { mount: put }, unlockStore] = await Promise.all([
        import("/pages/pinUnlockView.mjs"),
        import("/pages/popupFlow.mjs"),
        import("/pages/page.mjs"),
        import("/shared/dom.mjs"),
        import("/background/unlockStore.gen.mjs"),
      ]);
      /** The clock of the store: the real one, moved on by a test that cannot wait for the long waits. */
      const harness = /** @type {any} */ (window).unlockHarness ?? { offset: 0, asked: [], vault: "locked", done: [], ended: [] };
      harness.vault = "locked";
      harness.done = [];
      harness.ended = [];
      /** @type {any} */ (window).unlockHarness = harness;
      const local = unlockStore.createLocalUnlock({ idb: indexedDB, session: browser.storage.session, now: () => Date.now() + harness.offset });
      const digest = async (/** @type {string} */ text) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
      await local.cachePolicy(server, { pin: { allowed: true, after_restart: true, min_length: 6 }, prf: { enabled: false } });
      if (where !== "") {
        const bytes = (/** @type {number} */ n) => crypto.getRandomValues(new Uint8Array(n));
        const wrap = bytes(104);
        wrap.set(await digest(right), 0);
        await local.save(server, id, { methodId: bytes(16), wrap, deviceSalt: bytes(16), pinProfile: 1, vkEpoch: 1, rule: { minLength: 6 } }, { location: where, acknowledged: true });
      }
      /** What the stand-in says of an attempt, as the background's `pin_unlock` does. */
      const answer = (/** @type {any} */ result) => {
        switch (result.result) {
          case "ok":
            harness.vault = "unlocked";
            return { ok: true, account_email: "ola@example.net", server };
          case "wrong":
          case "out_of_memory":
            return { ok: false, reason: result.result === "wrong" ? "wrong_pin" : "out_of_memory", left: result.failuresLeft, wait_ms: result.waitMs };
          case "wait":
            return { ok: false, reason: "pin_wait", left: result.failuresLeft, wait_ms: result.waitMs };
          case "wiped":
            return { ok: false, reason: "pin_wiped" };
          case "stale":
            return { ok: false, reason: "pin_stale" };
          case "offline_expired":
            return { ok: false, reason: "pin_offline_expired" };
          default:
            return { ok: false, reason: "pin_unavailable" };
        }
      };
      /** @type {(type: string, body: any) => Promise<any>} */
      const request = async (type, body) => {
        harness.asked.push([type, Object.keys(body)]);
        if (type === "state") return { state: harness.vault, server, account: "ola@example.net" };
        if (type === "sync_state") return { running: false };
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
            },
            prf: { enabled: false, count: 0 },
          };
        }
        if (type === "pin_unlock") {
          const typed = await digest(body.pin);
          const attempt = await local.attempt(server, id, { online: false }, async (/** @type {any} */ blob) => {
            const same = typed.every((byte, i) => byte === blob.wrap[i]);
            return same ? { ok: true } : { ok: false, reason: "wrong" };
          });
          return answer(attempt);
        }
        throw new Error(`not_available ${type}`);
      };
      const flow = createPopupFlow(request);
      harness.request = request;
      harness.local = local;
      harness.id = id;
      harness.server = server;
      const offer = await flow.pinPolicy();
      harness.offered = offer !== null;
      const root = document.getElementById("root");
      if (offer === null) {
        put(root);
        return;
      }
      const texts = await loadTexts();
      const part = createPinUnlockPart({
        texts,
        flow,
        offer,
        onDone: (/** @type {any} */ view) => harness.done.push(view.view),
        onEnded: (/** @type {string} */ message) => harness.ended.push(message),
        onUseMaster: () => {},
      });
      put(root, part.root);
      part.focus();
    },
    account,
    save ?? "",
    pin,
    SERVER,
  );
}

/** Reads what the page shows of the part. @param {Session} session */
const look = (session) =>
  session.content(() => {
    const harness = /** @type {any} */ (window).unlockHarness;
    const node = (/** @type {string} */ role) => /** @type {HTMLElement | null} */ (document.querySelector(`[data-role=${role}]`));
    const shown = (/** @type {HTMLElement | null} */ element) => element !== null && element.offsetParent !== null;
    const field = /** @type {HTMLInputElement | null} */ (node("pin-input"));
    return {
      offered: harness.offered === true,
      form: shown(node("pin-unlock-form")),
      field: shown(field),
      fieldType: field?.getAttribute("type") ?? null,
      value: field?.value ?? null,
      inputmode: field?.getAttribute("inputmode") ?? null,
      text: node("pin-error")?.textContent ?? "",
      countdown: shown(node("pin-countdown")) ? node("pin-countdown")?.textContent : null,
      attempts: shown(node("pin-attempts")) ? node("pin-attempts")?.textContent : null,
      button: /** @type {HTMLButtonElement | null} */ (node("pin-unlock"))?.disabled ?? null,
      useMaster: shown(node("use-master")),
      focus: document.activeElement?.getAttribute("data-role") ?? null,
      done: harness.done,
      ended: harness.ended,
    };
  });

/**
 * Types a PIN and submits the form, as Enter in the field does.
 * @param {Session} session @param {string} pin
 */
async function enter(session, pin) {
  await session.content((/** @type {string} */ value) => {
    const field = /** @type {HTMLInputElement} */ (document.querySelector("[data-role=pin-input]"));
    field.value = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
    /** @type {HTMLFormElement} */ (document.querySelector("[data-role=pin-unlock-form]")).requestSubmit();
  }, pin);
  await new Promise((resolve) => setTimeout(resolve, 700));
}

/** What the real store holds for the account of the page. @param {Session} session */
const stored = (session) =>
  session.content(async () => {
    const { local, server, id } = /** @type {any} */ (window).unlockHarness;
    const status = await local.status(server, id);
    return { set: status.set, location: status.location, failuresLeft: status.failuresLeft };
  });

/** Whether the store of the account has a PIN, read without a view (after a restart). @param {Session} session @param {string} account */
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

describe("pin unlock on the locked popup in real Firefox (stand-in background)", () => {
  test("pin_unlock_after_lock_in_release_and_esr", async () => {
    for (const channel of channels()) {
      const where = channel;
      const session = await launch({ channel });
      try {
        await session.waitFor(async () => (await session.backgroundState(TEST_ADDON_ID)) === "running", 30_000, `${where}: a running background`);

        // The locked popup of an account with a PIN on disk: the field is there, and the master password is one click away.
        await mount(session, { account: DISK_ACCOUNT, save: "disk" });
        let seen = await look(session);
        assert.equal(seen.offered, true, `${where}: the PIN is offered`);
        assert.equal(seen.form && seen.field, true, `${where}: the field is shown`);
        assert.equal(seen.fieldType, "password", where);
        assert.equal(seen.useMaster, true, `${where}: "Use master password instead" is there`);
        assert.equal(seen.focus, "pin-input", `${where}: the focus is on the field`);
        assert.equal(seen.attempts, null, `${where}: five tries left says nothing`);

        // A wrong PIN: said with the tries left, the field is empty, the focus is back, and the counter is in the browser's storage.
        await enter(session, "not-the-pin");
        seen = await look(session);
        assert.match(seen.text, /not right\. 4 tries left/, `${where}: the wrong PIN is said`);
        assert.equal(seen.value, "", `${where}: the field is empty after the answer`);
        assert.equal(seen.focus, "pin-input", `${where}: the focus is back on the field`);
        assert.equal(seen.attempts, "Tries left before the PIN is deleted: 4", where);
        assert.equal(seen.countdown, null, `${where}: no wait after the first wrong try`);
        assert.equal((await stored(session)).failuresLeft, 4, `${where}: the counter is raised in the store`);

        // The second wrong PIN starts the wait: the countdown shows, the button is off, and Enter does nothing.
        await enter(session, "not-it-either");
        seen = await look(session);
        assert.match(seen.countdown ?? "", /^Next try in [1-5] s$/, `${where}: the wait is shown`);
        assert.equal(seen.button, true, `${where}: the button is off during the wait`);
        assert.match(seen.text, /Wait 5 seconds/, where);
        const asked = () => session.content(() => /** @type {any} */ (window).unlockHarness.asked.filter(([type]) => type === "pin_unlock").length);
        const before = await asked();
        await enter(session, PIN);
        assert.equal(await asked(), before, `${where}: Enter during the wait sends nothing`);
        assert.equal((await look(session)).value, PIN, `${where}: the typed PIN stays during the wait`);
        await new Promise((resolve) => setTimeout(resolve, 5200));
        seen = await look(session);
        assert.equal(seen.button, false, `${where}: the button is back after the wait`);
        assert.equal(seen.countdown, null, where);
        assert.equal(seen.text, "You can try again now.", where);
        assert.equal(seen.focus, "pin-input", `${where}: the focus is on the field after the wait`);

        // The right PIN opens the vault, the field is empty, and the counter is back at five.
        await enter(session, PIN);
        seen = await look(session);
        assert.deepEqual(seen.done, ["unlocked"], `${where}: the popup is told the vault is open`);
        assert.equal(seen.value, "", where);
        assert.equal((await stored(session)).failuresLeft, 5, `${where}: the counter is reset by a right PIN`);
        // Only the PIN's own request carried the PIN, and nothing went to the local storage.
        const requests = await session.content(() => /** @type {any} */ (window).unlockHarness.asked);
        assert.ok(requests.every(([type, keys]) => type !== "pin_unlock" || (keys.length === 1 && keys[0] === "pin")), where);
        assert.deepEqual(await session.content(async () => Object.keys(await browser.storage.local.get(null)).filter((key) => /pin/i.test(key))), [], where);

        // After a lock the same account is offered the PIN again: the record is on disk, not in the page.
        await mount(session, { account: DISK_ACCOUNT });
        seen = await look(session);
        assert.equal(seen.offered, true, `${where}: the PIN is offered again after a lock`);
        assert.equal(seen.field, true, where);

        // The "123" button changes only the keyboard and is not remembered by the next view.
        await session.content(() => /** @type {HTMLElement} */ (document.querySelector("[data-role=pin-numeric]")).click());
        assert.equal((await look(session)).inputmode, "numeric", `${where}: the keyboard is numeric`);
        assert.equal((await look(session)).fieldType, "password", `${where}: the field is the same field`);
        await mount(session, { account: DISK_ACCOUNT });
        assert.notEqual((await look(session)).inputmode, "numeric", `${where}: the choice is not remembered`);

        // A PIN kept in memory and one kept on disk, then the browser restarts: the disk PIN is offered, the memory one is gone.
        await mount(session, { account: MEMORY_ACCOUNT, save: "session" });
        assert.equal((await look(session)).offered, true, where);
        await session.restart();
        await session.waitFor(async () => (await session.addonInfo(TEST_ADDON_ID))?.active, 30_000, `${where}: the add-on after the restart`);
        await session.navigate(BRIDGE_URL);
        await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, `${where}: the bridge page after the restart`);
        assert.deepEqual(await storedFor(session, DISK_ACCOUNT), { set: true, location: "disk" }, `${where}: the PIN on disk is still there`);
        assert.deepEqual(await storedFor(session, MEMORY_ACCOUNT), { set: false, location: null }, `${where}: the PIN in memory is gone`);
        await mount(session, { account: DISK_ACCOUNT });
        assert.equal((await look(session)).offered, true, `${where}: the popup offers the PIN after the restart`);
        await mount(session, { account: MEMORY_ACCOUNT });
        seen = await look(session);
        assert.equal(seen.offered, false, `${where}: the popup offers no PIN that is gone`);
        assert.equal(seen.form, false, where);
      } finally {
        await session.quit();
      }
    }
  });

  test("five_wrong_pins_leave_no_pin_to_offer", async () => {
    for (const channel of channels()) {
      const where = channel;
      const session = await launch({ channel });
      try {
        await session.waitFor(async () => (await session.backgroundState(TEST_ADDON_ID)) === "running", 30_000, `${where}: a running background`);
        await mount(session, { account: WIPE_ACCOUNT, save: "disk" });
        // The waits are the store's; the clock it reads is moved on past each of them so the test does not sit for a minute.
        const tries = [];
        for (let i = 0; i < 5; i += 1) {
          tries.push(
            await session.content(async (/** @type {number} */ n) => {
              const harness = /** @type {any} */ (window).unlockHarness;
              harness.offset += 60_000;
              return harness.request("pin_unlock", { pin: `wrong-${n}` });
            }, i),
          );
        }
        assert.deepEqual(tries.slice(0, 4).map((reply) => reply.reason), ["wrong_pin", "wrong_pin", "wrong_pin", "wrong_pin"], where);
        assert.deepEqual(tries.slice(0, 4).map((reply) => reply.left), [4, 3, 2, 1], `${where}: the tries left count down`);
        assert.deepEqual(tries[4], { ok: false, reason: "pin_wiped" }, `${where}: the fifth wrong PIN wipes it`);
        assert.deepEqual((await stored(session)).set, false, `${where}: no PIN is left in the store`);
        // The right PIN no longer opens anything, and a new view offers nothing.
        const after = await session.content(async () => /** @type {any} */ (window).unlockHarness.request("pin_unlock", { pin: "pin-unlock-246810" }));
        assert.equal(after.ok, false, where);
        await mount(session, { account: WIPE_ACCOUNT });
        const seen = await look(session);
        assert.equal(seen.offered, false, `${where}: nothing to offer after the wipe`);
      } finally {
        await session.quit();
      }
    }
  });
});
