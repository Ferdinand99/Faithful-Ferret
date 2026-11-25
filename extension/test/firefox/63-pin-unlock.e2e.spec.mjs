// The PIN on the real popup page (pages/popup.html) in real Firefox, against the end-to-end stack (run by
// `scripts/lanbox-ext.sh e2e`): a real server, the real background with its handlers and the real core with its Argon2id, and
// the popup talking to them over the UI port (`connectUi`). The PIN is set over the port of the sign-in page, the vault is
// locked, and the popup is opened: it offers the PIN. What the spec checks that the unit tests cannot: the real replies
// (`unlock_policy`, `pin_unlock`) are read by the real page, a PIN outside the rule is not sent and costs nothing, a wrong PIN
// counts and its wait is held in real time, a right PIN opens the vault and gives the tries back, the master password is
// always one click away (and a master-password unlock works), and five wrong PINs leave the master password's form with the
// reason in it and no PIN to offer.
//
// The stack must be fresh (`e2e-up`), as for the other end-to-end specs; the account is the one the first channel made.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { POPUP_URL, SLOW, extensionSignIn, helpers, pace, start, webVaultAccount } from "./e2e.mjs";
import { channels, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const PIN = "739415-popup-pin";

/**
 * One request over the UI port of the extension page the current tab shows.
 * @param {import("./driver.mjs").Session} session
 * @param {string} type @param {unknown} body
 * @returns {Promise<any>} the reply body
 */
function ask(session, type, body) {
  return session.content(
    (/** @type {string} */ kind, /** @type {unknown} */ payload) =>
      new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-ui" });
        const timer = setTimeout(() => reject(new Error("the UI port did not answer")), 170_000);
        port.onMessage.addListener((raw) => {
          const message = JSON.parse(typeof raw === "string" ? raw : JSON.stringify(raw));
          clearTimeout(timer);
          port.disconnect();
          resolve(message.body);
        });
        port.onDisconnect.addListener(() => reject(new Error("the UI port hung up")));
        port.postMessage(JSON.stringify({ v: 1, id: "a1", type: kind, body: payload }));
      }),
    type,
    body,
  );
}

/** @param {import("./driver.mjs").Session} session */
function popup(session) {
  const page = helpers(session);
  return {
    page,
    /** Opens the popup as a page of its own (the vault is locked or not as it is). */
    async open() {
      await session.navigate(POPUP_URL);
      await page.ready();
    },
    /** What the page shows of the PIN. */
    look: () =>
      session.content(() => {
        const node = (/** @type {string} */ name) => /** @type {HTMLElement | null} */ (document.querySelector(`[data-role="${name}"]`));
        const shown = (/** @type {HTMLElement | null} */ element) => element !== null && element.closest("[hidden]") === null && element.getClientRects().length > 0;
        const field = /** @type {HTMLInputElement | null} */ (node("pin-input"));
        return {
          pinForm: shown(node("pin-unlock-form")),
          masterForm: shown(node("unlock-form")),
          unlocked: shown(node("unlocked-view")),
          usePin: shown(node("use-pin")),
          useMaster: shown(node("use-master")),
          value: field?.value ?? null,
          text: node("pin-error")?.textContent ?? "",
          alert: [...document.querySelectorAll('[data-role="unlock-form"] [role="alert"]')].map((n) => (n.hasAttribute("hidden") ? "" : (n.textContent ?? ""))).join(""),
          countdown: shown(node("pin-countdown")) ? node("pin-countdown")?.textContent : null,
          disabled: /** @type {HTMLButtonElement | null} */ (node("pin-unlock"))?.disabled ?? null,
          focus: document.activeElement?.getAttribute("data-role") ?? null,
        };
      }),
    /** Types a PIN in the field and presses "Unlock with PIN". @param {string} pin */
    async tryPin(pin) {
      await page.type('[data-role="pin-input"]', pin);
      await page.click('[data-role="pin-unlock"]');
    },
    /** Waits until the page has said something about the try (the Argon2id takes seconds). */
    answered: () =>
      session.waitFor(
        async () => {
          const seen = await session.content(() => {
            const text = document.querySelector('[data-role="pin-error"]')?.textContent ?? "";
            const busy = document.querySelector('[data-role="pin-unlock-form"]')?.getAttribute("aria-busy") === "true";
            const master = document.querySelector('[data-role="unlock-form"]');
            const unlocked = document.querySelector('[data-role="unlocked-view"]') !== null;
            const ended = master !== null && !master.hasAttribute("hidden");
            return { text, busy, done: unlocked || ended };
          });
          return !seen.busy && (seen.text !== "" || seen.done);
        },
        SLOW,
        "the answer to the PIN",
      ),
  };
}

test("pin_unlock_after_lock_in_release_and_esr", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      // Setting a PIN asks for the master password again: the server counts it as a sign-in start.
      await pace();
      const set = await ask(session, "pin_set", { mp: account.password, pin: PIN, location: "disk", acknowledged: true });
      assert.deepEqual(set, { ok: true }, `${channel}: ${JSON.stringify(set)}`);
      await ask(session, "lock", {});

      // The locked popup offers the PIN: its form is shown and the master password's is not, the focus is on the field.
      const view = popup(session);
      await view.open();
      await view.page.waitVisible('[data-role="pin-unlock-form"]');
      let seen = await view.look();
      assert.deepEqual([seen.pinForm, seen.masterForm, seen.useMaster, seen.focus], [true, false, true, "pin-input"], `${channel}: ${JSON.stringify(seen)}`);

      // A PIN outside the rule is not sent: the page says the rule, and the tries are as they were.
      await view.tryPin("abc");
      await session.waitFor(async () => (await view.look()).text !== "", 10_000, "the rule text");
      seen = await view.look();
      assert.match(seen.text, /at least 6 characters/, channel);
      assert.equal((await ask(session, "unlock_policy", {})).pin_state.failures_left, 5, `${channel}: nothing was counted`);
      await session.content(() => {
        /** @type {HTMLInputElement} */ (document.querySelector('[data-role="pin-input"]')).value = "";
      });

      // A wrong PIN: counted, said with the tries left, the field is empty and has the focus.
      await view.tryPin("wrong-pin-one");
      await view.answered();
      seen = await view.look();
      assert.match(seen.text, /not right\. 4 tries left/, `${channel}: ${seen.text}`);
      assert.equal(seen.value, "", `${channel}: the field is empty`);
      assert.equal(seen.focus, "pin-input", channel);
      assert.equal((await ask(session, "unlock_policy", {})).pin_state.failures_left, 4, `${channel}: the real counter went down`);

      // The second wrong PIN starts a wait: shown, the button is off, and Enter does nothing while it runs.
      await view.tryPin("wrong-pin-two");
      await view.answered();
      seen = await view.look();
      assert.match(seen.text, /not right\. 3 tries left.*Wait 5 seconds/, `${channel}: ${seen.text}`);
      assert.match(seen.countdown ?? "", /^Next try in [1-5] s$/, channel);
      assert.equal(seen.disabled, true, channel);
      await session.content((/** @type {string} */ typed) => {
        const field = /** @type {HTMLInputElement} */ (document.querySelector('[data-role="pin-input"]'));
        field.value = typed;
        /** @type {HTMLFormElement} */ (document.querySelector('[data-role="pin-unlock-form"]')).requestSubmit();
      }, PIN);
      await new Promise((resolve) => setTimeout(resolve, 500));
      seen = await view.look();
      assert.equal(seen.value, PIN, `${channel}: Enter during the wait sent nothing, the PIN stays`);
      await session.waitFor(async () => (await view.look()).disabled === false, 15_000, "the end of the wait");
      seen = await view.look();
      assert.equal(seen.text, "You can try again now.", channel);
      assert.equal(seen.focus, "pin-input", channel);

      // The right PIN (still in the field) opens the vault, and the tries are back.
      await view.page.click('[data-role="pin-unlock"]');
      await view.page.waitVisible('[data-role="unlocked-view"]', SLOW);
      assert.equal((await ask(session, "state", {})).state, "unlocked", channel);
      assert.equal((await ask(session, "unlock_policy", {})).pin_state.failures_left, 5, `${channel}: a right PIN gives the tries back`);

      // Locked again: the PIN is offered again, "Use master password instead" opens that form, and a master-password unlock works.
      await ask(session, "lock", {});
      await view.open();
      await view.page.waitVisible('[data-role="pin-unlock-form"]');
      await view.page.click('[data-role="use-master"]');
      await view.page.waitVisible('[data-role="unlock-form"]');
      seen = await view.look();
      assert.deepEqual([seen.pinForm, seen.masterForm, seen.usePin], [false, true, true], `${channel}: ${JSON.stringify(seen)}`);
      await view.page.type('[data-role="password"]', account.password);
      await pace();
      await view.page.click('[data-role="unlock"]');
      await view.page.waitVisible('[data-role="unlocked-view"]', SLOW);

      // Five wrong PINs: the fifth leaves the master password's form with the reason in it, and no PIN to offer.
      await ask(session, "lock", {});
      await view.open();
      await view.page.waitVisible('[data-role="pin-unlock-form"]');
      for (let i = 1; i <= 5; i += 1) {
        await session.waitFor(async () => (await view.look()).disabled === false, 45_000, `the wait before try ${i}`);
        await view.tryPin(`wrong-pin-${i}-again`);
        await view.answered();
      }
      seen = await view.look();
      assert.deepEqual([seen.pinForm, seen.masterForm, seen.usePin], [false, true, false], `${channel}: ${JSON.stringify(seen)}`);
      assert.match(seen.alert, /The PIN on this device was deleted: after five wrong tries/, `${channel}: ${seen.alert}`);
      assert.equal((await ask(session, "unlock_policy", {})).pin_state.set, false, `${channel}: no PIN is left`);
      await view.open();
      await session.waitFor(async () => (await view.look()).masterForm, 10_000, "the master password's form");
      assert.equal((await view.look()).pinForm, false, `${channel}: the next popup offers no PIN`);
    } finally {
      await session.quit();
    }
  }
}, { timeout: SLOW * 5 });
