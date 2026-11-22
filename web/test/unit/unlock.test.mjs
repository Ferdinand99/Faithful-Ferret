// The unlock screen: the master password, and the secret key only when this
// device does not hold it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { prepareUnlock, unlockScreen, unlockView } from "../../src/views/unlock.mjs";
import { coded, fakeSession, find, settle, submit, t, textOf, withDom } from "./vaultHelpers.mjs";

const PASSWORD = "master-password-for-tests";
const SK = "FFS1-TESTA-TESTB-TESTC-TESTD-TESTE-TESTF";

/** The unlock screen, filled in. */
async function screen(session, extra = {}) {
  const moves = [];
  let unlocked = 0;
  const host = unlockScreen({ session, t, go: (p) => moves.push(p), onUnlocked: () => void (unlocked += 1), ...extra });
  await settle();
  return { host, moves, unlocked: () => unlocked };
}

const type = (root, role, value) => {
  find(root, role).value = value;
};

test("unlock_asks_for_the_password_only_when_the_device_holds_the_sk", async () => {
  await withDom(async () => {
    const session = fakeSession({ status: { pinned: true, skBit: true, skStored: true } });
    const { host, unlocked } = await screen(session);
    assert.ok(find(host, "password"), "the master password is asked for");
    assert.equal(find(host, "secret-key"), null, "the secret key is not");
    assert.ok(textOf(host).includes("vault.unlock.as"));

    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(session.unlocks, [{ password: PASSWORD }], "the password goes alone; the device supplies the key");
    assert.equal(unlocked(), 1);
  });
  // An account without a secret key asks for nothing more either.
  await withDom(async () => {
    const session = fakeSession({ status: { pinned: true, skBit: false, skStored: false } });
    const { host } = await screen(session);
    assert.equal(find(host, "secret-key"), null);
  });
});

test("unlock_asks_for_sk_when_the_device_does_not_remember_it", async () => {
  await withDom(async () => {
    const session = fakeSession({ status: { pinned: true, skBit: true, skStored: false } });
    const { host, unlocked } = await screen(session);
    assert.ok(find(host, "secret-key"), "the secret key is asked for");

    // Without it, nothing is sent.
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(session.unlocks, []);
    assert.ok(textOf(find(host, "error")).includes("account.error.sk_required"));

    type(host, "password", PASSWORD);
    type(host, "secret-key", ` ${SK} `);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(session.unlocks, [{ password: PASSWORD, skCode: SK }]);
    assert.equal(unlocked(), 1);
    assert.equal(find(host, "secret-key").value, "", "the typed key is cleared");
  });
});

test("the_screen_never_guesses_the_secret_key_answer_for_a_device_that_does_not_know", async () => {
  await withDom(async () => {
    // No record of the account on this device: the screen asks nothing extra, and the session says what it needs.
    const session = fakeSession({ status: { pinned: false, skBit: null, skStored: false } });
    assert.deepEqual(await prepareUnlock(session), { signedIn: true, email: "ada@example.test", accountId: "aa".repeat(16), skRequired: false });
    const { host, moves } = await screen(session);
    assert.equal(find(host, "secret-key"), null);
    session.unlockError = coded("sk_answer_required");
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(moves, ["/login"], "the sign-in page asks the question");
  });
});

test("the_core_can_ask_for_the_key_after_the_first_try", async () => {
  await withDom(async () => {
    const session = fakeSession({ status: { pinned: true, skBit: true, skStored: true } });
    const { host, unlocked } = await screen(session);
    session.unlockError = coded("sk_required"); // the stored key could not be read
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.ok(find(host, "secret-key"), "the field appears");
    assert.ok(textOf(find(host, "error")).includes("account.error.sk_required"));

    session.unlockError = null;
    type(host, "password", PASSWORD);
    type(host, "secret-key", SK);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(session.unlocks.at(-1), { password: PASSWORD, skCode: SK });
    assert.equal(unlocked(), 1);
  });
});

test("the_password_leaves_the_input_before_the_slow_call_and_the_form_shows_it_is_busy", async () => {
  await withDom(async () => {
    const session = fakeSession();
    const seen = {};
    let release;
    let shown = null;
    session.unlock = async (args) => {
      const host = shown;
      seen.inputDuringCall = find(host, "password").value;
      seen.busy = host.getAttribute?.("aria-busy");
      seen.disabled = find(host, "submit").disabled;
      seen.args = { ...args };
      await new Promise((resolve) => { release = resolve; });
    };
    const { host } = await screen(session);
    shown = find(host, "unlock");
    type(host, "password", PASSWORD);
    const pending = submit(find(host, "unlock-form"));
    await settle();
    assert.equal(seen.inputDuringCall, "", "the input was emptied before the call");
    assert.equal(seen.args.password, PASSWORD);
    assert.equal(seen.busy, "true");
    assert.equal(seen.disabled, true);
    assert.ok(textOf(find(host, "status")).includes("vault.unlock.busy"));
    release();
    await pending;
    assert.equal(find(host, "submit").disabled, false);
    assert.equal(textOf(find(host, "status")).trim(), "");
  });
});

test("a_wrong_password_shows_a_message_and_leaves_nothing_in_the_form", async () => {
  await withDom(async () => {
    const session = fakeSession();
    session.unlockError = coded("decrypt");
    const { host, unlocked } = await screen(session);
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.equal(find(host, "error").hidden, false);
    assert.ok(textOf(find(host, "error")).includes("account.error.decrypt"));
    assert.equal(find(host, "password").value, "");
    assert.equal(find(host, "submit").disabled, false, "another try is possible");
    assert.equal(unlocked(), 0);
    assert.ok(!textOf(host).includes(PASSWORD));
  });
});

test("a_warning_about_the_servers_answer_is_loud_and_not_wrong_password", async () => {
  await withDom(async () => {
    for (const code of ["pinned_server_key", "pinned_sk_bit", "method_list_changed", "kdf_profile_downgrade"]) {
      const session = fakeSession();
      session.unlockError = coded(code);
      const { host } = await screen(session);
      type(host, "password", PASSWORD);
      await submit(find(host, "unlock-form"));
      const text = textOf(find(host, "error"));
      assert.ok(text.includes(`account.error.${code}`), code);
      assert.ok(!text.includes("account.error.decrypt"), code);
    }
  });
});

test("unlock_uses_the_sign_in_pages_texts_for_the_codes_they_know", async () => {
  await withDom(async () => {
    for (const code of ["epoch_mismatch", "methods_invalid", "two_factor_unsupported", "ids_changed", "pinned_auth_key", "pin_save_failed"]) {
      const session = fakeSession();
      session.unlockError = coded(code);
      const { host } = await screen(session);
      type(host, "password", PASSWORD);
      await submit(find(host, "unlock-form"));
      assert.ok(textOf(find(host, "error")).includes(`account.error.${code}`), code);
    }
    // A code nobody knows gets the general text, never the error's own message.
    const session = fakeSession();
    session.unlockError = Object.assign(new Error("typed secret: hunter2"), { code: "brand_new" });
    const { host } = await screen(session);
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.ok(textOf(find(host, "error")).includes("account.error.unknown"));
    assert.ok(!textOf(host).includes("hunter2"));
  });
});

test("an_ended_sign_in_goes_to_the_sign_in_page", async () => {
  await withDom(async () => {
    // No session on the server.
    const none = fakeSession({ info: null, open: false });
    const first = await screen(none);
    assert.deepEqual(first.moves, ["/login"]);
    assert.ok(find(first.host, "unlock"));
    assert.equal(find(first.host, "password"), null, "no form without a session");

    // The session ends while the screen is open.
    const session = fakeSession();
    session.unlockError = coded("session_ended");
    const { host, moves } = await screen(session);
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(moves, ["/login"]);
  });
});

test("an_empty_password_is_not_sent", async () => {
  await withDom(async () => {
    const session = fakeSession();
    const { host } = await screen(session);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(session.unlocks, []);
    assert.ok(textOf(find(host, "error")).includes("account.error.password_required"));
  });
});

test("unlock_view_takes_the_facts_it_is_given", async () => {
  await withDom(async () => {
    const view = unlockView({ session: fakeSession(), t, go() {}, email: "x@example.test", skRequired: true, onUnlocked() {} });
    assert.ok(textOf(view).includes("vault.unlock.as"));
    assert.ok(find(view, "secret-key"));
    assert.equal(find(view, "password").getAttribute("type"), "password");
    assert.equal(find(view, "password").getAttribute("autocomplete"), "current-password");
  });
});

test("the_lock_screen_links_to_account_recovery", async () => {
  await withDom(async () => {
    const session = fakeSession({ status: { pinned: true, skBit: false, skStored: false } });
    const { host } = await screen(session);
    const link = find(host, "recover-link");
    assert.ok(link, "a link for a forgotten master password");
    assert.equal(link.getAttribute("href"), "#/recover");
    assert.ok(textOf(link).includes("recover.link"));
  });
});

test("a_refusal_of_an_older_password_after_a_restore_offers_the_recovery_key_on_the_lock_screen", async () => {
  await withDom(async () => {
    const session = fakeSession({ status: { pinned: true, skBit: false, skStored: false } });
    session.unlockError = Object.assign(coded("pinned_kek_generation"), { recoveryOffer: "recover" });
    const { host, moves } = await screen(session);
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.equal(find(host, "recovery-offer").hidden, false);
    assert.ok(textOf(find(host, "error")).includes("recover.offer.recover"));
    const button = find(host, "use-recovery-key");
    assert.ok(button);
    await button.listeners.find(([kind]) => kind === "click")[1]();
    assert.deepEqual(moves, ["/recover"]);
    assert.equal(find(host, "password").value, "", "the password is not left in the form");

    // When the recovery key was renewed after the backup, the way out is to forget the server, with the warning text.
    session.unlockError = Object.assign(coded("pinned_kek_generation"), { recoveryOffer: "old_sheet" });
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.ok(find(host, "offer-forget"));
    assert.ok(textOf(find(host, "error")).includes("recover.offer.old_sheet"));
    assert.equal(find(host, "use-recovery-key"), null);
  });
});

/** A session whose server session has ended, on a browser that remembers the account. */
function endedSession({ remembered = { accountId: "aa".repeat(16), email: "ada@example.test", skBit: true, skStored: true } } = {}) {
  const session = fakeSession({ info: null, open: false });
  session.signOuts = 0;
  session.forgotten = [];
  session.remembered = async () => remembered;
  session.forgetRemembered = async (accountId) => {
    session.forgotten.push(accountId);
  };
  session.signOut = async () => {
    session.signOuts += 1;
  };
  return session;
}

test("an_ended_session_on_a_browser_that_remembers_the_account_is_unlock_with_the_email_read_only", async () => {
  await withDom(async () => {
    const session = endedSession();
    assert.deepEqual(await prepareUnlock(session), { signedIn: false, remembered: true, email: "ada@example.test", accountId: "aa".repeat(16), skRequired: false });
    const { host, moves, unlocked } = await screen(session);
    assert.deepEqual(moves, [], "the screen stays: no move to the sign-in page");
    const email = find(host, "remembered-email");
    assert.equal(email.value, "ada@example.test");
    assert.equal(email.getAttribute("readonly"), "", "read only");
    assert.equal(email.getAttribute("autocomplete"), "username");
    assert.ok(find(host, "not-you"), "Not you? Sign out");
    assert.equal(find(host, "secret-key"), null, "the device holds the key");
    assert.equal(find(host, "other-account"), null);
    assert.ok(textOf(host).includes("vault.unlock.ended"));

    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(session.unlocks, [{ password: PASSWORD, email: "ada@example.test" }], "a full sign-in with the remembered e-mail");
    assert.equal(find(host, "password").value, "");
    assert.equal(unlocked(), 1);
  });
});

test("an_ended_session_without_a_usable_memory_goes_to_the_sign_in_page", async () => {
  await withDom(async () => {
    // The account has a secret key and this device holds none.
    const missing = endedSession({ remembered: { accountId: "aa".repeat(16), email: "ada@example.test", skBit: true, skStored: false } });
    assert.deepEqual(await prepareUnlock(missing), { signedIn: false });
    assert.deepEqual((await screen(missing)).moves, ["/login"]);
    // Nothing remembered (signed out, forgotten, new device).
    const none = endedSession({ remembered: null });
    assert.deepEqual((await screen(none)).moves, ["/login"]);
    // A store that fails is nothing remembered.
    const broken = endedSession();
    broken.remembered = async () => {
      throw new Error("store");
    };
    assert.deepEqual((await screen(broken)).moves, ["/login"]);
  });
});

test("a_wrong_password_on_unlock_keeps_the_page_with_the_sign_in_pages_text", async () => {
  await withDom(async () => {
    const session = endedSession();
    session.unlockError = coded("decrypt");
    const { host, moves } = await screen(session);
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.deepEqual(moves, []);
    assert.ok(textOf(find(host, "error")).includes("account.error.decrypt"));
    assert.deepEqual(session.forgotten, [], "the device still remembers the account");
    assert.equal(find(host, "password").value, "");
    // The kit's second factor: the sign-in page's text, on the same page.
    session.unlockError = coded("two_factor_unsupported");
    type(host, "password", PASSWORD);
    await submit(find(host, "unlock-form"));
    assert.ok(textOf(find(host, "error")).includes("account.error.two_factor_unsupported"));
    assert.deepEqual(moves, []);
  });
});

test("a_refused_pin_on_unlock_forgets_the_account_and_hands_the_refusal_to_the_sign_in_page", async () => {
  const { takeRefusal } = await import("../../src/flows/rememberedAccount.mjs");
  for (const code of ["pinned_server_key", "pinned_elsewhere", "sk_required"]) {
    await withDom(async () => {
      const session = endedSession();
      session.unlockError = coded(code);
      const { host, moves } = await screen(session);
      type(host, "password", PASSWORD);
      await submit(find(host, "unlock-form"));
      assert.deepEqual(session.forgotten, ["aa".repeat(16)], `${code}: the device forgets the account`);
      assert.deepEqual(moves, ["/login"], `${code}: the full sign-in page`);
      assert.equal(takeRefusal(), session.unlockError, `${code}: the sign-in page gets the refusal`);
      assert.equal(takeRefusal(), null, "once");
    });
  }
});

test("not_you_signs_out_and_goes_to_the_sign_in_page", async () => {
  await withDom(async () => {
    const session = endedSession();
    const { host, moves } = await screen(session);
    await find(host, "not-you").listeners.find(([kind]) => kind === "click")[1]();
    assert.equal(session.signOuts, 1);
    assert.deepEqual(moves, ["/login"]);
    assert.deepEqual(session.unlocks, []);

    // A sign-out that could not reach the server still leaves for the sign-in page (the device has forgotten the account).
    const offline = endedSession();
    offline.signOut = async () => {
      throw coded("signout_incomplete");
    };
    const second = await screen(offline);
    await find(second.host, "not-you").listeners.find(([kind]) => kind === "click")[1]();
    assert.deepEqual(second.moves, ["/login"]);
  });
});
