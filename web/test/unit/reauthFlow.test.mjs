// Fresh re-authentication (spec Fase 1 § 4.6 (a)): the flow over a fake core and a fake
// server, the dialog that asks for the password, and the session's memory of the freshness.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { REAUTH_SKIP_MS, coversNext } from "../../src/flows/reauth.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { reauthDialog } from "../../src/views/reauthDialog.mjs";
import { ACCOUNT, accountDocument, byRole, coded, dumpDatabase, fire, settle, textOf, wiped } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { EMAIL, GRANT, PASSWORD, SK_CODE, answer, signedInWorld } from "./securityHelpers.mjs";

const catalog = (lang) => ({
  ...JSON.parse(readFileSync(join(web, "src", "locales", lang, "account.json"), "utf8")),
  ...JSON.parse(readFileSync(join(web, "src", "locales", lang, "security.json"), "utf8")),
});
const t = createI18n({ en: catalog("en"), nb: catalog("nb") }, "en").t;

async function withDom(body) {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  try {
    return await body(globalThis.document);
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

const NOW = 1_800_000_000_000;

// ------------------------------------------------------------------ the dialog

test("reauth_dialog_is_skipped_while_reauth_until_covers_the_next_minute", async () => {
  await withDom(async (document) => {
    const run = async () => assert.fail("the password is not asked for");
    // Covered: at least a minute is left, so the answer comes at once and nothing is put in the page.
    assert.equal(await reauthDialog({ t, run, until: NOW + REAUTH_SKIP_MS, now: () => NOW, host: document.body }), "ok");
    assert.equal(await reauthDialog({ t, run, until: NOW + 240_000, now: () => NOW, host: document.body }), "ok");
    assert.equal(document.body.childNodes.length, 0);
    assert.equal(document.created.length, 0, "no element was even made");

    // Not covered: less than a minute left, nothing, or already past. The dialog opens and waits for the user.
    for (const until of [NOW + REAUTH_SKIP_MS - 1, NOW + 1, NOW, NOW - 5_000, null]) {
      document.body.childNodes.length = 0;
      const pending = reauthDialog({ t, run: async () => {}, until, now: () => NOW, host: document.body });
      assert.ok(byRole(document.body, "reauth-dialog"), `the dialog opens for ${until}`);
      await fire(byRole(document.body, "reauth-cancel"), "click");
      assert.equal(await pending, "cancelled");
      assert.equal(byRole(document.body, "reauth-dialog"), null, "a closed dialog leaves the page");
    }
  });

  // The rule itself, with its edges.
  assert.equal(coversNext(NOW + REAUTH_SKIP_MS, NOW), true);
  assert.equal(coversNext(NOW + REAUTH_SKIP_MS - 1, NOW), false);
  assert.equal(coversNext(undefined, NOW), false);
  assert.equal(coversNext(Number.NaN, NOW), false);
  assert.equal(coversNext(NOW + 90_000, NOW, 120_000), false);
});

test("reauth_clears_the_password_field_before_the_call", async () => {
  await withDom(async (document) => {
    /** What the field held when the call started, and again when it had failed. */
    const seen = [];
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    let fail = true;
    const run = async (typed) => {
      seen.push({ typed, field: byRole(document.body, "reauth-password").value, disabled: byRole(document.body, "reauth-confirm").disabled });
      await gate;
      if (fail) throw coded("decrypt");
    };
    const pending = reauthDialog({ t, run, until: null, now: () => NOW, host: document.body });
    const password = byRole(document.body, "reauth-password");
    password.value = PASSWORD;
    const submitted = fire(byRole(document.body, "reauth-form"), "submit");
    await settle();
    // The call has started and waits: the field is already empty, and the dialog is busy.
    assert.deepEqual(seen, [{ typed: { password: PASSWORD }, field: "", disabled: true }]);
    assert.equal(password.value, "");
    assert.equal(byRole(document.body, "reauth-dialog").getAttribute("aria-busy"), "true");
    assert.equal(byRole(document.body, "reauth-cancel").disabled, true, "cancel waits for the call");
    release();
    await submitted;
    // A refusal shows its text, never the password, and keeps the dialog for another try.
    assert.equal(password.value, "");
    assert.match(textOf(byRole(document.body, "reauth-error")), /secret key is not right|master password or the secret key/i);
    assert.doesNotMatch(textOf(document.body), new RegExp(PASSWORD));
    assert.equal(byRole(document.body, "reauth-dialog").getAttribute("aria-busy"), "false");
    assert.equal(password.disabled, false);

    // The next try goes through and closes the dialog.
    fail = false;
    password.value = PASSWORD;
    await fire(byRole(document.body, "reauth-form"), "submit");
    assert.equal(await pending, "ok");
    assert.equal(byRole(document.body, "reauth-dialog"), null);
    assert.equal(seen.length, 2);
  });
});

test("the_dialog_asks_for_the_secret_key_when_the_device_has_none_and_a_lock_removes_it", async () => {
  await withDom(async (document) => {
    const scope = createWipeScope();
    const seen = [];
    const pending = reauthDialog({ t, run: async (typed) => seen.push(typed), until: null, now: () => NOW, host: document.body, skRequired: true, scope });
    assert.ok(byRole(document.body, "reauth-secret-key"));
    // The password alone is not enough.
    byRole(document.body, "reauth-password").value = PASSWORD;
    await fire(byRole(document.body, "reauth-form"), "submit");
    assert.deepEqual(seen, []);
    assert.match(textOf(byRole(document.body, "reauth-error")), /secret key/i);
    byRole(document.body, "reauth-secret-key").value = `  ${SK_CODE} `;
    await fire(byRole(document.body, "reauth-form"), "submit");
    assert.equal(await pending, "ok");
    assert.deepEqual(seen, [{ password: PASSWORD, skCode: SK_CODE }]);

    // A dialog that is open when the vault locks is removed, with what was typed in it.
    const second = reauthDialog({ t, run: async () => {}, until: null, now: () => NOW, host: document.body, scope });
    const field = byRole(document.body, "reauth-password");
    field.value = PASSWORD;
    scope.run();
    assert.equal(await second, "cancelled");
    assert.equal(field.value, "");
    assert.equal(byRole(document.body, "reauth-dialog"), null);

    // A dialog may be answered once: Escape cancels it, and a late submit does nothing.
    const third = reauthDialog({ t, run: async () => assert.fail("not run"), until: null, now: () => NOW, host: document.body });
    await fire(byRole(document.body, "reauth-dialog"), "keydown", { key: "Escape" });
    assert.equal(await third, "cancelled");
  });
});

// ------------------------------------------------------------------- the flow

test("reauthenticate_is_a_reauth_sign_in_that_leaves_the_open_vault_alone", async () => {
  const world = await signedInWorld({ reauthUntil: Math.floor(NOW / 1000) + 300 });
  const done = await world.session.reauthenticate({ password: PASSWORD, skCode: undefined });
  assert.deepEqual(world.log, [
    "GET /api/auth/session",
    "vault.login_start",
    "POST /api/auth/opaque/login/start",
    "vault.login_finish",
    "POST /api/auth/opaque/login/finish",
    "GET /api/auth/session",
    "vault.clear",
  ]);
  const [start, finish] = world.requests.filter((r) => r.method === "POST");
  assert.equal(start.body.purpose, "reauth");
  assert.equal(start.body.email, EMAIL);
  assert.equal(finish.body.purpose, "reauth");
  // The core is told the record this device pinned, as an early guard, and never opens another vault.
  assert.equal(world.client.called("login_finish")[0].snapshot[2].kind, "pinned");
  assert.equal(world.client.called("unlock_password").length, 0);
  assert.equal(world.client.locked, 0);
  assert.equal(world.session.current().accountId, ACCOUNT, "the vault is still open");
  assert.equal(world.client.called("reauth_grant").length, 0);
  assert.equal(done.grant, undefined);
  // The password reached the core as a byte array that was wiped afterwards.
  const start1 = world.client.called("login_start")[0];
  assert.ok(wiped(start1.args[0]));
  // The secret key came from this device: the account has one, the page did not type it.
  assert.equal(start1.snapshot[1], SK_CODE);
});

test("reauthenticate_takes_the_freshness_from_the_server_and_never_more_than_five_minutes", async () => {
  // The server says 300 seconds from the clock the world uses.
  let world = await signedInWorld({ reauthUntil: Math.floor(Date.now() / 1000) + 300 });
  let done = await world.session.reauthenticate({ password: PASSWORD });
  assert.ok(done.until <= Date.now() + 300_000 && done.until > Date.now() + 290_000);
  assert.equal(world.session.reauthUntil(), done.until);

  // A server clock far ahead never makes this device believe in more than five minutes.
  world = await signedInWorld({ reauthUntil: Math.floor(Date.now() / 1000) + 86_400 });
  done = await world.session.reauthenticate({ password: PASSWORD });
  assert.ok(done.until <= Date.now() + 300_000);

  // An answer without `reauth_until`, or no answer, is no freshness: it fails closed and the next operation asks again.
  for (const overrides of [{}, { "GET /api/auth/session": (_b, state) => (state.requests.length > 3 ? answer(500, { error: "x" }) : undefined) }]) {
    world = await signedInWorld({ overrides });
    done = await world.session.reauthenticate({ password: PASSWORD });
    assert.equal(done.until, null);
    assert.equal(world.session.reauthUntil(), null);
  }

  // A lock forgets it: the next operation asks again.
  await world.session.lock();
  assert.equal(world.session.reauthUntil(), null);
});

test("reauthenticate_with_wantgrant_gives_the_token_from_the_password_wrap_and_wipes_the_sign_in", async () => {
  const world = await signedInWorld({ reauthUntil: Math.floor(Date.now() / 1000) + 300 });
  const done = await world.session.reauthenticate({ password: PASSWORD, wantGrant: true });
  assert.deepEqual(done.grant, GRANT);
  assert.deepEqual(world.log.slice(-4), ["GET /api/auth/session", "GET /api/vault/unlock-methods", "vault.reauth_grant", "vault.clear"]);
  // The core gets the server's password wrap (with the sign-in's profile) and the time of this device.
  const [wrap, nowMs] = world.client.called("reauth_grant")[0].snapshot;
  assert.equal(wrap.method.type, "password");
  assert.equal(wrap.method.ksf_profile, 1);
  assert.ok(Math.abs(nowMs - Date.now()) < 5_000);
});

test("a_wrong_password_says_so_leaves_the_vault_open_and_drops_the_sign_in", async () => {
  const world = await signedInWorld({
    handlers: {
      login_finish: () => {
        throw coded("decrypt");
      },
    },
  });
  await assert.rejects(world.session.reauthenticate({ password: PASSWORD }), { code: "decrypt" });
  assert.equal(world.client.locked, 0, "the vault stays open");
  assert.ok(world.session.current());
  assert.equal(world.session.reauthUntil(), null);
  assert.ok(world.log.includes("vault.clear"));
  assert.equal(world.requests.filter((r) => r.url.endsWith("login/finish")).length, 0, "the proof of a wrong password never reaches the server");
  // The session of the server is not ended by a failed check.
  assert.equal(world.requests.some((r) => r.url === "/api/auth/logout"), false);
});

test("two_factor_on_the_account_and_a_session_that_ended_are_told_apart", async () => {
  let world = await signedInWorld({
    overrides: { "POST /api/auth/opaque/login/finish": () => answer(403, { error: "forbidden" }) },
  });
  await assert.rejects(world.session.reauthenticate({ password: PASSWORD }), { code: "two_factor_unsupported" });

  world = await signedInWorld({ overrides: { "GET /api/auth/session": () => answer(401, { error: "unauthorized" }) } });
  await assert.rejects(world.session.reauthenticate({ password: PASSWORD }), { code: "session_ended" });
  assert.equal(world.requests.filter((r) => r.method === "POST").length, 0, "nothing is sent without a session");

  // The server names another account than the session's: nothing was confirmed.
  world = await signedInWorld({
    overrides: { "POST /api/auth/opaque/login/finish": () => answer(200, { account_id: "ee".repeat(16), vault_id: "ff".repeat(16), vk_epoch: 1 }) },
  });
  await assert.rejects(world.session.reauthenticate({ password: PASSWORD }), { code: "pinned_account_mismatch" });
});

test("the_secret_key_is_asked_for_only_when_the_account_has_one_and_the_device_does_not", async () => {
  // Remembered on this device (the sign-in saved it): not asked for.
  let world = await signedInWorld();
  await world.session.reauthenticate({ password: PASSWORD });
  assert.equal(world.client.called("login_start")[0].snapshot[1], SK_CODE);
  // An account without a secret key never sends one, even if the page passes a code.
  world = await signedInWorld({ skBit: false });
  await world.session.reauthenticate({ password: PASSWORD, skCode: SK_CODE });
  assert.equal(world.client.called("login_start")[0].snapshot[1], null);
  // An account with one that the device does not remember: the flow says so before anything is sent.
  world = await signedInWorld({ forgetKey: true });
  await assert.rejects(world.session.reauthenticate({ password: PASSWORD }), { code: "sk_required" });
  assert.equal(world.requests.filter((r) => r.method === "POST").length, 0);
  assert.equal(world.client.called("login_start").length, 0);
  await world.session.reauthenticate({ password: PASSWORD, skCode: SK_CODE });
  assert.equal(world.client.called("login_start")[0].snapshot[1], SK_CODE);
});

test("nothing_typed_reaches_the_address_the_console_or_the_database_during_a_reauth", async () => {
  const world = await signedInWorld();
  const logged = [];
  const saved = {};
  for (const name of ["log", "info", "warn", "error", "debug"]) {
    saved[name] = console[name];
    console[name] = (...args) => logged.push(args.map(String).join(" "));
  }
  try {
    await world.session.reauthenticate({ password: PASSWORD, skCode: SK_CODE });
  } catch (error) {
    assert.fail(`unexpected: ${error?.code}`);
  } finally {
    Object.assign(console, saved);
  }
  assert.deepEqual(logged, []);
  for (const request of world.requests) {
    assert.ok(!request.url.includes(PASSWORD) && !request.url.includes(SK_CODE) && !request.url.includes("?"), request.url);
    assert.ok(!JSON.stringify(request.body ?? "").includes(PASSWORD), "the password is not in a body");
  }
  assert.ok(!(await dumpDatabase(world.db.store)).includes(PASSWORD), "nothing typed is stored");
});

test("a_lock_while_the_password_is_being_checked_does_not_bring_the_freshness_back", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const world = await signedInWorld({
    reauthUntil: Math.floor(Date.now() / 1000) + 300,
    handlers: { login_finish: async () => (await gate, { ke3: new Uint8Array(64).fill(2), server_public_key: new Uint8Array(32).fill(9) }) },
  });
  const pending = world.session.reauthenticate({ password: PASSWORD });
  await settle();
  await world.session.lock();
  release();
  await pending;
  assert.equal(world.session.reauthUntil(), null, "the lock cleared it and the late answer did not write it back");
});

test("a_caller_that_needs_the_grant_is_never_skipped_by_the_freshness", async () => {
  await withDom(async (document) => {
    const seen = [];
    const pending = reauthDialog({ t, run: async (typed) => seen.push(typed), until: NOW + 240_000, now: () => NOW, host: document.body, needGrant: true });
    assert.ok(byRole(document.body, "reauth-dialog"), "the dialog opens although the freshness covers the next minute");
    byRole(document.body, "reauth-password").value = PASSWORD;
    await fire(byRole(document.body, "reauth-form"), "submit");
    assert.equal(await pending, "ok");
    assert.equal(seen.length, 1, "the check ran, so a grant can be made");
  });
});

test("tab_stays_inside_the_dialog_and_focus_goes_back_when_it_closes", async () => {
  await withDom(async (document) => {
    const opener = { focused: 0, focus() { this.focused += 1; } };
    document.activeElement = opener;
    const pending = reauthDialog({ t, run: async () => {}, until: null, now: () => NOW, host: document.body, skRequired: true });
    const password = byRole(document.body, "reauth-password");
    const sk = byRole(document.body, "reauth-secret-key");
    const cancel = byRole(document.body, "reauth-cancel");
    const confirm = byRole(document.body, "reauth-confirm");
    let focused = null;
    for (const node of [password, sk, cancel, confirm]) node.focus = () => { focused = node; };
    const dialog = byRole(document.body, "reauth-dialog");
    const tab = async (target, shiftKey = false) => {
      const event = { key: "Tab", shiftKey, target, prevented: false, preventDefault() { this.prevented = true; } };
      for (const [kind, fn] of dialog.listeners) if (kind === "keydown") await fn(event);
      return event;
    };
    // In the middle Tab goes on by itself; at the ends it goes round.
    assert.equal((await tab(password)).prevented, false);
    assert.equal((await tab(cancel, true)).prevented, false);
    let event = await tab(confirm);
    assert.equal(event.prevented, true);
    assert.equal(focused, password);
    event = await tab(password, true);
    assert.equal(event.prevented, true);
    assert.equal(focused, confirm);
    // From outside the dialog it comes in at the first control.
    event = await tab({}, false);
    assert.equal(event.prevented, true);
    assert.equal(focused, password);
    // While it works no control is enabled: Tab is held still.
    for (const node of [password, sk, cancel, confirm]) node.disabled = true;
    assert.equal((await tab(password)).prevented, true);
    for (const node of [password, sk, cancel, confirm]) node.disabled = false;

    await fire(cancel, "click");
    assert.equal(await pending, "cancelled");
    assert.equal(opener.focused, 1, "focus went back to the opener");
  });
});
