// The account pages (sign-in, setup, sheet, password), the entry of the page and
// the hand-over to the admin pages, against a small fake DOM.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createI18n } from "../../src/i18n.mjs";
import { configuredAdminUrl } from "../../src/flows/adminUrl.mjs";
import { consumeEntry, getEntry, plainNext, readEntry } from "../../src/flows/entry.mjs";
import { completeHandoff } from "../../src/flows/handoff.mjs";
import { KNOWN_ERRORS } from "../../src/views/form.mjs";
import { loginView } from "../../src/views/login.mjs";
import { passwordView } from "../../src/views/password.mjs";
import { setupView } from "../../src/views/setup.mjs";
import { EMAIL, PASSWORD, RK_CODE, SK_CODE, accountDocument, byRole, coded, fire, scenario, settle, textOf, until } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";

const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "account.json"), "utf8"));
const i18n = (lang = "en") => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);
const CHALLENGE = "C".repeat(43);
const ADMIN = "https://admin.ferret.test";

/** Runs an async test body with a fake `document` as the global one. */
async function withDom(body) {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  try {
    return await body();
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};

/** A session for the sign-in page that records what it is asked. */
function fakeSession({ device = { pinned: false, skBit: null, skStored: false }, signIn, unlock, current = null, fresh = true } = {}) {
  const calls = [];
  return {
    calls,
    deviceStatus: async () => device,
    signIn: async (args) => {
      calls.push(["signIn", args]);
      return signIn ? signIn(args) : { accountId: "a" };
    },
    unlock: async (args) => {
      calls.push(["unlock", args]);
      return unlock ? unlock(args) : { accountId: "a" };
    },
    current: () => current,
    freshReauth: () => fresh,
    lock: async () => calls.push(["lock"]),
    signOut: async () => calls.push(["signOut"]),
    forgetSecretKey: async (id) => calls.push(["forgetSecretKey", id]),
  };
}

function loginDeps(overrides = {}) {
  const went = [];
  const handoffs = [];
  const toAdmin = [];
  const deps = {
    t: i18n().t,
    session: fakeSession(),
    entry: { page: "login", handoff: null, brokenHandoff: false, setupToken: null },
    adminUrl: ADMIN,
    api: {},
    go: (path) => went.push(path),
    handoff: {
      completeHandoff: async (options) => handoffs.push(options),
      goToAdmin: async (options) => toAdmin.push(options),
    },
    info: null,
    ...overrides,
  };
  return { deps, went, handoffs, toAdmin };
}

/** Types into the sign-in form and submits it. */
async function submitSignIn(root, { email = EMAIL, password = PASSWORD, sk } = {}) {
  byRole(root, "email").value = email;
  byRole(root, "password").value = password;
  if (sk === true) {
    byRole(root, "sk-yes").checked = true;
    await fire(byRole(root, "sk-yes"), "change");
  } else if (sk === false) {
    byRole(root, "sk-no").checked = true;
    await fire(byRole(root, "sk-no"), "change");
  }
  await fire(byRole(root, "credentials"), "submit");
}

test("trust_boundary_notice_is_on_the_login_and_setup_pages", async () => {
  await withDom(async () => {
    const english = catalog("en")["account.trust.notice"];
    const norwegian = catalog("nb")["account.trust.notice"];
    // The text of the design: the web vault trusts the server that delivers its code.
    assert.match(english, /trusts the server that delivers its code/);
    assert.match(english, /malicious operator/);
    assert.match(english, /browser extension and the apps are the real protection/);
    assert.equal(
      norwegian,
      "Webhvelvet stoler på serveren som leverer koden. En ondsinnet driftsansvarlig kan levere endret JavaScript som stjeler hovedpassordet. Nettleserutvidelsen og appene er det virkelige vernet.",
    );
    for (const [lang, expected] of [["en", english], ["nb", norwegian]]) {
      const t = i18n(lang).t;
      const { deps } = loginDeps({ t });
      const login = loginView(deps);
      const setup = setupView({ t, session: fakeSession(), setupToken: null, adminUrl: null, go() {}, handoff: {} });
      for (const page of [login, setup]) {
        const notice = byRole(page, "trust-notice");
        assert.ok(notice, `${lang}: the notice is on the page`);
        assert.equal(textOf(notice).trim(), expected);
        // Last in the card, so it is always in the same place.
        assert.equal(page.childNodes.at(-1), notice);
      }
    }
  });
});

test("busy_state_is_shown_during_argon2", async () => {
  await withDom(async () => {
    const slow = deferred();
    const session = fakeSession({ signIn: () => slow.promise });
    const { deps, went } = loginDeps({ session });
    const root = loginView(deps);
    const submit = byRole(root, "submit");
    const status = byRole(root, "status");
    assert.equal(submit.disabled, false);
    assert.equal(textOf(status).trim(), "");

    const pending = submitSignIn(root, { sk: false });
    await settle();
    // While the key stretching runs: the form is locked, and the page says it is working.
    assert.equal(submit.disabled, true);
    assert.equal(byRole(root, "password").disabled, true);
    assert.match(textOf(status), /Working/);
    assert.equal(byRole(root, "credentials").getAttribute("aria-busy"), "true");
    // A second submit while busy does nothing.
    await fire(byRole(root, "credentials"), "submit");
    assert.equal(session.calls.filter(([name]) => name === "signIn").length, 1);

    slow.resolve({ accountId: "a" });
    await pending;
    await settle();
    assert.equal(submit.disabled, false);
    assert.equal(textOf(status).trim(), "");
    assert.deepEqual(went, ["/"]);
  });
});

test("a_failed_sign_in_shows_the_error_and_unlocks_the_form", async () => {
  await withDom(async () => {
    const session = fakeSession({
      signIn: () => {
        throw Object.assign(coded("decrypt"), { skHint: true });
      },
    });
    const { deps, went } = loginDeps({ session });
    const root = loginView(deps);
    await submitSignIn(root);
    await settle();
    const error = byRole(root, "error");
    assert.equal(error.hidden, false);
    assert.match(textOf(error), /could not be opened/);
    assert.equal(byRole(root, "submit").disabled, false);
    assert.deepEqual(went, []);
    // The hint is shown as a suggestion and preselects the answer, since none was given.
    assert.equal(byRole(root, "sk-hint").hidden, false);
    assert.equal(byRole(root, "sk-yes").checked, true);
    assert.equal(byRole(root, "sk-no").checked, false);

    // An answer the user gave is not overridden by the hint.
    const again = loginView(loginDeps({ session }).deps);
    await submitSignIn(again, { sk: false });
    await settle();
    assert.equal(byRole(again, "sk-no").checked, true);
    assert.equal(byRole(again, "sk-yes").checked, false);
  });
});

test("password_inputs_are_cleared_after_submit_and_the_view_keeps_no_copy", async () => {
  await withDom(async () => {
    const slow = deferred();
    const session = fakeSession({ signIn: () => slow.promise });
    const root = loginView(loginDeps({ session }).deps);
    byRole(root, "sk-code").value = SK_CODE;
    const pending = submitSignIn(root, { sk: true });
    await settle();
    // Emptied at once, while the call is still running.
    assert.equal(byRole(root, "password").value, "");
    assert.equal(byRole(root, "sk-code").value, "");
    const [, args] = session.calls[0];
    assert.equal(args.password, PASSWORD);
    assert.equal(args.skCode, SK_CODE);
    assert.equal(args.skBit, true);
    slow.resolve({});
    await pending;
    await settle();
    assert.ok(!textOf(root).includes(PASSWORD));
    assert.ok(!textOf(root).includes(SK_CODE));

    // The same on a failure.
    const failing = fakeSession({ signIn: () => { throw coded("decrypt"); } });
    const second = loginView(loginDeps({ session: failing }).deps);
    await submitSignIn(second, { sk: false });
    await settle();
    assert.equal(byRole(second, "password").value, "");
  });
});

test("remember_choice_is_shown_at_first_sign_in_on_a_new_device", async () => {
  await withDom(async () => {
    // A device that knows nothing about the e-mail: the question, and the choice once "yes" is picked.
    const root = loginView(loginDeps().deps);
    byRole(root, "email").value = EMAIL;
    await fire(byRole(root, "email"), "change");
    await settle();
    assert.equal(byRole(root, "sk-question").hidden, false);
    assert.equal(byRole(root, "remember-row").hidden, true);
    byRole(root, "sk-yes").checked = true;
    await fire(byRole(root, "sk-yes"), "change");
    assert.equal(byRole(root, "remember-row").hidden, false);
    assert.equal(byRole(root, "remember").checked, true);
    assert.equal(byRole(root, "sk-code").parentNode.hidden, false);
    byRole(root, "sk-yes").checked = false;
    byRole(root, "sk-no").checked = true;
    await fire(byRole(root, "sk-no"), "change");
    assert.equal(byRole(root, "remember-row").hidden, true);
    assert.equal(byRole(root, "sk-code").parentNode.hidden, true);

    // What goes to the session follows the choice, and is left out when it is not offered.
    const session = fakeSession();
    const again = loginView(loginDeps({ session }).deps);
    byRole(again, "sk-code").value = SK_CODE;
    byRole(again, "remember").checked = false;
    await submitSignIn(again, { sk: true });
    await settle();
    assert.equal(session.calls[0][1].rememberSk, false);

    // A device that has the account and the sealed key asks for nothing.
    const known = fakeSession({ device: { pinned: true, skBit: true, skStored: true } });
    const quiet = loginView(loginDeps({ session: known }).deps);
    byRole(quiet, "email").value = EMAIL;
    await fire(byRole(quiet, "email"), "change");
    await settle();
    assert.equal(byRole(quiet, "sk-question").hidden, true);
    assert.equal(byRole(quiet, "sk-code").parentNode.hidden, true);
    assert.equal(byRole(quiet, "remember-row").hidden, true);
    assert.equal(byRole(quiet, "sk-remembered").hidden, false);
    await submitSignIn(quiet, {});
    await settle();
    const args = known.calls[0][1];
    assert.equal(args.skBit, undefined);
    assert.equal("rememberSk" in args, false);

    // A device that has the account but not the key asks for the key only.
    const missing = fakeSession({ device: { pinned: true, skBit: true, skStored: false } });
    const ask = loginView(loginDeps({ session: missing }).deps);
    byRole(ask, "email").value = EMAIL;
    await fire(byRole(ask, "email"), "change");
    await settle();
    assert.equal(byRole(ask, "sk-question").hidden, true);
    assert.equal(byRole(ask, "sk-code").parentNode.hidden, false);
    assert.equal(byRole(ask, "remember-row").hidden, true);
  });
});

test("handoff_query_triggers_complete_handoff_after_sign_in_and_a_plain_vault_path_does_not", async () => {
  await withDom(async () => {
    const entry = readEntry({ pathname: "/vault/login", search: `?handoff=1&challenge=${CHALLENGE}&next=%2Fsettings%2Fusers`, hash: "" });
    assert.deepEqual(entry.handoff, { challenge: CHALLENGE, next: "/settings/users", purpose: "login" });

    // Opening the page starts nothing.
    const viaHandoff = loginDeps({ entry });
    const root = loginView(viaHandoff.deps);
    await settle();
    assert.deepEqual(viaHandoff.handoffs, []);
    // The sign-in click does, and the vault is not opened in this tab.
    await submitSignIn(root, { sk: false });
    await settle();
    assert.equal(viaHandoff.handoffs.length, 1);
    assert.deepEqual(
      { challenge: viaHandoff.handoffs[0].challenge, next: viaHandoff.handoffs[0].next, purpose: viaHandoff.handoffs[0].purpose, adminUrl: viaHandoff.handoffs[0].adminUrl },
      { challenge: CHALLENGE, next: "/settings/users", purpose: "login", adminUrl: ADMIN },
    );
    assert.deepEqual(viaHandoff.went, []);

    // A plain vault path opens the vault.
    const plain = loginDeps();
    const plainRoot = loginView(plain.deps);
    await submitSignIn(plainRoot, { sk: false });
    await settle();
    assert.deepEqual(plain.handoffs, []);
    assert.deepEqual(plain.went, ["/"]);

    // The same for a session that already exists: only the click on "Continue" mints the code.
    const signedIn = loginDeps({ entry, info: { accountId: "a", email: EMAIL }, session: fakeSession({ current: {} }) });
    const panel = loginView(signedIn.deps);
    await settle();
    assert.deepEqual(signedIn.handoffs, []);
    assert.equal(byRole(panel, "credentials"), null);
    await fire(byRole(panel, "continue-admin"), "click");
    await settle();
    assert.equal(signedIn.handoffs.length, 1);

    // Without a configured admin address nothing is minted, and the page says why.
    const unconfigured = loginDeps({ entry, adminUrl: null });
    const noAdmin = loginView(unconfigured.deps);
    await submitSignIn(noAdmin, { sk: false });
    await settle();
    assert.deepEqual(unconfigured.handoffs, []);
    assert.match(textOf(byRole(noAdmin, "error")), /admin pages is not set/);

    // A link with a broken challenge is told so, and a sign-in then opens the vault as usual.
    const broken = readEntry({ pathname: "/vault/login", search: "?handoff=1&challenge=short", hash: "" });
    assert.equal(broken.handoff, null);
    assert.equal(broken.brokenHandoff, true);
    const brokenPage = loginView(loginDeps({ entry: broken }).deps);
    assert.ok(byRole(brokenPage, "handoff-broken"));
  });
});

test("the_real_handoff_function_navigates_to_the_admin_origin_with_the_code_in_the_fragment", async () => {
  const navigated = [];
  const code = "D".repeat(43);
  await completeHandoff({
    api: { post: async (path, body) => { assert.equal(path, "/api/auth/handoff"); assert.equal(body.challenge, CHALLENGE); return { code, expires_in: 60 }; } },
    challenge: CHALLENGE,
    next: "/settings",
    purpose: "login",
    adminUrl: ADMIN,
    navigate: (url) => navigated.push(url),
  });
  assert.deepEqual(navigated, [`${ADMIN}/auth/handoff#code=${code}`]);
});

test("next_must_be_a_configured_admin_or_vault_path", async () => {
  // The path the admin pages asked for is kept only as a plain path on the admin origin.
  for (const next of ["/settings/users", "/", "/a/b?c=d"]) assert.equal(plainNext(next), next);
  for (const next of ["https://evil.example/x", "//evil.example", "/\\evil.example", "/a b", "/a\nb", "javascript:alert(1)", "", null, undefined, 7, `/${"a".repeat(600)}`]) {
    assert.equal(plainNext(next), "/", String(next));
  }
  const entry = readEntry({ pathname: "/vault/login", search: `?handoff=1&challenge=${CHALLENGE}&next=%2F%2Fevil.example`, hash: "" });
  assert.equal(entry.handoff?.next, "/");

  // The admin address comes from the page that delivered the code and nowhere else.
  const page = (content) => ({ querySelector: (selector) => (selector === 'meta[name="ferret-admin-url"]' ? { getAttribute: () => content } : null) });
  assert.equal(configuredAdminUrl(page("https://admin.example.com/ignored/path"), "https://vault.example.com"), "https://admin.example.com");
  for (const bad of ["", "not a url", "ftp://admin.example", "https://user:pw@admin.example", "javascript:alert(1)", "https://vault.example.com", null]) {
    assert.equal(configuredAdminUrl(page(bad), "https://vault.example.com"), null, String(bad));
  }
  assert.equal(configuredAdminUrl({ querySelector: () => null }, "https://vault.example.com"), null);
  assert.equal(configuredAdminUrl(undefined, "https://vault.example.com"), null);
});

test("reauth_purpose_handoff_is_only_started_right_after_a_fresh_reauth", async () => {
  await withDom(async () => {
    const entry = readEntry({ pathname: "/vault/reauth", search: `?handoff=1&challenge=${CHALLENGE}&next=%2Fsettings%2Fsecurity`, hash: "" });
    assert.equal(entry.handoff?.purpose, "reauth");
    const info = { accountId: "a", email: EMAIL };

    // Opening the page, or having a session, starts nothing.
    const idle = loginDeps({ entry, info, reauth: true, session: fakeSession({ fresh: false }) });
    const page = loginView(idle.deps);
    await settle();
    assert.deepEqual(idle.handoffs, []);
    assert.equal(byRole(page, "email"), null, "the page asks for the password only");

    // A password that checks out: the hand-over starts with purpose reauth.
    const good = loginDeps({ entry, info, reauth: true });
    const goodPage = loginView(good.deps);
    byRole(goodPage, "password").value = PASSWORD;
    await fire(byRole(goodPage, "credentials"), "submit");
    await settle();
    assert.equal(good.handoffs.length, 1);
    assert.equal(good.handoffs[0].purpose, "reauth");
    assert.deepEqual(good.went, []);

    // A password that does not check out starts nothing.
    const bad = loginDeps({ entry, info, reauth: true, session: fakeSession({ unlock: () => { throw coded("decrypt"); } }) });
    const badPage = loginView(bad.deps);
    byRole(badPage, "password").value = "nope";
    await fire(byRole(badPage, "credentials"), "submit");
    await settle();
    assert.deepEqual(bad.handoffs, []);

    // A reauth that is not fresh (too old) starts nothing even if the unlock call succeeded.
    const stale = loginDeps({ entry, info, reauth: true, session: fakeSession({ fresh: false }) });
    const stalePage = loginView(stale.deps);
    byRole(stalePage, "password").value = PASSWORD;
    await fire(byRole(stalePage, "credentials"), "submit");
    await settle();
    assert.deepEqual(stale.handoffs, []);
    assert.match(textOf(byRole(stalePage, "error")), /run out of time/);

    // No vault session: the page says so and offers the sign-in page; the password is not asked.
    const ended = loginDeps({ entry, info: null, reauth: true });
    const endedPage = loginView(ended.deps);
    assert.ok(byRole(endedPage, "ended"));
    assert.equal(byRole(endedPage, "password"), null);
    assert.deepEqual(ended.handoffs, []);
  });
});

test("the_signed_in_panel_offers_lock_sign_out_forget_and_the_admin_pages", async () => {
  await withDom(async () => {
    const session = fakeSession({ current: {} });
    const { deps, went, toAdmin } = loginDeps({ session, info: { accountId: "ab".repeat(16), email: EMAIL } });
    const panel = loginView(deps);
    for (const role of ["open-vault", "admin", "lock", "sign-out", "forget-sk"]) assert.ok(byRole(panel, role), role);
    assert.equal(byRole(panel, "continue-admin"), null);
    await fire(byRole(panel, "admin"), "click");
    await settle();
    assert.deepEqual(toAdmin, [{ adminUrl: ADMIN, next: "/", purpose: "login" }]);
    await fire(byRole(panel, "forget-sk"), "click");
    await settle();
    assert.deepEqual(session.calls.at(-1), ["forgetSecretKey", "ab".repeat(16)]);
    await fire(byRole(panel, "lock"), "click");
    await settle();
    assert.deepEqual(session.calls.at(-1), ["lock"]);
    await fire(byRole(panel, "sign-out"), "click");
    await settle();
    assert.deepEqual(session.calls.at(-1), ["signOut"]);
    assert.deepEqual(went, ["/login", "/login"]);

    // Signed in at the server but locked (a reload): the password form comes first.
    const locked = loginView(loginDeps({ info: { accountId: "a", email: EMAIL } }).deps);
    assert.ok(byRole(locked, "password"));
    assert.equal(byRole(locked, "email"), null);
  });
});

test("sheet_text_is_removed_from_the_dom_after_confirmation", async () => {
  await withDom(async () => {
    const world = await scenario();
    const went = [];
    const root = setupView({
      t: i18n().t,
      session: world.session,
      setupToken: "setup-token-1",
      spentToken: () => went.push("spent"),
      adminUrl: null,
      go: (path) => went.push(path),
      handoff: {},
    });
    byRole(root, "email").value = EMAIL;
    byRole(root, "password").value = PASSWORD;
    byRole(root, "password-repeat").value = PASSWORD;
    await fire(byRole(root, "setup-form"), "submit");
    await until(() => textOf(root).includes(RK_CODE));
    // The password fields were emptied; the sheet shows the keys once.
    assert.ok(textOf(root).includes(SK_CODE));
    assert.ok(textOf(root).includes(EMAIL));
    assert.equal(world.requests.filter((r) => r.url.endsWith("/register/finish")).length, 0);

    byRole(root, "rk-typed").value = RK_CODE;
    byRole(root, "sk-typed").value = SK_CODE;
    await fire(byRole(root, "confirm-form"), "submit");
    await until(() => byRole(root, "open-vault") !== null);
    // Once both keys checked out the sheet is gone from the page.
    const after = textOf(root);
    for (const secret of [RK_CODE, SK_CODE, PASSWORD, "ferret-setup", "account.sheet"]) assert.ok(!after.includes(secret), secret);
    assert.ok(byRole(root, "open-vault"));
    assert.equal(world.requests.filter((r) => r.url.endsWith("/register/finish")).length, 1);
    assert.deepEqual(went, ["spent"]);
    await fire(byRole(root, "open-vault"), "click");
    assert.deepEqual(went, ["spent", "/"]);
  });
});

test("a_wrong_key_on_the_sheet_keeps_the_sheet_and_uploads_nothing", async () => {
  await withDom(async () => {
    const world = await scenario({
      handlers: {
        verify_recovery_setup: (typed) => {
          if (typed !== RK_CODE) throw coded("checksum");
        },
      },
    });
    const root = setupView({ t: i18n().t, session: world.session, setupToken: null, adminUrl: null, go() {}, handoff: {} });
    byRole(root, "email").value = EMAIL;
    byRole(root, "password").value = PASSWORD;
    byRole(root, "password-repeat").value = PASSWORD;
    byRole(root, "setup-token").value = "pasted-token";
    await fire(byRole(root, "setup-form"), "submit");
    await until(() => textOf(root).includes(RK_CODE));
    assert.equal(world.requests[0].body.setup_token, "pasted-token");

    byRole(root, "rk-typed").value = "FFR1-WRONG";
    byRole(root, "sk-typed").value = SK_CODE;
    await fire(byRole(root, "confirm-form"), "submit");
    await until(() => byRole(root, "error")?.hidden === false);
    assert.match(textOf(byRole(root, "error")), /typing error/);
    // The typed fields are empty again, the sheet is still there, nothing was uploaded.
    assert.equal(byRole(root, "rk-typed").value, "");
    assert.ok(textOf(root).includes(RK_CODE));
    assert.equal(world.requests.filter((r) => r.url.endsWith("/register/finish")).length, 0);
  });
});

test("the_setup_form_checks_that_the_two_passwords_match_before_anything_is_started", async () => {
  await withDom(async () => {
    const world = await scenario();
    const root = setupView({ t: i18n().t, session: world.session, setupToken: "t", adminUrl: null, go() {}, handoff: {} });
    byRole(root, "email").value = EMAIL;
    byRole(root, "password").value = PASSWORD;
    byRole(root, "password-repeat").value = `${PASSWORD}x`;
    await fire(byRole(root, "setup-form"), "submit");
    await settle();
    assert.match(textOf(byRole(root, "error")), /not the same/);
    assert.equal(world.client.calls.length, 0);
    assert.equal(byRole(root, "password").value, "");
    // Turning the secret key off shows the warning and hides the remember choice.
    assert.equal(byRole(root, "no-sk-warning").hidden, true);
    byRole(root, "use-sk").checked = false;
    await fire(byRole(root, "use-sk"), "change");
    assert.equal(byRole(root, "no-sk-warning").hidden, false);
    assert.equal(byRole(root, "remember-row").hidden, true);
  });
});

test("the_password_page_is_a_real_page_and_starts_no_hand_over", async () => {
  await withDom(async () => {
    const page = passwordView({ t: i18n().t });
    assert.ok(byRole(page, "password-page"));
    assert.match(textOf(page), /not available in this version/);
    assert.equal(byRole(page, "password"), null, "no password field");
    // The route is a page of its own, not a sign-in.
    const route = (await import("../../src/routes/password.route.mjs")).default;
    assert.equal(route.path, "/password");
    const loaded = await route.load({ i18n: i18n() });
    assert.ok(byRole(loaded, "password-page"));
    const source = readFileSync(join(web, "src", "routes", "password.route.mjs"), "utf8") + readFileSync(join(web, "src", "views", "password.mjs"), "utf8");
    assert.doesNotMatch(source, /handoff|goToAdmin/i);
  });
});

test("the_address_is_read_once_and_the_challenge_and_the_token_are_taken_out_of_it", () => {
  const replaced = [];
  const win = (pathname, search = "", hash = "") => ({
    location: { pathname, search, hash },
    history: { replaceState: (state, title, url) => replaced.push(url) },
  });

  let entry = consumeEntry(win("/vault/login", `?handoff=1&challenge=${CHALLENGE}&next=%2Fsettings`));
  assert.equal(entry.page, "login");
  assert.equal(entry.handoff?.challenge, CHALLENGE);
  assert.equal(getEntry(), entry);
  assert.deepEqual(replaced, ["/vault/#/login"]);

  entry = consumeEntry(win("/vault/reauth/", `?handoff=1&challenge=${CHALLENGE}`));
  assert.equal(entry.page, "reauth");
  assert.equal(entry.handoff?.purpose, "reauth");

  // The setup token is read from the fragment only, and only when it is well formed.
  entry = consumeEntry(win("/vault/setup", "", "#token=abc.DEF_123~-x"));
  assert.equal(entry.setupToken, "abc.DEF_123~-x");
  assert.equal(replaced.at(-1), "/vault/#/setup");
  assert.equal(readEntry({ pathname: "/vault/setup", search: "?token=abc", hash: "" }).setupToken, null);
  for (const hash of ["#token=", "#token=a b", "#token=a&x=1", "#token=<script>", `#token=${"a".repeat(129)}`, "#other=abc"]) {
    assert.equal(readEntry({ pathname: "/vault/setup", search: "", hash }).setupToken, null, hash);
  }
  // A token on another page, or a hand-over request on the setup page, is not used.
  assert.equal(readEntry({ pathname: "/vault/login", search: "", hash: "#token=abc" }).setupToken, null);
  assert.equal(readEntry({ pathname: "/vault/setup", search: `?handoff=1&challenge=${CHALLENGE}`, hash: "" }).handoff, null);

  // /vault/password is a page of its own; other addresses are left alone.
  entry = consumeEntry(win("/vault/password"));
  assert.equal(entry.page, "password");
  assert.equal(replaced.at(-1), "/vault/#/password");
  const before = replaced.length;
  entry = consumeEntry(win("/vault/", "", "#/items"));
  assert.equal(entry.page, null);
  assert.equal(replaced.length, before);
});

test("every_text_the_account_pages_use_exists_in_both_languages", () => {
  const en = catalog("en");
  const nb = catalog("nb");
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  for (const [key, value] of [...Object.entries(en), ...Object.entries(nb)]) {
    assert.ok(key.startsWith("account."), key);
    assert.equal(typeof value, "string");
    assert.ok(value.length > 0, key);
  }
  // Every key named in the sources exists.
  const used = new Set();
  for (const dir of ["views", "flows", "crypto", "routes"]) {
    for (const file of readdirSync(join(web, "src", dir))) {
      const source = readFileSync(join(web, "src", dir, file), "utf8");
      for (const match of source.matchAll(/["'`](account\.[a-z0-9_.]+)["'`]/g)) used.add(match[1]);
    }
  }
  for (const key of used) assert.ok(key in en, `missing text: ${key}`);
  for (const code of KNOWN_ERRORS) assert.ok(`account.error.${code}` in en, `missing error text: ${code}`);
  // The route titles are texts too.
  for (const file of readdirSync(join(web, "src", "routes"))) {
    const title = /title: "([^"]+)"/.exec(readFileSync(join(web, "src", "routes", file), "utf8"))?.[1];
    if (file.startsWith("login") || file.startsWith("reauth") || file.startsWith("setup") || file.startsWith("password")) assert.ok(title in en, file);
  }
  // No unused text is left behind.
  for (const key of Object.keys(en)) {
    const known = key.startsWith("account.error.") && KNOWN_ERRORS.includes(key.slice("account.error.".length));
    assert.ok(known || used.has(key), `unused text: ${key}`);
  }
});

test("the_pages_never_use_innerhtml_or_inline_handlers", () => {
  for (const dir of ["views", "flows", "crypto", "routes"]) {
    for (const file of readdirSync(join(web, "src", dir))) {
      const source = readFileSync(join(web, "src", dir, file), "utf8");
      assert.doesNotMatch(source, /\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|localStorage|sessionStorage|console\./, `${dir}/${file}`);
    }
  }
});
