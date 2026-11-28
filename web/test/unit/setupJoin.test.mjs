// The setup page in its "join" form: a person opens an invitation link, the page
// checks the link before it asks for anything, says who invited her and when the
// link runs out, and then runs the same setup as for the first administrator
// (secret key on by default, the emergency sheet typed back before the upload).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createI18n } from "../../src/i18n.mjs";
import { setupView } from "../../src/views/setup.mjs";
import { EMAIL, PASSWORD, RK_CODE, SK_CODE, accountDocument, byRole, fire, scenario, settle, textOf, until } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";

const INVITE = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hJ7kL9x";
const EXPIRES = 1_800_604_800;
const INVITER = "grace@example.test";
const HOST = "vault.example";

const catalog = (lang, name) => JSON.parse(readFileSync(join(web, "src", "locales", lang, `${name}.json`), "utf8"));
const i18n = (lang = "en") =>
  createI18n({ en: { ...catalog("en", "account"), ...catalog("en", "sheet") }, nb: { ...catalog("nb", "account"), ...catalog("nb", "sheet") } }, lang);

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
  const promise = new Promise((a) => {
    resolve = a;
  });
  return { promise, resolve };
};

/** The deps of the join page; `check` answers the check of the link. */
function joinDeps({ lang = "en", session = {}, check = async () => ({ ok: true, expiresAt: EXPIRES, invitedBy: INVITER }), ...rest } = {}) {
  const checks = [];
  const went = [];
  const spent = [];
  const deps = {
    t: i18n(lang).t,
    locale: lang,
    session,
    setupToken: null,
    invite: INVITE,
    host: HOST,
    checkInvite: async (invite) => {
      checks.push(invite);
      return check(invite);
    },
    spentInvite: () => spent.push("spent"),
    adminUrl: "https://admin.example",
    go: (path) => went.push(path),
    handoff: { goToAdmin: async () => went.push("admin") },
    ...rest,
  };
  return { deps, checks, went, spent };
}

/** The text of a node without the line ends of the fake DOM. */
const plain = (node) => textOf(node).trim();

const when = (lang) => new Intl.DateTimeFormat(lang, { dateStyle: "long", timeStyle: "short" }).format(new Date(EXPIRES * 1000));

test("join_view_shows_inviter_and_expiry", async () => {
  await withDom(async () => {
    for (const lang of ["en", "nb"]) {
      const { deps, checks } = joinDeps({ lang });
      const root = setupView(deps);
      await until(() => byRole(root, "setup-form") !== null);
      assert.deepEqual(checks, [INVITE]);
      // The heading is the first thing on the card.
      assert.equal(root.childNodes[0], byRole(root, "join-heading"));
      if (lang === "en") assert.equal(plain(byRole(root, "join-heading")), `Join Ferret on ${HOST}`);
      else assert.equal(plain(byRole(root, "join-heading")), `Bli med i Ferret på ${HOST}`);
      assert.ok(textOf(byRole(root, "invited-by")).includes(INVITER), `${lang}: who invited`);
      assert.ok(textOf(byRole(root, "invite-expires")).includes(when(lang)), `${lang}: when the link runs out`);
      // The first administrator's parts are not here: no setup token field, no "token received".
      assert.equal(byRole(root, "setup-token"), null);
      assert.equal(byRole(root, "token-received"), null);
      // The rest is the usual setup.
      for (const role of ["email", "password", "password-repeat", "use-sk", "remember", "submit", "trust-notice"]) assert.ok(byRole(root, role), `${lang}: ${role}`);
      // The token itself is not shown.
      assert.ok(!textOf(root).includes(INVITE));
    }
    // An inviter whose account is gone: the page still says it is an invitation, without a name.
    const { deps } = joinDeps({ check: async () => ({ ok: true, expiresAt: EXPIRES, invitedBy: "" }) });
    const root = setupView(deps);
    await until(() => byRole(root, "setup-form") !== null);
    assert.equal(plain(byRole(root, "invited-by")), i18n().t("account.join.invited_unknown"));
  });
});

test("the_join_view_keeps_the_secret_key_on_by_default_and_requires_the_sheet", async () => {
  await withDom(async () => {
    const world = await scenario();
    const { deps, went, spent } = joinDeps({ session: world.session });
    const root = setupView(deps);
    await until(() => byRole(root, "setup-form") !== null);
    assert.equal(byRole(root, "use-sk").checked, true);
    assert.equal(byRole(root, "remember").checked, true);
    assert.equal(byRole(root, "no-sk-warning").hidden, true);

    byRole(root, "email").value = EMAIL;
    byRole(root, "password").value = PASSWORD;
    byRole(root, "password-repeat").value = PASSWORD;
    await fire(byRole(root, "setup-form"), "submit");
    await until(() => textOf(root).includes(RK_CODE));
    // The registration went with the invitation and no setup token; nothing is uploaded before the sheet is typed back.
    const starts = world.requests.filter((r) => r.url.endsWith("/register/start"));
    assert.equal(starts.length, 1);
    assert.equal(starts[0].body.invite, INVITE);
    assert.equal("setup_token" in starts[0].body, false);
    assert.ok(textOf(root).includes(SK_CODE), "the sheet shows the secret key");
    assert.equal(world.requests.filter((r) => r.url.endsWith("/register/finish")).length, 0);
    assert.deepEqual(spent, []);

    byRole(root, "rk-typed").value = RK_CODE;
    byRole(root, "sk-typed").value = SK_CODE;
    await fire(byRole(root, "confirm-form"), "submit");
    await until(() => byRole(root, "open-vault") !== null);
    assert.equal(world.requests.filter((r) => r.url.endsWith("/register/finish")).length, 1);
    assert.equal(world.requests.filter((r) => r.url.endsWith("/register/finish"))[0].body.sk_bit, true);
    assert.deepEqual(spent, ["spent"]);
    // A new account from an invitation is not an administrator: the done page has no way to the admin pages.
    assert.equal(byRole(root, "admin"), null);
    for (const secret of [RK_CODE, SK_CODE, PASSWORD, INVITE]) assert.ok(!textOf(root).includes(secret), secret);
    await fire(byRole(root, "open-vault"), "click");
    assert.deepEqual(went, ["/"]);
  });
});

test("a_dead_link_is_said_before_any_password_is_asked", async () => {
  await withDom(async () => {
    // While the link is checked, there is no field to type a password into.
    const pending = deferred();
    const slow = joinDeps({ check: () => pending.promise });
    const root = setupView(slow.deps);
    await settle();
    assert.equal(byRole(root, "password"), null);
    assert.ok(byRole(root, "invite-checking"));
    pending.resolve({ ok: false, code: "invite_invalid" });
    await until(() => byRole(root, "invite-dead") !== null);
    assert.equal(byRole(root, "password"), null);
    assert.equal(byRole(root, "setup-form"), null);
    assert.equal(plain(byRole(root, "invite-dead")), i18n().t("account.error.invite_invalid"));
    // A way on: sign in instead; there is no retry for a dead link.
    assert.ok(root.childNodes.some((n) => textOf(n).includes(i18n().t("account.setup.login_link"))));
    assert.equal(byRole(root, "invite-retry"), null);

    // A check that could not be made (the limit, no network) says so and can be tried again.
    let answers = [{ ok: false, code: "throttled" }, { ok: true, expiresAt: EXPIRES, invitedBy: INVITER }];
    const busy = joinDeps({ check: async () => answers.shift() });
    const second = setupView(busy.deps);
    await until(() => byRole(second, "invite-dead") !== null);
    assert.equal(plain(byRole(second, "invite-dead")), i18n().t("account.error.throttled"));
    assert.equal(byRole(second, "password"), null);
    await fire(byRole(second, "invite-retry"), "click");
    await until(() => byRole(second, "setup-form") !== null);
    assert.equal(busy.checks.length, 2);

    // A link that dies between the check and the start of the registration: the same message, and the form is gone.
    const world = await scenario({
      overrides: { "POST /api/auth/opaque/register/start": () => new Response(JSON.stringify({ error: "invite_invalid" }), { status: 403, headers: { "content-type": "application/json" } }) },
    });
    const late = setupView(joinDeps({ session: world.session }).deps);
    await until(() => byRole(late, "setup-form") !== null);
    byRole(late, "email").value = EMAIL;
    byRole(late, "password").value = PASSWORD;
    byRole(late, "password-repeat").value = PASSWORD;
    await fire(byRole(late, "setup-form"), "submit");
    await until(() => byRole(late, "invite-dead") !== null);
    assert.equal(byRole(late, "setup-form"), null);
    assert.equal(plain(byRole(late, "invite-dead")), i18n().t("account.error.invite_invalid"));

    // A taken e-mail keeps the form, so she can choose another one.
    const taken = await scenario({
      overrides: { "POST /api/auth/opaque/register/start": () => new Response(JSON.stringify({ error: "email_taken" }), { status: 409, headers: { "content-type": "application/json" } }) },
    });
    const again = setupView(joinDeps({ session: taken.session }).deps);
    await until(() => byRole(again, "setup-form") !== null);
    byRole(again, "email").value = EMAIL;
    byRole(again, "password").value = PASSWORD;
    byRole(again, "password-repeat").value = PASSWORD;
    await fire(byRole(again, "setup-form"), "submit");
    await until(() => byRole(again, "error")?.hidden === false);
    assert.equal(plain(byRole(again, "error")), i18n().t("account.error.email_taken"));
    assert.ok(byRole(again, "setup-form"));
    assert.equal(byRole(again, "password").value, "");
  });
});

test("the_first_administrator_setup_is_unchanged_without_an_invitation", async () => {
  await withDom(async () => {
    const checks = [];
    const root = setupView({
      t: i18n().t,
      session: {},
      setupToken: null,
      invite: null,
      checkInvite: async (x) => checks.push(x),
      adminUrl: null,
      go() {},
      handoff: {},
    });
    await settle();
    assert.deepEqual(checks, [], "no check without an invitation");
    assert.ok(byRole(root, "setup-token"));
    assert.equal(byRole(root, "join-heading"), null);
    assert.equal(plain(root.childNodes[0]), i18n().t("account.setup.heading"));
  });
});

test("a_reload_after_the_token_was_read_says_the_link_is_lost_and_asks_for_nothing", async () => {
  await withDom(async () => {
    for (const lang of ["en", "nb"]) {
      const checks = [];
      const root = setupView({
        t: i18n(lang).t,
        locale: lang,
        session: {},
        setupToken: null,
        invite: null,
        joinLost: true,
        host: HOST,
        checkInvite: async (x) => checks.push(x),
        adminUrl: "https://admin.example",
        go() {},
        handoff: {},
      });
      await settle();
      assert.equal(plain(byRole(root, "invite-lost")), i18n(lang).t("account.join.lost"), lang);
      assert.ok(plain(byRole(root, "join-heading")).includes(HOST));
      // Not the first administrator's form, and no field at all: nothing to type a password into.
      for (const role of ["setup-form", "email", "password", "password-repeat", "setup-token", "submit"]) assert.equal(byRole(root, role), null, `${lang}: ${role}`);
      assert.deepEqual(checks, [], "nothing is asked of the server");
      assert.ok(root.childNodes.some((n) => textOf(n).includes(i18n(lang).t("account.setup.login_link"))));
      assert.ok(byRole(root, "trust-notice"));
    }
  });
});
