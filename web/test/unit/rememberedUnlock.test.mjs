// "Unlock" after the server session has ended: which page a visit gets, and that the Unlock page's password runs a
// full sign-in with the remembered e-mail and the secret key this device holds, through the same checks as the
// sign-in page (flows/rememberedAccount.mjs, crypto/vaultSession.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { cache } from "../../src/store/cache.mjs";
import { forgetServer } from "../../src/store/forget.mjs";
import { loadPinned } from "../../src/store/pinned.mjs";
import { getSetting, setSetting } from "../../src/store/settings.mjs";
import { entryPage, findRemembered, leavesUnlock, rememberedKey } from "../../src/flows/rememberedAccount.mjs";
import { ACCOUNT, EMAIL, PASSWORD, SERVER, SK_CODE, VAULT, coded, dumpDatabase, filled, pinnedRecord, scenario } from "./accountHelpers.mjs";

/** A full sign-in on the sign-in page; the device keeps the secret key unless `rememberSk` is false. */
const signIn = (world, extra = {}) =>
  world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE, rememberSk: true, ...extra });

/** The server's session ends (it expired, or the server ended it), and the page is loaded again. */
async function sessionEnds(world) {
  world.server.state.signedIn = false;
  await world.session.lock();
}

/** The page a visit gets now, as the routes decide it. */
async function pageNow(world) {
  const info = await world.session.info();
  const remembered = info === null ? await world.session.remembered() : null;
  return entryPage({ info, remembered });
}

/** A JSON answer with a status. */
const answer = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("the_page_decision_table", () => {
  const known = { accountId: ACCOUNT, email: EMAIL, skBit: true, skStored: true };
  const rows = [
    ["a live session", { info: { accountId: ACCOUNT, email: EMAIL }, remembered: null }, "unlock"],
    ["a live session, remembered too", { info: { accountId: ACCOUNT, email: EMAIL }, remembered: known }, "unlock"],
    ["an ended session with the pin and the secret key", { info: null, remembered: known }, "unlock_remembered"],
    ["an ended session, an account without a secret key", { info: null, remembered: { ...known, skBit: false, skStored: false } }, "unlock_remembered"],
    ["no pinned record (a new device, or the server was forgotten)", { info: null, remembered: null }, "signin"],
    ["the secret key is missing but the account has one", { info: null, remembered: { ...known, skStored: false } }, "signin"],
  ];
  for (const [what, facts, page] of rows) assert.equal(entryPage(facts), page, what);
});

test("after_a_sign_in_an_ended_session_is_unlock_with_the_remembered_email", async () => {
  const world = await scenario();
  assert.equal(await pageNow(world), "signin", "a new device signs in");
  await signIn(world);
  assert.equal(await pageNow(world), "unlock", "the session is live");
  await sessionEnds(world);
  assert.equal(await pageNow(world), "unlock_remembered");
  assert.deepEqual(await world.session.remembered(), { accountId: ACCOUNT, email: EMAIL, skBit: true, skStored: true });
});

test("the_marker_holds_the_account_id_and_nothing_new_is_stored_in_clear", async () => {
  const world = await scenario();
  await signIn(world);
  const withMarker = await dumpDatabase(world.db.store);
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), ACCOUNT, "the marker is the account id alone");
  // Without the marker the database holds the e-mail exactly as often: the marker adds no copy of it.
  await world.session.forgetRemembered();
  const withoutMarker = await dumpDatabase(world.db.store);
  const count = (text, needle) => text.split(needle).length - 1;
  assert.equal(count(withMarker, EMAIL), count(withoutMarker, EMAIL));
  assert.ok(count(withMarker, EMAIL) >= 1, "the e-mail comes with the pinned record's index");
  assert.equal(count(withMarker, PASSWORD), 0);
  assert.equal(count(withMarker, SK_CODE), 0);
});

test("unlock_runs_a_full_sign_in_with_the_remembered_email_and_the_stored_secret_key", async () => {
  const world = await scenario();
  await signIn(world);
  await sessionEnds(world);
  world.requests.length = 0;
  const remembered = await world.session.remembered();
  const opened = await world.session.unlock({ password: PASSWORD, email: remembered.email });

  assert.equal(opened.accountId, ACCOUNT);
  assert.equal(opened.purpose, "login", "a sign-in, not a re-authentication of a session");
  assert.deepEqual(world.requests.map((r) => `${r.method} ${r.url}`), [
    "GET /api/auth/session",
    "POST /api/auth/opaque/login/start",
    "POST /api/auth/opaque/login/finish",
    "GET /api/vault/unlock-methods",
  ]);
  const start = world.requests[1].body;
  assert.equal(start.email, EMAIL);
  assert.equal(start.purpose, "login");
  // The secret key sealed on this device, and the pinned record as the core's guard and pin state.
  assert.equal(world.client.called("login_start").at(-1).snapshot[1], SK_CODE);
  assert.equal(world.client.called("login_finish").at(-1).snapshot[2].kind, "pinned");
  assert.equal(world.client.called("unlock_password").at(-1).snapshot[3].kind, "pinned");
  assert.ok(world.client.called("check_server_methods").length > 0, "the manifest check ran");
  assert.ok(world.session.current());
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), ACCOUNT, "still remembered");
});

test("a_wrong_password_on_unlock_renews_nothing_and_keeps_the_page", async () => {
  let wrong = false;
  const world = await scenario({
    handlers: {
      login_finish: () => {
        if (wrong) throw coded("decrypt");
        return { ke3: filled(64, 7), server_public_key: filled(32, 9) };
      },
    },
  });
  await signIn(world);
  await sessionEnds(world);
  world.requests.length = 0;
  wrong = true;
  const error = await world.session.unlock({ password: `${PASSWORD}-wrong`, email: EMAIL }).catch((e) => e);
  assert.equal(error.code, "decrypt", "the sign-in page's own refusal");
  assert.equal(leavesUnlock(error.code), false, "the Unlock page stays");
  assert.equal(world.requests.filter((r) => r.url.endsWith("/login/finish")).length, 0, "the proof of a wrong password never reaches the server");
  assert.equal(world.server.state.signedIn, false, "no session was made");
  assert.equal(world.session.current(), null);
  assert.ok(world.log.includes("vault.clear"));
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), ACCOUNT);
  assert.equal(await pageNow(world), "unlock_remembered");
});

test("a_refused_pin_on_unlock_ends_the_new_session_and_leads_to_the_sign_in_page", async () => {
  let refuse = false;
  const world = await scenario({
    handlers: {
      unlock_password: () => {
        if (refuse) throw coded("pinned_server_key");
        return { pinned: pinnedRecord({ skBit: true }) };
      },
    },
  });
  await signIn(world);
  await sessionEnds(world);
  world.requests.length = 0;
  refuse = true;
  const error = await world.session.unlock({ password: PASSWORD, email: EMAIL }).catch((e) => e);
  assert.equal(error.code, "pinned_server_key", "the core's refusal, as on the sign-in page");
  assert.equal(leavesUnlock(error.code), true, "the sign-in page shows it");
  assert.equal(world.session.current(), null);
  assert.ok(world.requests.some((r) => r.url === "/api/auth/logout"), "the new session is ended");
  assert.equal(world.server.state.signedIn, false);
  assert.ok(await loadPinned(world.db.store, SERVER, EMAIL), "the pinned record is not touched");
});

test("the_kits_second_factor_on_unlock_gets_the_sign_in_pages_message", async () => {
  let twoFactor = false;
  const world = await scenario({ overrides: { "POST /api/auth/opaque/login/finish": () => (twoFactor ? answer(403, { error: "forbidden" }) : null) } });
  await signIn(world);
  await sessionEnds(world);
  twoFactor = true;
  const error = await world.session.unlock({ password: PASSWORD, email: EMAIL }).catch((e) => e);
  assert.equal(error.code, "two_factor_unsupported");
  assert.equal(leavesUnlock(error.code), false);
  assert.equal(world.session.current(), null);
  assert.equal(await pageNow(world), "unlock_remembered", "nothing changed on the device");
});

test("an_explicit_sign_out_forgets_the_account_and_keeps_the_pinned_record", async () => {
  const world = await scenario();
  await signIn(world);
  const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };
  await world.session.signOut();
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), undefined);
  assert.ok(await loadPinned(world.db.store, SERVER, EMAIL), "the pinned record stays");
  assert.equal(await pageNow(world), "signin");

  // "Not you? Sign out" on the Unlock page: there is no session, and the device still forgets the account and its rows.
  await signIn(world);
  await sessionEnds(world);
  await cache.putRows(world.db.store, scope, [{ itemId: "ab".repeat(16), rev: 1, seq: 1, deleted: false, envelope: filled(80), tag: filled(32), tomb: null }]);
  await world.session.signOut();
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), undefined);
  assert.equal((await cache.getRows(world.db.store, scope)).length, 0, "the cached rows of the remembered account go");
  assert.equal(await pageNow(world), "signin");
});

test("a_sign_out_that_cannot_reach_the_server_still_forgets_the_account", async () => {
  let offline = false;
  const world = await scenario({ overrides: { "POST /api/auth/logout": () => { if (offline) throw new TypeError("offline"); return null; } } });
  await signIn(world);
  offline = true;
  await assert.rejects(world.session.signOut(), { code: "signout_incomplete" });
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), undefined);
});

test("a_revoked_browser_is_shown_unlock_and_still_needs_the_full_sign_in", async () => {
  // The server ends a revoked browser's sessions and keeps nothing else about it: to the browser it is an ended session.
  const world = await scenario();
  await signIn(world);
  await sessionEnds(world);
  assert.equal(await pageNow(world), "unlock_remembered");
  world.requests.length = 0;
  await world.session.unlock({ password: PASSWORD, email: EMAIL });
  assert.ok(world.requests.some((r) => r.url.endsWith("/login/finish")), "a new session needs the OPAQUE proof of the password");
});

test("forget_this_server_leads_to_the_sign_in_page", async () => {
  const world = await scenario();
  await signIn(world);
  await sessionEnds(world);
  await forgetServer(world.db.store, SERVER, ACCOUNT);
  await world.session.forgetRemembered(ACCOUNT);
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), undefined);
  assert.equal(await pageNow(world), "signin");

  // A marker left behind without its pinned record leads nowhere and removes itself.
  await setSetting(world.db.store, rememberedKey(SERVER), ACCOUNT);
  assert.equal(await findRemembered(world.store, SERVER), null);
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), undefined);
  // A value of another shape too.
  await setSetting(world.db.store, rememberedKey(SERVER), { email: EMAIL });
  assert.equal(await findRemembered(world.store, SERVER), null);
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), undefined);
});

test("a_missing_secret_key_leads_to_the_sign_in_page", async () => {
  const kept = await scenario();
  await signIn(kept, { rememberSk: false });
  await sessionEnds(kept);
  assert.equal(await pageNow(kept), "signin", "the device was told not to keep the key");

  const forgotten = await scenario();
  await signIn(forgotten);
  await forgotten.session.forgetSecretKey(ACCOUNT);
  await sessionEnds(forgotten);
  assert.equal(await pageNow(forgotten), "signin", "the key was forgotten on this device");

  const without = await scenario({ skBit: false });
  await signIn(without, { skBit: false, skCode: undefined });
  await sessionEnds(without);
  assert.equal(await pageNow(without), "unlock_remembered", "an account without a secret key needs none");
});

test("a_refused_sign_in_remembers_nothing", async () => {
  const world = await scenario({ overrides: { "POST /api/auth/opaque/login/finish": () => answer(401, { error: "denied" }) } });
  await signIn(world).catch(() => undefined);
  assert.equal(await getSetting(world.db.store, rememberedKey(SERVER)), undefined, "a refused sign-in remembers nothing");
});

test("leaves_unlock_covers_the_pinned_checks_and_a_missing_key_only", () => {
  for (const code of ["pinned_server_key", "pinned_auth_key", "pinned_kek_generation", "pinned_elsewhere", "pinned_account_mismatch", "pinned_profile_downgrade",
    "epoch_mismatch", "method_list_changed", "method_list_missing", "method_list_unknown", "methods_invalid", "kdf_profile_downgrade", "sk_required", "sk_answer_required"]) {
    assert.equal(leavesUnlock(code), true, code);
  }
  for (const code of ["decrypt", "denied", "throttled", "network", "two_factor_unsupported", "unknown", "worker_failed", "session_ended"]) {
    assert.equal(leavesUnlock(code), false, code);
  }
});
