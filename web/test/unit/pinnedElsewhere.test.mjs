// One pinning per account id: a sign-in that would pin a second server address for an account is refused.
import assert from "node:assert/strict";
import { test } from "node:test";
import { forgetServer } from "../../src/store/forget.mjs";
import { loadPinnedByAccount, pinnedElsewhere, savePinned } from "../../src/store/pinned.mjs";
import { loginView } from "../../src/views/login.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ACCOUNT, EMAIL, PASSWORD, SERVER, accountDocument, byRole, fire, pinnedRecord, scenario, settle, textOf } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";

const OTHER = "https://other.example";
const THIRD = "http://10.0.0.5:3000";
const ANOTHER_ACCOUNT = "9a8b7c6d5e4f30211203f4e5d6c7b8a9";
const signIn = (world, extra = {}) => world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false, ...extra });
const pinOther = (world, server = OTHER, accountId = ACCOUNT, email = "other@example.test") =>
  savePinned(world.db.store, server, accountId, email, pinnedRecord({ server, accountId, skBit: false }));

test("pinned_elsewhere_finds_the_other_address_of_an_account", async () => {
  const world = await scenario({ skBit: false });
  const db = world.db.store;
  assert.equal(await pinnedElsewhere(db, SERVER, ACCOUNT), null);
  // A record under the server's own address is not "elsewhere".
  await pinOther(world, SERVER, ACCOUNT, EMAIL);
  assert.equal(await pinnedElsewhere(db, SERVER, ACCOUNT), null);
  // Another account under another address is not it either.
  await pinOther(world, OTHER, ANOTHER_ACCOUNT);
  assert.equal(await pinnedElsewhere(db, SERVER, ACCOUNT), null);
  // The same account under another address is, and so it is from that address's own side.
  await pinOther(world, THIRD);
  await pinOther(world, OTHER);
  assert.equal(await pinnedElsewhere(db, SERVER, ACCOUNT), THIRD);
  assert.equal(await pinnedElsewhere(db, THIRD, ACCOUNT), OTHER);
  // The address is compared as one origin.
  assert.equal(await pinnedElsewhere(db, `${OTHER}/`, ACCOUNT), THIRD);
  await assert.rejects(pinnedElsewhere(db, SERVER, "nope"), TypeError);
  await assert.rejects(pinnedElsewhere(db, "not a url", ACCOUNT), TypeError);
});

test("pinned_elsewhere_runs_after_login_finish_before_pinning_and_signs_the_new_session_out", async () => {
  const world = await scenario({ skBit: false });
  await pinOther(world);
  const before = await loadPinnedByAccount(world.db.store, OTHER, ACCOUNT);
  const error = await signIn(world).catch((e) => e);
  assert.equal(error.code, "pinned_elsewhere");
  // The page gets the address and the account to offer "Forget the other server".
  assert.deepEqual(error.details, { server: OTHER, accountId: ACCOUNT });
  // It ran after login/finish (the account was not known before) and before anything was fetched or pinned.
  const finish = world.log.indexOf("POST /api/auth/opaque/login/finish");
  const out = world.log.indexOf("POST /api/auth/logout");
  assert.ok(finish > 0 && out > finish, world.log.join(", "));
  assert.ok(!world.log.includes("GET /api/vault/unlock-methods"));
  assert.ok(!world.log.includes("vault.unlock_password"));
  // The new session is signed out and the vault is not open.
  assert.equal(world.server.state.signedIn, false);
  assert.ok(world.client.locked >= 1);
  assert.equal(world.session.current(), null);
  // Nothing was pinned for this server, and the other record is as it was.
  assert.equal(await loadPinnedByAccount(world.db.store, SERVER, ACCOUNT), null);
  assert.deepEqual(await loadPinnedByAccount(world.db.store, OTHER, ACCOUNT), before);
});

test("after_forgetting_the_other_server_the_pin_is_allowed", async () => {
  const world = await scenario({ skBit: false });
  await pinOther(world);
  await assert.rejects(signIn(world), { code: "pinned_elsewhere" });
  await forgetServer(world.db.store, OTHER, ACCOUNT);
  assert.equal(await pinnedElsewhere(world.db.store, SERVER, ACCOUNT), null);
  const unlocked = await signIn(world);
  assert.equal(unlocked.accountId, ACCOUNT);
  assert.ok(await loadPinnedByAccount(world.db.store, SERVER, ACCOUNT));
  assert.ok(world.session.current());
});

test("a_re_authentication_is_not_refused_for_a_record_elsewhere", async () => {
  // The session already belongs to this server; the check is for a new sign-in only, and a refusal would end that session.
  const world = await scenario({ skBit: false });
  await savePinned(world.db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ skBit: false }));
  await world.session.signIn({ email: EMAIL, password: PASSWORD });
  await pinOther(world);
  const unlocked = await world.session.unlock({ password: PASSWORD });
  assert.equal(unlocked.purpose, "reauth");
  assert.equal(world.server.state.signedIn, true);
});

test("the_page_offers_to_forget_the_other_server_first", async () => {
  const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "account.json"), "utf8"));
  const t = createI18n({ en: catalog("en"), nb: catalog("nb") }, "en").t;
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  try {
    const forgot = [];
    const error = Object.assign(new Error("pinned_elsewhere"), { code: "pinned_elsewhere", details: { server: OTHER, accountId: ACCOUNT } });
    const session = {
      deviceStatus: async () => ({ pinned: false, skBit: null, skStored: false }),
      signIn: async () => {
        throw error;
      },
      current: () => null,
      freshReauth: () => true,
    };
    const root = loginView({
      t, session, entry: { page: "login", handoff: null, brokenHandoff: false, setupToken: null }, adminUrl: null, api: {}, go() {}, handoff: {}, info: null,
      store: {},
      forget: async (options) => {
        forgot.push(options);
        return "forgotten";
      },
    });
    await settle();
    assert.equal(byRole(root, "pinned-elsewhere").hidden, true);
    byRole(root, "email").value = EMAIL;
    byRole(root, "password").value = PASSWORD;
    byRole(root, "sk-no").checked = true;
    await fire(byRole(root, "sk-no"), "change");
    await fire(byRole(root, "credentials"), "submit");
    await settle();
    // The text names the other address; the way out is there, and it asks nothing before the user clicks.
    assert.match(textOf(byRole(root, "error")), /under another server address \(https:\/\/other\.example\)/);
    assert.equal(byRole(root, "pinned-elsewhere").hidden, false);
    assert.equal(forgot.length, 0);
    await fire(byRole(root, "forget-other"), "click");
    await settle();
    assert.equal(forgot.length, 1);
    assert.equal(forgot[0].serverUrl, OTHER);
    assert.equal(forgot[0].accountId, ACCOUNT);
    assert.equal(byRole(root, "pinned-elsewhere").hidden, true);
    assert.match(textOf(byRole(root, "done")), /forgotten https:\/\/other\.example/);
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
});
