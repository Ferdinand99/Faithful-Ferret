// Sign-in, unlock, sign-out and the guards around them.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { ApiError } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { cache } from "../../src/store/cache.mjs";
import { loadPinned, loadPinnedByAccount, savePinned } from "../../src/store/pinned.mjs";
import { getSetting } from "../../src/store/settings.mjs";
import { describeError, errorKey } from "../../src/views/form.mjs";
import {
  ACCOUNT, EMAIL, PASSWORD, RK_CODE, SERVER, SK_CODE, VAULT, coded, dumpDatabase, filled, pinnedRecord, scenario, wiped,
} from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";

const signIn = (world, extra = {}) =>
  world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE, ...extra });

const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "account.json"), "utf8"));
const text = (lang = "en") => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);

/** A JSON answer with a status. */
const answer = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("sign_in_runs_the_calls_in_the_documented_order", async () => {
  const world = await scenario();
  const unlocked = await signIn(world);
  assert.deepEqual(world.log, [
    "vault.login_start",
    "POST /api/auth/opaque/login/start",
    "vault.login_finish",
    "POST /api/auth/opaque/login/finish",
    "GET /api/vault/unlock-methods",
    "vault.unlock_password",
    "vault.seed_pinned",
    "vault.check_server_methods",
  ]);
  assert.deepEqual([unlocked.accountId, unlocked.vaultId, unlocked.vkEpoch, unlocked.email], [ACCOUNT, VAULT, 1, EMAIL]);
  assert.equal((await loadPinned(world.db.store, SERVER, EMAIL)).vk_epoch_max, 1);
  assert.deepEqual(world.session.current().accountId, ACCOUNT);

  // What went on the wire: purpose login, the device id, the profile the core was told.
  const [start, finish] = world.requests.filter((r) => r.method === "POST");
  assert.equal(start.body.purpose, "login");
  assert.equal(b64u.decode(start.body.ke1).length, 96);
  assert.equal(finish.body.purpose, "login");
  assert.match(finish.body.device_id, /^[0-9a-f]{32}$/);
  assert.equal(world.client.called("login_finish")[0].snapshot[1], 1);
  // The password wrap carries the profile of the sign-in.
  const wrap = world.client.called("unlock_password")[0].snapshot[2];
  assert.deepEqual(wrap.method, { type: "password", ksf_profile: 1 });
});

test("sign_in_first_use_requires_an_sk_answer", async () => {
  const world = await scenario();
  await assert.rejects(world.session.signIn({ email: EMAIL, password: PASSWORD }), { code: "sk_answer_required" });
  assert.equal(world.requests.length, 0);
  assert.equal(world.client.calls.length, 0);
  // Saying yes needs the code.
  await assert.rejects(world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true }), { code: "sk_required" });
  assert.equal(world.requests.length, 0);
  // The answer is passed on as the first-use pin of the core.
  await world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false });
  assert.deepEqual(world.client.called("login_finish")[0].snapshot[2], { kind: "first_use", sk_bit: false });
  assert.deepEqual(world.client.called("unlock_password")[0].snapshot[3], { kind: "first_use", sk_bit: false });
});

test("sk_hint_only_preselects", async () => {
  // The server says "yes"; the user answered "no". What is sent follows the user.
  const world = await scenario({
    skHint: true,
    handlers: {
      login_finish: () => {
        throw coded("decrypt");
      },
    },
  });
  const error = await world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false }).catch((e) => e);
  assert.equal(error.code, "decrypt");
  // The hint is handed to the page as a suggestion on the error.
  assert.equal(error.skHint, true);
  assert.equal(world.client.called("login_start")[0].snapshot[1], null);
  assert.deepEqual(world.client.called("login_finish")[0].snapshot[2], { kind: "first_use", sk_bit: false });
  // And a hint alone never answers the question.
  await assert.rejects(world.session.signIn({ email: EMAIL, password: PASSWORD }), { code: "sk_answer_required" });
  // The job state is dropped after the failed attempt.
  assert.ok(world.client.called("clear").length >= 1);
});

test("sign_in_with_a_pinned_record_passes_it_to_the_core", async () => {
  const world = await scenario();
  const record = pinnedRecord({ skBit: true, vk: 1 });
  await savePinned(world.db.store, SERVER, ACCOUNT, EMAIL, record);
  await world.session.signIn({ email: EMAIL.toUpperCase(), password: PASSWORD, skCode: SK_CODE });
  const early = world.client.called("login_finish")[0].snapshot[2];
  assert.equal(early.kind, "pinned");
  assert.deepEqual(early.record.account_id, record.account_id);
  const pin = world.client.called("unlock_password")[0].snapshot[3];
  assert.equal(pin.kind, "pinned");
  assert.equal(pin.record.vk_epoch_max, 1);
  // The record also gives the secret key bit: a page need not ask.
  assert.equal(world.client.called("login_start")[0].snapshot[1], SK_CODE);
});

test("the_pinned_record_is_looked_up_by_account_when_the_email_changed_on_another_device", async () => {
  const world = await scenario({ skBit: false });
  await savePinned(world.db.store, SERVER, ACCOUNT, "old@example.test", pinnedRecord({ skBit: false }));
  await world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false });
  // No record by the new e-mail for the guard of login_finish, but the record of the account opens the vault.
  assert.equal(world.client.called("login_finish")[0].snapshot[2].kind, "first_use");
  assert.equal(world.client.called("unlock_password")[0].snapshot[3].kind, "pinned");
  assert.ok(await loadPinnedByAccount(world.db.store, SERVER, ACCOUNT));
  assert.ok(await loadPinned(world.db.store, SERVER, EMAIL));
});

test("a_record_for_another_account_than_the_server_names_is_a_hard_error", async () => {
  const world = await scenario();
  const other = "9a8b7c6d5e4f30211203f4e5d6c7b8a9";
  await savePinned(world.db.store, SERVER, other, EMAIL, pinnedRecord({ accountId: other, skBit: false }));
  await assert.rejects(world.session.signIn({ email: EMAIL, password: PASSWORD, skBit: false }), { code: "pinned_account_mismatch" });
  // The vault is closed, the session ended, nothing was opened.
  assert.equal(world.client.called("unlock_password").length, 0);
  assert.ok(world.client.locked >= 1);
  assert.ok(world.requests.some((r) => r.url === "/api/auth/logout"));
  assert.equal(world.session.current(), null);
});

test("pin_errors_are_loud_not_wrong_password", async () => {
  const cases = [
    ["pinned_sk_bit", "login_finish"],
    ["pinned_server_key", "login_finish"],
    ["kdf_profile_downgrade", "login_finish"],
    ["pinned_account_id", "unlock_password"],
  ];
  const en = text("en");
  const nb = text("nb");
  const wrongPassword = en.t(errorKey(coded("decrypt")));
  for (const [code, step] of cases) {
    const world = await scenario({
      handlers: {
        [step]: () => {
          throw coded(code);
        },
      },
    });
    const error = await signIn(world).catch((e) => e);
    // The code reaches the page unchanged, and the page has its own explanation for it.
    assert.equal(error.code, code, step);
    assert.equal(world.session.current(), null);
    assert.equal(errorKey(error), `account.error.${code}`);
    for (const lang of [en, nb]) {
      const message = describeError(lang.t, error);
      assert.notEqual(message, lang.t("account.error.decrypt"));
      assert.notEqual(message, lang.t("account.error.unknown"));
      assert.ok(message.length > 40, `${lang.lang}: ${code} has an explanation`);
    }
    assert.notEqual(en.t(errorKey(error)), wrongPassword);
  }
  assert.deepEqual(en.missing, []);
  assert.deepEqual(nb.missing, []);
  // A failure of the core in login_finish ends before any session exists: nothing to log out.
  const early = await scenario({ handlers: { login_finish: () => { throw coded("pinned_sk_bit"); } } });
  await signIn(early).catch(() => undefined);
  assert.ok(!early.requests.some((r) => r.url === "/api/auth/logout"));
  // A pin error after the session exists ends the session.
  const late = await scenario({ handlers: { unlock_password: () => { throw coded("pinned_account_id"); } } });
  await signIn(late).catch(() => undefined);
  assert.ok(late.requests.some((r) => r.url === "/api/auth/logout"));
  assert.ok(late.client.locked >= 1);
});

test("insecure_transport_error_has_its_own_message", async () => {
  const world = await scenario({ overrides: { "POST /api/auth/opaque/login/start": () => answer(400, { error: "insecure_transport" }) } });
  const error = await signIn(world).catch((e) => e);
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, "insecure_transport");
  for (const lang of [text("en"), text("nb")]) {
    const message = describeError(lang.t, error);
    assert.equal(message, lang.t("account.error.insecure_transport"));
    assert.notEqual(message, lang.t("account.error.decrypt"));
    assert.notEqual(message, lang.t("account.error.network"));
    assert.match(message, /https/);
  }
});

test("an_account_with_the_kits_two_factor_on_gets_a_clear_message", async () => {
  const world = await scenario({ overrides: { "POST /api/auth/opaque/login/finish": () => answer(403, { error: "forbidden" }) } });
  const error = await signIn(world).catch((e) => e);
  assert.equal(error.code, "two_factor_unsupported");
  assert.equal(world.session.current(), null);
  assert.equal(world.client.called("unlock_password").length, 0);
  assert.equal(await loadPinned(world.db.store, SERVER, EMAIL), null);
  for (const lang of [text("en"), text("nb")]) {
    const message = describeError(lang.t, error);
    assert.notEqual(message, lang.t("account.error.forbidden"));
    assert.match(message, lang.lang === "en" ? /two-factor/i : /tofaktor/i);
  }
});

test("throttling_and_network_failures_have_their_own_messages", async () => {
  const slow = await scenario({
    overrides: { "POST /api/auth/opaque/login/start": () => new Response(JSON.stringify({ error: "throttled" }), { status: 429, headers: { "content-type": "application/json", "retry-after": "30" } }) },
  });
  const error = await signIn(slow).catch((e) => e);
  assert.equal(error.code, "throttled");
  assert.match(describeError(text("en").t, error), /30 seconds/);
  const down = await scenario({ overrides: { "POST /api/auth/opaque/login/start": () => { throw new TypeError("offline"); } } });
  assert.equal((await signIn(down).catch((e) => e)).code, "network");
});

test("a_changed_method_list_or_account_key_closes_the_vault_and_saves_nothing", async () => {
  const list = await scenario({ handlers: { check_server_methods: () => { throw coded("method_list_unknown"); } } });
  await assert.rejects(signIn(list), { code: "method_list_unknown" });
  assert.equal(await loadPinned(list.db.store, SERVER, EMAIL), null);
  assert.ok(list.client.locked >= 1);

  const key = await scenario({ handlers: { seed_pinned: (p) => ({ ...p, pk_a: filled(32, 77) }) } });
  await assert.rejects(signIn(key), { code: "pinned_auth_key" });
  assert.equal(await loadPinned(key.db.store, SERVER, EMAIL), null);
  assert.equal(key.session.current(), null);

  // Two key epochs in one answer, or no single password wrap, stop the sign-in too.
  const epoch = await scenario({ overrides: { "POST /api/auth/opaque/login/finish": () => answer(200, { account_id: ACCOUNT, vault_id: VAULT, vk_epoch: 2 }) } });
  await assert.rejects(signIn(epoch), { code: "epoch_mismatch" });
});

test("the_server_address_reaches_the_core_and_the_store_in_one_canonical_form", async () => {
  const { createCryptoSession } = await import("../../src/crypto/session.mjs");
  const world = await scenario();
  const session = createCryptoSession({
    client: world.client,
    api: world.api,
    store: world.store,
    serverUrl: `${SERVER}/some/path?x=1#y`,
  });
  assert.equal(session.serverUrl, SERVER);
  await session.signIn({ email: EMAIL, password: PASSWORD, skBit: false });
  assert.equal(world.client.called("unlock_password")[0].snapshot[0], SERVER);
  assert.equal((await loadPinned(world.db.store, SERVER, EMAIL)).server_url, SERVER);
  assert.throws(() => createCryptoSession({ client: world.client, api: world.api, store: world.store, serverUrl: "ftp://x" }), TypeError);
});

test("unlock_is_a_reauth_when_the_session_is_valid_and_asks_to_sign_in_when_it_is_not", async () => {
  const world = await scenario();
  await signIn(world, { rememberSk: true });
  await world.session.lock();
  assert.equal(world.session.current(), null);
  world.requests.length = 0;

  const unlocked = await world.session.unlock({ password: PASSWORD });
  assert.equal(unlocked.accountId, ACCOUNT);
  const [info, start, finish] = world.requests;
  assert.equal(info.url, "/api/auth/session");
  assert.equal(start.body.purpose, "reauth");
  assert.equal(finish.body.purpose, "reauth");
  // The secret key comes from the device and the record is the pin.
  assert.equal(world.client.called("login_start").at(-1).snapshot[1], SK_CODE);
  assert.equal(world.client.called("login_finish").at(-1).snapshot[2].kind, "pinned");
  assert.ok(world.session.freshReauth());
  assert.ok(world.session.current());

  // A failed re-authentication does not end the session it was made for.
  const broken = await scenario({ handlers: { unlock_password: () => { throw coded("decrypt"); } } });
  await signIn(broken).catch(() => undefined);
  broken.server.state.signedIn = true;
  broken.requests.length = 0;
  await assert.rejects(broken.session.unlock({ password: PASSWORD, skBit: false }), { code: "decrypt" });
  assert.ok(!broken.requests.some((r) => r.url === "/api/auth/logout"));

  // No session: unlock says so; with an e-mail it is an ordinary sign-in.
  const none = await scenario();
  await assert.rejects(none.session.unlock({ password: PASSWORD }), { code: "session_ended" });
  assert.equal(none.session.freshReauth(), false);
  const viaSignIn = await none.session.unlock({ password: PASSWORD, email: EMAIL, skBit: false });
  assert.equal(none.requests.find((r) => r.url.endsWith("/login/start")).body.purpose, "login");
  assert.equal(viaSignIn.purpose, "login");
  assert.equal(none.session.freshReauth(), false);
});

test("a_reauth_is_fresh_only_for_a_short_time", async () => {
  let now = 1_000_000;
  const { createCryptoSession } = await import("../../src/crypto/session.mjs");
  const world = await scenario();
  const session = createCryptoSession({ client: world.client, api: world.api, store: world.store, serverUrl: SERVER, now: () => now });
  await session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE, rememberSk: true });
  assert.equal(session.freshReauth(), false);
  await session.unlock({ password: PASSWORD });
  assert.equal(session.freshReauth(), true);
  now += 59_000;
  assert.equal(session.freshReauth(), true);
  now += 2_000;
  assert.equal(session.freshReauth(), false);
  await session.unlock({ password: PASSWORD });
  await session.lock();
  assert.equal(session.freshReauth(), false);
});

test("device_id_is_created_once_and_reused", async () => {
  const world = await scenario();
  await signIn(world);
  await world.session.signOut();
  await signIn(world);
  const ids = world.requests.filter((r) => r.url.endsWith("/login/finish")).map((r) => r.body.device_id);
  assert.equal(ids.length, 2);
  assert.equal(ids[0], ids[1]);
  assert.equal(await getSetting(world.db.store, "device_id"), ids[0]);
});

test("sign_out_clears_the_cache_but_keeps_pinned_and_the_device_id", async () => {
  const stops = [];
  const world = await scenario({ sync: { start: async () => {}, stop: () => stops.push("stop") } });
  await signIn(world, { rememberSk: true });
  const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };
  await cache.putRows(world.db.store, scope, [{ itemId: "ab".repeat(16), rev: 1, seq: 1, deleted: false, envelope: filled(80), tag: filled(32), tomb: null }]);
  assert.equal((await cache.getRows(world.db.store, scope)).length, 1);
  const deviceId = await getSetting(world.db.store, "device_id");

  await world.session.signOut();
  assert.equal((await cache.getRows(world.db.store, scope)).length, 0);
  assert.ok(await loadPinned(world.db.store, SERVER, EMAIL));
  assert.equal(await getSetting(world.db.store, "device_id"), deviceId);
  // The sealed secret key stays too: it belongs to the device, not to the session.
  assert.equal((await world.store.deviceSecrets.get(world.db.store, SERVER, ACCOUNT)) !== null, true);
  // The worker is ended, the server session is ended, the sync engine is stopped.
  assert.ok(world.client.locked >= 1);
  assert.ok(world.requests.some((r) => r.method === "POST" && r.url === "/api/auth/logout"));
  assert.deepEqual(stops, ["stop"]);
  assert.equal(world.session.current(), null);
});

test("sign_out_locks_even_when_the_server_cannot_be_reached", async () => {
  const world = await scenario({ overrides: { "POST /api/auth/logout": () => { throw new TypeError("offline"); } } });
  await signIn(world);
  await assert.rejects(world.session.signOut(), { code: "signout_incomplete" });
  assert.equal(world.session.current(), null);
  assert.ok(world.client.locked >= 1);
});

test("the_sync_engine_is_started_after_an_unlock_and_stopped_on_lock_and_sign_out", async () => {
  const events = [];
  const sync = { start: async (scope) => events.push(["start", scope]), stop: () => events.push(["stop"]) };
  const world = await scenario({ sync });
  await signIn(world, { rememberSk: true });
  assert.deepEqual(events, [["start", { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 }]]);
  let locked = 0;
  const off = world.session.onLock(() => { locked += 1; });
  await world.session.lock();
  assert.equal(locked, 1);
  assert.deepEqual(events.at(-1), ["stop"]);
  off();
  await world.session.unlock({ password: PASSWORD });
  assert.deepEqual(events.at(-1)[0], "start");
  await world.session.lock();
  assert.equal(locked, 1);
  await world.session.unlock({ password: PASSWORD });
  await world.session.signOut();
  assert.deepEqual(events.at(-1), ["stop"]);

  // An engine attached later, a missing one and a failing one never stop a sign-in.
  const bare = await scenario();
  await signIn(bare);
  bare.session.attachSync(sync);
  const before = events.length;
  await bare.session.lock();
  assert.equal(events.length, before + 1);
  const failing = await scenario({ sync: { start: async () => { throw new Error("engine down"); }, stop: () => { throw new Error("engine down"); } } });
  await signIn(failing);
  await failing.session.lock();
  assert.equal(failing.session.current(), null);
});

test("password_inputs_are_cleared_and_arguments_wiped_after_submit", async () => {
  const world = await scenario();
  await signIn(world);
  const call = world.client.called("login_start")[0];
  assert.equal(new TextDecoder().decode(call.snapshot[0]), PASSWORD);
  // The array that went to the worker is all zero afterwards: it cannot be used twice.
  assert.ok(wiped(call.args[0]));
  // A failed sign-in wipes it too.
  const failed = await scenario({ handlers: { login_finish: () => { throw coded("decrypt"); } } });
  await signIn(failed).catch(() => undefined);
  assert.ok(wiped(failed.client.called("login_start")[0].args[0]));
  // A password with a lone surrogate is refused before anything is encoded.
  const odd = await scenario();
  await assert.rejects(odd.session.signIn({ email: EMAIL, password: "ab\ud800", skBit: false }), { code: "input_not_utf8" });
  assert.equal(odd.requests.length, 0);
});

test("no_secret_in_storage_or_console", async () => {
  const seen = [];
  const keep = (...args) => seen.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  const consoleBefore = {};
  for (const name of ["log", "info", "warn", "error", "debug", "trace"]) {
    consoleBefore[name] = console[name];
    console[name] = keep;
  }
  const writes = [];
  const storage = { setItem: (...a) => writes.push(a), getItem: () => null, removeItem: () => {}, clear: () => {} };
  const savedLocal = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const savedSession = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true });
  Object.defineProperty(globalThis, "sessionStorage", { value: storage, configurable: true });
  let dump = "";
  try {
    const world = await scenario();
    const flow = await world.session.register({ email: EMAIL, password: PASSWORD, setupToken: "setup-token-1" });
    await flow.confirm(RK_CODE, SK_CODE);
    await flow.finish();
    await world.session.signOut();
    await signIn(world, { rememberSk: true });
    await world.session.lock();
    await world.session.unlock({ password: PASSWORD });
    // A failed attempt with other text typed leaves nothing behind either.
    await world.session.signIn({ email: EMAIL, password: `other-${PASSWORD}`, skCode: "not-a-code" }).catch(() => undefined);
    dump = await dumpDatabase(world.db.store);
  } finally {
    for (const name of Object.keys(consoleBefore)) console[name] = consoleBefore[name];
    if (savedLocal) Object.defineProperty(globalThis, "localStorage", savedLocal);
    else delete globalThis.localStorage;
    if (savedSession) Object.defineProperty(globalThis, "sessionStorage", savedSession);
    else delete globalThis.sessionStorage;
  }
  for (const secret of [PASSWORD, SK_CODE, RK_CODE, "setup-token-1"]) {
    assert.ok(!dump.includes(secret), `IndexedDB holds a secret: ${secret.slice(0, 6)}`);
    assert.ok(!seen.join("\n").includes(secret), `the console got a secret: ${secret.slice(0, 6)}`);
    assert.ok(!JSON.stringify(writes).includes(secret), `web storage got a secret: ${secret.slice(0, 6)}`);
  }
  assert.deepEqual(writes, []);
});

test("every_lock_goes_through_the_session_on_the_failure_paths_too", async () => {
  const events = [];
  const sync = { start: async () => events.push("start"), stop: () => events.push("stop") };
  // The check works at first and is broken for the later attempts.
  // A check after login/finish fails over an open vault: the vault is closed through the session.
  let broken = false;
  const probe = await scenario({
    sync,
    handlers: {
      check_server_methods: () => {
        if (broken) throw coded("method_list_unknown");
      },
    },
  });
  await signIn(probe, { rememberSk: true });
  let heard = 0;
  probe.session.onLock(() => { heard += 1; });
  assert.notEqual(probe.session.current(), null);
  events.length = 0;
  broken = true;
  await assert.rejects(probe.session.unlock({ password: PASSWORD }), { code: "method_list_unknown" });
  assert.equal(probe.session.current(), null);
  assert.ok(events.includes("stop"), "sync stopped");
  assert.ok(heard >= 1, "the lock listeners were told");
  assert.equal(probe.session.freshReauth(), false);

  // The same for a failed sign-in over an open vault.
  broken = false;
  await signIn(probe, { rememberSk: true });
  events.length = 0;
  heard = 0;
  broken = true;
  await assert.rejects(signIn(probe), { code: "method_list_unknown" });
  assert.equal(probe.session.current(), null);
  assert.ok(events.includes("stop"));
  assert.ok(heard >= 1);

  // A sign-in that works over an open vault locks the old one first: stop, then start.
  broken = false;
  await signIn(probe, { rememberSk: true });
  events.length = 0;
  heard = 0;
  await signIn(probe);
  assert.deepEqual(events, ["stop", "start"]);
  assert.equal(heard, 1);

  // A failed registration also ends the worker through the session.
  const reg = await scenario({ sync, handlers: { register_finish: () => { throw coded("kdf_out_of_memory"); } } });
  let regHeard = 0;
  reg.session.onLock(() => { regHeard += 1; });
  await assert.rejects(reg.session.register({ email: EMAIL, password: PASSWORD }), { code: "kdf_out_of_memory" });
  assert.equal(regHeard, 1);
});

test("sign_out_always_asks_the_server_and_wipes_the_device_even_when_a_step_fails", async () => {
  // The cache cannot be cleared: the server is still asked, the error is the cache's.
  const world = await scenario();
  await signIn(world);
  world.store.cache = { ...world.store.cache, clearAccount: async () => { throw new Error("idb down"); } };
  await assert.rejects(world.session.signOut(), /idb down/);
  assert.ok(world.requests.some((r) => r.method === "POST" && r.url === "/api/auth/logout"));
  assert.equal(world.session.current(), null);
  assert.ok(world.client.locked >= 1);

  // The store cannot even be opened.
  const nostore = await scenario();
  await signIn(nostore);
  nostore.store.open = async () => { throw new Error("no idb"); };
  await assert.rejects(nostore.session.signOut(), /no idb/);
  assert.ok(nostore.requests.some((r) => r.url === "/api/auth/logout"));

  // The server cannot be reached: the device is wiped, and the error says the session may live on.
  const offline = await scenario({ overrides: { "POST /api/auth/logout": () => { throw new TypeError("offline"); } } });
  await signIn(offline);
  await assert.rejects(offline.session.signOut(), { code: "signout_incomplete" });
  assert.equal(offline.session.current(), null);
  assert.ok(offline.client.locked >= 1);
});
