// Sign-in with the text of the emergency sheet's QR code: what is checked, in which order, and what the page shows.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createI18n } from "../../src/i18n.mjs";
import { loadPinned, savePinned } from "../../src/store/pinned.mjs";
import { loginView } from "../../src/views/login.mjs";
import {
  ACCOUNT, EMAIL, PASSWORD, SERVER, SK_CODE, accountDocument, byRole, coded, dumpDatabase, filled, fire, pinnedRecord, scenario, settle, textOf,
} from "./accountHelpers.mjs";
import { SERVER_KEY, qrHandlers, qrText } from "./setupQrHelpers.mjs";
import { web } from "./helpers.mjs";

const OTHER_KEY = filled(32, 8);
const OTHER_ACCOUNT = "9a8b7c6d5e4f30211203f4e5d6c7b8a9";
const signIn = (world, qr, extra = {}) => world.session.signIn({ email: EMAIL, password: PASSWORD, qr, ...extra });
const world = ({ handlers = {}, ...rest } = {}) => scenario({ handlers: { ...qrHandlers, ...handlers }, ...rest });
const posted = (w, path) => w.requests.some((r) => r.method === "POST" && r.url === path);

const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "account.json"), "utf8"));
const i18n = (lang = "en") => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);

test("a_matching_sheet_signs_in_and_the_checks_run_in_order", async () => {
  const w = await world();
  const unlocked = await signIn(w, qrText({ sk: true }), { skCode: SK_CODE });
  assert.equal(unlocked.accountId, ACCOUNT);
  // The sheet is read first, with nothing sent; the checks sit between the core and the posts.
  assert.deepEqual(w.log, [
    "vault.setup_qr_parse",
    "vault.login_start",
    "POST /api/auth/opaque/login/start",
    "vault.login_finish",
    "POST /api/auth/opaque/login/finish",
    "GET /api/vault/unlock-methods",
    "vault.unlock_password",
    "vault.seed_pinned",
    "vault.check_server_methods",
  ]);
  assert.ok(await loadPinned(w.db.store, SERVER, EMAIL));
});

test("a_server_url_other_than_this_origin_is_refused", async () => {
  for (const url of ["https://other.example", "http://vault.example", "https://vault.example:8443", `${SERVER}/vault`]) {
    const w = await world();
    await assert.rejects(signIn(w, qrText({ url }), { skCode: SK_CODE }), { code: "qr_server_url" }, url);
    // Nothing went to any server, the password was never handed to the core, and nothing was saved.
    assert.equal(w.requests.length, 0);
    assert.deepEqual(w.client.calls.map((c) => c.method), ["setup_qr_parse", "clear"]);
    assert.equal(await loadPinned(w.db.store, SERVER, EMAIL), null);
  }
});

test("a_lower_server_profile_than_the_sheet_is_refused", async () => {
  const w = await world();
  // The sheet says profile 2; this server says 1.
  const error = await signIn(w, qrText({ profile: 2 }), { skCode: SK_CODE }).catch((e) => e);
  assert.equal(error.code, "qr_profile");
  // The password was not stretched, and KE3 was not posted.
  assert.equal(w.client.called("login_finish").length, 0);
  assert.ok(posted(w, "/api/auth/opaque/login/start"));
  assert.ok(!posted(w, "/api/auth/opaque/login/finish"));
  assert.ok(w.client.called("clear").length >= 1);
  assert.equal(await loadPinned(w.db.store, SERVER, EMAIL), null);
  // A server at the sheet's profile, or above it, is fine.
  const same = await world();
  await signIn(same, qrText({ profile: 1 }), { skCode: SK_CODE });
});

test("a_different_server_key_is_refused_before_ke3_is_posted", async () => {
  const w = await world({ handlers: { login_finish: () => ({ ke3: filled(64, 2), server_public_key: OTHER_KEY }) } });
  const error = await signIn(w, qrText({ key: SERVER_KEY }), { skCode: SK_CODE }).catch((e) => e);
  assert.equal(error.code, "qr_server_key");
  // The core made KE3, but it was never posted: no session, no unlock, nothing pinned.
  assert.equal(w.client.called("login_finish").length, 1);
  assert.ok(!posted(w, "/api/auth/opaque/login/finish"));
  assert.equal(w.client.called("unlock_password").length, 0);
  assert.ok(w.client.called("clear").length >= 1);
  assert.equal(await loadPinned(w.db.store, SERVER, EMAIL), null);
  // A core that gives no key is refused the same way, not skipped.
  const none = await world({ handlers: { login_finish: () => ({ ke3: filled(64, 2) }) } });
  await assert.rejects(signIn(none, qrText(), { skCode: SK_CODE }), { code: "qr_server_key" });
  assert.ok(!posted(none, "/api/auth/opaque/login/finish"));
});

test("a_different_account_id_is_refused_and_nothing_is_pinned", async () => {
  const w = await world();
  const error = await signIn(w, qrText({ account: OTHER_ACCOUNT }), { skCode: SK_CODE }).catch((e) => e);
  assert.equal(error.code, "qr_account");
  // The server named its account only after KE3, so the session exists: it is ended, the vault is not opened.
  assert.ok(posted(w, "/api/auth/opaque/login/finish"));
  assert.equal(w.requests.filter((r) => r.url === "/api/vault/unlock-methods").length, 0);
  assert.equal(w.client.called("unlock_password").length, 0);
  assert.ok(w.requests.some((r) => r.url === "/api/auth/logout"));
  assert.equal(w.server.state.signedIn, false);
  assert.ok(w.client.locked >= 1);
  assert.equal(w.session.current(), null);
  assert.equal(await loadPinned(w.db.store, SERVER, EMAIL), null);
  assert.equal(await loadPinned(w.db.store, SERVER, OTHER_ACCOUNT), null);
});

test("a_record_for_another_account_than_the_sheet_is_refused_before_anything_is_sent", async () => {
  const w = await world();
  await savePinned(w.db.store, SERVER, OTHER_ACCOUNT, EMAIL, pinnedRecord({ accountId: OTHER_ACCOUNT, skBit: true }));
  await assert.rejects(signIn(w, qrText(), { skCode: SK_CODE }), { code: "qr_account" });
  assert.equal(w.requests.length, 0);
  assert.equal(w.client.called("login_start").length, 0);
});

test("the_sheet_sk_bit_answers_the_secret_key_question", async () => {
  // No answer given: the sheet's "no" is the answer, and the first-use pin carries it.
  const no = await world({ skBit: false });
  await signIn(no, qrText({ sk: false }));
  assert.deepEqual(no.client.called("login_finish")[0].snapshot[2], { kind: "first_use", sk_bit: false });
  assert.deepEqual(no.client.called("unlock_password")[0].snapshot[3], { kind: "first_use", sk_bit: false });
  assert.equal(no.client.called("login_start")[0].snapshot[1], null);

  // The sheet's "yes" is the answer, and the code is then needed (nothing is sent without it).
  const yes = await world();
  await assert.rejects(signIn(yes, qrText({ sk: true })), { code: "sk_required" });
  assert.equal(yes.requests.length, 0);
  await signIn(yes, qrText({ sk: true }), { skCode: SK_CODE });
  assert.deepEqual(yes.client.called("login_finish")[0].snapshot[2], { kind: "first_use", sk_bit: true });
  assert.equal(yes.client.called("login_start")[0].snapshot[1], SK_CODE);

  // An answer that differs from the sheet is not a wrong password and is not sent.
  const clash = await world();
  await assert.rejects(signIn(clash, qrText({ sk: true }), { skBit: false }), { code: "pinned_sk_bit" });
  assert.equal(clash.requests.length, 0);
  // Neither is a record on this device that differs from it.
  const record = await world({ skBit: false });
  await savePinned(record.db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ skBit: false }));
  await assert.rejects(signIn(record, qrText({ sk: true }), { skCode: SK_CODE }), { code: "pinned_sk_bit" });
  assert.equal(record.requests.length, 0);
});

test("a_sheet_with_a_pinned_record_of_the_same_account_signs_in", async () => {
  const w = await world();
  await savePinned(w.db.store, SERVER, ACCOUNT, EMAIL, pinnedRecord({ skBit: true }));
  await signIn(w, qrText(), { skCode: SK_CODE });
  assert.equal(w.client.called("login_finish")[0].snapshot[2].kind, "pinned");
});

test("a_blank_sheet_text_is_no_sheet_and_a_bad_one_stops_the_sign_in", async () => {
  const w = await world();
  await assert.rejects(signIn(w, "not a sheet", { skCode: SK_CODE }), { code: "malformed_setup_qr" });
  assert.equal(w.requests.length, 0);
  assert.equal(w.client.called("login_start").length, 0);
  // No text at all is the sign-in of before: no sheet checks, first use, the answer from the user.
  const plain = await world();
  await signIn(plain, undefined, { skBit: true, skCode: SK_CODE });
  assert.equal(plain.client.called("setup_qr_parse").length, 0);
});

test("the_qr_text_never_reaches_url_storage_or_console", async () => {
  const text = qrText({ url: SERVER });
  const marks = [text, "ferret-setup", encodeURIComponent(text), "a=" + ACCOUNT];
  const saved = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug, trace: console.trace };
  const heard = [];
  for (const name of Object.keys(saved)) console[name] = (...args) => void heard.push(args.map((a) => (a instanceof Error ? `${a.message}\n${a.stack}` : String(a))).join(" "));
  const storage = () => {
    const items = new Map();
    return { items, getItem: (k) => items.get(k) ?? null, setItem: (k, v) => void items.set(k, String(v)), removeItem: (k) => void items.delete(k), clear: () => items.clear() };
  };
  const savedStorage = [globalThis.localStorage, globalThis.sessionStorage];
  const local = storage();
  const session = storage();
  Object.defineProperty(globalThis, "localStorage", { value: local, configurable: true });
  Object.defineProperty(globalThis, "sessionStorage", { value: session, configurable: true });
  const errors = [];
  try {
    // A sign-in that works, one with a different key, one with a different account and one with a bad text.
    const ok = await world();
    await signIn(ok, text, { skCode: SK_CODE });
    const worlds = [ok];
    for (const [qr, handlers] of [
      [text, { login_finish: () => ({ ke3: filled(64, 2), server_public_key: OTHER_KEY }) }],
      [qrText({ account: OTHER_ACCOUNT }), {}],
      [qrText({ url: "https://other.example" }), {}],
      [`${text}&x=1`, {}],
    ]) {
      const w = await world({ handlers });
      errors.push(await signIn(w, qr, { skCode: SK_CODE }).catch((e) => e));
      worlds.push(w);
    }
    for (const w of worlds) {
      // The address of every request and the body of every request.
      for (const r of w.requests) {
        for (const mark of marks) {
          assert.ok(!String(r.url).includes(mark), `url: ${r.url}`);
          assert.ok(!JSON.stringify(r.body ?? null).includes(mark), `body of ${r.url}`);
          assert.ok(!JSON.stringify(r.headers ?? null).includes(mark), `headers of ${r.url}`);
        }
      }
      // Everything this device keeps.
      const stored = await dumpDatabase(w.db.store);
      for (const mark of marks.slice(0, 3)) assert.ok(!stored.includes(mark), `stored: ${mark}`);
    }
    // The errors name a code and carry nothing of the text.
    for (const error of errors) {
      const dump = `${error.message}\n${error.stack}\n${JSON.stringify(error, Object.getOwnPropertyNames(error))}`;
      for (const mark of marks.slice(0, 3)) assert.ok(!dump.includes(mark), `error: ${mark}`);
    }
    assert.deepEqual(errors.map((e) => e.code), ["qr_server_key", "qr_account", "qr_server_url", "malformed_setup_qr"]);
  } finally {
    Object.assign(console, saved);
    for (const [name, value] of [["localStorage", savedStorage[0]], ["sessionStorage", savedStorage[1]]]) {
      if (value === undefined) delete globalThis[name];
      else Object.defineProperty(globalThis, name, { value, configurable: true });
    }
  }
  assert.equal(local.items.size + session.items.size, 0, "nothing was written to web storage");
  for (const line of heard) for (const mark of marks.slice(0, 3)) assert.ok(!line.includes(mark), `console: ${mark}`);
});

// ---------------------------------------------------------------- the page

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

/** A session for the page: the real reader over the fake client, a recorded sign-in. */
async function pageSession({ device = { pinned: false, skBit: null, skStored: false }, signIn: onSignIn } = {}) {
  const w = await world();
  const calls = [];
  return {
    w,
    calls,
    serverUrl: SERVER,
    deviceStatus: async () => device,
    readSetupQr: (text) => {
      calls.push(["readSetupQr", text]);
      return w.session.readSetupQr(text);
    },
    signIn: async (args) => {
      calls.push(["signIn", args]);
      if (onSignIn) return onSignIn(args);
      return { accountId: ACCOUNT };
    },
    current: () => null,
    freshReauth: () => true,
    lock: async () => {},
    signOut: async () => {},
    forgetSecretKey: async () => {},
  };
}

function page(session, overrides = {}, lang = "en") {
  const went = [];
  const root = loginView({
    t: i18n(lang).t,
    session,
    entry: { page: "login", handoff: null, brokenHandoff: false, setupToken: null },
    adminUrl: null,
    api: {},
    go: (path) => went.push(path),
    handoff: {},
    info: null,
    ...overrides,
  });
  return { root, went };
}

const type = async (root, role, value) => {
  byRole(root, role).value = value;
  await fire(byRole(root, role), "input");
};

test("without_a_sheet_the_page_says_trust_on_first_use", async () => {
  await withDom(async () => {
    for (const lang of ["en", "nb"]) {
      const session = await pageSession();
      const { root } = page(session, {}, lang);
      await settle();
      const notice = byRole(root, "tofu-notice");
      assert.equal(notice.hidden, false, lang);
      assert.match(textOf(notice), lang === "en" ? /first sign-in on this device trusts the server the first time/ : /første innloggingen på denne enheten stoler på tjeneren første gang/);
      // With text in the sheet field the page waits for it to be read; with a sheet read, the notice goes.
      await type(root, "qr-text", qrText());
      assert.equal(byRole(root, "tofu-notice").hidden, true);
      await fire(byRole(root, "qr-read"), "click");
      await settle();
      assert.equal(byRole(root, "tofu-notice").hidden, true);
      await type(root, "qr-text", "");
      assert.equal(byRole(root, "tofu-notice").hidden, false);
    }
    // A device that knows the account does not say it.
    const known = await pageSession({ device: { pinned: true, skBit: true, skStored: false } });
    const { root } = page(known);
    byRole(root, "email").value = EMAIL;
    await fire(byRole(root, "email"), "change");
    await settle();
    assert.equal(byRole(root, "tofu-notice").hidden, true);
  });
});

test("the_page_shows_host_and_port_and_sends_nothing_until_it_is_confirmed", async () => {
  await withDom(async () => {
    const session = await pageSession();
    const { root, went } = page(session);
    await settle();
    byRole(root, "email").value = EMAIL;
    await type(root, "qr-text", qrText({ url: SERVER, sk: true }));
    assert.equal(byRole(root, "qr-shown").hidden, true);
    await fire(byRole(root, "qr-read"), "click");
    await settle();
    const shown = textOf(byRole(root, "qr-shown"));
    assert.match(shown, /The sheet is for vault\.example\./);
    assert.match(shown, /Secret key on the account: yes/);
    // The sheet answers the secret key question, so the page does not ask it.
    assert.equal(byRole(root, "sk-question").hidden, true);
    assert.equal(byRole(root, "sk-code").parentNode.hidden, false);
    // Reading sent no sign-in, and no request left the page.
    assert.deepEqual(session.calls.map((c) => c[0]), ["readSetupQr"]);
    assert.equal(session.w.requests.length, 0);

    // Submitting without confirming is refused, and the password stays where it is.
    byRole(root, "password").value = PASSWORD;
    byRole(root, "sk-code").value = SK_CODE;
    await fire(byRole(root, "credentials"), "submit");
    await settle();
    assert.ok(!session.calls.some((c) => c[0] === "signIn"));
    assert.match(textOf(byRole(root, "error")), /confirm the address/);
    assert.equal(byRole(root, "password").value, PASSWORD);

    // Confirmed: the sign-in is sent with the text and the sheet's bit.
    byRole(root, "qr-confirm").checked = true;
    await fire(byRole(root, "credentials"), "submit");
    await settle();
    const sent = session.calls.find((c) => c[0] === "signIn")[1];
    assert.equal(sent.qr, qrText({ url: SERVER, sk: true }));
    assert.equal(sent.skBit, true);
    assert.equal(sent.skCode, SK_CODE);
    assert.deepEqual(went, ["/"]);
  });
});

test("the_page_refuses_a_sheet_for_another_server_before_asking_for_a_confirmation", async () => {
  await withDom(async () => {
    const session = await pageSession();
    const { root } = page(session);
    await settle();
    await type(root, "qr-text", qrText({ url: "https://other.example" }));
    await fire(byRole(root, "qr-read"), "click");
    await settle();
    assert.equal(byRole(root, "qr-shown").hidden, true);
    assert.equal(byRole(root, "error").hidden, false);
    assert.match(textOf(byRole(root, "error")), /another server address than the one of this page/);
    // A text that is not a sheet text says so.
    await type(root, "qr-text", "hello");
    await fire(byRole(root, "qr-read"), "click");
    await settle();
    assert.match(textOf(byRole(root, "error")), /not the text of an emergency sheet/);
    // Editing the text after it was read takes the confirmation back.
    await type(root, "qr-text", qrText());
    await fire(byRole(root, "qr-read"), "click");
    await settle();
    byRole(root, "qr-confirm").checked = true;
    await type(root, "qr-text", qrText({ sk: false }));
    assert.equal(byRole(root, "qr-shown").hidden, true);
    assert.equal(byRole(root, "qr-confirm").checked, false);
    assert.ok(!session.calls.some((c) => c[0] === "signIn"));
  });
});

test("the_page_without_a_sheet_signs_in_as_before", async () => {
  await withDom(async () => {
    const session = await pageSession();
    const { root, went } = page(session);
    await settle();
    byRole(root, "email").value = EMAIL;
    byRole(root, "password").value = PASSWORD;
    byRole(root, "sk-no").checked = true;
    await fire(byRole(root, "sk-no"), "change");
    await fire(byRole(root, "credentials"), "submit");
    await settle();
    const sent = session.calls.find((c) => c[0] === "signIn")[1];
    assert.equal(sent.qr, undefined);
    assert.equal(sent.skBit, false);
    assert.deepEqual(went, ["/"]);
  });
});

test("the_error_texts_of_the_sheet_checks_are_in_both_languages", () => {
  for (const code of ["qr_server_url", "qr_server_key", "qr_profile", "qr_account", "qr_not_confirmed", "malformed_setup_qr", "qr_unsupported", "qr_too_large", "pinned_elsewhere"]) {
    for (const lang of ["en", "nb"]) {
      const texts = catalog(lang);
      assert.ok(texts[`account.error.${code}`], `${lang}: ${code}`);
    }
  }
  assert.match(catalog("en")["account.error.qr_server_key"], /can be an attack/);
  assert.match(catalog("nb")["account.error.qr_server_key"], /kan være et angrep/);
  assert.equal(coded("x").code, "x");
});
