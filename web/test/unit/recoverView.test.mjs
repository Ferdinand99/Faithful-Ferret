// The recovery page: the host of the sheet is shown and confirmed before anything is sent, a new
// browser needs both pages of the sheet, a refused code has one text, and the new recovery key is
// shown alone and typed back. Against a small fake DOM and the real flow over a fake server.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { readSetupQr } from "../../src/flows/setupQr.mjs";
import { recoverAccount } from "../../src/flows/recover.mjs";
import { RECOVER_ERRORS, recoverView } from "../../src/views/recover.mjs";
import { accountDocument, byRole, fire, settle, textOf, until } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { CODE, EMAIL, NEW_PASSWORD, NEW_RK, RK_CODE, SERVER, SK_CODE, qrText, recoverWorld } from "./recoverHelpers.mjs";
import { parseQr } from "./setupQrHelpers.mjs";
import { EN, NB, translator } from "./syncWarningsHelpers.mjs";

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

/**
 * The page over the real flow in a recovery world (or over `recover` when given).
 * @param {{ world?: any, recover?: (args: any) => Promise<any>, info?: any, lang?: string, device?: any }} [options]
 */
function page({ world, recover, info = null, lang = "en", device = { pinned: false, skBit: null, skStored: false }, resetOpen = false, passkeysOffered } = {}) {
  const went = [];
  const root = recoverView({
    t: translator(lang),
    info,
    resetOpen,
    serverUrl: SERVER,
    readSetupQr: (text) => readSetupQr({ vault: { setup_qr_parse: parseQr } }, text),
    deviceStatus: async () => device,
    passkeysOffered,
    recover: recover ?? ((args) => recoverAccount(world.env, args, { signIn: (a) => world.session.unlock(a) })),
    go: (path) => went.push(path),
    print: () => undefined,
  });
  return { root, went };
}

/** Fills the form; `sheet` reads the QR text and confirms its host. */
async function fill(root, { code = CODE, sheet = qrText(), read = true, confirm = true, sk = SK_CODE, rk = RK_CODE, next = NEW_PASSWORD, again = NEW_PASSWORD } = {}) {
  const set = (role, value) => {
    const node = byRole(root, role);
    if (node) node.value = value;
  };
  set("email", EMAIL);
  set("code", code);
  if (sheet !== null) {
    set("qr-text", sheet);
    if (read) {
      await fire(byRole(root, "qr-read"), "click");
      await settle();
    }
    if (confirm) byRole(root, "qr-confirm").checked = true;
  }
  set("sk-code", sk);
  set("rk-code", rk);
  set("new-password", next);
  set("new-password-again", again);
}

const submit = async (root) => {
  await fire(byRole(root, "recover-form"), "submit");
  await settle();
};

test("a_new_device_needs_both_pages_of_the_sheet_and_shows_the_host_first", async () => {
  await withDom(async () => {
    const calls = [];
    const { root } = page({ recover: async (args) => void calls.push(args) });
    await settle();
    // The page says what a new browser needs: both pages.
    assert.equal(textOf(byRole(root, "new-browser")).trim(), EN["recover.new_browser"]);
    assert.match(EN["recover.new_browser"], /both pages/);
    // A sheet text that was not read and confirmed: nothing is started, and the secrets stay in their fields.
    await fill(root, { read: false, confirm: false });
    await submit(root);
    assert.deepEqual(calls, []);
    assert.equal(textOf(byRole(root, "error")).trim(), EN["account.error.qr_not_confirmed"]);
    assert.equal(byRole(root, "rk-code").value, RK_CODE);
    // Read: the host is shown, and the sheet says the account has a secret key, so its field is there.
    await fire(byRole(root, "qr-read"), "click");
    await settle();
    assert.equal(byRole(root, "qr-shown").hidden, false);
    assert.match(textOf(byRole(root, "qr-summary")), /vault\.example/);
    assert.equal(byRole(root, "sk-code").parentNode.hidden ?? false, false);
    // Read but not confirmed: still nothing.
    await submit(root);
    assert.deepEqual(calls, []);
    // Confirmed: the flow gets page 1 (QR text and secret key) and page 2 (the recovery key), and the fields are empty.
    byRole(root, "qr-confirm").checked = true;
    await submit(root);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].qrText, qrText());
    assert.equal(calls[0].skCode, SK_CODE);
    assert.equal(calls[0].rkCode, RK_CODE);
    assert.equal(calls[0].code, CODE);
    for (const role of ["rk-code", "sk-code", "new-password", "new-password-again", "code"]) assert.equal(byRole(root, role).value, "", role);
    // A sheet for another server is refused when it is read, before anything else.
    const other = page({ recover: async (args) => void calls.push(args) });
    byRole(other.root, "qr-text").value = qrText({ url: "https://other.example" });
    await fire(byRole(other.root, "qr-read"), "click");
    await settle();
    assert.equal(byRole(other.root, "qr-shown").hidden, true);
    assert.equal(textOf(byRole(other.root, "error")).trim(), EN["account.error.qr_server_url"]);
  });
  // The flow itself: without page 1, or without the secret key of page 1, nothing is sent.
  for (const [args, code] of [[{ qrText: "" }, "qr_required"], [{ skCode: "" }, "sk_required"]]) {
    const world = await recoverWorld();
    const error = await recoverAccount(world.env, {
      email: EMAIL, code: CODE, qrText: qrText(), skCode: SK_CODE, rkCode: RK_CODE, newPassword: NEW_PASSWORD, newPasswordAgain: NEW_PASSWORD,
      confirmNewRk: async () => undefined, ...args,
    }).catch((e) => e);
    assert.equal(error.code, code);
    assert.deepEqual(world.requests.filter((r) => r.method !== "GET"), [], `${code}: nothing was sent`);
  }
});

test("the_new_key_is_shown_alone_typed_back_and_the_page_ends_signed_in", async () => {
  await withDom(async () => {
    const world = await recoverWorld();
    const { root, went } = page({ world });
    await settle();
    await fill(root);
    void fire(byRole(root, "recover-form"), "submit");
    await until(() => byRole(root, "sheet-page") !== null);
    // Page 2 only: the new key, no page 1, and the rest of the page is out of the way.
    const sheet = byRole(root, "sheet-page");
    assert.equal(textOf(byRole(sheet, "sheet-recovery-key")).trim(), NEW_RK);
    assert.equal(byRole(sheet, "sheet-server"), null, "page 1 is not shown");
    assert.equal(byRole(root, "recover-form"), null);
    assert.equal(world.recovers.length, 0, "nothing was sent while the sheet shows");
    // A wrong key typed back is refused, and still nothing goes out.
    byRole(sheet, "rk-typed").value = RK_CODE;
    await fire(byRole(sheet, "confirm-form"), "submit");
    await settle();
    assert.equal(world.recovers.length, 0);
    // The right one: the request goes out, and the page ends signed in.
    byRole(sheet, "rk-typed").value = NEW_RK;
    await fire(byRole(sheet, "confirm-form"), "submit");
    await until(() => byRole(root, "recover-done") !== null);
    assert.equal(world.recovers.length, 1);
    assert.equal(byRole(root, "sheet-page"), null, "the sheet left the page");
    assert.equal(textOf(byRole(root, "done-signed-in")).trim(), EN["recover.done_signed_in"]);
    assert.ok(textOf(byRole(root, "recover-done")).includes(EN["recover.done_old_key"]));
    assert.equal(byRole(root, "qr-text").value, "", "the sheet text left the page");
    await fire(byRole(root, "open-vault"), "click");
    assert.deepEqual(went, ["/"]);
  });
  // "Stop" while the sheet shows: nothing is sent, and the form comes back with the text.
  await withDom(async () => {
    const world = await recoverWorld();
    const { root } = page({ world });
    await settle();
    await fill(root);
    void fire(byRole(root, "recover-form"), "submit");
    await until(() => byRole(root, "recover-cancel") !== null);
    await fire(byRole(root, "recover-cancel"), "click");
    await until(() => byRole(root, "recover-form") !== null && byRole(root, "error").hidden === false);
    assert.equal(textOf(byRole(root, "error")).trim(), EN["recover.error.cancelled"]);
    assert.equal(world.recovers.length, 0);
  });
});

test("after_a_recovery_the_page_asks_the_user_to_look_at_the_passkeys_when_they_are_offered", async () => {
  // A recovery rewrites the password and the recovery key and leaves the passkeys: the page says so and links to the list.
  for (const [lang, texts] of [["en", EN], ["nb", NB]]) {
    for (const offered of [true, false]) {
      await withDom(async () => {
        const world = await recoverWorld();
        const { root } = page({ world, lang, passkeysOffered: async () => offered });
        await settle();
        await fill(root);
        void fire(byRole(root, "recover-form"), "submit");
        await until(() => byRole(root, "sheet-page") !== null);
        byRole(byRole(root, "sheet-page"), "rk-typed").value = NEW_RK;
        await fire(byRole(byRole(root, "sheet-page"), "confirm-form"), "submit");
        await until(() => byRole(root, "recover-done") !== null);
        await settle();
        const note = byRole(root, "done-passkeys");
        assert.equal(note.hidden, !offered, `${lang} ${offered}`);
        if (offered) {
          assert.ok(textOf(note).includes(texts["recover.done_passkeys"]));
          assert.equal(byRole(note, "done-passkeys-link").getAttribute("href"), "#/unlock-methods");
        }
      });
    }
  }
  // A page that cannot tell (no such offer, or the check fails) says nothing about passkeys.
  await withDom(async () => {
    const world = await recoverWorld();
    const { root } = page({ world, passkeysOffered: async () => { throw new Error("no answer"); } });
    await settle();
    await fill(root);
    void fire(byRole(root, "recover-form"), "submit");
    await until(() => byRole(root, "sheet-page") !== null);
    byRole(byRole(root, "sheet-page"), "rk-typed").value = NEW_RK;
    await fire(byRole(byRole(root, "sheet-page"), "confirm-form"), "submit");
    await until(() => byRole(root, "recover-done") !== null);
    await settle();
    assert.equal(byRole(root, "done-passkeys").hidden, true);
  });
});

test("a_recovery_that_did_not_sign_in_says_where_to_look_at_the_passkeys_later", async () => {
  for (const [lang, texts] of [["en", EN], ["nb", NB]]) {
    await withDom(async () => {
      const world = await recoverWorld();
      const failing = async () => {
        throw Object.assign(new Error("no sign-in"), { code: "network" });
      };
      const { root } = page({ world, lang, recover: (args) => recoverAccount(world.env, args, { signIn: failing }), passkeysOffered: async () => true });
      await settle();
      await fill(root);
      void fire(byRole(root, "recover-form"), "submit");
      await until(() => byRole(root, "sheet-page") !== null);
      byRole(byRole(root, "sheet-page"), "rk-typed").value = NEW_RK;
      await fire(byRole(byRole(root, "sheet-page"), "confirm-form"), "submit");
      await until(() => byRole(root, "recover-done") !== null);
      await settle();
      assert.equal(textOf(byRole(root, "done-signed-in")).trim(), texts["recover.done_not_signed_in"]);
      assert.equal(textOf(byRole(root, "done-passkeys-later")).trim(), texts["recover.done_passkeys_later"]);
      assert.equal(byRole(root, "done-passkeys").hidden, true, "the list itself cannot be read before the sign-in");
    });
  }
});

test("a_wrong_code_shows_the_single_failure_text", async () => {
  await withDom(async () => {
    const texts = [];
    for (const lang of ["en", "nb"]) {
      // A wrong code, and too many tries (429 with a wait): the same text, with nothing about the account or the wait.
      for (const options of [{ redeemStatus: 401 }, { redeemStatus: 429 }, {}]) {
        const world = await recoverWorld(options);
        const { root } = page({ world, lang });
        await settle();
        await fill(root, { code: options.redeemStatus === undefined ? "WRONG-CODE" : CODE });
        await submit(root);
        await until(() => byRole(root, "error").hidden === false);
        texts.push([lang, textOf(byRole(root, "error")).trim()]);
        assert.equal(world.client.called("register_start").length, 0, "nothing after a refused code");
      }
    }
    for (const [lang, text] of texts) assert.equal(text, (lang === "en" ? EN : NB)["recover.error.code_refused"]);
    assert.match(EN["recover.error.code_refused"], /wait five minutes/);
  });
  // The page has no note that a stranger can hold a right code back: the server counts failures per address.
  await withDom(async () => {
    for (const lang of ["en", "nb"]) {
      const { root } = page({ recover: async () => "recovered", lang });
      assert.equal(byRole(root, "code-limit"), null);
    }
    assert.equal(EN["recover.code_limit"], undefined);
    assert.equal(NB["recover.code_limit"], undefined);
    // With a full session there is no code to type.
    const { root } = page({ recover: async () => "recovered", info: { accountId: "aa".repeat(16), email: EMAIL } });
    assert.equal(byRole(root, "code").parentNode.hidden, true);
    assert.equal(byRole(root, "email").parentNode.hidden, true);
    assert.ok(textOf(byRole(root, "signed-in")).includes(EMAIL));
  });
});

test("the_code_field_follows_the_session", async () => {
  await withDom(async () => {
    // The code is never a "required" field: a reset session that is still open needs none, and the page says so.
    const { root } = page({ recover: async () => "recovered", resetOpen: true });
    assert.equal(byRole(root, "code").getAttribute("required") ?? null, null);
    assert.equal(byRole(root, "reset-open").hidden, false);
    assert.equal(textOf(byRole(root, "reset-open")).trim(), EN["recover.reset_open"]);
    assert.equal(byRole(page({ recover: async () => "recovered" }).root, "reset-open").hidden, true, "no note without an open reset session");
    // The full session the page was opened with ends before the submit: the e-mail and the code fields come back.
    const calls = [];
    const full = page({
      info: { accountId: "aa".repeat(16), email: EMAIL },
      recover: async (args) => {
        calls.push(args);
        throw Object.assign(new Error("code_required"), { code: "code_required" });
      },
    });
    await settle();
    await fill(full.root, { sheet: null });
    await submit(full.root);
    await until(() => byRole(full.root, "error").hidden === false);
    assert.equal(calls[0].email, EMAIL, "the session's e-mail was used");
    assert.equal(byRole(full.root, "code").parentNode.hidden, false);
    assert.equal(byRole(full.root, "email").parentNode.hidden, false);
    assert.equal(byRole(full.root, "signed-in").hidden, true);
    assert.equal(textOf(byRole(full.root, "error")).trim(), EN["recover.error.code_required"]);
    // The next try sends what was typed.
    await fill(full.root, { sheet: null });
    byRole(full.root, "email").value = "ada@example.test";
    await submit(full.root);
    await until(() => calls.length === 2);
    assert.equal(calls[1].code, CODE);
  });
});

test("recover_texts_exist_in_both_languages", () => {
  const read = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "recover.json"), "utf8"));
  const en = read("en");
  const nb = read("nb");
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  for (const [key, value] of [...Object.entries(en), ...Object.entries(nb)]) {
    assert.ok(key.startsWith("recover."), key);
    assert.equal(typeof value, "string");
    assert.ok(value.trim().length > 0, key);
    // The same placeholders in both languages.
    const names = (text) => [...text.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();
    assert.deepEqual(names(en[key]), names(nb[key]), key);
  }
  // Every key named in the sources exists, and none is left unused.
  const used = new Set();
  for (const dir of ["views", "flows", "routes"]) {
    for (const file of readdirSync(join(web, "src", dir))) {
      const source = readFileSync(join(web, "src", dir, file), "utf8");
      for (const match of source.matchAll(/["'`](recover\.[a-z0-9_.]+)["'`]/g)) used.add(match[1]);
    }
  }
  for (const key of used) assert.ok(key in en, `missing text: ${key}`);
  const built = [...RECOVER_ERRORS.map((code) => `recover.error.${code}`), "recover.offer.recover", "recover.offer.old_sheet"];
  for (const key of built) assert.ok(key in en, `missing text: ${key}`);
  for (const key of Object.keys(en)) assert.ok(used.has(key) || built.includes(key), `unused text: ${key}`);
  // What the texts promise: both pages on a new browser, never the old password, everyone signed out, and that old
  // exports and backups still open with the old secrets.
  assert.match(en["recover.new_browser"], /both pages/);
  assert.match(nb["recover.new_browser"], /begge sidene/);
  assert.match(en["recover.intro"], /never asked for the old one/);
  assert.match(nb["recover.intro"], /aldri bedt om det gamle/);
  assert.match(en["recover.done_old_files"], /still open with the old master password/);
  assert.match(en["recover.done_old_key"], /backup made before today/);
  assert.match(nb["recover.done_old_key"], /backup fra før i dag/);
  // The route title is a text too.
  const route = readFileSync(join(web, "src", "routes", "recover.route.mjs"), "utf8");
  assert.ok(/title: "([^"]+)"/.exec(route)[1] in en);
});
