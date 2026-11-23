// The question of "Forget this server" names what forgetting would lose, as
// the web vault's question does: the changes this device never sent (they are
// lost), and an account that another address of the server keeps (then the
// saved items, the trash, the sync flags and those changes stay, for that
// address). The background answers with two counts of its own records and
// changes nothing; the question works on an open, a locked and a signed-out
// device alike. The background is the real one with the sync wired in.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { SERVER, pkg } from "./sessionHelpers.mjs";
import { OTHER, syncWorld } from "./syncWorld.mjs";

const here = dirname(fileURLToPath(import.meta.url));

/** The texts of the extension's built package. @param {string} lang @returns {Promise<Record<string, string>>} */
async function extensionTexts(lang) {
  const { dir } = await pkg();
  return JSON.parse(await readFile(join(dir, `locales.${lang}.json`), "utf8"));
}

/** The web vault's sync texts, with the extension's word for the server in Norwegian ("server", not "tjener"). @param {string} lang */
async function webTexts(lang) {
  const raw = JSON.parse(await readFile(join(here, "..", "..", "..", "web", "src", "locales", lang, "syncwarnings.json"), "utf8"));
  /** @type {Record<string, string>} */
  const out = {};
  for (const [key, text] of Object.entries(raw)) {
    out[key] = String(text).replaceAll("tjenerens", "serverens").replaceAll("tjeneren", "serveren").replaceAll("tjener", "server");
  }
  return out;
}

/** The sentences of a text. @param {string} text */
const sentences = (text) => text.split(/(?<=[.:]) (?=[A-ZÆØÅ])/u);

test("forget_dialog_names_pending_and_shared_writes_like_the_web_vault", async () => {
  const { load } = await pkg();
  const { forgetBodyKey } = await load("pages/popupFlow.mjs");

  // The four questions, as the web vault has them.
  // Without an answer the question still says that unsent changes, if any, are lost.
  assert.equal(forgetBodyKey(null), "sync.forget.body_unknown");
  assert.equal(forgetBodyKey({ pending: 0, shared: false }), "sync.forget.body");
  assert.equal(forgetBodyKey({ pending: 2, shared: false }), "sync.forget.body_pending");
  assert.equal(forgetBodyKey({ pending: 0, shared: true }), "sync.forget.body_shared");
  assert.equal(forgetBodyKey({ pending: 2, shared: true }), "sync.forget.body_shared_pending");

  // Each says what the web vault's says about unsent and shared writes, in its words, in both languages. The
  // extension's own sentence (the device is signed out at the server) stays in each.
  const KEYS = /** @type {const} */ ({
    "sync.forget.body_pending": "syncwarnings.forget.dialog_body_pending",
    "sync.forget.body_shared": "syncwarnings.forget.dialog_body_shared",
    "sync.forget.body_shared_pending": "syncwarnings.forget.dialog_body_shared_pending",
  });
  for (const lang of ["en", "nb"]) {
    const ours = await extensionTexts(lang);
    const web = await webTexts(lang);
    const signedOut = sentences(ours["sync.forget.body"]).find((s) => /signed out|logges ut/.test(s));
    assert.ok(signedOut, `${lang}: the plain question names the sign-out`);
    for (const [key, webKey] of Object.entries(KEYS)) {
      const text = ours[key];
      assert.equal(typeof text, "string", `${lang}: ${key}`);
      // The web vault's last sentence about the changes, and its sentence about the other address, word for word.
      const webSentences = sentences(web[webKey]);
      if (key.endsWith("pending")) assert.ok(text.endsWith(webSentences.at(-1) ?? "?"), `${lang}: ${key} ends with the web vault's sentence about unsent changes`);
      if (key.includes("shared")) {
        const shared = webSentences.find((s) => /another address|annen adresse/.test(s));
        assert.ok(shared && text.includes(shared), `${lang}: ${key} has the web vault's sentence about the other address`);
      }
      assert.ok(text.includes(signedOut), `${lang}: ${key} still says the device is signed out at the server`);
      assert.match(text, key.endsWith("pending") ? /\{count\}/ : /^[^{}]*$/, `${lang}: ${key}`);
    }
  }

  // The background's answer: what this device's own records say, and nothing changes.
  const { world, engines, server, store, popup, signIn } = await syncWorld();
  await signIn();
  const [engine] = engines.made;
  store.writes.pending = 2;
  assert.deepEqual(await popup.forgetPreview(SERVER), { pending: 2, shared: false });
  store.writes.shared = true;
  assert.deepEqual(await popup.forgetPreview(SERVER), { pending: 2, shared: true });
  assert.equal(engine.stopped, false, "asking stops nothing");
  assert.equal(world.coreHost.state(), "unlocked");
  assert.deepEqual(store.forgotten, []);
  assert.equal(server.to("/api/auth/token/revoke").length, 0, "nothing is revoked");

  // Another server than the one kept: no answer about it.
  const ui = world.page();
  assert.deepEqual(await ui.request("forget_preview", { server: OTHER }), { ok: false, reason: "another_server" });
  assert.equal(await popup.forgetPreview(OTHER), null, "the popup then asks the plain question");

  // A locked device asks the same question (the forget itself works there too); asking does not move the deadline.
  await popup.lock();
  assert.equal(world.coreHost.state(), "locked");
  const lockAt = await world.sessionStorage.get("lock_at");
  store.writes.shared = false;
  assert.deepEqual(await popup.forgetPreview(SERVER), { pending: 2, shared: false });
  assert.deepEqual(await world.sessionStorage.get("lock_at"), lockAt);

  // What the user sees: the count is in the question.
  const en = await extensionTexts("en");
  const key = forgetBodyKey({ pending: 2, shared: false });
  assert.match(en[key].replace("{count}", "2"), /: 2\.$/);

  for (const lang of ["en", "nb"]) {
    const ours = await extensionTexts(lang);
    assert.ok(ours["sync.forget.body_unknown"].startsWith(ours["sync.forget.body"]), lang);
    assert.match(ours["sync.forget.body_unknown"], /lost|tapt/, lang);
  }

  // A forget that would lose more than its question named does nothing: the user is asked again.
  store.writes.pending = 3;
  assert.deepEqual(await ui.request("forget_server", { server: SERVER, expect_pending: 2 }), { ok: false, reason: "changed" });
  assert.deepEqual(store.forgotten, []);
  assert.equal(server.to("/api/auth/token/revoke").length, 0, "nothing is revoked");
  assert.deepEqual((await popup.forget(SERVER, 2)).result, { ok: false, reason: "changed" });
  // The popup has a text for it.
  assert.equal(typeof en["sync.error.changed"], "string");

  // With the count it showed (or more room), forgetting goes on as before: after it, there is nothing left to name.
  assert.deepEqual(await ui.request("forget_server", { server: SERVER, expect_pending: 3 }), { ok: true });
  assert.deepEqual(await ui.request("forget_preview", { server: SERVER }), { ok: true, pending: 0, shared: false });
});
