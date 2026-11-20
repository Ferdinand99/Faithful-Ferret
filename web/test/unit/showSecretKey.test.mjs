// The secret key shown again: only after the password check, as text or as a QR code (never both),
// a QR code that holds the code's text and nothing else, gone on "Hide", a lock and leaving the page,
// and, without a remembered key, a pointer to page 1 of the sheet instead of anything else.
import assert from "node:assert/strict";
import { test } from "node:test";
import jsQR from "jsqr";
import { secretKeyView } from "../../src/views/secretKey.mjs";
import { byRole, dumpDatabase, fire, settle, textOf } from "./accountHelpers.mjs";
import { SK_CODE } from "./securityHelpers.mjs";
import { catalog, i18n, keysWorld, reauthWith, withDom } from "./keysHelpers.mjs";

/** What a decoder reads from the modules (black on white, four modules of quiet zone). */
function readQr(code, scale = 4) {
  const quiet = 4;
  const side = (code.size + 2 * quiet) * scale;
  const data = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < code.size; y += 1) {
    for (let x = 0; x < code.size; x += 1) {
      if (!code.dark(x, y)) continue;
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          const at = ((y + quiet) * scale + dy) * side * 4 + ((x + quiet) * scale + dx) * 4;
          data[at] = data[at + 1] = data[at + 2] = 0;
        }
      }
    }
  }
  const result = jsQR(data, side, side, { inversionAttempts: "dontInvert" });
  assert.ok(result, "the decoder reads the code");
  return Buffer.from(result.binaryData).toString("utf8");
}

/** A wipe scope and a window whose address change can be fired. */
function surroundings() {
  const wipers = new Set();
  const listeners = new Map();
  return {
    scope: { add: (fn) => (wipers.add(fn), () => wipers.delete(fn)) },
    win: { addEventListener: (type, fn) => listeners.set(type, fn), removeEventListener: (type) => listeners.delete(type) },
    lock: () => [...wipers].forEach((fn) => fn()),
    leave: () => listeners.get("hashchange")?.(),
    listeners,
  };
}

test("secret_key_and_its_qr_are_shown_one_at_a_time_after_reauth", async () => {
  // The flow: nothing is read before the password check, and a cancelled check shows nothing.
  const world = await keysWorld();
  await assert.rejects(world.session.showSecretKey({ reauth: reauthWith(world, "cancelled") }), { code: "cancelled" });
  assert.equal(world.client.called("check_code").length, 0);
  world.log.length = 0;
  const shown = await world.session.showSecretKey({ reauth: reauthWith(world) });
  assert.equal(shown.code, SK_CODE);
  assert.deepEqual(world.log, ["GET /api/auth/session", "reauth", "vault.check_code"]);
  // Nothing went to the server but the question who the session is.
  assert.deepEqual(world.requests.map((r) => `${r.method} ${r.url}`), ["GET /api/auth/session", "GET /api/auth/session"]);

  for (const lang of ["en", "nb"]) {
    await withDom(async () => {
      const around = surroundings();
      let checks = 0;
      const page = secretKeyView({
        t: i18n(lang).t,
        show: () => world.session.showSecretKey({ reauth: async () => ((checks += 1), "ok") }),
        status: { skBit: true, skStored: true },
        scope: around.scope,
        win: around.win,
      });
      const texts = catalog(lang);
      // Before the click: no key, no QR code, and the warning.
      assert.equal(byRole(page, "sk-code"), null);
      assert.equal(byRole(page, "sk-qr"), null);
      assert.ok(!textOf(page).includes(SK_CODE));
      assert.equal(textOf(byRole(page, "sk-warning")).trim(), texts["keys.secret.warning"]);

      await fire(byRole(page, "sk-show"), "click");
      await settle();
      assert.equal(checks, 1, "the password check ran first");
      // The text, and not the QR code.
      assert.equal(textOf(byRole(page, "sk-code")).trim(), SK_CODE);
      assert.equal(byRole(page, "sk-qr"), null);
      assert.equal(textOf(byRole(page, "sk-toggle")).trim(), texts["keys.secret.as_qr"]);

      // The QR code, and not the text.
      await fire(byRole(page, "sk-toggle"), "click");
      assert.ok(byRole(page, "sk-qr"));
      assert.equal(byRole(page, "sk-qr").getAttribute("aria-label"), texts["keys.secret.qr_alt"]);
      assert.equal(byRole(page, "sk-code"), null);
      assert.ok(!textOf(page).includes(SK_CODE));
      assert.equal(textOf(byRole(page, "sk-toggle")).trim(), texts["keys.secret.as_text"]);
      await fire(byRole(page, "sk-toggle"), "click");
      assert.ok(byRole(page, "sk-code"));
      assert.equal(byRole(page, "sk-qr"), null);

      // "Hide": both go.
      await fire(byRole(page, "sk-hide"), "click");
      assert.equal(byRole(page, "sk-code"), null);
      assert.equal(byRole(page, "sk-qr"), null);
      assert.ok(!textOf(page).includes(SK_CODE));
      assert.equal(around.listeners.size, 0, "nothing listens once the key is hidden");

      // A lock and leaving the page hide it too.
      for (const end of [around.lock, around.leave]) {
        await fire(byRole(page, "sk-show"), "click");
        await settle();
        assert.ok(byRole(page, "sk-code"));
        end();
        assert.equal(byRole(page, "sk-code"), null);
        assert.ok(!textOf(page).includes(SK_CODE));
      }
    });
  }
  // The key was never written anywhere on this device in clear.
  assert.ok(!(await dumpDatabase(world.db.store)).includes(SK_CODE));
});

test("the_secret_key_qr_holds_the_code_text_only", async () => {
  const world = await keysWorld();
  const shown = await world.session.showSecretKey({ reauth: reauthWith(world) });
  assert.equal(readQr(shown.qr), SK_CODE);
});

test("without_a_remembered_secret_key_the_page_points_to_page_1_of_the_sheet", async () => {
  // The flow says so without asking for the password: there is nothing to show.
  const world = await keysWorld({ forgetKey: true });
  assert.equal(await world.session.showSecretKey({ reauth: reauthWith(world) }), "not_remembered");
  assert.ok(!world.log.includes("reauth"));
  // An account without a secret key has nothing to show either.
  const none = await keysWorld({ skBit: false });
  assert.equal(await none.session.showSecretKey({ reauth: reauthWith(none) }), "no_secret_key");

  for (const lang of ["en", "nb"]) {
    await withDom(async () => {
      const texts = catalog(lang);
      let asked = 0;
      // The device says it holds no key: the page points to page 1 and has no button.
      const page = secretKeyView({ t: i18n(lang).t, show: async () => ((asked += 1), "not_remembered"), status: { skBit: true, skStored: false }, win: {} });
      assert.equal(textOf(byRole(page, "sk-not-remembered")).trim(), texts["keys.secret.not_remembered"]);
      assert.match(texts["keys.secret.not_remembered"], lang === "en" ? /page 1 of your emergency sheet/ : /side 1 av nødarket/);
      assert.equal(byRole(page, "sk-show"), null);
      // A key that turns out not to open any more gives the same pointer.
      const later = secretKeyView({ t: i18n(lang).t, show: async () => ((asked += 1), "not_remembered"), status: { skBit: true, skStored: true }, win: {} });
      await fire(byRole(later, "sk-show"), "click");
      await settle();
      assert.equal(textOf(byRole(later, "sk-not-remembered")).trim(), texts["keys.secret.not_remembered"]);
      assert.equal(asked, 1);
      // No secret key at all.
      const without = secretKeyView({ t: i18n(lang).t, show: async () => "no_secret_key", status: { skBit: false, skStored: false }, win: {} });
      assert.equal(textOf(byRole(without, "sk-none")).trim(), texts["keys.secret.no_secret_key"]);
    });
  }
});


test("the_secret_key_is_not_shown_on_a_page_that_was_left_and_goes_when_the_tab_is_hidden", async () => {
  await withDom(async () => {
    // Left while the password was checked: the answer is dropped.
    const left = secretKeyView({ t: i18n("en").t, show: async () => ({ code: SK_CODE, qr: { size: 1, dark: () => true } }), status: { skBit: true, skStored: true }, win: {} });
    left.isConnected = false;
    await fire(byRole(left, "sk-show"), "click");
    await settle();
    assert.equal(byRole(left, "sk-code"), null);
    assert.ok(!textOf(left).includes(SK_CODE));

    // Hidden tab: the key goes.
    const listeners = new Map();
    const doc = { visibilityState: "visible", addEventListener: (type, fn) => listeners.set(type, fn), removeEventListener: (type) => listeners.delete(type) };
    const page = secretKeyView({ t: i18n("en").t, show: async () => ({ code: SK_CODE, qr: { size: 1, dark: () => true } }), status: { skBit: true, skStored: true }, win: { document: doc } });
    await fire(byRole(page, "sk-show"), "click");
    await settle();
    assert.ok(byRole(page, "sk-code"));
    doc.visibilityState = "hidden";
    listeners.get("visibilitychange")();
    assert.equal(byRole(page, "sk-code"), null);
    assert.ok(!textOf(page).includes(SK_CODE));
    assert.equal(listeners.size, 0);

    // "Not remembered" is said once and the button goes.
    const once = secretKeyView({ t: i18n("en").t, show: async () => "not_remembered", status: { skBit: true, skStored: true }, win: {} });
    await fire(byRole(once, "sk-show"), "click");
    await settle();
    assert.equal(byRole(once, "sk-show"), null);
    assert.equal(textOf(once).split(catalog("en")["keys.secret.not_remembered"]).length, 2);
  });
});
