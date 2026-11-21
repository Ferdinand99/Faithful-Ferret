// Page 1 of the emergency sheet again: one page, made after the password check from this device's record
// and the secret key it remembers, never page 2, never a page 1 that leaves out a secret key the account
// has; the page warns before the file is saved and zeroes the bytes after.
import assert from "node:assert/strict";
import { test } from "node:test";
import { loadPinned } from "../../src/store/pinned.mjs";
import { accessSheetView } from "../../src/views/secretKey.mjs";
import { byRole, coded, fire, settle, textOf } from "./accountHelpers.mjs";
import { SK_CODE } from "./securityHelpers.mjs";
import { decodeQr, pages, streams } from "./sheetHelpers.mjs";
import { ACCOUNT, EMAIL, RK_CODE, SERVER, catalog, i18n, keysWorld, reauthWith, withDom } from "./keysHelpers.mjs";

/** A world whose record holds the server's key, as a sign-in with the sheet pins it. */
async function withServerKey(options) {
  const world = await keysWorld(options);
  const record = await loadPinned(world.db.store, SERVER, EMAIL);
  await world.store.savePinned(world.db.store, SERVER, ACCOUNT, EMAIL, { ...record, server_public_key: new Uint8Array(32).fill(9) });
  return world;
}

test("access_sheet_reprint_has_page_1_only", async () => {
  const world = await withServerKey();
  const t = i18n("en").t;
  // A cancelled password check makes nothing.
  await assert.rejects(world.session.accessSheet({ reauth: reauthWith(world, "cancelled"), t }), { code: "cancelled" });
  assert.equal(world.client.called("setup_qr_build").length, 0);

  const bytes = await world.session.accessSheet({ reauth: reauthWith(world), t });
  const text = pages(bytes);
  assert.equal(text.length, 1, "one page");
  const page = text[0].join("\n");
  assert.ok(page.includes(catalog("en")["sheet.pdf.title_access"]));
  // Page 1: the address, the e-mail, the account id as a UUID, the secret key and the setup text.
  assert.ok(page.includes(SERVER));
  assert.ok(page.includes(EMAIL));
  assert.ok(page.includes("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"));
  assert.ok(page.replace(/\n/g, "").includes(SK_CODE));
  // Never page 2: no recovery key, no FFR1 at all.
  assert.ok(!page.includes("FFR1"));
  assert.ok(!page.includes(RK_CODE));
  // The QR code is the setup text the core built for this record, with the secret key bit set.
  const [server, accountId, profile, skBit, serverKey] = world.client.called("setup_qr_build")[0].snapshot;
  assert.equal(server, SERVER);
  assert.equal(Buffer.from(accountId).toString("hex"), ACCOUNT);
  assert.equal(profile, 1);
  assert.equal(skBit, true);
  assert.deepEqual(serverKey, new Uint8Array(32).fill(9));
  assert.match(decodeQr(streams(bytes)[0]), /^ferret-setup:v1\?.*&s=1&/);
  // Nothing went to the server but the question who the session is.
  assert.ok(world.requests.every((r) => r.method === "GET" && r.url === "/api/auth/session"));

  // An account without a secret key: page 1 without one, and a QR text that says so.
  const plain = await withServerKey({ skBit: false });
  const only = pages(await plain.session.accessSheet({ reauth: reauthWith(plain), t }));
  assert.equal(only.length, 1);
  assert.ok(!only[0].join("").includes("FFS1"));
  assert.equal(plain.client.called("setup_qr_build")[0].snapshot[3], false);
});

test("no_page_1_is_made_without_the_secret_key_or_the_server_key", async () => {
  const t = i18n("en").t;
  // The device forgot the secret key: refused before the password is asked for.
  const forgot = await withServerKey({ forgetKey: true });
  await assert.rejects(forgot.session.accessSheet({ reauth: reauthWith(forgot), t }), { code: "sk_not_remembered" });
  assert.ok(!forgot.log.includes("reauth"));
  // A record without the server's key cannot make the QR code.
  const old = await keysWorld();
  await assert.rejects(old.session.accessSheet({ reauth: reauthWith(old), t }), { code: "sheet_server_key_missing" });
  // A QR text that disagrees with the record about the secret key is never printed.
  const odd = await withServerKey({ handlers: { setup_qr_build: () => "ferret-setup:v1?u=x&a=y&k=1&s=0&o=z" } });
  await assert.rejects(odd.session.accessSheet({ reauth: reauthWith(odd), t }), /sheet_secret_key_mismatch/);
});

test("the_sheet_page_warns_before_the_file_and_zeroes_the_bytes", async () => {
  for (const lang of ["en", "nb"]) {
    await withDom(async () => {
      const texts = catalog(lang);
      const made = new Uint8Array([1, 2, 3, 4]);
      const handed = [];
      const page = accessSheetView({
        t: i18n(lang).t,
        make: async () => made,
        status: { skBit: true, skStored: true },
        download: (bytes, name, mime) => handed.push({ copy: bytes.slice(), name, mime }),
      });
      // Page 2 is not offered again; the way to a new one is.
      assert.equal(textOf(byRole(page, "sheet-page-two")).includes(texts["keys.sheet.page_two"]), true);
      assert.equal(byRole(page, "sheet-new-key").getAttribute("href"), "#/recovery-key");
      // The warning first, nothing made yet.
      await fire(byRole(page, "sheet-download"), "click");
      assert.ok(textOf(byRole(page, "sheet-download-warning")).includes(texts["keys.sheet.download_warning"]));
      assert.equal(handed.length, 0);
      await fire(byRole(page, "sheet-download-continue"), "click");
      await settle();
      assert.equal(handed.length, 1);
      assert.deepEqual([...handed[0].copy], [1, 2, 3, 4]);
      assert.equal(handed[0].name, "ferret-emergency-sheet-page-1.pdf");
      assert.equal(handed[0].mime, "application/pdf");
      assert.ok(made.every((n) => n === 0), "the bytes are zeroed after the hand-over");

      // A refusal has its text; a PDF that could not be made has a fixed one.
      const refused = accessSheetView({ t: i18n(lang).t, make: async () => Promise.reject(coded("sk_not_remembered")), download: () => {} });
      await fire(byRole(refused, "sheet-download"), "click");
      await fire(byRole(refused, "sheet-download-continue"), "click");
      await settle();
      assert.equal(textOf(byRole(refused, "sheet-error")).trim(), texts["keys.error.sk_not_remembered"]);
      const broken = accessSheetView({ t: i18n(lang).t, make: async () => Promise.reject(new TypeError("sheet_non_ascii")), download: () => {} });
      await fire(byRole(broken, "sheet-download"), "click");
      await fire(byRole(broken, "sheet-download-continue"), "click");
      await settle();
      assert.equal(textOf(byRole(broken, "sheet-error")).trim(), texts["keys.sheet.failed"]);

      // Without a remembered key there is no button, and the page says why.
      const without = accessSheetView({ t: i18n(lang).t, make: async () => made, status: { skBit: true, skStored: false } });
      assert.equal(byRole(without, "sheet-download"), null);
      assert.equal(textOf(byRole(without, "sheet-not-remembered")).trim(), texts["keys.sheet.not_remembered"]);
    });
  }
});
