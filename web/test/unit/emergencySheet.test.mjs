// The emergency sheet as a PDF (spec Fase 1 § 6.1): page 1 has the access fields, the secret key and the
// QR code and no recovery key; page 2 has the recovery key and nothing else; the QR code decodes to the
// setup text; both pages say that a new browser needs both; a page 1 for an account with a secret key
// and no secret key is never made.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { accessPdf, checkAccessPage, httpWarning, pageTwoOnly, sheetPdf } from "../../src/flows/emergencySheet.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { web } from "./helpers.mjs";
import { ACCOUNT_ID, EMAIL, QR_TEXT, RK, SERVER_URL, SK, decodeQr, pages, rects, sheet, streams } from "./sheetHelpers.mjs";

const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "sheet.json"), "utf8"));
const i18n = (lang = "en") => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);

test("pdf_page_1_has_the_access_fields_the_secret_key_and_the_qr_and_no_recovery_key", () => {
  const { t } = i18n();
  const bytes = sheetPdf({ sheet: sheet(), t });
  const [one, two] = pages(bytes);
  assert.equal(pages(bytes).length, 2);
  const text = one.join("");
  for (const value of [SERVER_URL, EMAIL, ACCOUNT_ID, SK, QR_TEXT]) assert.ok(text.includes(value), `page 1 holds ${value}`);
  assert.ok(one.includes("1"), "the profile");
  assert.ok(one.includes(t("sheet.pdf.title_access")));
  for (const key of ["sheet.server", "sheet.email", "sheet.account_id", "sheet.profile", "sheet.secret_key"]) assert.ok(one.includes(t(key)), key);
  assert.ok(rects(streams(bytes)[0]).length > 0, "a QR code is drawn on page 1");
  assert.ok(!text.includes(RK.slice(0, 12)) && !text.includes("FFR1"), "no recovery key on page 1");
  assert.equal(rects(streams(bytes)[1]).length, 0, "no QR code on page 2");
  assert.ok(two.length > 0);
});

test("pdf_page_2_has_only_the_recovery_key", () => {
  const { t } = i18n();
  const bytes = sheetPdf({ sheet: sheet(), t });
  const two = pages(bytes)[1];
  assert.ok(two.join("").includes(RK), "the whole recovery key, in lines that read back as the key");
  assert.ok(two.includes(t("sheet.pdf.title_recovery")));
  for (const value of [SERVER_URL, EMAIL, ACCOUNT_ID, SK, "ferret-setup", "FFS1"]) assert.ok(!two.join("").includes(value), `page 2 holds no ${value}`);
  // The sheet without a page 1 is page 2 alone.
  const alone = sheetPdf({ sheet: pageTwoOnly(RK), t });
  assert.equal(pages(alone).length, 1);
  assert.deepEqual(pages(alone)[0], two);
});

test("the_qr_on_page_1_decodes_to_the_setup_text", () => {
  const { t } = i18n();
  assert.equal(decodeQr(streams(sheetPdf({ sheet: sheet(), t }))[0]), QR_TEXT);
  // The longest text a code carries (512 bytes) and a long address still fit on the page and decode.
  const long = `ferret-setup:v1?u=${"a".repeat(512 - 18 - 100)}&a=${"0".repeat(32)}&k=1&s=1&o=${"ab".repeat(32)}`.slice(0, 512);
  assert.ok(long.length <= 512);
  const big = sheet({ qr: long, server: `https://${"h".repeat(180)}.example.net` });
  assert.equal(decodeQr(streams(sheetPdf({ sheet: big, t }))[0]), long);
});

test("the_texts_say_both_pages_are_needed_on_a_new_browser_and_page_2_is_kept_apart", () => {
  const phrases = {
    en: { both: /both pages/, apart: /apart from page 1/ },
    nb: { both: /begge sidene/, apart: /adskilt fra side 1/ },
  };
  for (const lang of ["en", "nb"]) {
    const { t } = i18n(lang);
    const [one, two] = pages(sheetPdf({ sheet: sheet(), t })).map((lines) => lines.join(" "));
    // Both pages carry the sentence that a new browser needs both; page 2 also says to keep it apart.
    assert.match(one, phrases[lang].both, `${lang}: page 1`);
    assert.match(two, phrases[lang].both, `${lang}: page 2`);
    assert.match(two, phrases[lang].apart, `${lang}: page 2`);
    assert.doesNotMatch(one, phrases[lang].apart);
    assert.ok(!t("sheet.new_browser").startsWith("sheet."), "the text exists");
    // The promise is what the product does: the QR text and the secret key from page 1, the recovery key from page 2.
    assert.match(t("sheet.new_browser"), lang === "en" ? /QR code.*secret key.*page 1.*recovery key.*page 2/ : /QR-koden.*hemmelige nøkkelen.*side 1.*gjenopprettingsnøkkelen.*side 2/);
  }
});

test("access_pdf_has_page_1_only", () => {
  const { t } = i18n();
  const bytes = accessPdf({ access: sheet().access, t });
  const [one] = pages(bytes);
  assert.equal(pages(bytes).length, 1);
  assert.ok(one.join("").includes(SK) && one.join("").includes(QR_TEXT));
  assert.ok(!one.join("").includes("FFR1"));
  assert.equal(decodeQr(streams(bytes)[0]), QR_TEXT);
});

test("a_page_1_is_never_made_for_a_secret_key_the_sheet_lacks", () => {
  const { t } = i18n();
  // The QR text says "SK: yes" and the sheet has no secret key (the setup holds none after a renewal or a recovery).
  for (const missing of [null, ""]) {
    const broken = sheet({ secretKey: missing });
    assert.throws(() => sheetPdf({ sheet: broken, t }), /sheet_secret_key_mismatch/);
    assert.throws(() => accessPdf({ access: broken.access, t }), /sheet_secret_key_mismatch/);
  }
  // The other way round: a secret key on a sheet whose QR text says there is none.
  const noBit = sheet({ qr: QR_TEXT.replace("&s=1&", "&s=0&") });
  assert.throws(() => sheetPdf({ sheet: noBit, t }), /sheet_secret_key_mismatch/);
  // An account without a secret key is a sheet without one, with a QR text that says so.
  const plain = sheet({ secretKey: null, qr: QR_TEXT.replace("&s=1&", "&s=0&") });
  const bytes = sheetPdf({ sheet: plain, t });
  assert.ok(!pages(bytes)[0].includes(t("sheet.secret_key")));
  assert.equal(decodeQr(streams(bytes)[0]), plain.access.qr_payload);
  // The caller's own idea of whether the account has a secret key is checked too.
  assert.throws(() => checkAccessPage(plain.access, true), /sheet_secret_key_mismatch/);
  assert.throws(() => sheetPdf({ sheet: sheet({ qr: "" }), t }), /sheet_qr_missing/);
});

test("the_sheet_holds_ascii_values_only", () => {
  const { t } = i18n();
  for (const bad of [{ secretKey: "FFS1-ÆØÅ" }, { server: "https://vault.example.net/é" }]) {
    assert.throws(() => sheetPdf({ sheet: sheet(bad), t }), (e) => e instanceof TypeError && e.message === "sheet_non_ascii");
  }
  assert.throws(() => sheetPdf({ sheet: { ...sheet(), recoveryKeyCode: "FFR1-日本" }, t }), /sheet_non_ascii/);
  const withEmail = sheet();
  withEmail.access.email = "ada@exämple.test";
  assert.throws(() => sheetPdf({ sheet: withEmail, t }), /sheet_non_ascii/);
  // The texts of the page may use the letters of Norwegian: WinAnsi has them.
  assert.ok(pages(sheetPdf({ sheet: sheet(), t: i18n("nb").t }))[0].join(" ").includes("Tjener"));
});

test("the_pdf_of_a_sheet_has_no_active_content", () => {
  const { t } = i18n();
  const text = Buffer.from(sheetPdf({ sheet: sheet(), t })).toString("latin1");
  for (const forbidden of ["/JS", "/JavaScript", "/OpenAction", "/URI", "/AcroForm", "/Info", "/Metadata", "/Annots", "/Filter", "/EmbeddedFile"]) {
    assert.ok(!text.includes(forbidden), forbidden);
  }
});

test("http_warning_is_true_for_anything_but_https", () => {
  assert.equal(httpWarning("http://localhost:8080"), true);
  assert.equal(httpWarning("http://10.0.0.5"), true);
  assert.equal(httpWarning(""), true);
  assert.equal(httpWarning(undefined), true);
  assert.equal(httpWarning("https://vault.example.net"), false);
  assert.equal(httpWarning("HTTPS://vault.example.net"), false);
});
