// The emergency sheet on the screen: the download that warns first and wipes its bytes, the print version,
// the cleartext warning, the modes for a new recovery key, and the sheet leaving the page after the check.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createI18n } from "../../src/i18n.mjs";
import { sheetView } from "../../src/views/sheet.mjs";
import { accountDocument, byRole, fire, settle, textOf, until, walk } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { QR_TEXT, RK, SK, decodeQr, pages, sheet, streams } from "./sheetHelpers.mjs";

const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "sheet.json"), "utf8"));
const i18n = (lang = "en") => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);

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

/** A view with recording stand-ins for the download, the print and the check. */
function make(options = {}) {
  const log = { downloads: [], prints: 0, confirms: [], snapshots: [] };
  const view = sheetView({
    t: i18n().t,
    sheet: sheet(),
    useSecretKey: true,
    onConfirm: async (rk, sk) => {
      log.confirms.push([rk, sk]);
    },
    download: (bytes, name, mime) => {
      log.downloads.push({ bytes, name, mime });
      // What the file held when it was handed over.
      log.snapshots.push(Uint8Array.from(bytes));
    },
    print: () => {
      log.prints += 1;
    },
    ...options,
  });
  return { view, log };
}

const hidden = (node) => node.hidden === true;

test("download_warns_about_synced_folders_first", async () => {
  await withDom(async () => {
    const { view, log } = make();
    assert.equal(byRole(view.root, "download-warning"), null, "no warning before the click");
    await fire(byRole(view.root, "download"), "click");
    // The warning is up and nothing has been made or saved yet.
    const warning = byRole(view.root, "download-warning");
    assert.ok(warning);
    assert.equal(log.downloads.length, 0);
    const words = textOf(warning);
    assert.match(words, /synced|backed up/);
    assert.match(words, /OneDrive/);
    // Cancel: nothing is saved.
    await fire(byRole(view.root, "download-cancel"), "click");
    assert.equal(byRole(view.root, "download-warning"), null);
    assert.equal(log.downloads.length, 0);
    // Continue: one file, a PDF with a fixed name.
    await fire(byRole(view.root, "download"), "click");
    await fire(byRole(view.root, "download-continue"), "click");
    assert.equal(log.downloads.length, 1);
    assert.equal(log.downloads[0].mime, "application/pdf");
    assert.match(log.downloads[0].name, /^[a-z-]+\.pdf$/);
    assert.equal(byRole(view.root, "download-warning"), null);
    // The Norwegian warning says the same.
    const nb = make({ t: i18n("nb").t });
    await fire(byRole(nb.view.root, "download"), "click");
    assert.match(textOf(byRole(nb.view.root, "download-warning")), /synkroniseres|skyen/);
  });
});

test("the_file_that_is_handed_over_is_the_sheet", async () => {
  await withDom(async () => {
    const { view, log } = make();
    await fire(byRole(view.root, "download"), "click");
    await fire(byRole(view.root, "download-continue"), "click");
    const bytes = log.snapshots[0];
    assert.equal(pages(bytes).length, 2);
    assert.equal(decodeQr(streams(bytes)[0]), QR_TEXT);
    assert.ok(pages(bytes)[0].join("").includes(SK));
    assert.ok(pages(bytes)[1].join("").includes(RK));
  });
});

test("pdf_bytes_are_wiped_after_the_download", async () => {
  await withDom(async () => {
    const { view, log } = make();
    await fire(byRole(view.root, "download"), "click");
    await fire(byRole(view.root, "download-continue"), "click");
    assert.equal(log.downloads.length, 1);
    const { bytes } = log.downloads[0];
    assert.ok(log.snapshots[0].some((b) => b !== 0), "the file had content at the hand-over");
    assert.ok(bytes.every((b) => b === 0), "the bytes are zero after it");
    // A download that fails wipes the bytes too, and says so with a fixed text.
    let kept;
    const failing = make({
      download: (b) => {
        kept = b;
        throw new Error("the disk is full and the name of ada@example.test");
      },
    });
    await fire(byRole(failing.view.root, "download"), "click");
    await fire(byRole(failing.view.root, "download-continue"), "click");
    assert.ok(kept.every((b) => b === 0));
    const error = byRole(failing.view.root, "error");
    assert.ok(!hidden(error));
    assert.equal(textOf(error).trim(), i18n().t("sheet.download_failed"));
  });
});

test("print_css_hides_everything_but_the_sheet_and_puts_page_2_on_its_own_page", async () => {
  const css = readFileSync(join(web, "src", "styles", "sheet.css"), "utf8");
  const print = css.slice(css.indexOf("@media print"));
  assert.ok(print.startsWith("@media print"));
  // Everything outside the page of the sheet, the buttons, the forms and the typing-back part are not printed.
  assert.match(print, /body > :not\(#app\)/);
  assert.match(print, /\.no-print/);
  assert.match(print, /\.account \.btn/);
  assert.match(print, /\.account form/);
  // Page 2 starts a sheet of paper of its own, and the colours are the light ones in any theme.
  assert.match(print, /\.sheet-page-two\s*\{[^}]*break-before:\s*page/);
  assert.match(print, /color-scheme:\s*light/);
  // The view carries the classes the styles hang on.
  await withDom(async () => {
    const { view } = make();
    const all = [...walk(view.root)];
    const two = all.find((n) => n.tagName === "h2" && n.getAttribute("class") === "sheet-page-two");
    assert.ok(two, "page 2 has its own heading with the break");
    assert.ok(textOf(two).includes("Page 2"));
    const noPrint = all.filter((n) => (n.getAttribute?.("class") ?? "").split(" ").includes("no-print"));
    // The buttons and the part where the keys are typed back stay off the paper.
    assert.ok(noPrint.length >= 3);
    assert.ok(noPrint.some((n) => [...walk(n)].includes(byRole(view.root, "print"))));
    // The screen version holds what the paper should: the page 1 fields, the QR text and the recovery key.
    for (const role of ["sheet-server", "sheet-email", "sheet-account-id", "sheet-secret-key", "sheet-qr", "sheet-recovery-key"]) assert.ok(byRole(view.root, role), role);
  });
  // No file leaves with a print.
  await withDom(async () => {
    const { view, log } = make();
    await fire(byRole(view.root, "print"), "click");
    assert.equal(log.prints, 1);
    assert.equal(log.downloads.length, 0);
  });
});

test("an_http_localhost_server_gets_the_cleartext_warning", async () => {
  await withDom(async () => {
    const plain = make({ sheet: sheet({ server: "http://localhost:8080" }) });
    assert.ok(byRole(plain.view.root, "http-warning"));
    assert.match(textOf(byRole(plain.view.root, "http-warning")), /plain http/);
    // The warning is repeated where the file is about to be saved.
    await fire(byRole(plain.view.root, "download"), "click");
    assert.match(textOf(byRole(plain.view.root, "download-warning")), /plain http/);
    const secure = make();
    assert.equal(byRole(secure.view.root, "http-warning"), null);
    assert.doesNotMatch(textOf(secure.view.root), /plain http/);
  });
});

test("recover_and_renew_modes_ask_only_for_the_new_recovery_key", async () => {
  await withDom(async () => {
    for (const mode of ["recover", "renew"]) {
      const { view, log } = make({ mode, useSecretKey: true });
      // Page 2 and the form for the new recovery key; no page 1, no secret key, no QR code.
      assert.ok(byRole(view.root, "sheet-recovery-key"), mode);
      assert.equal(byRole(view.root, "sheet"), null, mode);
      assert.equal(byRole(view.root, "sheet-secret-key"), null, mode);
      assert.equal(byRole(view.root, "sheet-qr"), null, mode);
      assert.equal(byRole(view.root, "sheet-qr-image"), null, mode);
      assert.ok(byRole(view.root, "page-one-unchanged"), mode);
      assert.ok(byRole(view.root, "rk-typed"), mode);
      assert.equal(byRole(view.root, "sk-typed"), null, mode);
      assert.ok(!textOf(view.root).includes(SK), mode);
      byRole(view.root, "rk-typed").value = RK;
      await fire(byRole(view.root, "confirm-form"), "submit");
      await settle();
      assert.deepEqual(log.confirms, [[RK, ""]], mode);
      // The file of such a sheet is page 2 alone.
      const again = make({ mode });
      await fire(byRole(again.view.root, "download"), "click");
      await fire(byRole(again.view.root, "download-continue"), "click");
      assert.equal(pages(again.log.snapshots[0]).length, 1, mode);
      assert.ok(pages(again.log.snapshots[0])[0].join("").includes(RK));
      assert.ok(!pages(again.log.snapshots[0])[0].join("").includes("ferret-setup"));
    }
    // A setup asks for both keys.
    const setup = make();
    assert.ok(byRole(setup.view.root, "rk-typed") && byRole(setup.view.root, "sk-typed"));
  });
});

test("a_sheet_without_a_usable_page_1_shows_page_2_only_and_never_a_qr_without_the_secret_key", async () => {
  await withDom(async () => {
    const cases = [
      ["no page 1", { sheet: { access: null, recoveryKeyCode: RK }, useSecretKey: true }],
      // The core refused page 1 or the account lost its secret key: the QR text still says "SK: yes".
      ["no secret key", { sheet: sheet({ secretKey: null }), useSecretKey: true }],
      ["empty secret key", { sheet: sheet({ secretKey: "" }), useSecretKey: true }],
      ["the caller expects a secret key", { sheet: sheet({ secretKey: null, qr: QR_TEXT.replace("&s=1&", "&s=0&") }), useSecretKey: true }],
    ];
    for (const [name, options] of cases) {
      const { view, log } = make(options);
      assert.equal(byRole(view.root, "sheet"), null, name);
      assert.equal(byRole(view.root, "sheet-qr"), null, name);
      assert.equal(byRole(view.root, "sheet-qr-image"), null, name);
      assert.ok(byRole(view.root, "page-one-missing"), name);
      assert.ok(byRole(view.root, "sheet-recovery-key"), name);
      assert.ok(!textOf(view.root).includes("ferret-setup"), name);
      await fire(byRole(view.root, "download"), "click");
      await fire(byRole(view.root, "download-continue"), "click");
      assert.equal(pages(log.snapshots[0]).length, 1, name);
    }
    // A sheet that is whole has no such notice.
    assert.equal(byRole(make().view.root, "page-one-missing"), null);
  });
});

test("the_sheet_leaves_the_page_after_confirmation", async () => {
  await withDom(async () => {
    const { view, log } = make();
    assert.ok(textOf(view.root).includes(RK) && textOf(view.root).includes(SK));
    await fire(byRole(view.root, "download"), "click");
    const proceed = byRole(view.root, "download-continue");
    byRole(view.root, "rk-typed").value = RK;
    byRole(view.root, "sk-typed").value = SK;
    await fire(byRole(view.root, "confirm-form"), "submit");
    await until(() => view.root.childNodes.length === 0);
    // The fields were emptied before the check ran; the sheet, the QR text and the form are gone.
    assert.deepEqual(log.confirms, [[RK, SK]]);
    const left = textOf(view.root);
    for (const secret of [RK, SK, QR_TEXT, "ada@example.test", "ferret-setup"]) assert.ok(!left.includes(secret), secret);
    assert.equal([...walk(view.root)].length, 1, "nothing is left below the card");
    // After the wipe the file cannot be made any more.
    await fire(proceed, "click");
    assert.equal(log.downloads.length, 0);
  });
});

test("a_failed_check_keeps_the_sheet_and_the_form", async () => {
  await withDom(async () => {
    const { view } = make({
      onConfirm: async () => {
        throw Object.assign(new Error("checksum"), { code: "checksum" });
      },
    });
    byRole(view.root, "rk-typed").value = "FFR1-WRONG";
    byRole(view.root, "sk-typed").value = SK;
    await fire(byRole(view.root, "confirm-form"), "submit");
    await until(() => !hidden(byRole(view.root, "error")));
    assert.ok(byRole(view.root, "sheet-recovery-key"));
    assert.ok(byRole(view.root, "confirm-form"));
    assert.equal(byRole(view.root, "rk-typed").value, "", "what was typed is emptied");
  });
});

test("sheet_texts_exist_in_both_languages", () => {
  const en = catalog("en");
  const nb = catalog("nb");
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  const names = (s) => [...s.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
  for (const [key, value] of Object.entries(en)) {
    assert.ok(key.startsWith("sheet."), key);
    assert.ok(typeof value === "string" && value.length > 0 && typeof nb[key] === "string" && nb[key].length > 0, key);
    assert.deepEqual(names(nb[key]), names(value), key);
    assert.notEqual(nb[key], value, `${key} is translated`);
  }
  // Every key the sheet's sources ask for is in the catalog, and the old account.sheet keys are gone.
  const used = new Set();
  for (const file of ["views/sheet.mjs", "flows/emergencySheet.mjs", "views/setup.mjs"]) {
    const source = readFileSync(join(web, "src", file), "utf8");
    for (const m of source.matchAll(/["'](sheet\.[a-z_]+(?:\.[a-z_]+)*)["']/g)) used.add(m[1]);
  }
  assert.ok(used.size > 25, "the scan found the keys");
  assert.deepEqual([...used].filter((key) => !(key in en)), []);
  for (const lang of ["en", "nb"]) {
    for (const name of readdirSync(join(web, "src", "locales", lang))) {
      const keys = Object.keys(JSON.parse(readFileSync(join(web, "src", "locales", lang, name), "utf8")));
      assert.deepEqual(keys.filter((key) => key.startsWith("account.sheet.")), [], `${lang}/${name}`);
    }
  }
});
