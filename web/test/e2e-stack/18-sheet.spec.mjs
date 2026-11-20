// The emergency sheet of a new account, with the real core and the real server: the sheet on the screen, the QR code that
// the page draws, the PDF file that "Download" hands over (two pages, nothing in it but the sheet), and what the print view
// shows. This is the first scenario of the recovery run: it makes the account that the scenarios 19 to 26 start from, by the
// whole path a first user takes, so it needs an empty server.
import { readFileSync } from "node:fs";
import jsQR from "jsqr";
import { decodeQr, lines, streams } from "../unit/sheetHelpers.mjs";
import { addNeedle, adminUrl, confirmSheet, expect, fillSetup, freshContext, leave, noViolations, readSheet, remember, secrets, setupToken, test, vaultUrl } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

/**
 * The text that a decoder reads from the QR code that the page draws on a canvas (one pixel to a module).
 * @param {import("@playwright/test").Page} page
 */
async function decodeScreenQr(page) {
  const picture = await page.evaluate(() => {
    const canvas = /** @type {HTMLCanvasElement | null} */ (document.querySelector('[data-role="sheet-qr-image"]'));
    if (!canvas) return null;
    const data = canvas.getContext("2d")?.getImageData(0, 0, canvas.width, canvas.height);
    return data ? { width: canvas.width, height: canvas.height, pixels: Array.from(data.data) } : null;
  });
  expect(picture, "the page draws the QR code").not.toBeNull();
  const { width, height, pixels } = /** @type {NonNullable<typeof picture>} */ (picture);
  // Six pixels to a module, as a screen would show it.
  const scale = 6;
  const big = new Uint8ClampedArray(width * scale * height * scale * 4);
  for (let y = 0; y < height * scale; y += 1) {
    for (let x = 0; x < width * scale; x += 1) {
      const from = (Math.floor(y / scale) * width + Math.floor(x / scale)) * 4;
      const to = (y * width * scale + x) * 4;
      for (let c = 0; c < 4; c += 1) big[to + c] = pixels[from + c];
    }
  }
  const result = jsQR(big, width * scale, height * scale, { inversionAttempts: "dontInvert" });
  expect(result, "a decoder reads the QR code on the screen").not.toBeNull();
  return Buffer.from(/** @type {NonNullable<typeof result>} */ (result).binaryData).toString("utf8");
}

/** The text of the lines of a PDF page, joined as they were cut (the cuts keep every character). */
const joined = (/** @type {string} */ stream) => lines(stream).join("");

test("setup_downloads_a_two_page_pdf_and_prints_only_the_sheet", async ({ browser }, testInfo) => {
  test.setTimeout(300_000);
  const context = await freshContext(browser, { acceptDownloads: true });
  const page = await context.newPage();

  await page.goto(`${adminUrl}/setup?token=${setupToken}`);
  await expect(page.locator('[data-role="setup-page"]')).toBeVisible({ timeout: 20_000 });
  await fillSetup(page, { token: null });

  // The sheet on the screen: page 1 with the address, the e-mail, the account id, the secret key and the QR text; page 2 with
  // the recovery key.
  const keys = await readSheet(page);
  const text = async (/** @type {string} */ role) => ((await page.locator(`[data-role="${role}"]`).textContent()) ?? "").trim();
  const server = await text("sheet-server");
  const email = await text("sheet-email");
  const accountId = await text("sheet-account-id");
  const qrText = await text("sheet-qr");
  expect(server).toBe(vaultUrl);
  expect(email).toBe(secrets.email);
  expect(accountId).toMatch(/^[0-9a-f-]{32,36}$/);
  expect(qrText).toMatch(/^ferret-setup:v1\?/);
  expect(keys.secretKey).toMatch(/^FFS1-/);
  expect(keys.recoveryKey).toMatch(/^FFR1-/);
  secrets.recoveryKey = keys.recoveryKey;
  secrets.secretKey = keys.secretKey;
  secrets.qrText = qrText;
  remember();
  addNeedle("setup recovery key", keys.recoveryKey);
  addNeedle("setup secret key", keys.secretKey);
  addNeedle("setup qr text", qrText);
  addNeedle("setup password", secrets.password);

  // The QR code that the page draws says what the text under it says.
  expect(await decodeScreenQr(page), "the QR code on the screen holds the setup text").toBe(qrText);
  // The recovery key is on its own part of the page, and not among the fields of page 1.
  await expect(page.locator('[data-role="sheet"] [data-role="sheet-recovery-key"]')).toHaveCount(0);
  await expect(page.locator('[data-role="sheet-recovery"] [data-role="sheet-recovery-key"]')).toHaveCount(1);

  // ---- Download: a warning first, the file only after the second click.
  let downloads = 0;
  page.on("download", () => {
    downloads += 1;
  });
  await page.locator('[data-role="download"]').click();
  await expect(page.locator('[data-role="download-warning"]')).toBeVisible();
  await expect(page.locator('[data-role="download-warning"]')).toContainText(/sync/i);
  await page.waitForTimeout(500);
  expect(downloads, "no file before the warning is answered").toBe(0);
  await page.locator('[data-role="download-cancel"]').click();
  await expect(page.locator('[data-role="download-warning"]')).toHaveCount(0);
  await page.waitForTimeout(500);
  expect(downloads, "no file after Cancel").toBe(0);

  await page.locator('[data-role="download"]').click();
  const [download] = await Promise.all([page.waitForEvent("download", { timeout: 30_000 }), page.locator('[data-role="download-continue"]').click()]);
  expect(download.suggestedFilename()).toBe("ferret-emergency-sheet.pdf");
  const file = await download.path();
  const bytes = readFileSync(/** @type {string} */ (file));
  expect(bytes.subarray(0, 8).toString("latin1"), "a PDF 1.7 file").toBe("%PDF-1.7");

  // Two pages. Page 1: the address, the e-mail, the account id, the secret key, the QR code and its text. Page 2: the recovery
  // key and nothing of page 1.
  const pages = streams(bytes);
  expect(pages.length, "two pages").toBe(2);
  expect(bytes.toString("latin1")).toMatch(/\/Count 2\b/);
  const one = joined(pages[0]);
  const two = joined(pages[1]);
  expect(one).toContain(server);
  expect(one).toContain(email);
  expect(one).toContain(accountId);
  expect(one).toContain(keys.secretKey);
  expect(one).toContain(qrText);
  expect(one, "page 1 does not hold the recovery key").not.toContain(keys.recoveryKey);
  expect(one).not.toContain(keys.recoveryKey.slice(5, 25));
  expect(two).toContain(keys.recoveryKey);
  for (const [name, value] of [["the secret key", keys.secretKey], ["the e-mail", email], ["the account id", accountId], ["the QR text", qrText], ["the address", server]]) {
    expect(two, `page 2 does not hold ${name}`).not.toContain(value);
  }
  // The QR code of the file, read back from its rectangles, says the setup text too.
  expect(decodeQr(pages[0]), "the QR code in the file holds the setup text").toBe(qrText);
  // Nothing in the file that a reader could run, follow, fill in or learn about the writer from.
  const raw = bytes.toString("latin1");
  for (const marker of ["/JavaScript", "/JS", "/URI", "/Launch", "/AcroForm", "/OpenAction", "/EmbeddedFile", "/Info", "/Metadata", "/Annots", "/Encrypt", "/Producer", "/Creator", "/CreationDate"]) {
    expect(raw, `the file has no ${marker}`).not.toContain(marker);
  }
  // The file is saved for the review (a made-up sheet: the account of this run is thrown away).
  await testInfo.attach("ferret-emergency-sheet.pdf", { body: bytes, contentType: "application/pdf" });

  // ---- Print: the button asks the browser to print, and what prints is the sheet and nothing else.
  await page.evaluate(() => {
    const w = /** @type {any} */ (window);
    w.__printed = 0;
    w.print = () => {
      w.__printed += 1;
    };
  });
  await page.locator('[data-role="print"]').click();
  expect(await page.evaluate(() => /** @type {any} */ (window).__printed), "Print asks the browser to print once").toBe(1);
  expect(downloads, "printing makes no file").toBe(1);

  await page.emulateMedia({ media: "print" });
  // Out of the print view: the form that asks for the keys, the buttons, the status lines, the footer.
  await expect(page.locator('[data-role="confirm-form"]')).toBeHidden();
  await expect(page.locator('[data-role="download"]')).toBeHidden();
  await expect(page.locator('[data-role="print"]')).toBeHidden();
  // In it: both pages, the sentence that page 2 repeats on paper, and the QR code.
  await expect(page.locator('[data-role="sheet"]')).toBeVisible();
  await expect(page.locator('[data-role="sheet-recovery"]')).toBeVisible();
  await expect(page.locator('[data-role="new-browser-print"]')).toBeVisible();
  await expect(page.locator('[data-role="sheet-qr-image"]')).toBeVisible();
  const printView = await page.evaluate(() => {
    const visible = (/** @type {Element} */ node) => {
      const style = getComputedStyle(node);
      return style.display !== "none" && style.visibility !== "hidden";
    };
    const outside = Array.from(document.body.children).filter((node) => node.id !== "app" && visible(node)).map((node) => node.tagName + (node.id ? `#${node.id}` : ""));
    const pageTwo = document.querySelector(".sheet-page-two");
    const style = pageTwo ? getComputedStyle(pageTwo) : null;
    return {
      outside,
      breakBefore: style ? (style.breakBefore || style.getPropertyValue("page-break-before")) : null,
      text: document.body.innerText,
    };
  });
  expect(printView.outside, "nothing outside the sheet prints").toEqual([]);
  expect(["page", "always", "left", "right"], "the recovery key starts a sheet of paper of its own").toContain(printView.breakBefore);
  expect(printView.text).toContain(keys.secretKey);
  expect(printView.text).toContain(keys.recoveryKey);
  expect(printView.text).toContain(qrText);
  if (testInfo.project.name === "chromium") {
    // Chromium can make the print file itself: the sheet is at least two sheets of paper, and the page is not part of it.
    const printed = await page.pdf({ format: "A4", printBackground: false });
    const count = (printed.toString("latin1").match(/\/Type\s*\/Page[^s]/g) ?? []).length;
    expect(count, "the printed sheet is two sheets of paper or more").toBeGreaterThanOrEqual(2);
  }
  await page.emulateMedia({ media: "screen" });
  await expect(page.locator('[data-role="confirm-form"]')).toBeVisible();

  // ---- The sheet is typed back and the account is made; the file and the sheet are the user's, the page forgets them.
  await confirmSheet(page, keys);
  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
  await context.close();
  leave("m3-18", { done: true });
});
